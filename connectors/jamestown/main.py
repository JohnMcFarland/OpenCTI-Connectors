"""
The Jamestown Foundation OpenCTI connector.

Purpose
-------
External-import connector that ingests new analytical articles from
https://jamestown.org as container-only OpenCTI Reports, one per feed item, with
the live source page attached as a full-fidelity PDF.

Collection model (forward-only RSS)
-----------------------------------
The Jamestown origin (nginx behind Cloudflare) blocks the WordPress REST API
(/wp-json/) and the XML sitemaps (/sitemap*.xml): both return HTTP 403 to a plain
HTTP client, to headless Chromium, and to a cleared same-origin in-page fetch. The
only reachable structured surface is the main RSS feed at {base_url}/feed/
(HTTP 200, valid RSS 2.0), and individual article pages render at 200.

Collection is therefore a single forward poll of the main feed:

  - GET {base_url}/feed/ with a plain requests.Session (browser UA), parsed with
    feedparser. Per item the connector reads link, title, summary/description,
    pubDate, and category terms.

RSS exposes only a recent-items window, not the archive, so collection is
FORWARD-ONLY from the moment the connector is turned on. Full historical backfill
is not achievable on this origin. This supersedes the prior (2026-06-26) decision
to ingest the entire corpus via the API/sitemap (see CONNECTOR_SCOPE.md).

Per-item publication date comes from the RSS pubDate (RFC 822), parsed to a
timezone-aware datetime and emitted as ISO 8601. An item with no parseable pubDate
is skipped (never dated to ingestion time). Playwright is used purely to render the
article page to PDF: the feed fetch itself never goes through Playwright.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id) and
skips if the Report already exists. For a new item it creates the External
Reference (upsert-safe), then the Report (with the deterministic stix_id), then
attaches the PDF. Because the existence check keys on the Report id (not on the
External Reference), every sub-write is idempotent and a crash anywhere leaves the
item still "not done"; the next poll re-enters and completes it while the item is
still in the feed window. No compensating deletes, no orphan-marker suppression.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects, no
Observables, no Relationships, no Labels. Named-entity / IOC extraction is a
separate, out-of-scope downstream phase. Keeping this connector container-only
makes it purely additive and prevents it from acting as a graph-contamination
vector.

Key decisions (see CONNECTOR_SCOPE.md)
--------------------------------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published think-tank source).
- Author: the single "The Jamestown Foundation" Organization identity. Never the
  connector account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (Medium band: expert secondary analysis built
  on primary sources).
- Category terms are observed (logged once per cycle) but NOT bound to Reports.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import time
import html
import uuid
from email.utils import parsedate_to_datetime

import requests
import feedparser
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside the renderer so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Browser User-Agent for BOTH the feed HTTP client and the Playwright context. A
# realistic UA keeps fetching and rendering consistent and avoids UA gating
# (Jamestown is Cloudflare-fronted).
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Recycle the Chromium browser after this many renders to cap memory growth on a
# host that co-locates Elasticsearch.
BROWSER_RECYCLE_EVERY = 50

# Substrings indicating a Cloudflare interstitial rather than article content.
CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")


def _strip_html(value: str) -> str:
    """Strip tags and decode HTML entities from a text fragment.

    Args:
        value: raw string that may contain tags/entities (may be empty/None).

    Returns:
        Plain text, tags removed and entities decoded.
    """
    if not value:
        return ""
    no_tags = re.sub(r"<[^>]+>", "", value)
    return html.unescape(no_tags).strip()


class JamestownConnector:
    """External-import connector that mirrors Jamestown feed items into Reports."""

    def __init__(self):
        """Load configuration, build the OpenCTI helper, and prepare the HTTP
        client. Fixed graph references are resolved later in run() via
        _resolve_graph_references().
        """
        config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        # --- Source configuration ------------------------------------------ #
        self.base_url = get_config_variable(
            "JAMESTOWN_BASE_URL", ["jamestown", "base_url"], config,
            default="https://jamestown.org",
        ).rstrip("/")

        # Main RSS feed. Defaults to {base_url}/feed/; overridable for testing or
        # if the origin moves the feed.
        self.feed_url = get_config_variable(
            "JAMESTOWN_FEED_URL", ["jamestown", "feed_url"], config,
            default="",
        ) or f"{self.base_url}/feed/"

        # Poll interval (seconds) between forward feed polls. Hourly by default so
        # the recent-items window is sampled often enough to avoid dropping items.
        self.poll_interval = get_config_variable(
            "JAMESTOWN_POLL_INTERVAL", ["jamestown", "poll_interval"], config,
            isNumber=True, default=3600,  # 1 hour
        )

        # Politeness delay (seconds) between successive renders.
        self.request_delay = get_config_variable(
            "JAMESTOWN_REQUEST_DELAY", ["jamestown", "request_delay"], config,
            isNumber=True, default=2,
        )

        # Per-run cap on new Reports. 0 == unlimited. Set small (e.g. 3) for a
        # bounded test.
        self.max_reports = get_config_variable(
            "JAMESTOWN_MAX_REPORTS", ["jamestown", "max_reports"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ------------------------------------------ #
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["jamestown", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "JAMESTOWN_RENDER_RETRIES", ["jamestown", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        # OpenCTI confidence 0-100. Medium band: expert secondary analysis on
        # primary sources.
        self.confidence = get_config_variable(
            "JAMESTOWN_CONFIDENCE", ["jamestown", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "JAMESTOWN_REPORT_TYPE", ["jamestown", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "JAMESTOWN_TLP", ["jamestown", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "JAMESTOWN_AUTHOR_NAME", ["jamestown", "author_name"], config,
            default="The Jamestown Foundation",
        )

        # HTTP session for the feed fetch: browser UA + feed/XML accept.
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "application/rss+xml, application/xml, text/xml, */*",
        })

        # Resolved at startup.
        self.author_id = None          # author Organization internal UUID
        self.marking_id = None         # TLP marking internal UUID

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Resolve fixed graph objects and probe the feed.

        Resolves internal OpenCTI UUIDs for the author identity and the TLP
        marking, registers the report_type vocabulary value, and probes the feed
        once. The marking resolution is fail-closed (raises). The feed probe is
        NOT fail-closed: the feed is known-good, so a transient Cloudflare blip at
        startup is logged and the connector enters the poll loop anyway rather than
        crash-looping the container.

        Raises:
            RuntimeError: if the marking cannot be resolved, since Reports must not
                be created without a resolved marking UUID.
        """
        # Author: identity.create is upsert-safe (returns existing if present).
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Washington, D.C. think tank providing primary-source intelligence "
                        "and analysis on Eurasia, China, and global terrorism. Source "
                        "organization for ingested reports.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved author identity '{self.author_name}': {self.author_id}")

        # Marking: read to an internal UUID (TLP markings ship with the platform).
        marking = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [self.tlp_name]}],
                "filterGroups": [],
            }
        )
        if not marking:
            raise RuntimeError(
                f"Could not resolve marking '{self.tlp_name}'. Refusing to create "
                f"Reports without a resolved marking UUID."
            )
        self.marking_id = marking["id"]
        self.helper.log_info(f"Resolved marking {self.tlp_name}: {self.marking_id}")

        # report_type open-vocabulary registration. Idempotent; harmless failure if
        # the vocabulary is locked (operator adds it via Settings).
        try:
            self.helper.api.vocabulary.create(
                name=self.report_type,
                category="report_types_ov",
                description="Open-source reporting ingested from public OSINT publishers.",
            )
            self.helper.log_info(f"Ensured report_type vocabulary value: {self.report_type}")
        except Exception as exc:  # noqa: BLE001 - non-fatal, operator-actionable
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc}). "
                f"Add it under Settings -> Taxonomies -> Report types if missing."
            )

        # Feed probe (non-fatal). Logs reachability and the item count.
        feed = self._fetch_feed()
        if feed is None:
            self.helper.log_error(
                f"Feed {self.feed_url} unreachable at startup; entering poll loop "
                f"anyway and retrying next cycle."
            )
        else:
            self.helper.log_info(
                f"Feed reachable at {self.feed_url}: {len(feed.entries)} items in window."
            )

    # ------------------------------------------------------------------ #
    # Feed fetch and helpers
    # ------------------------------------------------------------------ #

    def _fetch_feed(self):
        """Fetch and parse the main RSS feed with the plain HTTP session.

        The feed fetch deliberately does NOT use Playwright (Playwright is for
        rendering article pages only).

        Returns:
            feedparser.FeedParserDict on success, or None on any fetch/HTTP error.
        """
        try:
            resp = self.session.get(self.feed_url, timeout=60)
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001 - cycle is skipped on failure
            self.helper.log_error(f"Failed to fetch feed {self.feed_url}: {exc}")
            return None
        return feedparser.parse(resp.content)

    @staticmethod
    def _report_id(link):
        """Deterministic Report STIX id derived from the article URL.

        Same URL always maps to the same Report id, which makes the existence
        check and every write idempotent.
        """
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))

    @staticmethod
    def _published_iso(entry):
        """Parse the RSS pubDate (RFC 822) to a timezone-aware ISO 8601 string.

        Returns:
            str ISO 8601 timestamp, or None if there is no parseable pubDate.
        """
        raw = entry.get("published") or entry.get("updated")
        if not raw:
            return None
        try:
            dt = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if dt is None:
            return None
        return dt.isoformat()

    @staticmethod
    def _entry_categories(entry):
        """Distinct category terms on a feed item (feedparser maps <category> to
        entry.tags[*].term).
        """
        terms = []
        for tag in entry.get("tags", []) or []:
            term = (tag.get("term") or "").strip()
            if term:
                terms.append(term)
        return terms

    # ------------------------------------------------------------------ #
    # PDF rendering (Playwright)
    # ------------------------------------------------------------------ #

    def _auto_scroll(self, page):
        """Scroll to the page bottom to trigger lazy-loaded media before render."""
        page.evaluate(
            """
            async () => {
              await new Promise((resolve) => {
                let total = 0;
                const step = 400;
                const timer = setInterval(() => {
                  window.scrollBy(0, step);
                  total += step;
                  if (total >= document.body.scrollHeight) {
                    clearInterval(timer);
                    window.scrollTo(0, 0);
                    resolve();
                  }
                }, 100);
              });
            }
            """
        )

    def _render_pdf(self, browser, url):
        """Render an article to PDF.

        Args:
            browser: active Playwright Chromium browser.
            url: canonical article URL.

        Returns:
            bytes: rendered article PDF.

        Raises:
            RuntimeError: on a Cloudflare challenge interstitial.
            playwright errors: navigation timeouts propagate for retry handling.
        """
        context = browser.new_context(
            viewport={"width": 1280, "height": 1696},
            user_agent=BROWSER_UA,
        )
        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)

            title = (page.title() or "").lower()
            if any(marker in title for marker in CHALLENGE_MARKERS):
                raise RuntimeError("Cloudflare challenge interstitial detected")

            self._auto_scroll(page)
            page.wait_for_timeout(1500)  # final settle for post-scroll loads

            from datetime import datetime, timezone
            ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            footer = (
                "<div style='font-size:8px; width:100%; padding:0 12px; "
                "color:#444; display:flex; justify-content:space-between;'>"
                f"<span>{html.escape(url)}</span>"
                f"<span>OpenCTI Jamestown connector &middot; ingested {ingested_at} "
                "&middot; page <span class='pageNumber'></span>/"
                "<span class='totalPages'></span></span></div>"
            )
            return page.pdf(
                print_background=True,
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=footer,
                margin={"top": "10mm", "bottom": "16mm", "left": "8mm", "right": "8mm"},
                format="A4",
            )
        finally:
            page.close()
            context.close()

    def _render_with_retry(self, browser, url):
        """Render with bounded exponential backoff.

        Returns:
            bytes: PDF on success, or None if all retries are exhausted.
        """
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._render_pdf(browser, url)
            except Exception as exc:  # noqa: BLE001 - retried, then skipped
                self.helper.log_warning(
                    f"Render attempt {attempt}/{self.render_retries} failed for {url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay *= 2
        return None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, entry, published, pdf_bytes):
        """Create one Report container for a feed item and attach its PDF.

        Container-only: no object_refs. The Report carries a deterministic stix_id
        derived from the article URL so the write is idempotent. Category terms are
        deliberately NOT written to the Report or the External Reference.

        Args:
            entry: feedparser entry.
            published: ISO 8601 published timestamp (already validated non-None).
            pdf_bytes: rendered article PDF.
        """
        url = entry.get("link")
        name = _strip_html(entry.get("title") or "") or url
        description = _strip_html(entry.get("summary") or "")
        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on jamestown.org",
        )

        report = self.helper.api.report.create(
            stix_id=report_id,
            name=name,
            description=description,
            published=published,
            report_types=[self.report_type],
            confidence=self.confidence,
            createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[external_reference["id"]],
            update=True,
        )

        slug = url.rstrip("/").rsplit("/", 1)[-1] or "report"
        file_name = f"jamestown-{slug}.pdf"
        self.helper.api.stix_domain_object.add_file(
            id=report["id"],
            file_name=file_name,
            data=pdf_bytes,
            mime_type="application/pdf",
        )
        self.helper.log_info(f"Created Report for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        """Execute one forward poll of the feed.

        Fetches the feed, logs the distinct category terms observed this cycle
        (not bound to Reports), then for each item: dedup-checks by deterministic
        Report id, renders new items, and creates Reports. Order is immaterial
        because dedup is per-item.
        """
        from playwright.sync_api import sync_playwright  # lazy import

        feed = self._fetch_feed()
        if feed is None:
            self.helper.log_warning("Feed fetch failed; skipping this cycle.")
            return

        entries = list(feed.entries)
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "The Jamestown Foundation feed poll"
        )
        self.helper.log_info(f"Fetched {len(entries)} feed items from {self.feed_url}.")

        # Observe category terms across the cycle; surface them once, bind nothing.
        observed = sorted({t for e in entries for t in self._entry_categories(e)})
        self.helper.log_info(
            f"Distinct feed categories observed (not bound to Reports): {observed}"
        )

        processed = 0   # new Reports created
        skipped = 0     # already present in the graph
        failed = 0      # render failed or unparseable date

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                for entry in entries:
                    url = entry.get("link")
                    if not url:
                        continue

                    if self.max_reports and processed >= self.max_reports:
                        self.helper.log_info(
                            f"Reached JAMESTOWN_MAX_REPORTS={self.max_reports}; stopping run."
                        )
                        break

                    # Dedup BEFORE rendering, keyed on the deterministic Report id.
                    report_id = self._report_id(url)
                    if self.helper.api.report.read(id=report_id) is not None:
                        skipped += 1
                        continue

                    # Skip items without a parseable pubDate rather than date them
                    # to ingestion time.
                    published = self._published_iso(entry)
                    if not published:
                        failed += 1
                        self.helper.log_warning(
                            f"Skipping {url}: no parseable pubDate."
                        )
                        continue

                    if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                        browser.close()
                        browser = pw.chromium.launch(
                            args=["--no-sandbox", "--disable-dev-shm-usage"]
                        )
                        renders_since_recycle = 0

                    pdf_bytes = self._render_with_retry(browser, url)
                    renders_since_recycle += 1

                    if pdf_bytes is None:
                        failed += 1
                        self.helper.log_warning(f"Skipping {url}: render failed after retries.")
                        continue

                    self._create_report(entry, published, pdf_bytes)
                    processed += 1
                    time.sleep(self.request_delay)
            finally:
                browser.close()

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render or unparseable date)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        """Connector entrypoint: resolve references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info("The Jamestown Foundation connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001 - keep the connector alive
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        JamestownConnector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
