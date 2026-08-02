"""
Palo Alto Networks Unit 42 OpenCTI connector.

Purpose
-------
External-import connector that ingests posts from the Unit 42 research blog
(https://unit42.paloaltonetworks.com) as container-only OpenCTI Reports, one per
post, with the live source page attached as a full-fidelity Playwright-rendered
PDF. Scoped by default to the "Threat Research" category.

Collection model (paginated category RSS feed + steady state)
-------------------------------------------------------------
Unit 42 is a WordPress site (Yoast). Its structured surfaces are unevenly gated by
the edge WAF: the WordPress REST API (/wp-json/wp/v2/posts) is hard-blocked (HTTP
403 "Forbidden" even to a browser User-Agent), but the per-category RSS feed and
the article pages return HTTP 200 to a browser UA. The category feed is therefore
the enumeration surface, because it is category-native (server-side filtered to the
chosen category) and paginated.

The feed lives at:
    {base}/category/{category}/feed/            (page 1)
    {base}/category/{category}/feed/?paged=N    (pages 2..last)
Page 1 MUST use the bare `/feed/` URL: `?paged=1` is edge-blocked and returns an
empty body. Each page carries 15 items newest-first; requesting a page past the
last one returns HTTP 404, which is the end-of-list signal. At the time of writing,
Threat Research spans ~61 pages (~915 posts).

Enumeration walks the feed from page 1 forward until the 404 end-of-list. Unlike the
Hellenic Shipping News / ScienceDaily connectors, this connector holds NO positional
cursor: an RSS feed is ordered newest-first and shifts every time a post is
published, so a persisted {page, index} cursor would silently mis-position. The
corpus is also two orders of magnitude smaller than those origins (~900 vs ~90k
posts), so re-walking the whole feed each poll is cheap. Correctness rests entirely
on graph-driven deduplication: each post maps to a deterministic Report STIX id
(uuid5 over the article URL), and the connector skips any post whose Report already
exists before rendering. New posts always receive the highest ids and land at the
front of page 1, so the same uniform forward walk covers both the historical
backfill and steady state.

Per-post title, excerpt (description), publication date, and link are read directly
from the feed item. Playwright is used purely to render the article page to PDF;
enumeration never goes through Playwright.

Publication date comes from the item's RFC-822 <pubDate>, parsed to UTC.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects, no
Observables, no Relationships, no Labels, no Indicators. Named-entity and IOC
extraction from the article body is a deliberately separate, downstream phase (the
"processor"); keeping this connector container-only makes it purely additive, keeps
it clear of the data-model relationship allowlist entirely, and prevents it from
acting as a graph-contamination vector. This mirrors the house pattern established by
the Hellenic Shipping News, Jamestown, ScienceDaily, and DFIR Report connectors.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id) and
skips if the Report already exists. For a new post it creates the External Reference
(upsert-safe), then the Report (with the deterministic stix_id), then attaches the
PDF. Because the existence check keys on the Report id (not on the External
Reference), every sub-write is idempotent and a crash anywhere leaves the post still
"not done"; the next poll re-enters and completes it. There is no state file and no
cursor: the graph lookup is the sole correctness backstop.

Key decisions (see CONNECTOR_SCOPE.md)
--------------------------------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published vendor research).
- Author: the single "Unit 42" Organization identity. Never the connector account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band), matching the other OSINT-publisher connectors.
- Scope: the "threat-research" category by default; operator-configurable.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import time
import html
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside the renderer so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Browser User-Agent for BOTH the RSS client and the Playwright context. The
# origin's edge WAF gates non-browser UAs (the REST API is 403 to anything; the
# feed and article pages are 200 to a realistic browser UA). Deliberately NOT
# ClaudeBot: the connector performs reference-use ingestion of a public blog.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Recycle the Chromium browser after this many renders to cap memory growth on a
# host that co-locates Elasticsearch.
BROWSER_RECYCLE_EVERY = 50

# Substrings indicating a Cloudflare/edge interstitial rather than article content.
CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")

# Earliest plausible real publication year; guards against a malformed pubDate.
MIN_VALID_YEAR = 1990

# Trailing WordPress boilerplate appended to every feed <description>:
#   "The post <TITLE> appeared first on Unit 42."
_BOILERPLATE_RE = re.compile(
    r"\s*The post .*? appeared first on Unit 42\.?\s*$",
    re.IGNORECASE | re.DOTALL,
)


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


def _clean_description(raw: str) -> str:
    """Turn a feed <description> into a plain-text excerpt.

    Strips HTML/entities and removes the trailing "The post ... appeared first on
    Unit 42." boilerplate WordPress appends to every item.
    """
    text = _strip_html(raw)
    return _BOILERPLATE_RE.sub("", text).strip()


class Unit42Connector:
    """External-import connector that mirrors Unit 42 posts into Reports."""

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
            "UNIT42_BASE_URL", ["unit42", "base_url"], config,
            default="https://unit42.paloaltonetworks.com",
        ).rstrip("/")

        # WordPress category slug to ingest (server-side filtered by the feed).
        # Default: the flagship "threat-research" umbrella category.
        self.category = get_config_variable(
            "UNIT42_CATEGORY", ["unit42", "category"], config,
            default="threat-research",
        ).strip().strip("/")

        # Poll interval (seconds) between enumeration runs. Daily is ample: the
        # feed re-walk is cheap and Unit 42 publishes a handful of posts per week.
        self.poll_interval = get_config_variable(
            "UNIT42_POLL_INTERVAL", ["unit42", "poll_interval"], config,
            isNumber=True, default=86400,  # 24 hours
        )

        # Politeness delay (seconds) between successive renders / page fetches.
        # robots.txt sets no Crawl-Delay; a small default is courteous.
        self.request_delay = get_config_variable(
            "UNIT42_REQUEST_DELAY", ["unit42", "request_delay"], config,
            isNumber=True, default=3,
        )

        # Per-run cap on new Reports. 0 == unlimited. Set small (e.g. 3) for a
        # bounded test before the full backfill.
        self.max_reports = get_config_variable(
            "UNIT42_MAX_REPORTS", ["unit42", "max_reports"], config,
            isNumber=True, default=0,
        )

        # Safety bound on feed pages walked per run, in case the 404 end-of-list
        # signal ever fails. Far above the real page count (~61).
        self.max_pages = get_config_variable(
            "UNIT42_MAX_PAGES", ["unit42", "max_pages"], config,
            isNumber=True, default=500,
        )

        # --- Render configuration ------------------------------------------ #
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["unit42", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "UNIT42_RENDER_RETRIES", ["unit42", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        # OpenCTI confidence 0-100. Medium band, matching the OSINT-publisher
        # connectors; Unit 42 is a primary source but we keep cross-connector parity.
        self.confidence = get_config_variable(
            "UNIT42_CONFIDENCE", ["unit42", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "UNIT42_REPORT_TYPE", ["unit42", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "UNIT42_TLP", ["unit42", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "UNIT42_AUTHOR_NAME", ["unit42", "author_name"], config,
            default="Unit 42",
        )

        # HTTP session for RSS enumeration: browser UA + feed accept.
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

    def _feed_url(self, page):
        """RSS feed URL for a 1-based page number.

        Page 1 uses the bare `/feed/` URL; `?paged=1` is edge-blocked and returns
        an empty body, so it must never be used.
        """
        base = f"{self.base_url}/category/{self.category}/feed/"
        return base if page <= 1 else f"{base}?paged={page}"

    def _resolve_graph_references(self):
        """Resolve fixed graph objects, register the vocabulary, and probe the feed.

        Resolves internal OpenCTI UUIDs for the author identity and the TLP
        marking, registers the report_type vocabulary value, and probes the feed
        once. The marking resolution is fail-closed (raises); the feed probe is NOT
        fail-closed (a transient blip logs and the connector enters the poll loop).

        Raises:
            RuntimeError: if the marking cannot be resolved, since Reports must not
                be created without a resolved marking UUID.
        """
        # Author: identity.create is upsert-safe (returns existing if present).
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Palo Alto Networks Unit 42 threat intelligence and research "
                        "team. Source organization for ingested reports.",
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

        # Feed probe (non-fatal). Logs reachability and the item count on page 1.
        items = self._fetch_feed_page(1)
        if items is None:
            self.helper.log_error(
                f"Feed {self._feed_url(1)} unreachable at startup; entering poll "
                f"loop anyway and retrying next cycle."
            )
        else:
            self.helper.log_info(
                f"Feed reachable: {len(items)} items on page 1 "
                f"(category={self.category})."
            )

    # ------------------------------------------------------------------ #
    # RSS enumeration and helpers
    # ------------------------------------------------------------------ #

    def _fetch_feed_page(self, page):
        """Fetch and parse one RSS feed page into a list of item dicts.

        Args:
            page: 1-based page number.

        Returns:
            list[dict]: parsed items (possibly empty past the last page), each with
            keys ``link``, ``title``, ``description``, ``published`` (ISO 8601 UTC
            or None). Returns [] on the HTTP 404 end-of-list. Returns None on a
            transient/HTTP/parse error (caller ends the cycle and retries next poll).
        """
        url = self._feed_url(page)
        try:
            resp = self.session.get(url, timeout=90)
        except Exception as exc:  # noqa: BLE001 - cycle retries next poll
            self.helper.log_error(f"Failed to fetch feed page {page} ({url}): {exc}")
            return None
        if resp.status_code == 404:
            # Past the last page: WordPress returns 404 for the category feed.
            return []
        if resp.status_code != 200:
            self.helper.log_error(
                f"Feed page {page} returned HTTP {resp.status_code}; skipping this cycle."
            )
            return None
        if not resp.content or not resp.content.strip():
            # Empty body (e.g. the edge-blocked ?paged=1 form) — treat as no data.
            self.helper.log_warning(f"Feed page {page} returned an empty body.")
            return None
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError as exc:
            self.helper.log_error(f"Feed page {page} returned unparseable XML: {exc}")
            return None

        items = []
        for item in root.iter("item"):
            link_el = item.find("link")
            link = (link_el.text or "").strip() if link_el is not None else ""
            if not link:
                continue
            title_el = item.find("title")
            desc_el = item.find("description")
            date_el = item.find("pubDate")
            items.append({
                "link": link,
                "title": _strip_html(title_el.text if title_el is not None else "") or link,
                "description": _clean_description(desc_el.text if desc_el is not None else ""),
                "published": self._published_iso(date_el.text if date_el is not None else None),
            })
        return items

    @staticmethod
    def _report_id(link):
        """Deterministic Report STIX id derived from the article URL.

        Same URL always maps to the same Report id, which makes the existence check
        and every write idempotent.
        """
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))

    @staticmethod
    def _published_iso(raw):
        """Parse an RFC-822 <pubDate> to ISO 8601 UTC, or None.

        RSS dates look like "Fri, 31 Jul 2026 10:00:18 +0000".
        """
        if not raw:
            return None
        try:
            dt = parsedate_to_datetime(raw.strip())
        except (TypeError, ValueError, IndexError):
            return None
        if dt is None or dt.year < MIN_VALID_YEAR:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")

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
            RuntimeError: on an edge-challenge interstitial.
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
                raise RuntimeError("Edge challenge interstitial detected")

            self._auto_scroll(page)
            page.wait_for_timeout(1500)  # final settle for post-scroll loads

            ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            footer = (
                "<div style='font-size:8px; width:100%; padding:0 12px; "
                "color:#444; display:flex; justify-content:space-between;'>"
                f"<span>{html.escape(url)}</span>"
                f"<span>OpenCTI Unit 42 connector &middot; ingested "
                f"{ingested_at} &middot; page <span class='pageNumber'></span>/"
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

    def _create_report(self, item, published, pdf_bytes):
        """Create one Report container for a post and attach its PDF.

        Container-only: no object_refs. The Report carries a deterministic stix_id
        derived from the article URL so the write is idempotent.

        Args:
            item: parsed feed item dict.
            published: ISO 8601 published timestamp (already validated non-None).
            pdf_bytes: rendered article PDF.
        """
        url = item["link"]
        name = item["title"] or url
        description = item["description"]
        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on unit42.paloaltonetworks.com",
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
        file_name = f"unit42-{slug}.pdf"
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
        """Execute one enumeration-and-ingest pass over the category feed.

        Walks the feed from page 1 forward until the HTTP 404 end-of-list (or the
        max-pages safety bound), rendering each not-yet-ingested post to a
        Report+PDF. Deduplication is graph-driven: any post whose deterministic
        Report id already exists is skipped before rendering. There is no cursor;
        new posts appear at the front of page 1 and are picked up on the next poll.
        """
        from playwright.sync_api import sync_playwright  # lazy import

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Unit 42 enumeration run"
        )
        self.helper.log_info(
            f"Starting feed walk (category={self.category}, "
            f"request_delay={self.request_delay}s, max_reports={self.max_reports or 'unlimited'})."
        )

        processed = 0   # new Reports created
        skipped = 0     # already present in the graph
        failed = 0      # render failed
        stop = False

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                page_num = 1
                while not stop and page_num <= self.max_pages:
                    items = self._fetch_feed_page(page_num)
                    if items is None:
                        # Transient error: end this cycle, retry next poll from page 1.
                        self.helper.log_warning(
                            f"Feed page {page_num} fetch failed; ending cycle."
                        )
                        break
                    if not items:
                        # HTTP 404 past the last page: end of corpus for this run.
                        self.helper.log_info(f"Reached end of feed at page {page_num}.")
                        break

                    self.helper.log_info(f"Page {page_num}: {len(items)} items.")

                    for item in items:
                        url = item["link"]

                        if self.max_reports and processed >= self.max_reports:
                            self.helper.log_info(
                                f"Reached UNIT42_MAX_REPORTS={self.max_reports}; stopping run."
                            )
                            stop = True
                            break

                        # Dedup BEFORE rendering, keyed on the deterministic Report id.
                        if self.helper.api.report.read(id=self._report_id(url)) is not None:
                            skipped += 1
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

                        published = item["published"]
                        if not published:
                            published = datetime.now(timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%S+00:00"
                            )
                            self.helper.log_warning(
                                f"No usable pubDate for {url}; using ingestion time."
                            )

                        self._create_report(item, published, pdf_bytes)
                        processed += 1
                        time.sleep(self.request_delay)

                    if stop:
                        break

                    page_num += 1
                    time.sleep(self.request_delay)  # politeness between page fetches
            finally:
                browser.close()

        if page_num > self.max_pages and not stop:
            self.helper.log_warning(
                f"Hit UNIT42_MAX_PAGES={self.max_pages} safety bound without a 404 "
                f"end-of-list; check the feed pagination."
            )

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        """Connector entrypoint: resolve references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info("Unit 42 connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001 - keep the connector alive
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        Unit42Connector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
