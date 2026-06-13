"""
The DFIR Report OpenCTI connector.

Purpose
-------
External-import connector that ingests the full historic backlog of incident
reports from https://thedfirreport.com/reports/ and creates one OpenCTI Report
container per article, with the source page attached as a full-fidelity PDF.

Collection model
----------------
Unlike Bellingcat (whose WordPress wp/v2 content routes are disabled), The DFIR
Report exposes a live WordPress REST API. Collection therefore enumerates posts
directly through the API rather than walking front-end archives:

  - GET /wp-json/wp/v2/posts?per_page=100&page=N
    paginated to the X-WP-TotalPages boundary. The API returns a stable post id,
    canonical link, slug, date_gmt (publication date), and rendered title/excerpt
    for every post in one pass.

There is no category filter: The DFIR Report's categories are malware/tool/
technique-named (adfind, bazar, bumblebee, ...), not a report/non-report split,
and the post set is essentially the entire report corpus. Every published post is
ingested.

Per-article publication date comes from the API field date_gmt (naive UTC, marked
+00:00 on use); title and description come from the rendered title/excerpt fields.
Playwright is used purely to render the live page to PDF — there is no on-page
metadata extraction, because the API already supplies it.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects, no
Observables, no Relationships. The DFIR Report's content is rich in IOCs and MITRE
ATT&CK mappings, but those are defanged inline HTML; entity extraction is a
separate, out-of-scope phase. Keeping this connector container-only makes it purely
additive and prevents it from acting as a graph-contamination vector.

Key decisions (see plan / CONNECTOR_SCOPE)
------------------------------------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published source).
- Author: the "The DFIR Report" Organization identity. Never the connector account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (High band — well-evidenced incident analysis).
- Deduplication: graph-driven via External Reference URL lookup. No state file and
  no cursor; every run re-enumerates and skips URLs already on a Report, which makes
  an interrupted backfill inherently resumable.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import time
import html

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside the renderer so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Browser User-Agent for BOTH the API HTTP client and the Playwright context. A
# realistic UA keeps enumeration and rendering consistent and avoids any UA gating.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# WordPress REST API page size. The API caps per_page at 100; the full backlog
# (~95 posts) fits in a single page, but pagination is implemented for headroom.
API_PER_PAGE = 100

# Hard ceiling on API pages walked, a safety stop against a pagination bug that
# never returns the X-WP-TotalPages boundary.
MAX_API_PAGES = 1000

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


class DFIRReportConnector:
    """External-import connector that mirrors DFIR Report posts into Reports."""

    def __init__(self):
        """Load configuration, build the OpenCTI helper, and prepare the HTTP
        client. Fixed graph references are resolved later in run() via
        _resolve_graph_references().
        """
        # Classic config bootstrap: optional config.yml so the module runs both
        # in-container (env only) and locally (yaml) unchanged.
        config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        # --- Source configuration ------------------------------------------ #
        # Site root. Trailing slash stripped so path joins are clean.
        self.base_url = get_config_variable(
            "DFIR_REPORT_BASE_URL", ["dfir_report", "base_url"], config,
            default="https://thedfirreport.com",
        ).rstrip("/")

        # Poll interval (seconds) between full enumeration runs. DFIR publishes
        # ~1-2 reports/month, so a daily re-scan is ample.
        self.poll_interval = get_config_variable(
            "DFIR_REPORT_POLL_INTERVAL", ["dfir_report", "poll_interval"], config,
            isNumber=True, default=86400,  # 24 hours
        )

        # Politeness delay (seconds) between successive HTTP/render operations.
        self.request_delay = get_config_variable(
            "DFIR_REPORT_REQUEST_DELAY", ["dfir_report", "request_delay"], config,
            isNumber=True, default=3,
        )

        # Per-run cap on new Reports. 0 == unlimited. Set small (e.g. 3) for a
        # bounded test before the full backfill.
        self.max_reports = get_config_variable(
            "DFIR_REPORT_MAX_REPORTS", ["dfir_report", "max_reports"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ------------------------------------------ #
        # Playwright navigation timeout (ms).
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["dfir_report", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        # Render attempts before a post is skipped.
        self.render_retries = get_config_variable(
            "DFIR_REPORT_RENDER_RETRIES", ["dfir_report", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        # OpenCTI confidence 0-100. High band: rigorous, evidence-backed incident
        # analysis from a well-regarded source.
        self.confidence = get_config_variable(
            "DFIR_REPORT_CONFIDENCE", ["dfir_report", "confidence"], config,
            isNumber=True, default=80,
        )
        self.report_type = get_config_variable(
            "DFIR_REPORT_TYPE", ["dfir_report", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "DFIR_REPORT_TLP", ["dfir_report", "tlp"], config,
            default="TLP:CLEAR",
        )

        # WP REST API posts endpoint, derived from the configured base_url.
        self.api_posts_url = f"{self.base_url}/wp-json/wp/v2/posts"

        # HTTP session for API enumeration, browser UA + JSON accept.
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA, "Accept": "application/json"})

        # Resolved graph references, populated by _resolve_graph_references().
        self.author_id = None      # "The DFIR Report" Organization internal UUID
        self.marking_id = None     # TLP marking internal UUID

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Resolve fixed graph objects and verify the API is reachable.

        Resolves internal OpenCTI UUIDs (not STIX IDs) for the DFIR Report author
        identity and the TLP marking, registers the report_type vocabulary value,
        and confirms the WordPress REST API returns HTTP 200 with the X-WP-Total
        header (the backlog signal enumeration depends on).

        Raises:
            RuntimeError: if the marking cannot be resolved or the API is not
                reachable, since neither can be silently tolerated.
        """
        # Author: identity.create is upsert-safe (returns existing if present).
        author = self.helper.api.identity.create(
            type="Organization",
            name="The DFIR Report",
            description="Threat intelligence team publishing in-depth, evidence-backed "
                        "analyses of real-world intrusions. Source organization for "
                        "ingested reports.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved DFIR Report author identity: {self.author_id}")

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

        # report_type open-vocabulary registration. Idempotent; harmless failure
        # if the vocabulary is locked (operator adds it via Settings).
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

        # API reachability: confirm the collection surface is up and exposes the
        # backlog count header. A missing X-WP-Total means the route is not the
        # expected WP REST posts endpoint.
        try:
            resp = self.session.get(self.api_posts_url, params={"per_page": 1}, timeout=30)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"WordPress REST API unreachable at {self.api_posts_url} ({exc})."
            )
        if resp.status_code != 200 or "X-WP-Total" not in resp.headers:
            raise RuntimeError(
                f"WordPress REST API at {self.api_posts_url} returned HTTP "
                f"{resp.status_code} without an X-WP-Total header; refusing to run."
            )
        self.helper.log_info(
            f"WP REST API reachable: {resp.headers.get('X-WP-Total')} posts in backlog."
        )

    # ------------------------------------------------------------------ #
    # Post enumeration (WordPress REST API)
    # ------------------------------------------------------------------ #

    def _enumerate_posts(self):
        """Yield every published post from the WordPress REST API.

        Paginates /wp-json/wp/v2/posts?per_page=100&page=N from page 1 until the
        X-WP-TotalPages boundary (signalled by HTTP 400 'rest_post_invalid_page_number'
        past the last page, or an empty result array). Requests only the fields the
        connector needs via _fields.

        Yields:
            dict per post with keys: link, slug, date_gmt, title, excerpt.
        """
        total_pages = None
        for page in range(1, MAX_API_PAGES + 1):
            params = {
                "per_page": API_PER_PAGE,
                "page": page,
                "_fields": "id,link,slug,date_gmt,title,excerpt",
            }
            resp = self.session.get(self.api_posts_url, params=params, timeout=60)

            # Past the last page WP returns 400 (rest_post_invalid_page_number).
            if resp.status_code == 400 and page > 1:
                break
            resp.raise_for_status()

            if total_pages is None:
                total_pages = int(resp.headers.get("X-WP-TotalPages", "1") or "1")

            posts = resp.json()
            if not posts:
                break

            for post in posts:
                yield {
                    "link": post.get("link"),
                    "slug": post.get("slug"),
                    "date_gmt": post.get("date_gmt"),
                    "title": (post.get("title") or {}).get("rendered", ""),
                    "excerpt": (post.get("excerpt") or {}).get("rendered", ""),
                }

            if page >= total_pages:
                break
            time.sleep(self.request_delay)  # politeness between API pages
        else:
            self.helper.log_warning(
                f"Enumeration hit MAX_API_PAGES={MAX_API_PAGES} without a boundary; "
                f"the post list may be incomplete."
            )

    def _already_ingested(self, url):
        """Return True if this article URL has already been ingested.

        Deduplication is graph-driven and keys off the External Reference this
        connector creates for each article. external_reference creation is the
        first write in _create_report and is upsert-keyed on url, so the presence
        of a DFIR Report external reference for a url is the connector's
        idempotency marker.

        Tradeoff (same as Bellingcat): if a prior run died between external-reference
        creation and Report creation, the orphaned reference would cause this url to
        be skipped without a Report. That window is narrow and self-evident (one
        missing article, not graph contamination), and is preferred over re-rendering
        the entire corpus every poll.

        Args:
            url: canonical article URL.

        Returns:
            bool: True if an External Reference with this url already exists.
        """
        existing_ref = self.helper.api.external_reference.read(
            filters={
                "mode": "and",
                "filters": [{"key": "url", "values": [url]}],
                "filterGroups": [],
            }
        )
        return existing_ref is not None

    # ------------------------------------------------------------------ #
    # PDF rendering (Playwright)
    # ------------------------------------------------------------------ #

    def _auto_scroll(self, page):
        """Scroll to the page bottom to trigger lazy-loaded media.

        DFIR reports carry 60+ lazy-loaded evidence screenshots, so this is load-
        bearing for PDF fidelity rather than cosmetic.

        Args:
            page: active Playwright page.
        """
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
                f"<span>OpenCTI DFIR Report connector &middot; ingested {ingested_at} "
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

        Args:
            browser: active Playwright Chromium browser.
            url: canonical article URL.

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

    def _create_report(self, post, pdf_bytes):
        """Create one Report container for an article and attach its PDF.

        Container-only: no object_refs, so the single-step report.create path is
        used.

        Args:
            post: enumerated post dict (link, slug, date_gmt, title, excerpt).
            pdf_bytes: rendered article PDF.
        """
        url = post["link"]
        name = _strip_html(post.get("title") or "") or (post.get("slug") or "report")
        description = _strip_html(post.get("excerpt") or "")

        # date_gmt is naive UTC (e.g. "2025-12-17T14:00:00"); mark it explicitly.
        date_gmt = post.get("date_gmt")
        published = f"{date_gmt}+00:00" if date_gmt else None

        external_reference = self.helper.api.external_reference.create(
            source_name="The DFIR Report",
            url=url,
            description="Source report on thedfirreport.com",
        )

        report = self.helper.api.report.create(
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

        file_name = f"dfir-report-{post.get('slug') or 'report'}.pdf"
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
        """Execute one full enumeration-and-ingest pass."""
        from playwright.sync_api import sync_playwright  # lazy import

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "The DFIR Report enumeration run"
        )

        posts = list(self._enumerate_posts())
        self.helper.log_info(f"Enumerated {len(posts)} posts from the WP REST API.")

        processed = 0   # new Reports created
        skipped = 0     # already present in the graph
        failed = 0      # render failed

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                for post in posts:
                    url = post.get("link")
                    if not url:
                        continue

                    if self.max_reports and processed >= self.max_reports:
                        self.helper.log_info(
                            f"Reached DFIR_REPORT_MAX_REPORTS={self.max_reports}; stopping run."
                        )
                        break

                    if self._already_ingested(url):
                        skipped += 1
                        continue

                    if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                        browser.close()
                        browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
                        renders_since_recycle = 0

                    pdf_bytes = self._render_with_retry(browser, url)
                    renders_since_recycle += 1

                    if pdf_bytes is None:
                        failed += 1
                        self.helper.log_warning(f"Skipping {url}: render failed after retries.")
                        continue

                    self._create_report(post, pdf_bytes)
                    processed += 1
                    time.sleep(self.request_delay)
            finally:
                browser.close()

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        """Connector entrypoint: resolve references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info("The DFIR Report connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001 - keep the connector alive
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        DFIRReportConnector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
