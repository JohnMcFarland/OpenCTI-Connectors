"""
ScienceDaily OpenCTI connector.

Purpose
-------
External-import connector that ingests the entire ScienceDaily release corpus
(all topics, 1997 -> present) and creates one OpenCTI Report container per
article, with the source page attached as a full-fidelity PDF.

Collection model
----------------
ScienceDaily is a general-science press-release aggregator. It exposes neither a
content API (unlike The DFIR Report's WordPress REST API) nor a complete RSS
surface: its RSS feeds show only a rolling ~50-item window per topic, which is
useless for a full historic corpus. The only complete enumeration surface is the
XML sitemap:

  - GET /sitemap-index.xml -> a list of per-year, gzipped release sitemaps
    (sitemap-releases-YYYY.xml.gz for 1997..present).
  - GET each sitemap-releases-YYYY.xml.gz, gunzip, and read every <loc> as a
    canonical article URL, in publication order within the year.

Collection walks the years chronologically (oldest -> newest) behind a persisted
cursor {year, url_index} stored in OpenCTI connector state. The cursor advances
one article at a time so an interrupted ~300k-article backfill resumes within a
few articles rather than restarting. The same cursor naturally drives steady
state: once it reaches the newest year, each subsequent poll re-enumerates that
year and the cursor picks up the freshly-appended articles, and rolls onto the
next year when a new yearly sitemap appears. One uniform code path covers both
backfill and steady state.

Per-article metadata is *derived*, never fetched in a separate request:
  - published date comes from the URL itself
    (/releases/YYYY/MM/<YYMMDDHHMMSS>.htm), so no extra round-trip is needed.
  - title and description are read from the rendered DOM during the same
    Playwright pass that produces the PDF (document.title minus the
    " -- ScienceDaily" suffix; the page's meta description / og:description).

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships. ScienceDaily content is research news with no
extractable CTI entities (no IOCs, no threat actors), so a container-only design
is both the correct shape per the data model and a guarantee that the connector
is purely additive and can never act as a graph-contamination vector, even across
hundreds of thousands of articles.

Key decisions (see plan / CONNECTOR_SCOPE)
------------------------------------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published source).
- Author: a "ScienceDaily" Organization identity. Never the connector account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (Medium band -- ScienceDaily is a secondary
  press-release aggregator, not original analysis).
- Deduplication: graph-driven via External Reference URL lookup, backed by a
  persisted chronological cursor. The graph lookup is the correctness backstop
  (idempotent even if state is lost); the cursor is the efficiency layer that
  avoids re-reading the whole corpus every poll.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import gzip
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

# Browser User-Agent for BOTH the sitemap HTTP client and the Playwright context.
# A realistic UA keeps enumeration and rendering consistent and avoids UA gating.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Recycle the Chromium browser after this many renders to cap memory growth on a
# host that co-locates Elasticsearch.
BROWSER_RECYCLE_EVERY = 50

# Substrings indicating a bot/challenge interstitial rather than article content.
CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")

# Yearly release sitemaps in the sitemap index: sitemap-releases-YYYY.xml.gz.
SITEMAP_RELEASES_RE = re.compile(r"sitemap-releases-(\d{4})\.xml\.gz", re.IGNORECASE)

# <loc> entries inside a sitemap (article URLs).
LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)

# Release URL date encoding: /releases/YYYY/MM/<YYMMDDHHMMSS...>.htm.
# The 4-digit year and 2-digit month come from the path; day and time come from
# the filename's leading YYMMDDHHMMSS digits.
RELEASE_DATE_RE = re.compile(r"/releases/(\d{4})/(\d{2})/(\d{6,})\.htm", re.IGNORECASE)


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


def _published_from_url(url: str):
    """Derive a STIX publication timestamp from a ScienceDaily release URL.

    ScienceDaily release URLs encode the publication date:
    /releases/YYYY/MM/<YYMMDDHHMMSS>.htm. The 4-digit year and 2-digit month are
    taken from the path (unambiguous); the day and time come from the filename's
    leading digits (YY MM DD HH MM SS).

    Args:
        url: canonical article URL.

    Returns:
        ISO-8601 string with an explicit +00:00 offset, or None if the URL does
        not match the release pattern. Falls back to the first of the month at
        midnight if the filename's day/time is malformed.
    """
    from datetime import datetime

    match = RELEASE_DATE_RE.search(url)
    if not match:
        return None
    year, month, fname = match.group(1), match.group(2), match.group(3)
    day = fname[4:6]
    hh = fname[6:8] if len(fname) >= 8 else "00"
    mm = fname[8:10] if len(fname) >= 10 else "00"
    ss = fname[10:12] if len(fname) >= 12 else "00"
    try:
        dt = datetime(int(year), int(month), int(day), int(hh), int(mm), int(ss))
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    except ValueError:
        try:
            dt = datetime(int(year), int(month), 1)
            return dt.strftime("%Y-%m-%dT00:00:00+00:00")
        except ValueError:
            return None


class ScienceDailyConnector:
    """External-import connector that mirrors ScienceDaily articles into Reports."""

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
            "SCIENCEDAILY_BASE_URL", ["sciencedaily", "base_url"], config,
            default="https://www.sciencedaily.com",
        ).rstrip("/")

        # Poll interval (seconds) between enumeration runs. Daily is ample: the
        # backfill resumes from its cursor, and ScienceDaily adds tens of new
        # articles per day.
        self.poll_interval = get_config_variable(
            "SCIENCEDAILY_POLL_INTERVAL", ["sciencedaily", "poll_interval"], config,
            isNumber=True, default=86400,  # 24 hours
        )

        # Politeness delay (seconds) between successive HTTP/render operations.
        self.request_delay = get_config_variable(
            "SCIENCEDAILY_REQUEST_DELAY", ["sciencedaily", "request_delay"], config,
            isNumber=True, default=2,
        )

        # Per-run cap on new Reports. 0 == unlimited. Set small (e.g. 3) for a
        # bounded test before the full backfill.
        self.max_reports = get_config_variable(
            "SCIENCEDAILY_MAX_REPORTS", ["sciencedaily", "max_reports"], config,
            isNumber=True, default=0,
        )

        # Earliest year to backfill. 0 == earliest year present in the sitemap
        # (the full corpus). Set e.g. 2015 to cap the backfill without code edits.
        self.backfill_start_year = get_config_variable(
            "SCIENCEDAILY_BACKFILL_START_YEAR", ["sciencedaily", "backfill_start_year"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ------------------------------------------ #
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["sciencedaily", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "SCIENCEDAILY_RENDER_RETRIES", ["sciencedaily", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        # OpenCTI confidence 0-100. Medium band: ScienceDaily restates primary
        # research as press releases; it adds aggregation, not original analysis.
        self.confidence = get_config_variable(
            "SCIENCEDAILY_CONFIDENCE", ["sciencedaily", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "SCIENCEDAILY_REPORT_TYPE", ["sciencedaily", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "SCIENCEDAILY_TLP", ["sciencedaily", "tlp"], config,
            default="TLP:CLEAR",
        )

        # Sitemap index URL, derived from the configured base_url.
        self.sitemap_index_url = f"{self.base_url}/sitemap-index.xml"

        # HTTP session for sitemap enumeration. Browser UA + XML accept.
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": BROWSER_UA, "Accept": "application/xml,text/xml,*/*"}
        )

        # Resolved graph references, populated by _resolve_graph_references().
        self.author_id = None      # "ScienceDaily" Organization internal UUID
        self.marking_id = None     # TLP marking internal UUID

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Resolve fixed graph objects and verify the sitemap is reachable.

        Resolves internal OpenCTI UUIDs (not STIX IDs) for the ScienceDaily author
        identity and the TLP marking, registers the report_type vocabulary value,
        and confirms the sitemap index returns HTTP 200 and lists release sitemaps
        (the enumeration surface the connector depends on).

        Raises:
            RuntimeError: if the marking cannot be resolved or the sitemap index is
                not reachable / not the expected shape.
        """
        # Author: identity.create is upsert-safe (returns existing if present).
        author = self.helper.api.identity.create(
            type="Organization",
            name="ScienceDaily",
            description="Science news aggregator that republishes research press "
                        "releases from universities and journals. Source publisher "
                        "for ingested articles.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved ScienceDaily author identity: {self.author_id}")

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

        # Sitemap reachability: confirm the enumeration surface is up and lists the
        # per-year release sitemaps the cursor walks.
        try:
            resp = self.session.get(self.sitemap_index_url, timeout=30)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"Sitemap index unreachable at {self.sitemap_index_url} ({exc})."
            )
        if resp.status_code != 200 or not SITEMAP_RELEASES_RE.search(resp.text):
            raise RuntimeError(
                f"Sitemap index at {self.sitemap_index_url} returned HTTP "
                f"{resp.status_code} without release sitemaps; refusing to run."
            )
        n_years = len(set(SITEMAP_RELEASES_RE.findall(resp.text)))
        self.helper.log_info(f"Sitemap index reachable: {n_years} release years available.")

    # ------------------------------------------------------------------ #
    # Sitemap enumeration
    # ------------------------------------------------------------------ #

    def _sitemap_years(self):
        """Return the per-year release sitemaps, ascending by year.

        Parses the sitemap index for sitemap-releases-YYYY.xml.gz entries, applies
        the backfill_start_year floor, and returns a chronologically sorted list.

        Returns:
            list[tuple[int, str]]: (year, sitemap_url) pairs, oldest year first.
        """
        resp = self.session.get(self.sitemap_index_url, timeout=60)
        resp.raise_for_status()

        seen = set()
        years = []
        for match in SITEMAP_RELEASES_RE.finditer(resp.text):
            year = int(match.group(1))
            if year in seen:
                continue
            if self.backfill_start_year and year < self.backfill_start_year:
                continue
            seen.add(year)
            years.append((year, f"{self.base_url}/sitemap-releases-{year}.xml.gz"))
        years.sort(key=lambda pair: pair[0])
        return years

    def _enumerate_year(self, sitemap_url):
        """Return every release article URL in a yearly sitemap, in file order.

        Args:
            sitemap_url: URL of a gzipped sitemap-releases-YYYY.xml.gz.

        Returns:
            list[str]: canonical /releases/ article URLs.
        """
        resp = self.session.get(sitemap_url, timeout=120)
        resp.raise_for_status()
        try:
            xml = gzip.decompress(resp.content).decode("utf-8", "replace")
        except OSError:
            # Not gzip-compressed (e.g. a transparently decompressed response).
            xml = resp.content.decode("utf-8", "replace")
        urls = [u.strip() for u in LOC_RE.findall(xml)]
        return [u for u in urls if "/releases/" in u]

    def _already_ingested(self, url):
        """Return True if this article URL has already been ingested.

        Deduplication is graph-driven and keys off the External Reference this
        connector creates for each article. external_reference creation is the
        first write in _create_report and is upsert-keyed on url, so the presence
        of an external reference for a url is the connector's idempotency marker.
        This is the correctness backstop that makes an interrupted backfill safe
        even if the cursor state is lost.

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

        ScienceDaily articles carry figures and related-story thumbnails that load
        on scroll, so this improves PDF fidelity.

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

    def _extract_meta(self, page):
        """Read the article title and description from the rendered DOM.

        Args:
            page: active Playwright page (post-navigation).

        Returns:
            dict: {"name": <title without the ScienceDaily suffix>,
                   "description": <meta description / og:description>}.
        """
        raw_title = page.title() or ""
        name = re.sub(r"\s*[-–—]+\s*ScienceDaily\s*$", "", raw_title).strip()
        try:
            description = page.evaluate(
                """() => {
                    const selectors = [
                      'meta[name="description"]',
                      'meta[property="og:description"]',
                    ];
                    for (const s of selectors) {
                      const el = document.querySelector(s);
                      if (el && el.content) return el.content;
                    }
                    return "";
                }"""
            ) or ""
        except Exception:  # noqa: BLE001 - description is best-effort
            description = ""
        return {"name": name, "description": description.strip()}

    def _render_pdf(self, browser, url):
        """Render an article to PDF and extract its on-page metadata.

        Args:
            browser: active Playwright Chromium browser.
            url: canonical article URL.

        Returns:
            tuple[bytes, dict]: (rendered PDF, {"name", "description"}).

        Raises:
            RuntimeError: on a bot/challenge interstitial.
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
                raise RuntimeError("Challenge interstitial detected")

            self._auto_scroll(page)
            page.wait_for_timeout(1000)  # final settle for post-scroll loads

            meta = self._extract_meta(page)

            from datetime import datetime, timezone
            ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            footer = (
                "<div style='font-size:8px; width:100%; padding:0 12px; "
                "color:#444; display:flex; justify-content:space-between;'>"
                f"<span>{html.escape(url)}</span>"
                f"<span>OpenCTI ScienceDaily connector &middot; ingested {ingested_at} "
                "&middot; page <span class='pageNumber'></span>/"
                "<span class='totalPages'></span></span></div>"
            )
            pdf = page.pdf(
                print_background=True,
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=footer,
                margin={"top": "10mm", "bottom": "16mm", "left": "8mm", "right": "8mm"},
                format="A4",
            )
            return pdf, meta
        finally:
            page.close()
            context.close()

    def _render_with_retry(self, browser, url):
        """Render with bounded exponential backoff.

        Args:
            browser: active Playwright Chromium browser.
            url: canonical article URL.

        Returns:
            tuple[bytes, dict]: (PDF, meta) on success, or (None, None) if all
            retries are exhausted.
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
        return None, None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, url, meta, published, pdf_bytes):
        """Create one Report container for an article and attach its PDF.

        Container-only: no object_refs, so the single-step report.create path is
        used.

        Args:
            url: canonical article URL.
            meta: {"name", "description"} extracted from the page.
            published: STIX publication timestamp (str) or None.
            pdf_bytes: rendered article PDF.
        """
        slug = url.rstrip("/").split("/")[-1].replace(".htm", "") or "article"
        name = (meta or {}).get("name") or slug
        description = (meta or {}).get("description") or ""

        if not published:
            # Release URLs always encode a date; this guards the rare malformed
            # URL so the (STIX-required) published field is never empty.
            from datetime import datetime, timezone
            published = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
            self.helper.log_warning(
                f"Could not derive publication date from {url}; using ingestion time."
            )

        external_reference = self.helper.api.external_reference.create(
            source_name="ScienceDaily",
            url=url,
            description="Source article on sciencedaily.com",
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

        file_name = f"sciencedaily-{slug}.pdf"
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
        """Execute one chronological enumeration-and-ingest pass from the cursor.

        Walks the yearly release sitemaps oldest -> newest starting at the persisted
        {year, url_index} cursor, rendering each not-yet-ingested article to a
        Report+PDF and advancing the cursor one article at a time. When the newest
        year is exhausted the cursor rests at its tail, so the next poll picks up
        freshly-appended articles (and rolls onto a new yearly sitemap when one
        appears) with no separate steady-state code path.
        """
        from playwright.sync_api import sync_playwright  # lazy import

        years = self._sitemap_years()
        if not years:
            self.helper.log_error(
                "No release sitemaps found in the sitemap index; nothing to do."
            )
            return

        state = self.helper.get_state() or {}
        cursor_year = state.get("year") or years[0][0]
        cursor_index = state.get("url_index", 0)

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "ScienceDaily enumeration run"
        )
        self.helper.log_info(
            f"Resuming at year={cursor_year}, url_index={cursor_index} "
            f"({len(years)} release years available, {years[0][0]}-{years[-1][0]})."
        )

        processed = 0   # new Reports created
        skipped = 0     # already present in the graph
        failed = 0      # render failed
        stop = False

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                for year, sitemap_url in years:
                    if year < cursor_year:
                        continue

                    article_urls = self._enumerate_year(sitemap_url)
                    start = cursor_index if year == cursor_year else 0
                    self.helper.log_info(
                        f"Year {year}: {len(article_urls)} articles; starting at index {start}."
                    )

                    for idx in range(start, len(article_urls)):
                        url = article_urls[idx]

                        if self.max_reports and processed >= self.max_reports:
                            self.helper.log_info(
                                f"Reached SCIENCEDAILY_MAX_REPORTS={self.max_reports}; stopping run."
                            )
                            stop = True
                            break

                        if self._already_ingested(url):
                            skipped += 1
                            self.helper.set_state({"year": year, "url_index": idx + 1})
                            continue

                        if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                            browser.close()
                            browser = pw.chromium.launch(
                                args=["--no-sandbox", "--disable-dev-shm-usage"]
                            )
                            renders_since_recycle = 0

                        pdf_bytes, meta = self._render_with_retry(browser, url)
                        renders_since_recycle += 1

                        if pdf_bytes is None:
                            failed += 1
                            self.helper.log_warning(
                                f"Skipping {url}: render failed after retries."
                            )
                            # Advance past a persistently-failing article so it does
                            # not block the chronological backfill. It is logged for
                            # operator review and is not revisited by the cursor.
                            self.helper.set_state({"year": year, "url_index": idx + 1})
                            continue

                        published = _published_from_url(url)
                        self._create_report(url, meta, published, pdf_bytes)
                        processed += 1
                        self.helper.set_state({"year": year, "url_index": idx + 1})
                        time.sleep(self.request_delay)

                    # After the resumed year, later years start from their first URL.
                    cursor_index = 0
                    if stop:
                        break
                    time.sleep(self.request_delay)  # politeness between year sitemaps
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
        self.helper.log_info("ScienceDaily connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001 - keep the connector alive
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        ScienceDailyConnector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
