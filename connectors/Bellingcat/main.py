"""
Bellingcat OpenCTI connector.

Purpose
-------
External-import connector that ingests Bellingcat investigative output and
creates one OpenCTI Report container per post, with the source article attached
as a full-fidelity PDF.

Collection model (re-scoped)
----------------------------
Bellingcat's WordPress REST API is disabled for the wp/v2 content routes
(the handler returns rest_no_route for posts and categories, on every path form
and User-Agent). Collection therefore walks the public front-end archives:

  - Category archives paginate: /category/<slug>/ , then /category/<slug>/page/N/
    until the boundary 404. (Confirmed: page/2 -> 200, rel="next" present.)
  - Tag archives are single-page here: /tag/<slug>/ with no pagination controls
    (page/2 -> 404). The same walk handles this: it simply stops at the first
    404 / empty page.

Article permalinks are extracted from the archive HTML (server-rendered) by the
dated-permalink pattern /<segment>/YYYY/MM/DD/<slug>/. The first path segment is
NOT hardcoded, so a post filed under a segment other than news/resources is not
silently dropped.

Per-article metadata (title, published date, description) is read from the
rendered page's Open Graph / JSON-LD tags during the same Playwright load that
produces the PDF. The published date comes from article:published_time (full
ISO-8601 with timezone), with a JSON-LD datePublished fallback. This replaces
the REST date_gmt field.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships. This keeps the connector purely additive and
prevents it from acting as a graph-contamination vector. Entity extraction is a
separate, out-of-scope phase.

Key decisions (see CONNECTOR_SCOPE.md decision log)
---------------------------------------------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (public source).
- Author: the Bellingcat Organization identity. Never the byline, never the
  connector service account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (Medium band).
- Deduplication: graph-driven via External Reference URL lookup. No state file
  and no cursor; every run re-enumerates and skips URLs already on a Report,
  which makes an interrupted backfill inherently resumable.
- Scope is defined purely by which archives are walked. With no Labels applied,
  the originating archive is NOT recorded on the Report; the three buckets are
  traversal-defined and overlapping, not disjoint partitions.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import time
import html
from urllib.parse import urlparse

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside the renderer so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Browser User-Agent for BOTH the archive HTTP client and the Playwright
# context. A realistic UA avoids any front-end UA gating and keeps enumeration
# and rendering consistent.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Hard ceiling on archive pages walked per archive, a safety stop against an
# archive that never returns a 404 boundary.
MAX_ARCHIVE_PAGES = 1000

# Recycle the Chromium browser after this many renders to cap memory growth on
# a host that co-locates Elasticsearch.
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


class BellingcatConnector:
    """External-import connector that mirrors Bellingcat posts into Reports."""

    def __init__(self):
        """Load configuration, build the OpenCTI helper, compile the article-URL
        matcher, and prepare the HTTP client. Fixed graph references are
        resolved later in run() via _resolve_graph_references().
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
            "BELLINGCAT_BASE_URL", ["bellingcat", "base_url"], config,
            default="https://www.bellingcat.com",
        ).rstrip("/")

        # Comma-separated archive base PATHS to walk. Each must start and end
        # with "/". Supports both taxonomies, e.g.
        #   /category/news/ , /category/resources/ , /tag/open-source-in-short/
        # This is the collection-time scope gate. (No Labels are applied, so the
        # archive is not recorded on the resulting Report.)
        raw_archives = get_config_variable(
            "BELLINGCAT_ARCHIVES", ["bellingcat", "archives"], config,
            default="/category/news/,/category/resources/,/tag/open-source-in-short/",
        )
        self.archives = [a.strip() for a in raw_archives.split(",") if a.strip()]

        # Poll interval (seconds) between full enumeration runs.
        self.poll_interval = get_config_variable(
            "BELLINGCAT_POLL_INTERVAL", ["bellingcat", "poll_interval"], config,
            isNumber=True, default=21600,  # 6 hours
        )

        # Politeness delay (seconds) between successive HTTP/render operations.
        self.request_delay = get_config_variable(
            "BELLINGCAT_REQUEST_DELAY", ["bellingcat", "request_delay"], config,
            isNumber=True, default=3,
        )

        # Per-run cap on new Reports. 0 == unlimited. Set small (e.g. 3) for a
        # bounded test before the full backfill.
        self.max_posts = get_config_variable(
            "BELLINGCAT_MAX_POSTS", ["bellingcat", "max_posts"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ------------------------------------------ #
        # Playwright navigation timeout (ms). Replaces the weasyprint render
        # timeout wrap for this connector.
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["bellingcat", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        # Render attempts before a post is skipped.
        self.render_retries = get_config_variable(
            "BELLINGCAT_RENDER_RETRIES", ["bellingcat", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        # OpenCTI confidence 0-100. Medium band per credible-OSINT tier.
        self.confidence = get_config_variable(
            "BELLINGCAT_CONFIDENCE", ["bellingcat", "confidence"], config,
            isNumber=True, default=60,
        )
        self.report_type = get_config_variable(
            "BELLINGCAT_REPORT_TYPE", ["bellingcat", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "BELLINGCAT_TLP", ["bellingcat", "tlp"], config,
            default="TLP:CLEAR",
        )

        # Article-permalink matcher, built from the configured host so it tracks
        # base_url rather than hardcoding the domain. Matches the dated
        # permalink shape /<segment>/YYYY/MM/DD/<slug>/ with any first segment.
        host = re.escape(urlparse(self.base_url).netloc)
        self.article_re = re.compile(
            r"https?://" + host + r"/[a-z0-9-]+/\d{4}/\d{2}/\d{2}/[a-z0-9-]+/?"
        )

        # HTTP session for archive enumeration, browser UA.
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA})

        # Resolved graph references, populated by _resolve_graph_references().
        self.author_id = None      # Bellingcat Organization internal UUID
        self.marking_id = None     # TLP marking internal UUID

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Resolve fixed graph objects and verify archive reachability.

        Resolves internal OpenCTI UUIDs (not STIX IDs) for the Bellingcat author
        identity and the TLP marking, registers the report_type vocabulary
        value, and confirms at least one configured archive returns HTTP 200.

        Raises:
            RuntimeError: if the marking cannot be resolved or no archive is
                reachable, since neither can be silently tolerated.
        """
        # Author: identity.create is upsert-safe (returns existing if present).
        author = self.helper.api.identity.create(
            type="Organization",
            name="Bellingcat",
            description="Netherlands-based investigative journalism and open-source "
                        "intelligence collective. Source organization for ingested reports.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved Bellingcat author identity: {self.author_id}")

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

        # Archive reachability: confirm the front-end collection surface is up.
        reachable = 0
        for base_path in self.archives:
            url = f"{self.base_url}{base_path}"
            try:
                resp = self.session.get(url, timeout=30)
                if resp.status_code == 200:
                    reachable += 1
                    self.helper.log_info(f"Archive reachable: {base_path}")
                else:
                    self.helper.log_warning(
                        f"Archive {base_path} returned HTTP {resp.status_code}; it will be skipped."
                    )
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Archive {base_path} unreachable ({exc}); it will be skipped.")
        if reachable == 0:
            raise RuntimeError(
                f"No configured archive reachable from {self.archives}. "
                f"Verify BELLINGCAT_ARCHIVES paths and site availability."
            )

    # ------------------------------------------------------------------ #
    # Archive enumeration
    # ------------------------------------------------------------------ #

    def _extract_article_urls(self, page_html):
        """Extract unique article permalinks from archive-listing HTML.

        Args:
            page_html: raw HTML of an archive page.

        Returns:
            list of unique article URLs in first-seen order.
        """
        seen = set()
        ordered = []
        for match in self.article_re.findall(page_html):
            # Normalise to a trailing slash so the same article is not treated
            # as two URLs by dedup.
            url = match if match.endswith("/") else match + "/"
            if url not in seen:
                seen.add(url)
                ordered.append(url)
        return ordered

    def _walk_archive(self, base_path):
        """Yield article URLs from one archive, paginating to the boundary.

        Page 1 is the archive root; subsequent pages are <root>page/N/. The walk
        stops at the first 404 (pagination boundary) or the first page that
        yields no article links (end / template change).

        Args:
            base_path: archive base path, e.g. "/category/news/".

        Yields:
            str: article URL.
        """
        for page in range(1, MAX_ARCHIVE_PAGES + 1):
            if page == 1:
                url = f"{self.base_url}{base_path}"
            else:
                url = f"{self.base_url}{base_path}page/{page}/"

            resp = self.session.get(url, timeout=60)
            if resp.status_code == 404:
                break  # clean pagination boundary
            resp.raise_for_status()

            urls = self._extract_article_urls(resp.text)
            if not urls:
                # 200 with zero article links: end of listing, or the listing is
                # JS-rendered / the template changed. Surface page 1 explicitly
                # since that would mean the whole archive yielded nothing.
                if page == 1:
                    self.helper.log_warning(
                        f"Archive {base_path} page 1 returned 200 but no article links were "
                        f"found. Possible JS-rendered listing or template change."
                    )
                break

            for u in urls:
                yield u

            time.sleep(self.request_delay)  # politeness between archive pages
        else:
            # Loop exhausted without a 404 boundary.
            self.helper.log_warning(
                f"Archive {base_path} hit MAX_ARCHIVE_PAGES={MAX_ARCHIVE_PAGES} "
                f"without a 404 boundary; enumeration may be incomplete."
            )

    def _all_article_urls(self):
        """Collect de-duplicated article URLs across all configured archives.

        Returns:
            list of unique article URLs (a URL appearing in multiple archives is
            returned once, under whichever archive reached it first).
        """
        seen = set()
        ordered = []
        for base_path in self.archives:
            for url in self._walk_archive(base_path):
                if url not in seen:
                    seen.add(url)
                    ordered.append(url)
        self.helper.log_info(f"Enumerated {len(ordered)} unique article URLs across {len(self.archives)} archives.")
        return ordered

    def _already_ingested(self, url):
        """Return True if this article URL has already been ingested.

        Deduplication is graph-driven. The reports query does NOT support the
        nested externalReferences.url filter on this platform build (it silently
        matches zero rows, defeating dedup). The externalReferences query DOES
        resolve by url, so dedup keys off the existence of the External
        Reference this connector creates for each article. external_reference
        creation is the first write in _create_report and is upsert-keyed on
        url, so the presence of a Bellingcat external reference for a url is the
        connector's idempotency marker.

        Tradeoff: if a prior run died between external-reference creation and
        Report creation, the orphaned reference would cause this url to be
        skipped without a Report. That window is narrow and self-evident (one
        missing article, not graph contamination), and is preferred over the
        prior failure mode of re-rendering the entire corpus every poll.

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
    # PDF rendering + metadata extraction (Playwright)
    # ------------------------------------------------------------------ #

    def _auto_scroll(self, page):
        """Scroll to the page bottom to trigger lazy-loaded media.

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

    def _extract_metadata(self, page):
        """Read title, published date, and description from the loaded page.

        Reads Open Graph / standard meta tags, with a JSON-LD datePublished
        fallback for the date. The published date is the source publication date
        (full ISO-8601 with timezone), replacing the former REST date_gmt field.

        Args:
            page: active Playwright page positioned on the article.

        Returns:
            dict with keys title, published, description (values may be None/"" ).
        """
        return page.evaluate(
            """
            () => {
              const attr = (sel, a) => { const e = document.querySelector(sel); return e ? e.getAttribute(a) : null; };
              let published = attr('meta[property="article:published_time"]', 'content');
              let title = attr('meta[property="og:title"]', 'content') || document.title;
              let description = attr('meta[property="og:description"]', 'content') || '';
              if (!published) {
                for (const s of document.querySelectorAll('script[type="application/ld+json"]')) {
                  try {
                    const data = JSON.parse(s.textContent);
                    const nodes = Array.isArray(data) ? data : (data['@graph'] || [data]);
                    for (const n of nodes) { if (n && n.datePublished) { published = n.datePublished; break; } }
                  } catch (e) { /* ignore malformed JSON-LD */ }
                  if (published) break;
                }
              }
              return { title, published, description };
            }
            """
        )

    def _render_and_extract(self, browser, url):
        """Render an article to PDF and extract its metadata in one load.

        Args:
            browser: active Playwright Chromium browser.
            url: canonical article URL.

        Returns:
            tuple (pdf_bytes, metadata_dict).

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

            meta = self._extract_metadata(page)

            from datetime import datetime, timezone
            ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            footer = (
                "<div style='font-size:8px; width:100%; padding:0 12px; "
                "color:#444; display:flex; justify-content:space-between;'>"
                f"<span>{html.escape(url)}</span>"
                f"<span>OpenCTI Bellingcat connector &middot; ingested {ingested_at} "
                "&middot; page <span class='pageNumber'></span>/"
                "<span class='totalPages'></span></span></div>"
            )
            pdf_bytes = page.pdf(
                print_background=True,
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=footer,
                margin={"top": "10mm", "bottom": "16mm", "left": "8mm", "right": "8mm"},
                format="A4",
            )
            return pdf_bytes, meta
        finally:
            page.close()
            context.close()

    def _render_with_retry(self, browser, url):
        """Render with bounded exponential backoff.

        Args:
            browser: active Playwright Chromium browser.
            url: canonical article URL.

        Returns:
            tuple (pdf_bytes, metadata) on success, or (None, None) if all
            retries are exhausted.
        """
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._render_and_extract(browser, url)
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

    def _slug_from_url(self, url):
        """Derive a filesystem-safe slug from an article URL.

        Args:
            url: canonical article URL.

        Returns:
            str: trailing path segment, used to name the attached PDF.
        """
        return url.rstrip("/").split("/")[-1] or "article"

    def _create_report(self, url, meta, pdf_bytes):
        """Create one Report container for an article and attach its PDF.

        Container-only: no object_refs, so the single-step report.create path
        is used.

        Args:
            url: canonical article URL (also the dedup key / external reference).
            meta: dict with title, published, description.
            pdf_bytes: rendered article PDF.
        """
        # Title: strip a trailing site-name suffix if the og:title carries one.
        name = _strip_html(meta.get("title") or "")
        name = re.sub(r"\s*[-|]\s*bellingcat\s*$", "", name, flags=re.IGNORECASE).strip()
        if not name:
            name = self._slug_from_url(url)

        description = _strip_html(meta.get("description") or "")
        published = meta.get("published")  # ISO-8601 with timezone from the page

        external_reference = self.helper.api.external_reference.create(
            source_name="Bellingcat",
            url=url,
            description="Source article on bellingcat.com",
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

        file_name = f"bellingcat-{self._slug_from_url(url)}.pdf"
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
            self.helper.connect_id, "Bellingcat enumeration run"
        )

        urls = self._all_article_urls()
        processed = 0   # new Reports created
        skipped = 0     # already present in the graph
        failed = 0      # render failed, or no published date extracted

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                for url in urls:
                    if self.max_posts and processed >= self.max_posts:
                        self.helper.log_info(f"Reached BELLINGCAT_MAX_POSTS={self.max_posts}; stopping run.")
                        break

                    if self._already_ingested(url):
                        skipped += 1
                        continue

                    if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                        browser.close()
                        browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
                        renders_since_recycle = 0

                    pdf_bytes, meta = self._render_with_retry(browser, url)
                    renders_since_recycle += 1

                    if pdf_bytes is None:
                        failed += 1
                        self.helper.log_warning(f"Skipping {url}: render failed after retries.")
                        continue

                    # A Report without a source publication date would corrupt
                    # temporal queries; skip rather than backfill a wrong date.
                    if not meta or not meta.get("published"):
                        failed += 1
                        self.helper.log_warning(f"Skipping {url}: no published date in page metadata.")
                        continue

                    self._create_report(url, meta, pdf_bytes)
                    processed += 1
                    time.sleep(self.request_delay)
            finally:
                browser.close()

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render or missing date)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        """Connector entrypoint: resolve references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info("Bellingcat connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001 - keep the connector alive
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        BellingcatConnector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
