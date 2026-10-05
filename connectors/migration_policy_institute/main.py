"""
Migration Policy Institute (MPI) OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://www.migrationpolicy.org as container-only OpenCTI Reports, one per
article, with the source article attached as a full-fidelity PDF.

Collection model (Playwright listing walk + graph-dedup early-stop)
-------------------------------------------------------------------
MPI is a Drupal site with aggressive WAF protection that blocks ALL non-browser
HTTP access (API endpoints, RSS feeds, sitemaps, and even standard listing pages
return 403 to non-browser clients). Only the homepage responds to plain HTTP.
Collection therefore uses Playwright for both enumeration and content retrieval.

Enumeration walks one or more configurable listing-page base URLs (default:
/research and /news) from page 0 (Drupal's 0-based ?page=N pagination) forward.
An early-stop optimisation halts the walk for a given listing when an entire page
contains only articles already present in the graph, since everything older is
also known (listings default to newest-first).

Article pages are fetched via Playwright for content extraction (the WAF would
block requests). BeautifulSoup extracts the article body from Drupal field
renderers. WeasyPrint renders the extracted HTML to PDF.

Content scope
-------------
IN:  Commentary, Research publications, Policy briefs, Explainers, Reports,
     Features, Spotlights.
OUT: Podcasts, Data hub / data tools, Multimedia.

URL patterns containing /podcast/, /data-hub/, or /multimedia/ are filtered
during enumeration.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels. Entity extraction is a separate
downstream phase.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (public source, no paywall).
- Author: the "Migration Policy Institute" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band, policy research institute).
- Deduplication: graph-driven via deterministic Report STIX ID
  (uuid5 of article URL). No cursor/state; every poll re-walks the listings
  with early-stop, which makes an interrupted backfill inherently resumable.
- PDF rendering: WeasyPrint (Playwright is for navigation only).
- Browser recycled every ~50 page loads to prevent memory leaks.
- request_delay: 3 seconds between page loads.
- MPI has sub-brands (MPI Europe, MPI en Espanol); identified from page
  content and included in Report description when present.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import html as html_mod
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

import yaml
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside _process() so a syntax/import check of
# this module does not require the browser stack to be present.

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from microservices.classify_report import classify_report
from microservices.make_pdf import render_html_to_pdf


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

MAX_LISTING_PAGES = 500  # safety cap per listing URL

BROWSER_RECYCLE_EVERY = 50

CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")

MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB

# URL path segments that indicate out-of-scope content.
SKIP_URL_SEGMENTS = ("/podcast/", "/data-hub/", "/multimedia/")

# Drupal body-field selectors, tried in priority order.
CONTENT_SELECTORS = [
    ".field--name-body",
    ".node__content",
    ".article-content",
    "article .content",
    ".field-item",
    ".field--name-field-body",
    "main article",
]

# Elements to strip from extracted article content.
STRIP_SELECTORS = [
    "nav",
    ".menu",
    ".sidebar",
    ".footer",
    ".share-links",
    ".social-share",
    ".social-media",
    ".breadcrumb",
    ".pager",
    ".block-system-breadcrumb-block",
    ".print-link",
    ".field--name-field-related",
    ".related-content",
    "script",
    "style",
    "iframe",
    "noscript",
]

def _strip_html(value):
    """Remove HTML tags and decode entities."""
    if not value:
        return ""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", value)).strip()


def _should_skip_url(url):
    """Return True if the URL matches an out-of-scope pattern."""
    path = urlparse(url).path.lower()
    return any(seg in path for seg in SKIP_URL_SEGMENTS)


def _build_listing_url(base_url, page_num):
    """Build a Drupal-style paginated listing URL (?page=N, 0-based)."""
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)
    params["page"] = [str(page_num)]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class MPIConnector:
    """External-import connector that mirrors MPI articles into Reports."""

    def __init__(self):
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = {}
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}

        self.helper = OpenCTIConnectorHelper(config)

        # --- Source configuration ------------------------------------------ #
        self.base_url = get_config_variable(
            "MPI_BASE_URL", ["migration_policy_institute", "base_url"], config,
            default="https://www.migrationpolicy.org",
        ).rstrip("/")

        listing_urls_raw = get_config_variable(
            "MPI_LISTING_URLS", ["migration_policy_institute", "listing_urls"], config,
            default="/research,/news",
        )
        self.listing_urls = [
            f"{self.base_url}{u.strip()}" if u.strip().startswith("/")
            else u.strip()
            for u in listing_urls_raw.split(",")
            if u.strip()
        ]

        self.poll_interval = get_config_variable(
            "MPI_POLL_INTERVAL", ["migration_policy_institute", "poll_interval"], config,
            isNumber=True, default=21600,
        )

        self.request_delay = get_config_variable(
            "MPI_REQUEST_DELAY", ["migration_policy_institute", "request_delay"], config,
            isNumber=True, default=3,
        )

        self.max_reports = get_config_variable(
            "MPI_MAX_REPORTS", ["migration_policy_institute", "max_reports"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ------------------------------------------ #
        self.nav_timeout_ms = get_config_variable(
            "MPI_PLAYWRIGHT_NAV_TIMEOUT", ["migration_policy_institute", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "MPI_RENDER_RETRIES", ["migration_policy_institute", "render_retries"], config,
            isNumber=True, default=3,
        )
        self.pdf_render_timeout = get_config_variable(
            "MPI_PDF_RENDER_TIMEOUT",
            ["migration_policy_institute", "pdf_render_timeout"],
            config,
            isNumber=True,
            default=120,
        )

        # --- Report field configuration ------------------------------------ #
        self.confidence = get_config_variable(
            "MPI_CONFIDENCE", ["migration_policy_institute", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "MPI_REPORT_TYPE", ["migration_policy_institute", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "MPI_TLP", ["migration_policy_institute", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "MPI_AUTHOR_NAME", ["migration_policy_institute", "author_name"], config,
            default="Migration Policy Institute",
        )

        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Nonpartisan migration policy research institute based "
                        "in Washington, D.C. Source organization for ingested "
                        "reports. Sub-brands include MPI Europe and MPI en "
                        "Espanol.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved author identity: {self.author_id}")

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

        try:
            self.helper.api.vocabulary.create(
                name=self.report_type,
                category="report_types_ov",
                description="Open-source reporting ingested from public OSINT publishers.",
            )
            self.helper.log_info(f"Ensured report_type vocabulary value: {self.report_type}")
        except Exception as exc:
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc}). "
                f"Add it under Settings -> Taxonomies -> Report types if missing."
            )

    # ------------------------------------------------------------------ #
    # Deduplication
    # ------------------------------------------------------------------ #

    @staticmethod
    def _report_id(url):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))

    def _already_ingested(self, url):
        return self.helper.api.report.read(id=self._report_id(url)) is not None

    # ------------------------------------------------------------------ #
    # Listing-page enumeration (Playwright)
    # ------------------------------------------------------------------ #

    def _scrape_listing_page(self, page, listing_url, page_num):
        """Navigate to a listing page and return unique article URLs.

        Returns a list of URLs on success, an empty list if the page is out of
        range or contains no article links, or ``None`` on failure (CF
        challenge, network error).
        """
        url = _build_listing_url(listing_url, page_num)
        try:
            page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)
        except Exception as exc:
            self.helper.log_warning(
                f"Failed to load listing page {page_num} of {listing_url}: {exc}"
            )
            return None

        title = (page.title() or "").lower()
        if any(marker in title for marker in CHALLENGE_MARKERS):
            self.helper.log_warning(f"WAF challenge on listing page {page_num}")
            return None

        base_url = self.base_url
        article_urls = page.evaluate(
            """
            (baseUrl) => {
              // Look for article links in the main content area.
              // Drupal Views render content in .view-content, .views-row, etc.
              const containers = [
                document.querySelector('.view-content'),
                document.querySelector('.views-element-container'),
                document.querySelector('main .content'),
                document.querySelector('main'),
                document.querySelector('#content'),
              ];
              const container = containers.find(c => c !== null) || document.body;

              const links = container.querySelectorAll('a[href]');
              const seen = new Set();
              const urls = [];
              for (const a of links) {
                let href = a.href;
                if (!href) continue;
                // Normalise: strip trailing slash for dedup, then re-add
                href = href.replace(/\\/+$/, '');
                if (!href.startsWith(baseUrl)) continue;

                const path = new URL(href).pathname;
                // Must have at least 2 path segments (section + article slug)
                const segments = path.split('/').filter(Boolean);
                if (segments.length < 2) continue;

                // Skip non-content patterns
                const lower = path.toLowerCase();
                if (/\\/(podcast|data-hub|multimedia|events|about|staff|donate|careers|contact|press-room)\\//i.test(lower)) continue;
                // Skip listing/section pages that end in common section names
                if (/^\\/(research|news|programs|topics|regions)\\/?$/i.test(lower)) continue;
                // Skip anchor-only or query-only links
                if (href.includes('#') && href.split('#')[0] === '') continue;

                if (!seen.has(href)) {
                  seen.add(href);
                  urls.push(href);
                }
              }
              return urls;
            }
            """,
            base_url,
        )
        return article_urls or []

    # ------------------------------------------------------------------ #
    # Article content extraction (Playwright + BS4)
    # ------------------------------------------------------------------ #

    def _extract_article(self, page, url):
        """Navigate to an article page and extract metadata + body HTML.

        Returns (meta_dict, body_html_string) or (None, None) on failure.
        Meta dict keys: title, published, description, topics, sub_brand.
        """
        page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)

        title = (page.title() or "").lower()
        if any(marker in title for marker in CHALLENGE_MARKERS):
            raise RuntimeError("WAF challenge interstitial detected")

        # --- Metadata extraction via JS -------------------------------- #
        meta = page.evaluate(
            """
            () => {
              // Title
              const h1 = document.querySelector('h1');
              const title = h1 ? h1.textContent.trim() : document.title;

              // Published date: Drupal <time> element, meta tags, or field
              let published = null;
              const timeEl = document.querySelector('time[datetime]');
              if (timeEl) {
                published = timeEl.getAttribute('datetime');
              }
              if (!published) {
                const metaDate = document.querySelector(
                  'meta[property="article:published_time"]'
                );
                if (metaDate) published = metaDate.getAttribute('content');
              }
              if (!published) {
                const dateField = document.querySelector(
                  '.field--name-field-date, .field--name-created, .date-display-single'
                );
                if (dateField) published = dateField.textContent.trim();
              }

              // Description
              const ogDesc = document.querySelector(
                'meta[property="og:description"]'
              );
              let description = ogDesc ? ogDesc.getAttribute('content') : '';
              if (!description) {
                const metaDesc = document.querySelector(
                  'meta[name="description"]'
                );
                description = metaDesc ? metaDesc.getAttribute('content') : '';
              }

              // Topics / taxonomy terms
              const topicEls = document.querySelectorAll(
                '.field--name-field-topics a, ' +
                '.field--name-field-tags a, ' +
                '.field--name-field-categories a, ' +
                '.taxonomy-term a, ' +
                '.field--name-field-program a, ' +
                '.field--name-field-regions a'
              );
              const topics = [];
              const topicSet = new Set();
              for (const el of topicEls) {
                const t = el.textContent.trim();
                if (t && !topicSet.has(t)) {
                  topicSet.add(t);
                  topics.push(t);
                }
              }

              // Sub-brand detection (MPI Europe, MPI en Espanol, etc.)
              let subBrand = null;
              const body = document.body.textContent || '';
              if (/MPI\\s+Europe/i.test(body.substring(0, 3000))) {
                subBrand = 'MPI Europe';
              } else if (/MPI\\s+en\\s+Espa[nñ]ol/i.test(body.substring(0, 3000))) {
                subBrand = 'MPI en Espanol';
              }

              // Author byline
              const authorEl = document.querySelector(
                '.field--name-field-author, ' +
                '.field--name-field-authors, ' +
                '.author-name, ' +
                '.byline'
              );
              const author = authorEl ? authorEl.textContent.trim() : null;

              return { title, published, description, topics, subBrand, author };
            }
            """
        )

        # --- Body extraction via BS4 ----------------------------------- #
        self._auto_scroll(page)
        page_html = page.content()
        soup = BeautifulSoup(page_html, "lxml")

        content = None
        for selector in CONTENT_SELECTORS:
            content = soup.select_one(selector)
            if content:
                break

        if not content:
            return meta, None

        # Strip cruft elements.
        for sel in STRIP_SELECTORS:
            for el in content.select(sel):
                el.decompose()

        # Resolve relative image URLs to absolute.
        for img in content.find_all("img"):
            src = img.get("src", "")
            if src and not src.startswith(("http://", "https://", "data:")):
                img["src"] = f"{self.base_url}{src}" if src.startswith("/") else f"{self.base_url}/{src}"

        body_html = str(content)
        return meta, body_html

    # ------------------------------------------------------------------ #
    # PDF rendering (WeasyPrint)
    # ------------------------------------------------------------------ #

    def _render_with_retry(self, title, byline, content_html, source_url):
        """Retry PDF rendering with exponential backoff."""
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return render_html_to_pdf(title, str(content_html), source_url, timeout=self.pdf_render_timeout)
            except Exception as exc:
                self.helper.log_warning(
                    f"PDF render attempt {attempt}/{self.render_retries} failed "
                    f"for {source_url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay *= 2
        return None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    @staticmethod
    def _slug_from_url(url):
        return urlparse(url).path.strip("/").rsplit("/", 1)[-1] or "article"

    @staticmethod
    def _content_type_from_url(url):
        """Infer a human-readable content type from the URL path."""
        path = urlparse(url).path.lower()
        if path.startswith("/research"):
            return "Research"
        if path.startswith("/commentary"):
            return "Commentary"
        if path.startswith("/news"):
            return "News"
        if path.startswith("/article"):
            return "Article"
        return None

    @staticmethod
    def _parse_published(raw):
        """Parse a date string into ISO-8601; return None if unparseable."""
        if not raw:
            return None
        raw = raw.strip()
        # ISO-8601 datetime (from Drupal <time datetime="...">)
        if re.match(r"\d{4}-\d{2}-\d{2}", raw):
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except (TypeError, ValueError):
                pass
        # Common US date formats
        for fmt in ("%B %d, %Y", "%b %d, %Y", "%m/%d/%Y", "%B %Y"):
            try:
                dt = datetime.strptime(raw, fmt)
                return dt.replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
        return None

    def _create_report(self, url, meta, pdf_bytes):
        """Create an OpenCTI Report with attached PDF."""
        name = _strip_html(meta.get("title") or "")
        # Clean trailing site name from title
        name = re.sub(r"\s*[-|]\s*Migration Policy Institute\s*$", "", name, flags=re.I).strip()
        if not name:
            name = self._slug_from_url(url)

        description_parts = []
        if meta.get("author"):
            description_parts.append(f"By {_strip_html(meta['author'])}.")
        if meta.get("subBrand"):
            description_parts.append(f"Published by {meta['subBrand']}.")
        content_type = self._content_type_from_url(url)
        if content_type:
            description_parts.append(f"Type: {content_type}.")
        if meta.get("topics"):
            description_parts.append(f"Topics: {', '.join(meta['topics'])}.")
        raw_desc = _strip_html(meta.get("description") or "")
        if raw_desc:
            description_parts.append(raw_desc)
        description = " ".join(description_parts)

        published = self._parse_published(meta.get("published"))
        if not published:
            published = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            self.helper.log_warning(
                f"No usable date for {url}; using ingestion time."
            )

        ref_desc = "Source article on migrationpolicy.org"
        if meta.get("author"):
            ref_desc = f"By {_strip_html(meta['author'])}. {ref_desc}"

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description=ref_desc,
        )

        _report_types = classify_report(
            title=name, description=description, content=description or "",
            source="Migration Policy Institute", source_url=url,
            default_types=[self.report_type],
        )

        report = self.helper.api.report.create(
            stix_id=self._report_id(url),
            name=name,
            description=description,
            published=published,
            report_types=_report_types,
            confidence=self.confidence,
            createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[external_reference["id"]],
            update=True,
        )

        file_name = f"mpi-{self._slug_from_url(url)}.pdf"
        if len(pdf_bytes) > MAX_PDF_BYTES:
            self.helper.log_warning(
                f"Skipping oversized PDF for {url} ({len(pdf_bytes):,} bytes)."
            )
        else:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=file_name,
                data=pdf_bytes,
                mime_type="application/pdf",
            )
        self.helper.log_info(f"Created Report for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Auto-scroll (trigger lazy-loaded images)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _auto_scroll(page):
        page.evaluate(
            """
            async () => {
              await new Promise((resolve) => {
                let total = 0;
                const step = 400;
                const timer = setInterval(() => {
                  window.scrollBy(0, step);
                  total += step;
                  if (total >= document.body.scrollHeight || total >= 50000) {
                    clearInterval(timer);
                    window.scrollTo(0, 0);
                    resolve();
                  }
                }, 100);
              });
            }
            """
        )

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        from playwright.sync_api import sync_playwright

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "MPI enumeration run"
        )

        processed = 0
        skipped = 0
        failed = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                listing_ctx = browser.new_context(user_agent=BROWSER_UA)
                listing_page = listing_ctx.new_page()

                for listing_url in self.listing_urls:
                    self.helper.log_info(
                        f"Walking listing: {listing_url}"
                    )

                    for page_num in range(0, MAX_LISTING_PAGES):
                        if self.max_reports and processed >= self.max_reports:
                            self.helper.log_info(
                                f"Reached MPI_MAX_REPORTS={self.max_reports}; stopping."
                            )
                            break

                        article_urls = self._scrape_listing_page(
                            listing_page, listing_url, page_num
                        )
                        if article_urls is None:
                            self.helper.log_warning(
                                f"Listing {listing_url} page {page_num}: "
                                f"scrape failed (CF challenge or network error); skipping page."
                            )
                            time.sleep(self.request_delay)
                            continue
                        if not article_urls:
                            self.helper.log_info(
                                f"Listing {listing_url} page {page_num}: "
                                f"no articles found; enumeration complete for this listing."
                            )
                            break

                        self.helper.log_info(
                            f"Listing {listing_url} page {page_num}: "
                            f"{len(article_urls)} articles"
                        )

                        all_known = True
                        for url in article_urls:
                            if self.max_reports and processed >= self.max_reports:
                                break

                            # Apply URL filter (skip podcasts, data-hub, etc.)
                            if _should_skip_url(url):
                                all_known = False
                                continue

                            if self._already_ingested(url):
                                skipped += 1
                                continue

                            all_known = False

                            # Recycle browser if needed.
                            if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                                listing_page.close()
                                listing_ctx.close()
                                browser.close()
                                browser = pw.chromium.launch(
                                    args=["--no-sandbox", "--disable-dev-shm-usage"]
                                )
                                renders_since_recycle = 0
                                listing_ctx = browser.new_context(user_agent=BROWSER_UA)
                                listing_page = listing_ctx.new_page()

                            # Extract article content via a separate context.
                            article_ctx = browser.new_context(
                                viewport={"width": 1280, "height": 1696},
                                user_agent=BROWSER_UA,
                            )
                            article_page = article_ctx.new_page()
                            try:
                                meta, body_html = self._extract_article(article_page, url)
                            except Exception as exc:
                                self.helper.log_warning(
                                    f"Article extraction failed for {url}: {exc}"
                                )
                                failed += 1
                                time.sleep(self.request_delay)
                                continue
                            finally:
                                renders_since_recycle += 1
                                article_page.close()
                                article_ctx.close()

                            if not body_html:
                                self.helper.log_warning(
                                    f"Skipping {url}: no article content found."
                                )
                                failed += 1
                                time.sleep(self.request_delay)
                                continue

                            title = _strip_html(meta.get("title") or "")
                            byline_parts = []
                            if meta.get("author"):
                                byline_parts.append(_strip_html(meta["author"]))
                            if meta.get("topics"):
                                byline_parts.append(", ".join(meta["topics"]))
                            byline = "  |  ".join(byline_parts) if byline_parts else ""

                            pdf_bytes = self._render_with_retry(
                                title, byline, body_html, url
                            )
                            if pdf_bytes is None:
                                failed += 1
                                self.helper.log_warning(
                                    f"Skipping {url}: PDF render failed after retries."
                                )
                                time.sleep(self.request_delay)
                                continue

                            self._create_report(url, meta, pdf_bytes)
                            processed += 1
                            time.sleep(self.request_delay)

                        if all_known and article_urls:
                            self.helper.log_info(
                                f"All articles on page {page_num} of {listing_url} "
                                f"already ingested; stopping walk for this listing."
                            )
                            break

                        time.sleep(self.request_delay)

                    if self.max_reports and processed >= self.max_reports:
                        break

                listing_page.close()
                listing_ctx.close()
            finally:
                browser.close()

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (extraction or render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info(
            f"MPI connector started. Listing URLs: {self.listing_urls}"
        )
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        MPIConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
