"""
Organized Crime and Corruption Reporting Project (OCCRP) OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://www.occrp.org as container-only OpenCTI Reports, one per
article, with a single PDF attached per Report rendered from the live
article HTML via WeasyPrint.

Collection model (sitemap crawl + positional cursor)
----------------------------------------------------
OCCRP is a custom Next.js site (~21,795 articles from 2004-present) with
three article sub-sitemaps discovered from the sitemap index at /sitemap.xml:
  sitemap_articles_1.xml  (10,000 URLs)
  sitemap_articles_2.xml  (10,000 URLs)
  sitemap_articles_3.xml  (1,795 URLs)

All sub-sitemap entries have <lastmod> dates. Enumeration walks the article
sub-sitemaps in order behind a persisted positional cursor {sitemap_idx,
url_idx} held in OpenCTI connector state. The sub-sitemap list is rebuilt
from the sitemap index on every poll cycle so that newly-added sitemaps are
picked up automatically.

Articles exist in English (/en/) and Russian (/ru/) variants. Only /en/
URLs are processed; Russian translations are filtered out during enumeration.
URL patterns: /en/investigation/{slug}, /en/news/{slug}, /en/feature/{slug}.

robots.txt specifies Crawl-delay: 1 which is strictly honoured via the
request_delay configuration parameter. AI bot user agents are blocked but
there is no technical enforcement.

Content extraction
------------------
Article pages are fetched with plain requests (no Cloudflare challenge or
WAF). Metadata (title, description) is extracted from OpenGraph meta tags.
The article body is extracted from the .article-template__content-generator
container with BeautifulSoup. The published date comes from the
.article-details__date element or OG meta tags. WeasyPrint renders the
final PDF.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id)
and skips if the Report already exists. The {sitemap_idx, url_idx} cursor is
the efficiency layer; the graph lookup is the correctness backstop.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import html as html_mod
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
from xml.etree import ElementTree

import requests
import weasyprint
import yaml
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper, get_config_variable

logging.getLogger("weasyprint").setLevel(logging.ERROR)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Prefix used to identify article sub-sitemaps from the sitemap index.
ARTICLE_SITEMAP_PREFIX = "sitemap_articles_"

# CSS selectors tried in order for the article body content.
CONTENT_SELECTORS = [
    ".article-template__content-generator",
    ".article-template__content",
    "article .content",
    "article",
]

# Elements to strip from extracted content.
STRIP_SELECTORS = [
    "nav",
    ".article-sidebar",
    ".related-articles",
    ".newsletter-signup",
    ".share-buttons",
    "script",
    "style",
    "iframe",
]

# XML namespace used in sitemaps.
_SITEMAP_NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB

_PDF_STYLE = (
    "body { font-family: Georgia, 'Times New Roman', serif; max-width: 800px; "
    "margin: 0 auto; padding: 20px; color: #222; line-height: 1.6; } "
    "h1 { font-size: 24px; margin-bottom: 0.3em; } "
    "h2 { font-size: 20px; } "
    ".byline { font-size: 14px; color: #555; margin-bottom: 1.5em; "
    "border-bottom: 1px solid #ccc; padding-bottom: 0.8em; } "
    "img { max-width: 100%; height: auto; } "
    "pre, code { background: #f4f4f4; padding: 2px 6px; "
    "font-size: 13px; white-space: pre-wrap; word-break: break-all; } "
    "table { border-collapse: collapse; width: 100%; } "
    "td, th { border: 1px solid #ccc; padding: 8px; } "
    "figure { margin: 1em 0; } "
    "figcaption { font-size: 0.85em; color: #666; margin-top: 4px; } "
    "blockquote { border-left: 3px solid #1a3c6e; margin: 1em 0; "
    "padding: 0.5em 1em; color: #555; } "
    "a { color: #1a3c6e; } "
)


def _escape_html(text):
    return html_mod.escape(text, quote=True) if text else ""


def _build_pdf_html(title, byline, content_html, source_url):
    """Wrap extracted article HTML in a styled document for WeasyPrint."""
    safe_title = _escape_html(title)
    safe_byline = _escape_html(byline) if byline else ""
    byline_block = f'<div class="byline">{safe_byline}</div>' if safe_byline else ""
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        + f"<meta name='source-url' content='{_escape_html(source_url)}'>"
        + "<style>"
        + _PDF_STYLE
        + "@page { margin: 15mm 12mm 15mm 12mm; } "
        + "</style></head><body>"
        + "<h1>"
        + safe_title
        + "</h1>"
        + byline_block
        + content_html
        + "</body></html>"
    )


def _is_article_sitemap(sitemap_url):
    """Return True if *sitemap_url* is an article sub-sitemap.

    Example: '.../sitemap_articles_1.xml' -> True
             '.../sitemap_pages.xml'      -> False
    """
    filename = urlparse(sitemap_url).path.rsplit("/", 1)[-1]
    return filename.startswith(ARTICLE_SITEMAP_PREFIX)


def _is_english_article(url):
    """Return True if *url* is an English article page.

    Keeps URLs with /en/ path prefix and filters out Russian translations
    (/ru/) and any other language variants.
    """
    path = urlparse(url).path
    return path.startswith("/en/")


class OccrpConnector:
    """External-import connector that mirrors OCCRP articles into Reports."""

    def __init__(self):
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = {}
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                config = yaml.load(fh, Loader=yaml.FullLoader) or {}

        self.helper = OpenCTIConnectorHelper(config)

        self.base_url = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_BASE_URL",
            ["organized_crime_corruption_reporting", "base_url"],
            config,
            default="https://www.occrp.org",
        ).rstrip("/")

        self.poll_interval = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_POLL_INTERVAL",
            ["organized_crime_corruption_reporting", "poll_interval"],
            config,
            isNumber=True,
            default=86400,
        )

        self.request_delay = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_REQUEST_DELAY",
            ["organized_crime_corruption_reporting", "request_delay"],
            config,
            isNumber=True,
            default=1,
        )

        self.max_reports = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_MAX_REPORTS",
            ["organized_crime_corruption_reporting", "max_reports"],
            config,
            isNumber=True,
            default=0,
        )

        self.render_retries = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_RENDER_RETRIES",
            ["organized_crime_corruption_reporting", "render_retries"],
            config,
            isNumber=True,
            default=3,
        )
        self.pdf_render_timeout = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_PDF_RENDER_TIMEOUT",
            ["organized_crime_corruption_reporting", "pdf_render_timeout"],
            config,
            isNumber=True,
            default=120,
        )

        self.confidence = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_CONFIDENCE",
            ["organized_crime_corruption_reporting", "confidence"],
            config,
            isNumber=True,
            default=50,
        )
        self.report_type = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_REPORT_TYPE",
            ["organized_crime_corruption_reporting", "report_type"],
            config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_TLP",
            ["organized_crime_corruption_reporting", "tlp"],
            config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "ORGANIZED_CRIME_CORRUPTION_REPORTING_AUTHOR_NAME",
            ["organized_crime_corruption_reporting", "author_name"],
            config,
            default="Organized Crime and Corruption Reporting Project",
        )

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": BROWSER_UA,
                "Accept": "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
            }
        )

        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Cursor helpers
    # ------------------------------------------------------------------ #

    def _save_cursor(self, sitemap_idx, url_idx):
        self.helper.set_state(
            {
                "sitemap_idx": sitemap_idx,
                "url_idx": url_idx,
            }
        )

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description=(
                "Organized Crime and Corruption Reporting Project (OCCRP). "
                "Investigative journalism network covering organized crime, "
                "corruption, and related threats. Source for ingested reports."
            ),
        )
        self.author_id = author["id"]
        self.helper.log_info(
            f"Resolved author identity '{self.author_name}': {self.author_id}"
        )

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
            self.helper.log_info(
                f"Ensured report_type vocabulary value: {self.report_type}"
            )
        except Exception as exc:
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc}). "
                f"Add it under Settings -> Taxonomies -> Report types if missing."
            )

    # ------------------------------------------------------------------ #
    # Sitemap enumeration
    # ------------------------------------------------------------------ #

    def _fetch_sitemap_index(self):
        """Fetch and parse the sitemap index, returning an ordered list of
        article sub-sitemap URLs."""
        url = f"{self.base_url}/sitemap.xml"
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch sitemap index: {exc}")
            return None

        try:
            root = ElementTree.fromstring(resp.content)
        except ElementTree.ParseError as exc:
            self.helper.log_error(f"Failed to parse sitemap index XML: {exc}")
            return None

        sitemaps = []
        for sitemap_el in root.findall("sm:sitemap", _SITEMAP_NS):
            loc_el = sitemap_el.find("sm:loc", _SITEMAP_NS)
            if loc_el is None or not loc_el.text:
                continue
            loc = loc_el.text.strip()
            if _is_article_sitemap(loc):
                sitemaps.append(loc)

        self.helper.log_info(
            f"Sitemap index: {len(sitemaps)} article sub-sitemaps found."
        )
        return sitemaps

    def _fetch_sub_sitemap(self, sitemap_url):
        """Fetch and parse a single sub-sitemap, returning a list of
        (url, lastmod) tuples for valid English article URLs."""
        try:
            resp = self.session.get(sitemap_url, timeout=60)
            resp.raise_for_status()
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch sub-sitemap {sitemap_url}: {exc}")
            return None

        try:
            root = ElementTree.fromstring(resp.content)
        except ElementTree.ParseError as exc:
            self.helper.log_error(
                f"Failed to parse sub-sitemap XML {sitemap_url}: {exc}"
            )
            return None

        entries = []
        for url_el in root.findall("sm:url", _SITEMAP_NS):
            loc_el = url_el.find("sm:loc", _SITEMAP_NS)
            if loc_el is None or not loc_el.text:
                continue
            loc = loc_el.text.strip()
            if not _is_english_article(loc):
                continue

            lastmod = None
            lastmod_el = url_el.find("sm:lastmod", _SITEMAP_NS)
            if lastmod_el is not None and lastmod_el.text:
                lastmod = lastmod_el.text.strip()

            entries.append((loc, lastmod))

        return entries

    # ------------------------------------------------------------------ #
    # Metadata extraction
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_metadata(soup):
        """Extract title, description, and published date from the page.

        Uses OG meta tags and CSS selectors (no JSON-LD on OCCRP).
        """
        title = None
        description = None
        published = None

        # OG meta tags.
        og_title = soup.select_one('meta[property="og:title"]')
        if og_title:
            title = og_title.get("content", "").strip()

        og_desc = soup.select_one('meta[property="og:description"]')
        if og_desc:
            description = og_desc.get("content", "").strip()
        if not description:
            meta_desc = soup.select_one('meta[name="description"]')
            if meta_desc:
                description = meta_desc.get("content", "").strip()

        # CSS selector for title as fallback.
        if not title:
            title_el = soup.select_one(".article-template__title")
            if title_el:
                title = title_el.get_text(strip=True)

        # Published date from CSS selector.
        date_el = soup.select_one(".article-details__date")
        if date_el:
            date_text = date_el.get_text(strip=True)
            # Try parsing common date formats (e.g. "January 15, 2024",
            # "15 January 2024", "2024-01-15").
            for fmt in (
                "%B %d, %Y",
                "%d %B %Y",
                "%Y-%m-%d",
                "%b %d, %Y",
                "%d %b %Y",
            ):
                try:
                    dt = datetime.strptime(date_text, fmt)
                    published = dt.replace(tzinfo=timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S+00:00"
                    )
                    break
                except ValueError:
                    continue

        # OG meta fallback for date.
        if not published:
            og_time = soup.select_one('meta[property="article:published_time"]')
            if og_time:
                published = og_time.get("content", "").strip()
            else:
                og_mod = soup.select_one('meta[property="article:modified_time"]')
                if og_mod:
                    published = og_mod.get("content", "").strip()

        # Title fallback to HTML <title>.
        if not title and soup.title and soup.title.string:
            title = soup.title.string.strip()

        return title, description or "", published

    # ------------------------------------------------------------------ #
    # Content extraction and PDF rendering
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_content(soup):
        """Extract article body content from the page."""
        content = None
        for selector in CONTENT_SELECTORS:
            content = soup.select_one(selector)
            if content:
                break
        if not content:
            return None

        for sel in STRIP_SELECTORS:
            for el in content.select(sel):
                el.decompose()
        return content

    @staticmethod
    def _report_id(url):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))

    def _retry(self, fn, label):
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return fn()
            except Exception as exc:
                self.helper.log_warning(
                    f"{label} attempt {attempt}/{self.render_retries} failed: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay *= 2
        return None

    def _wp_url_fetcher(self, url):
        if url.startswith("data:"):
            return weasyprint.default_url_fetcher(url)
        try:
            resp = self.session.get(url, timeout=15)
            if not resp.ok:
                return {"string": b"", "mime_type": "text/plain"}
            return {
                "string": resp.content,
                "mime_type": resp.headers.get(
                    "content-type", "application/octet-stream"
                ).split(";")[0],
            }
        except Exception:
            return {"string": b"", "mime_type": "text/plain"}

    def _render_pdf(self, url, title, content_html):
        """Render extracted article HTML to PDF via WeasyPrint."""
        doc_html = _build_pdf_html(title, "", content_html, url)

        content_bytes = len(doc_html.encode("utf-8", errors="replace"))
        if content_bytes > MAX_CONTENT_BYTES:
            self.helper.log_warning(
                f"Content too large for PDF render ({content_bytes:,} bytes)."
            )
            return None

        return weasyprint.HTML(
            string=doc_html, base_url=url, url_fetcher=self._wp_url_fetcher
        ).write_pdf()

    def _render_pdf_with_timeout(self, *args, **kwargs):
        """Wrap _render_pdf in a daemon thread with a wall-clock timeout."""
        import threading
        result = [None]
        exc_holder = [None]
        def target():
            """Run _render_pdf in a separate thread."""
            try:
                result[0] = self._render_pdf(*args, **kwargs)
            except Exception as e:
                exc_holder[0] = e
        t = threading.Thread(target=target, daemon=True)
        t.start()
        t.join(timeout=self.pdf_render_timeout)
        if t.is_alive():
            self.helper.log_warning(
                f"PDF render timed out after {self.pdf_render_timeout}s"
            )
            return None
        if exc_holder[0]:
            raise exc_holder[0]
        return result[0]

    def _fetch_and_render(self, url):
        """Fetch an article page, extract content and metadata, render PDF.

        Returns (title, description, published_iso, pdf_bytes) or None on failure.
        """
        resp = self.session.get(url, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")

        soup = BeautifulSoup(resp.text, "lxml")

        title, description, published = self._extract_metadata(soup)
        if not title:
            title = url

        content = self._extract_content(soup)
        if content is None:
            raise RuntimeError("No article content container found")

        content_html = str(content)

        pdf_bytes = self._render_pdf_with_timeout(url, title, content_html)
        return title, description, published, pdf_bytes

    def _fetch_and_render_with_retry(self, url):
        return self._retry(
            lambda: self._fetch_and_render(url),
            f"PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Date parsing
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_published_iso(date_str, lastmod_str=None):
        """Parse a date string into ISO 8601 format, falling back to lastmod."""
        for raw in (date_str, lastmod_str):
            if not raw:
                continue
            try:
                dt = datetime.fromisoformat(raw)
            except (TypeError, ValueError):
                continue
            dt = dt.astimezone(timezone.utc)
            if dt.year >= 2000:
                return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        return None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, url, title, description, published, pdf_bytes):
        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on occrp.org",
        )

        report = self.helper.api.report.create(
            stix_id=report_id,
            name=title,
            description=description,
            published=published,
            report_types=[self.report_type],
            confidence=self.confidence,
            createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[external_reference["id"]],
            update=True,
        )

        slug = urlparse(url).path.strip("/").rsplit("/", 1)[-1] or "article"

        if len(pdf_bytes) > MAX_PDF_BYTES:
            self.helper.log_warning(
                f"Skipping oversized PDF for {url} ({len(pdf_bytes):,} bytes)."
            )
        else:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"occrp-{slug}.pdf",
                data=pdf_bytes,
                mime_type="application/pdf",
            )

        self.helper.log_info(f"Created Report for {url} ({title[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        sitemaps = self._fetch_sitemap_index()
        if sitemaps is None:
            self.helper.log_warning(
                "Sitemap index unreachable; skipping this cycle."
            )
            return
        if not sitemaps:
            self.helper.log_warning(
                "Sitemap index returned no article sub-sitemaps; skipping."
            )
            return

        state = self.helper.get_state() or {}
        cursor_sitemap_idx = max(0, int(state.get("sitemap_idx", 0)))
        cursor_url_idx = max(0, int(state.get("url_idx", 0)))

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "OCCRP enumeration run"
        )
        self.helper.log_info(
            f"Resuming at sitemap_idx={cursor_sitemap_idx}, "
            f"url_idx={cursor_url_idx}, "
            f"total sub-sitemaps={len(sitemaps)}."
        )

        processed = 0
        skipped = 0
        failed = 0
        stop = False
        try:

            for sm_idx in range(cursor_sitemap_idx, len(sitemaps)):
                if stop:
                    break

                sitemap_url = sitemaps[sm_idx]

                self.helper.log_info(
                    f"Processing sub-sitemap {sm_idx + 1}/{len(sitemaps)}: "
                    f"{sitemap_url}"
                )

                entries = self._fetch_sub_sitemap(sitemap_url)
                if entries is None:
                    self.helper.log_warning(
                        f"Sub-sitemap {sitemap_url} fetch failed; "
                        f"preserving cursor for retry next cycle."
                    )
                    break

                time.sleep(self.request_delay)

                start_idx = cursor_url_idx if sm_idx == cursor_sitemap_idx else 0

                self.helper.log_info(
                    f"Sub-sitemap has {len(entries)} English article URLs; "
                    f"starting at index {start_idx}."
                )

                for url_idx in range(start_idx, len(entries)):
                    article_url, lastmod = entries[url_idx]

                    if self.max_reports and processed >= self.max_reports:
                        self.helper.log_info(
                            f"Reached max_reports={self.max_reports}; stopping run."
                        )
                        stop = True
                        break

                    # Graph dedup check.
                    if (
                        self.helper.api.report.read(id=self._report_id(article_url))
                        is not None
                    ):
                        skipped += 1
                        self._save_cursor(sm_idx, url_idx + 1)
                        continue

                    result = self._fetch_and_render_with_retry(article_url)
                    if result is None:
                        failed += 1
                        self.helper.log_warning(
                            f"Skipping {article_url}: render failed after retries."
                        )
                        self._save_cursor(sm_idx, url_idx + 1)
                        time.sleep(self.request_delay)
                        continue

                    title, description, published_raw, pdf_bytes = result
                    if pdf_bytes is None:
                        failed += 1
                        self.helper.log_warning(
                            f"Skipping {article_url}: content too large for PDF."
                        )
                        self._save_cursor(sm_idx, url_idx + 1)
                        time.sleep(self.request_delay)
                        continue

                    published = self._parse_published_iso(published_raw, lastmod)
                    if not published:
                        published = datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S+00:00"
                        )
                        self.helper.log_warning(
                            f"No usable date for {article_url}; using ingestion time."
                        )

                    self._create_report(
                        article_url, title, description, published, pdf_bytes,
                    )
                    processed += 1
                    self._save_cursor(sm_idx, url_idx + 1)
                    time.sleep(self.request_delay)

                if not stop:
                    # Finished this sub-sitemap; advance cursor to the next one.
                    self._save_cursor(sm_idx + 1, 0)
                    time.sleep(self.request_delay)

        finally:
            message = (
                f"Run complete: {processed} created, {skipped} already present, "
                f"{failed} failed (render)."
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("OCCRP connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        OccrpConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
