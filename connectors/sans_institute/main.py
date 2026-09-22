"""
SANS Institute Blog OpenCTI connector.

Purpose
-------
External-import connector that ingests blog posts from
https://www.sans.org/blog/ as container-only OpenCTI Reports, one per
article, with a single PDF attached per Report rendered from the live
article HTML via WeasyPrint.

Collection model (sitemap + graph-dedup re-walk)
------------------------------------------------
SANS is a ContentStack (headless CMS) + Next.js site with ~976 blog
posts. The sitemap at /sitemaps/blogs.xml is a single flat file listing
all blog URLs with <loc> and <lastmod> elements. However the lastmod
dates are all identical (a bulk re-index artifact), so they are NOT
useful as a cursor.

Instead the connector does a full re-walk of the sitemap on every poll
cycle, using graph dedup (report.read(id=report_id)) to skip articles
that already exist. This is safe because the corpus is small (~976
posts).

Content extraction
------------------
Article pages are fetched with plain requests (no Imperva/CDN challenge).
Metadata is extracted from the JSON-LD BlogPosting schema embedded in
each page (headline, description, datePublished, dateModified, author).
CSS selectors serve as fallback. WeasyPrint renders the final PDF.

robots.txt specifies no crawl-delay and blog paths are not disallowed.
A configurable request_delay (default 2 seconds) spaces requests.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain
Objects, no Observables, no Relationships, no Labels.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import html as html_mod
import json
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

# CSS selectors tried in order for the article body content.
CONTENT_SELECTORS = [
    ".c-rich-text.generic-content-block__rich-text",
    ".c-rich-text",
    "article .content",
    "article",
]

# Elements to strip from extracted content.
STRIP_SELECTORS = [
    "nav",
    "script",
    "style",
    "iframe",
    ".newsletter-signup",
    ".social-share",
    ".related-posts",
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


def _css_string_escape(s):
    return (
        s.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\a ")
        .replace("\r", "")
    )


def _build_pdf_html(title, byline, content_html, source_url, ingested_at):
    css_url = _css_string_escape(source_url)
    safe_title = _escape_html(title)
    safe_byline = _escape_html(byline) if byline else ""
    byline_block = f'<div class="byline">{safe_byline}</div>' if safe_byline else ""
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        + f"<meta name='source-url' content='{_escape_html(source_url)}'>"
        + "<style>"
        + _PDF_STYLE
        + "@page { margin: 15mm 12mm 20mm 12mm; "
        + "@bottom-center { content: '"
        + css_url
        + "  |  OpenCTI SANS Institute connector  |  "
        + ingested_at
        + "'; font-size: 7px; color: #888; } } "
        + "</style></head><body>"
        + "<h1>"
        + safe_title
        + "</h1>"
        + byline_block
        + content_html
        + "</body></html>"
    )


class SansInstituteConnector:
    """External-import connector that mirrors SANS blog posts into Reports."""

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
            "SANS_INSTITUTE_BASE_URL",
            ["sans_institute", "base_url"],
            config,
            default="https://www.sans.org",
        ).rstrip("/")

        self.sitemap_url = get_config_variable(
            "SANS_INSTITUTE_SITEMAP_URL",
            ["sans_institute", "sitemap_url"],
            config,
            default="https://www.sans.org/sitemaps/blogs.xml",
        )

        self.poll_interval = get_config_variable(
            "SANS_INSTITUTE_POLL_INTERVAL",
            ["sans_institute", "poll_interval"],
            config,
            isNumber=True,
            default=86400,
        )

        self.request_delay = get_config_variable(
            "SANS_INSTITUTE_REQUEST_DELAY",
            ["sans_institute", "request_delay"],
            config,
            isNumber=True,
            default=2,
        )

        self.max_reports = get_config_variable(
            "SANS_INSTITUTE_MAX_REPORTS",
            ["sans_institute", "max_reports"],
            config,
            isNumber=True,
            default=0,
        )

        self.render_retries = get_config_variable(
            "SANS_INSTITUTE_RENDER_RETRIES",
            ["sans_institute", "render_retries"],
            config,
            isNumber=True,
            default=3,
        )

        self.confidence = get_config_variable(
            "SANS_INSTITUTE_CONFIDENCE",
            ["sans_institute", "confidence"],
            config,
            isNumber=True,
            default=50,
        )
        self.report_type = get_config_variable(
            "SANS_INSTITUTE_REPORT_TYPE",
            ["sans_institute", "report_type"],
            config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "SANS_INSTITUTE_TLP",
            ["sans_institute", "tlp"],
            config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "SANS_INSTITUTE_AUTHOR_NAME",
            ["sans_institute", "author_name"],
            config,
            default="SANS Institute",
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
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description=(
                "SANS Institute. Information security training, certification, "
                "and research organization. Source for ingested reports."
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

    def _fetch_sitemap(self):
        """Fetch and parse the blog sitemap, returning a list of article URLs."""
        try:
            resp = self.session.get(self.sitemap_url, timeout=60)
            resp.raise_for_status()
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch sitemap: {exc}")
            return None

        try:
            root = ElementTree.fromstring(resp.content)
        except ElementTree.ParseError as exc:
            self.helper.log_error(f"Failed to parse sitemap XML: {exc}")
            return None

        urls = []
        for url_el in root.findall("sm:url", _SITEMAP_NS):
            loc_el = url_el.find("sm:loc", _SITEMAP_NS)
            if loc_el is None or not loc_el.text:
                continue
            loc = loc_el.text.strip()
            # Only include blog URLs.
            parsed = urlparse(loc)
            if parsed.path.startswith("/blog/"):
                urls.append(loc)

        self.helper.log_info(f"Sitemap: {len(urls)} blog URLs found.")
        return urls

    # ------------------------------------------------------------------ #
    # Metadata extraction
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_metadata(soup):
        """Extract title, description, published date, and authors from the page.

        Priority: JSON-LD BlogPosting > CSS selectors > OG meta tags.
        """
        title = None
        description = None
        published = None
        authors = []

        # Try JSON-LD first (BlogPosting schema).
        for script in soup.select('script[type="application/ld+json"]'):
            try:
                data = json.loads(script.string or "")
            except (json.JSONDecodeError, TypeError):
                continue

            # Handle both top-level and @graph-wrapped JSON-LD.
            items = []
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                if "@graph" in data:
                    items = data["@graph"]
                else:
                    items = [data]

            for item in items:
                item_type = item.get("@type", "")
                if isinstance(item_type, list):
                    type_match = "BlogPosting" in item_type
                else:
                    type_match = item_type == "BlogPosting"

                if type_match:
                    title = title or item.get("headline")
                    description = description or item.get("description")
                    published = published or item.get("datePublished")

                    # Extract authors from JSON-LD.
                    author_data = item.get("author", [])
                    if isinstance(author_data, dict):
                        author_data = [author_data]
                    for a in author_data:
                        name = a.get("name", "").strip() if isinstance(a, dict) else ""
                        if name and name not in authors:
                            authors.append(name)

        # CSS selector fallbacks for title.
        if not title:
            hero_title = soup.select_one(".blog-hero__title")
            if hero_title:
                title = hero_title.get_text(strip=True)

        # CSS selector fallbacks for date.
        if not published:
            hero_date = soup.select_one(".blog-hero__date")
            if hero_date:
                published = hero_date.get_text(strip=True)

        # CSS selector fallbacks for authors.
        if not authors:
            author_el = soup.select_one(".blog-hero__authors-name")
            if author_el:
                name = author_el.get_text(strip=True)
                if name:
                    authors.append(name)

        # OG meta fallbacks.
        if not title:
            og_title = soup.select_one('meta[property="og:title"]')
            if og_title:
                title = og_title.get("content", "")
        if not description:
            og_desc = soup.select_one('meta[property="og:description"]')
            if og_desc:
                description = og_desc.get("content", "")
            else:
                meta_desc = soup.select_one('meta[name="description"]')
                if meta_desc:
                    description = meta_desc.get("content", "")

        # Title fallback.
        if not title and soup.title and soup.title.string:
            title = soup.title.string.strip()

        return title, description, published, authors

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
                return {"string": b"", "mime_type": "image/png"}
            return {
                "string": resp.content,
                "mime_type": resp.headers.get(
                    "content-type", "application/octet-stream"
                ).split(";")[0],
            }
        except Exception:
            return {"string": b"", "mime_type": "text/plain"}

    def _render_pdf(self, url, title, byline, content_html):
        ingested = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        doc_html = _build_pdf_html(title, byline, content_html, url, ingested)

        if len(doc_html.encode("utf-8", errors="replace")) > MAX_CONTENT_BYTES:
            self.helper.log_warning(
                f"Skipping PDF render for {url}: content too large "
                f"({len(doc_html.encode('utf-8', errors='replace')):,} bytes)."
            )
            return None

        return weasyprint.HTML(
            string=doc_html, base_url=url, url_fetcher=self._wp_url_fetcher
        ).write_pdf()

    def _fetch_and_render(self, url):
        """Fetch an article page, extract content and metadata, render PDF.

        Returns (title, description, published_iso, authors, pdf_bytes) or
        raises on failure.
        """
        resp = self.session.get(url, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")

        soup = BeautifulSoup(resp.text, "lxml")

        title, description, published, authors = self._extract_metadata(soup)
        if not title:
            title = url

        content = self._extract_content(soup)
        if content is None:
            raise RuntimeError("No article content container found")

        byline = ", ".join(authors) if authors else ""
        content_html = str(content)

        pdf_bytes = self._render_pdf(url, title, byline, content_html)
        return title, description or "", published, authors, pdf_bytes

    def _fetch_and_render_with_retry(self, url):
        return self._retry(
            lambda: self._fetch_and_render(url),
            f"PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Date parsing
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_published_iso(date_str):
        """Parse a date string into ISO 8601 format."""
        if not date_str:
            return None
        try:
            dt = datetime.fromisoformat(date_str)
        except (TypeError, ValueError):
            pass
        else:
            dt = dt.astimezone(timezone.utc)
            if dt.year >= 2000:
                return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

        # Try common date formats from CSS selector fallback.
        for fmt in ("%B %d, %Y", "%b %d, %Y", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(date_str.strip(), fmt).replace(
                    tzinfo=timezone.utc
                )
                if dt.year >= 2000:
                    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            except ValueError:
                continue
        return None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, url, title, description, published, authors, pdf_bytes):
        report_id = self._report_id(url)

        # Build description with author attribution.
        if authors:
            byline_prefix = f"By {', '.join(authors)}. "
            description = byline_prefix + description if description else byline_prefix.rstrip()
        description = description or ""

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on sans.org",
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
                file_name=f"sans-{slug}.pdf",
                data=pdf_bytes,
                mime_type="application/pdf",
            )

        self.helper.log_info(f"Created Report for {url} ({title[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        urls = self._fetch_sitemap()
        if urls is None:
            self.helper.log_warning("Sitemap unreachable; skipping this cycle.")
            return
        if not urls:
            self.helper.log_warning("Sitemap returned no blog URLs; skipping.")
            return

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "SANS Institute blog enumeration run"
        )
        self.helper.log_info(f"Starting re-walk of {len(urls)} blog URLs.")

        processed = 0
        skipped = 0
        failed = 0

        for idx, article_url in enumerate(urls):
            if self.max_reports and processed >= self.max_reports:
                self.helper.log_info(
                    f"Reached max_reports={self.max_reports}; stopping run."
                )
                break

            # Graph dedup check.
            if (
                self.helper.api.report.read(id=self._report_id(article_url))
                is not None
            ):
                skipped += 1
                continue

            result = self._fetch_and_render_with_retry(article_url)
            if result is None:
                failed += 1
                self.helper.log_warning(
                    f"Skipping {article_url}: render failed after retries."
                )
                time.sleep(self.request_delay)
                continue

            title, description, published_raw, authors, pdf_bytes = result
            if pdf_bytes is None:
                failed += 1
                self.helper.log_warning(
                    f"Skipping {article_url}: content too large for PDF."
                )
                time.sleep(self.request_delay)
                continue

            published = self._parse_published_iso(published_raw)
            if not published:
                published = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
                self.helper.log_warning(
                    f"No usable date for {article_url}; using ingestion time."
                )

            self._create_report(
                article_url, title, description, published, authors, pdf_bytes,
            )
            processed += 1
            time.sleep(self.request_delay)

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("SANS Institute connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        SansInstituteConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
