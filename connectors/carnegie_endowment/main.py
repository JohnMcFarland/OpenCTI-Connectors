"""
Carnegie Endowment for International Peace OpenCTI connector.

Purpose
-------
External-import connector that ingests research articles from
https://carnegieendowment.org as container-only OpenCTI Reports, one per
article, with a single PDF attached per Report (native PDF when available,
otherwise rendered from article HTML via WeasyPrint).

Collection model (single sitemap + graph-dedup re-walk)
------------------------------------------------------
Carnegie runs Payload CMS + Next.js. The research sitemap at
/sitemaps/research-0.xml lists ~4,387 URLs total. Non-English language
variants (/ru/, /zh/, /ar/, /fr/, /hi/ path prefixes) are filtered out,
leaving ~4,049 English research articles spanning 1991 to the present.

There is no RSS feed available. The sitemap is the sole enumeration surface.

Enumeration walks every URL in the single sitemap on each poll cycle. There is
no positional cursor; deduplication relies on a graph lookup before rendering
(report.read(id=report_id)). This is the standard graph-dedup re-walk pattern
used when sitemaps are small enough and newest-first ordering is not available.

robots.txt only blocks /admin/ with no crawl-delay, but a configurable
request_delay (default 2s) is applied between requests to be polite.

Content extraction
------------------
Article pages are fetched with plain requests (no Cloudflare/WAF challenge).
Metadata (title, published date, author) is extracted from schema.org/Article
JSON-LD embedded in every page. The article body is extracted from
`section#content .cms-html.payload-richtext` with BeautifulSoup.

PDF strategy:
  1. Check if the article page links to a native PDF hosted at
     assets.carnegieendowment.org/files/.
  2. If a native PDF exists, download it directly.
  3. If no native PDF, render with WeasyPrint from article HTML.
  4. MAX_PDF_BYTES guard (50 MB) applied to both paths.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id)
and skips if the Report already exists. The re-walk is the enumeration layer;
the graph lookup is the correctness backstop.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels.

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

# Language prefixes to skip (non-English duplicates).
_SKIP_LANG_PREFIXES = ("/ru/", "/zh/", "/ar/", "/fr/", "/hi/")

# CSS selectors tried in order for the article body content.
CONTENT_SELECTORS = [
    "section#content .cms-html.payload-richtext",
    "section#content .cms-html",
    "section#content",
    "article",
]

# Elements to strip from extracted content.
STRIP_SELECTORS = [
    "nav",
    "script",
    "style",
    "iframe",
    ".share-buttons",
    ".social-share",
    ".related-content",
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
        + "  |  OpenCTI Carnegie Endowment connector  |  "
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


def _is_english_research_url(url):
    """Return True if *url* is an English research article.

    Filters out non-English language variants (paths starting with
    /ru/, /zh/, /ar/, /fr/, /hi/).
    """
    path = urlparse(url).path
    for prefix in _SKIP_LANG_PREFIXES:
        if path.startswith(prefix):
            return False
    return True


class CarnegieEndowmentConnector:
    """External-import connector that mirrors Carnegie Endowment research
    articles into Reports."""

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
            "CARNEGIE_ENDOWMENT_BASE_URL",
            ["carnegie_endowment", "base_url"],
            config,
            default="https://carnegieendowment.org",
        ).rstrip("/")

        self.poll_interval = get_config_variable(
            "CARNEGIE_ENDOWMENT_POLL_INTERVAL",
            ["carnegie_endowment", "poll_interval"],
            config,
            isNumber=True,
            default=86400,
        )

        self.request_delay = get_config_variable(
            "CARNEGIE_ENDOWMENT_REQUEST_DELAY",
            ["carnegie_endowment", "request_delay"],
            config,
            isNumber=True,
            default=2,
        )

        self.max_reports = get_config_variable(
            "CARNEGIE_ENDOWMENT_MAX_REPORTS",
            ["carnegie_endowment", "max_reports"],
            config,
            isNumber=True,
            default=0,
        )

        self.render_retries = get_config_variable(
            "CARNEGIE_ENDOWMENT_RENDER_RETRIES",
            ["carnegie_endowment", "render_retries"],
            config,
            isNumber=True,
            default=3,
        )

        self.confidence = get_config_variable(
            "CARNEGIE_ENDOWMENT_CONFIDENCE",
            ["carnegie_endowment", "confidence"],
            config,
            isNumber=True,
            default=50,
        )
        self.report_type = get_config_variable(
            "CARNEGIE_ENDOWMENT_REPORT_TYPE",
            ["carnegie_endowment", "report_type"],
            config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "CARNEGIE_ENDOWMENT_TLP",
            ["carnegie_endowment", "tlp"],
            config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "CARNEGIE_ENDOWMENT_AUTHOR_NAME",
            ["carnegie_endowment", "author_name"],
            config,
            default="Carnegie Endowment for International Peace",
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
                "Carnegie Endowment for International Peace. Global think tank "
                "focused on international affairs and public policy. Source for "
                "ingested reports."
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
        """Fetch and parse the research sitemap, returning a list of
        article URLs for English-language research articles."""
        url = f"{self.base_url}/sitemaps/research-0.xml"
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch research sitemap: {exc}")
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
            if _is_english_research_url(loc):
                urls.append(loc)

        self.helper.log_info(
            f"Research sitemap: {len(urls)} English article URLs."
        )
        return urls

    # ------------------------------------------------------------------ #
    # Metadata extraction
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_metadata(soup):
        """Extract title, description, published date, and author from
        schema.org/Article JSON-LD embedded in the page.

        Falls back to OG meta tags and HTML title tag.
        """
        title = None
        description = None
        published = None
        author = None

        # Try JSON-LD first (schema.org/Article).
        for script in soup.select('script[type="application/ld+json"]'):
            try:
                data = json.loads(script.string or "")
            except (json.JSONDecodeError, TypeError):
                continue

            # Handle both top-level and @graph-wrapped structures.
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
                type_list = item_type if isinstance(item_type, list) else [item_type]

                if any(t in ("Article", "ScholarlyArticle", "NewsArticle",
                             "WebPage", "Report") for t in type_list):
                    title = title or item.get("headline") or item.get("name")
                    description = description or item.get("description")
                    published = published or item.get("datePublished")

                    # Author extraction from JSON-LD.
                    if not author:
                        ld_author = item.get("author")
                        if isinstance(ld_author, dict):
                            author = ld_author.get("name")
                        elif isinstance(ld_author, list):
                            names = []
                            for a in ld_author:
                                if isinstance(a, dict) and a.get("name"):
                                    names.append(a["name"])
                                elif isinstance(a, str):
                                    names.append(a)
                            if names:
                                author = ", ".join(names)

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
        if not published:
            og_time = soup.select_one('meta[property="article:published_time"]')
            if og_time:
                published = og_time.get("content", "")

        # Title fallback.
        if not title and soup.title and soup.title.string:
            title = soup.title.string.strip()

        return title, description, published, author

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
    def _find_native_pdf(soup):
        """Look for a link to a native PDF hosted at
        assets.carnegieendowment.org/files/.

        Returns the PDF URL string if found, None otherwise.
        """
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            parsed = urlparse(href)
            if (parsed.netloc == "assets.carnegieendowment.org"
                    and parsed.path.startswith("/files/")
                    and parsed.path.lower().endswith(".pdf")):
                return href
        return None

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

    def _render_pdf(self, url, title, byline, content_html):
        ingested = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        doc_html = _build_pdf_html(title, byline, content_html, url, ingested)

        content_bytes = len(doc_html.encode("utf-8", errors="replace"))
        if content_bytes > MAX_CONTENT_BYTES:
            self.helper.log_warning(
                f"Content too large for PDF render ({content_bytes:,} bytes)."
            )
            return None

        return weasyprint.HTML(
            string=doc_html, base_url=url, url_fetcher=self._wp_url_fetcher
        ).write_pdf()

    def _download_native_pdf(self, pdf_url):
        """Download a native PDF directly. Returns bytes or None."""
        try:
            resp = self.session.get(pdf_url, timeout=60)
            resp.raise_for_status()
            content_type = resp.headers.get("Content-Type", "")
            if "application/pdf" in content_type or pdf_url.lower().endswith(".pdf"):
                if len(resp.content) > MAX_PDF_BYTES:
                    self.helper.log_warning(
                        f"Native PDF too large ({len(resp.content):,} bytes): {pdf_url}"
                    )
                    return None
                return resp.content
        except Exception as exc:
            self.helper.log_warning(f"Native PDF download failed: {pdf_url} -- {exc}")
        return None

    def _fetch_and_render(self, url):
        """Fetch an article page, extract content and metadata, produce PDF.

        PDF strategy:
          1. If native PDF linked at assets.carnegieendowment.org/files/, download it.
          2. Otherwise render from article HTML via WeasyPrint.

        Returns (title, description, published_iso, pdf_bytes) or raises on failure.
        """
        resp = self.session.get(url, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")

        soup = BeautifulSoup(resp.text, "lxml")

        title, description, published, author = self._extract_metadata(soup)
        if not title:
            title = url

        # Check for native PDF first.
        native_pdf_url = self._find_native_pdf(soup)
        if native_pdf_url:
            self.helper.log_info(f"Found native PDF for {url}: {native_pdf_url}")
            pdf_bytes = self._download_native_pdf(native_pdf_url)
            if pdf_bytes:
                return title, description or "", published, pdf_bytes

        # Fall back to WeasyPrint rendering.
        content = self._extract_content(soup)
        if content is None:
            raise RuntimeError("No article content container found")

        byline = author or ""
        content_html = str(content)

        pdf_bytes = self._render_pdf(url, title, byline, content_html)
        return title, description or "", published, pdf_bytes

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
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, url, title, description, published, pdf_bytes):
        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on carnegieendowment.org",
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
                file_name=f"carnegie-{slug}.pdf",
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
            self.helper.log_warning(
                "Research sitemap unreachable; skipping this cycle."
            )
            return
        if not urls:
            self.helper.log_warning(
                "Research sitemap returned no article URLs; skipping."
            )
            return

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Carnegie Endowment enumeration run"
        )
        self.helper.log_info(
            f"Starting enumeration of {len(urls)} article URLs."
        )

        processed = 0
        skipped = 0
        failed = 0

        for article_url in urls:
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

            title, description, published_raw, pdf_bytes = result
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
                article_url, title, description, published, pdf_bytes,
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
        self.helper.log_info("Carnegie Endowment connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        CarnegieEndowmentConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
