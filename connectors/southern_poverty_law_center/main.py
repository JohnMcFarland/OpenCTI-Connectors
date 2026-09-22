"""
Southern Poverty Law Center (SPLC) OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://www.splcenter.org as container-only OpenCTI Reports, one per
article, with a single PDF attached per Report rendered from the live
article HTML via WeasyPrint.

Collection model (sitemap crawl + positional cursor)
----------------------------------------------------
SPLC is a WordPress site (~106k URLs across custom post types) with Yoast SEO
sitemaps. The WP REST API returns empty results and RSS returns 403, so the
sitemap index at /sitemap_index.xml is the sole enumeration surface.

The sitemap index lists ~106 sub-sitemaps organised by post type:
  splc_hatewatch-sitemap.xml ... splc_hatewatch-sitemap33.xml  (~33k URLs)
  splc_story-sitemap.xml     ... splc_story-sitemap19.xml      (~19k URLs)
  splc_report-sitemap.xml    ... splc_report-sitemap12.xml     (~12k URLs)
  splc_press-sitemap.xml     ... splc_press-sitemap7.xml       (~7k URLs)
  splc_extremist-sitemap.xml ... splc_extremist-sitemap2.xml   (~2k URLs)
  splc_case-sitemap.xml      ... splc_case-sitemap2.xml        (~2k URLs)
  splc_hopewatch-sitemap.xml                                   (small)
  splc_guide-sitemap.xml                                       (small)
  splc_policy-sitemap.xml                                      (small)

Enumeration walks sub-sitemaps in order behind a persisted positional cursor
{sitemap_idx, url_idx} held in OpenCTI connector state. Each sub-sitemap
contains up to ~1000 URLs with <loc> and <lastmod> elements. The sub-sitemap
list is rebuilt from the sitemap index on every poll cycle so that newly-added
sitemaps are picked up automatically.

Sitemaps include language-variant URLs (e.g. /zh/, /vi/, /ar/ path prefixes)
and archive listing pages (e.g. /resources/hatewatch/ with no slug). Both are
filtered out during enumeration.

robots.txt specifies Crawl-delay: 10 which is strictly honoured via the
request_delay configuration parameter.

Content extraction
------------------
Article pages are fetched with plain requests (no Cloudflare challenge). The
article body is extracted from the `.entry-content` container with
BeautifulSoup. Metadata (title, published date, description) is extracted
from Yoast SEO JSON-LD and Open Graph meta tags embedded in every page.
WeasyPrint renders the final PDF.

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
import json
import logging
import os
import re
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

# Post type prefixes to include from the sitemap index.
ALLOWED_POST_TYPES = frozenset({
    "splc_hatewatch",
    "splc_story",
    "splc_report",
    "splc_press",
    "splc_extremist",
    "splc_case",
    "splc_hopewatch",
    "splc_guide",
    "splc_policy",
})

# Human-readable labels for each post type (used in Report description).
POST_TYPE_LABELS = {
    "splc_hatewatch": "Hatewatch",
    "splc_story": "Story",
    "splc_report": "Report",
    "splc_press": "Press Release",
    "splc_extremist": "Extremist Profile",
    "splc_case": "Case",
    "splc_hopewatch": "Hopewatch",
    "splc_guide": "Guide",
    "splc_policy": "Policy",
}

# CSS selectors tried in order for the article body content.
CONTENT_SELECTORS = [
    ".entry-content",
    ".wp-block-post-content",
    "article .content",
    "article",
]

# Elements to strip from extracted content.
STRIP_SELECTORS = [
    "nav",
    ".splc-related-content",
    ".wp-block-splc-alert-bar",
    ".wp-block-splc-newsletter",
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
        + "  |  OpenCTI SPLC connector  |  "
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


def _extract_post_type(sitemap_url):
    """Extract the post type prefix from a sub-sitemap URL.

    Example: '.../splc_hatewatch-sitemap2.xml' -> 'splc_hatewatch'
    """
    filename = urlparse(sitemap_url).path.rsplit("/", 1)[-1]
    match = re.match(r"(splc_\w+)-sitemap", filename)
    return match.group(1) if match else None


def _is_article_url(url):
    """Return True if *url* is a real article page, not a language variant or listing.

    Keeps English articles at /resources/<type>/<slug>/ and filters out:
      - Language-variant URLs like /zh/resources/... or /es/resources/...
      - Archive listing pages like /resources/hatewatch/ (no article slug)
    """
    path = urlparse(url).path.rstrip("/")
    if not path.startswith("/resources/"):
        return False
    # After /resources/<type>/ there must be at least one more path segment (the slug).
    segments = [s for s in path.split("/") if s]
    # segments: ['resources', '<type>', '<slug>']
    return len(segments) >= 3


class SplcConnector:
    """External-import connector that mirrors SPLC articles into Reports."""

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
            "SPLC_BASE_URL",
            ["southern_poverty_law_center", "base_url"],
            config,
            default="https://www.splcenter.org",
        ).rstrip("/")

        self.poll_interval = get_config_variable(
            "SPLC_POLL_INTERVAL",
            ["southern_poverty_law_center", "poll_interval"],
            config,
            isNumber=True,
            default=86400,
        )

        self.request_delay = get_config_variable(
            "SPLC_REQUEST_DELAY",
            ["southern_poverty_law_center", "request_delay"],
            config,
            isNumber=True,
            default=10,
        )

        self.max_reports = get_config_variable(
            "SPLC_MAX_REPORTS",
            ["southern_poverty_law_center", "max_reports"],
            config,
            isNumber=True,
            default=0,
        )

        self.render_retries = get_config_variable(
            "SPLC_RENDER_RETRIES",
            ["southern_poverty_law_center", "render_retries"],
            config,
            isNumber=True,
            default=3,
        )

        self.confidence = get_config_variable(
            "SPLC_CONFIDENCE",
            ["southern_poverty_law_center", "confidence"],
            config,
            isNumber=True,
            default=50,
        )
        self.report_type = get_config_variable(
            "SPLC_REPORT_TYPE",
            ["southern_poverty_law_center", "report_type"],
            config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "SPLC_TLP",
            ["southern_poverty_law_center", "tlp"],
            config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "SPLC_AUTHOR_NAME",
            ["southern_poverty_law_center", "author_name"],
            config,
            default="Southern Poverty Law Center",
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
                "Southern Poverty Law Center (SPLC). Hate/extremism tracking "
                "and civil rights organization. Source for ingested reports."
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
        sub-sitemap URLs for the allowed post types."""
        url = f"{self.base_url}/sitemap_index.xml"
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
            post_type = _extract_post_type(loc)
            if post_type and post_type in ALLOWED_POST_TYPES:
                sitemaps.append(loc)

        self.helper.log_info(
            f"Sitemap index: {len(sitemaps)} sub-sitemaps for allowed post types."
        )
        return sitemaps

    def _fetch_sub_sitemap(self, sitemap_url):
        """Fetch and parse a single sub-sitemap, returning a list of
        (url, lastmod) tuples for valid article URLs."""
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
            if not _is_article_url(loc):
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
        """Extract title, description, published date, and author from the page.

        Priority: Yoast JSON-LD > OG meta tags > HTML title tag.
        """
        title = None
        description = None
        published = None
        author = None

        # Try JSON-LD first (Yoast SEO).
        for script in soup.select('script[type="application/ld+json"]'):
            try:
                data = json.loads(script.string or "")
            except (json.JSONDecodeError, TypeError):
                continue
            graph = data.get("@graph", [])
            for item in graph:
                item_type = item.get("@type")
                if item_type == "WebPage" or (
                    isinstance(item_type, list) and "WebPage" in item_type
                ):
                    title = title or item.get("name")
                    description = description or item.get("description")
                    published = published or item.get("datePublished")

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
            else:
                og_mod = soup.select_one('meta[property="article:modified_time"]')
                if og_mod:
                    published = og_mod.get("content", "")

        # Title fallback.
        if not title and soup.title and soup.title.string:
            title = soup.title.string.strip()

        # Author from topper area.
        topper_details = soup.select_one(".topper-watch__details")
        if topper_details:
            # The author name is typically in a span or link inside the details.
            text = topper_details.get_text(" ", strip=True)
            # Try to extract just the author portion (after date, before Share).
            parts = re.split(r"\bShare\b", text, maxsplit=1)
            if parts:
                detail_text = parts[0].strip()
                # Split by date pattern to get the author after the date.
                date_split = re.split(
                    r"\b(?:January|February|March|April|May|June|July|August|"
                    r"September|October|November|December)\s+\d{1,2},\s+\d{4}\b",
                    detail_text,
                    maxsplit=1,
                )
                if len(date_split) > 1 and date_split[1].strip():
                    author = date_split[1].strip()

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

        Returns (title, description, published_iso, pdf_bytes) or None on failure.
        """
        resp = self.session.get(url, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")

        soup = BeautifulSoup(resp.text, "lxml")

        title, description, published, author = self._extract_metadata(soup)
        if not title:
            title = url

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

    def _create_report(self, url, title, description, published, pdf_bytes,
                       post_type_label):
        if post_type_label:
            description = (
                f"[{post_type_label}] {description}" if description
                else f"[{post_type_label}]"
            )

        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on splcenter.org",
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
                file_name=f"splc-{slug}.pdf",
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
                "Sitemap index returned no matching sub-sitemaps; skipping."
            )
            return

        state = self.helper.get_state() or {}
        cursor_sitemap_idx = max(0, int(state.get("sitemap_idx", 0)))
        cursor_url_idx = max(0, int(state.get("url_idx", 0)))

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "SPLC enumeration run"
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

        for sm_idx in range(cursor_sitemap_idx, len(sitemaps)):
            if stop:
                break

            sitemap_url = sitemaps[sm_idx]
            post_type = _extract_post_type(sitemap_url)
            post_type_label = POST_TYPE_LABELS.get(post_type, post_type or "")

            self.helper.log_info(
                f"Processing sub-sitemap {sm_idx + 1}/{len(sitemaps)}: "
                f"{sitemap_url} ({post_type_label})"
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
                f"Sub-sitemap has {len(entries)} article URLs; "
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
                    post_type_label,
                )
                processed += 1
                self._save_cursor(sm_idx, url_idx + 1)
                time.sleep(self.request_delay)

            if not stop:
                # Finished this sub-sitemap; advance cursor to the next one.
                self._save_cursor(sm_idx + 1, 0)
                time.sleep(self.request_delay)

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("SPLC connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        SplcConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
