"""
IISS OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://www.iiss.org (International Institute for Strategic Studies) as
container-only OpenCTI Reports, one per article, with the source article
attached as a PDF.

Collection model (Sitemap + Playwright hybrid)
----------------------------------------------
IISS runs on Episerver (Optimizely CMS), a .NET-based enterprise CMS. The
sitemap at /sitemap.xml is accessible via plain HTTP and lists ~200 URLs.
Content pages return 403 or near-empty responses to non-browser clients
(JS-rendered content behind a WAF), so Playwright is required for content
access.

Enumeration parses /sitemap.xml with requests + lxml to extract the URL list,
then filters URLs to keep only content pages (online analysis, publications,
research) and skip non-content pages (podcasts, events, careers).

For each content URL, Playwright navigates the page, waits for JS rendering,
then BeautifulSoup extracts the article body. WeasyPrint renders the extracted
content into a PDF. Since the corpus is small (~70 in-scope URLs out of ~200
total), a full re-walk each poll is acceptable. No cursor is needed -- graph
dedup (deterministic Report STIX ID checked before processing) prevents
duplicate ingestion.

Content scope
-------------
IN: Online analysis (all sub-series: Military Balance, Survival Online,
Strategic Comments, Charting China, Commentary, Missile Dialogue Initiative),
Publications, Research programs.

SKIP: Podcasts (Arms Control Poseur, Sounds Strategic, Japan Memo),
Events (Shangri-La Dialogue, Prague Defence Summit), Careers.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels. Entity extraction is a separate,
out-of-scope downstream phase.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (public source; some content may be paywalled -- those URLs are
  skipped with a warning).
- Author: the single "IISS" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band).
- Sub-series inferred from URL path and included in Report description.
- Deduplication: graph-driven via deterministic Report STIX ID (uuid5 of URL).

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import html as html_mod
import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import weasyprint
import yaml
from bs4 import BeautifulSoup
from lxml import etree
from pycti import OpenCTIConnectorHelper, get_config_variable

logging.getLogger("weasyprint").setLevel(logging.ERROR)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

SITEMAP_NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

KEEP_PATH_PREFIXES = (
    "/online-analysis/",
    "/publications/",
    "/research/",
)

SKIP_PATH_PREFIXES = (
    "/podcasts/",
    "/events/",
    "/careers/",
)

# Episerver content selectors, ordered from most specific to broadest.
CONTENT_SELECTORS = [
    "article .content-area",
    "article .article-content",
    ".article-body",
    ".article-content",
    ".content-area",
    ".page-content",
    "main .content",
    "[role='main'] .content",
    "article",
    "[role='main']",
    "main",
]

STRIP_SELECTORS = [
    "nav",
    "header",
    "footer",
    ".cookie-banner",
    ".cookie-consent",
    ".social-share",
    ".share-buttons",
    ".related-articles",
    ".newsletter-signup",
    ".sidebar",
    "aside",
    "script",
    "style",
    "iframe",
    ".breadcrumb",
    ".breadcrumbs",
]

PAYWALL_MARKERS = (
    "paywall",
    "subscribe to read",
    "sign in to continue",
    "login to access",
    "members only",
    "premium content",
    "purchase this",
    "subscription required",
    "sign in to read",
    "access denied",
)

CHALLENGE_MARKERS = (
    "just a moment",
    "attention required",
    "cf-browser-verification",
)

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
    "blockquote { border-left: 3px solid #1a3a6b; margin: 1em 0; "
    "padding: 0.5em 1em; color: #555; } "
    "a { color: #1a3a6b; } "
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _escape_html(text):
    return html_mod.escape(text, quote=True) if text else ""


def _css_string_escape(s):
    return (
        s.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\a ")
        .replace("\r", "")
    )


def _slug_to_title(slug):
    """Convert a URL slug like 'military-balance' to 'Military Balance'."""
    return slug.replace("-", " ").title()


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
        + "  |  OpenCTI IISS connector  |  "
        + ingested_at
        + "'; font-size: 7px; color: #888; } } "
        + "</style></head><body>"
        + "<h1>" + safe_title + "</h1>"
        + byline_block
        + content_html
        + "</body></html>"
    )


def _extract_date_from_url(url):
    """Extract a year/month date from the URL path if present.

    IISS URLs follow /section/series/YYYY/MM/slug/ patterns.
    Returns an ISO-8601 string or None.
    """
    m = re.search(r"/(\d{4})/(\d{2})/", url)
    if m:
        year, month = int(m.group(1)), int(m.group(2))
        if 2000 <= year <= 2100 and 1 <= month <= 12:
            return datetime(year, month, 1, tzinfo=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
    return None


class IISSConnector:
    """External-import connector that mirrors IISS articles into Reports."""

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
            "IISS_BASE_URL",
            ["international_institute_for_strategic_studies", "base_url"], config,
            default="https://www.iiss.org",
        ).rstrip("/")

        self.poll_interval = get_config_variable(
            "IISS_POLL_INTERVAL",
            ["international_institute_for_strategic_studies", "poll_interval"], config,
            isNumber=True, default=86400,
        )

        self.request_delay = get_config_variable(
            "IISS_REQUEST_DELAY",
            ["international_institute_for_strategic_studies", "request_delay"], config,
            isNumber=True, default=3,
        )

        self.max_reports = get_config_variable(
            "IISS_MAX_REPORTS",
            ["international_institute_for_strategic_studies", "max_reports"], config,
            isNumber=True, default=0,
        )

        self.nav_timeout_ms = get_config_variable(
            "IISS_PLAYWRIGHT_NAV_TIMEOUT",
            ["international_institute_for_strategic_studies", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )

        self.render_retries = get_config_variable(
            "IISS_RENDER_RETRIES",
            ["international_institute_for_strategic_studies", "render_retries"], config,
            isNumber=True, default=3,
        )

        self.confidence = get_config_variable(
            "IISS_CONFIDENCE",
            ["international_institute_for_strategic_studies", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "IISS_REPORT_TYPE",
            ["international_institute_for_strategic_studies", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "IISS_TLP",
            ["international_institute_for_strategic_studies", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "IISS_AUTHOR_NAME",
            ["international_institute_for_strategic_studies", "author_name"], config,
            default="IISS",
        )

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "*/*",
        })

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
                "International Institute for Strategic Studies. London-based "
                "think tank covering defence, security, and geopolitical analysis. "
                "Source organization for ingested reports."
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
    # Deduplication
    # ------------------------------------------------------------------ #

    @staticmethod
    def _report_id(url):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))

    def _already_ingested(self, url):
        return self.helper.api.report.read(id=self._report_id(url)) is not None

    # ------------------------------------------------------------------ #
    # Sitemap enumeration
    # ------------------------------------------------------------------ #

    def _fetch_sitemap_urls(self):
        """Fetch /sitemap.xml and return filtered (url, lastmod) tuples.

        Handles both a flat <urlset> and a <sitemapindex> (fetches each
        child sitemap if present).
        """
        sitemap_url = f"{self.base_url}/sitemap.xml"
        try:
            resp = self.session.get(sitemap_url, timeout=60)
            resp.raise_for_status()
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch sitemap: {exc}")
            return []

        return self._parse_sitemap_xml(resp.content)

    def _parse_sitemap_xml(self, xml_bytes, depth=3):
        """Parse sitemap XML, handling both urlset and sitemapindex."""
        try:
            root = etree.fromstring(xml_bytes)
        except etree.XMLSyntaxError as exc:
            self.helper.log_error(f"Sitemap XML parse error: {exc}")
            return []

        tag = etree.QName(root.tag).localname if root.tag else ""

        # Sitemap index: recurse into each child sitemap.
        if tag == "sitemapindex":
            if depth <= 0:
                self.helper.log_warning("Sitemap recursion depth exceeded; skipping nested sitemaps.")
                return []
            results = []
            for sitemap_el in root.findall("sm:sitemap/sm:loc", SITEMAP_NS):
                child_url = (sitemap_el.text or "").strip()
                if not child_url:
                    continue
                try:
                    resp = self.session.get(child_url, timeout=60)
                    resp.raise_for_status()
                    results.extend(self._parse_sitemap_xml(resp.content, depth=depth - 1))
                    time.sleep(1)
                except Exception as exc:
                    self.helper.log_warning(
                        f"Failed to fetch child sitemap {child_url}: {exc}"
                    )
            return results

        # Flat urlset: extract URLs directly.
        results = []
        for url_el in root.findall("sm:url", SITEMAP_NS):
            loc_el = url_el.find("sm:loc", SITEMAP_NS)
            if loc_el is None:
                continue
            loc = (loc_el.text or "").strip()
            if not loc:
                continue

            lastmod_el = url_el.find("sm:lastmod", SITEMAP_NS)
            lastmod = (lastmod_el.text or "").strip() if lastmod_el is not None else ""

            if self._url_in_scope(loc):
                results.append((loc, lastmod))

        return results

    @staticmethod
    def _url_in_scope(url):
        """Return True if the URL is in content scope (keep), False to skip."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Explicit skip prefixes.
        for prefix in SKIP_PATH_PREFIXES:
            if path.startswith(prefix):
                return False

        # Explicit keep prefixes.
        for prefix in KEEP_PATH_PREFIXES:
            if path.startswith(prefix):
                return True

        # Everything else (homepage, about, contact, etc.) is out of scope.
        return False

    # ------------------------------------------------------------------ #
    # Series inference
    # ------------------------------------------------------------------ #

    @staticmethod
    def _infer_series(url):
        """Infer the IISS sub-series from the URL path.

        Examples:
          /online-analysis/military-balance/... -> "Military Balance"
          /publications/strategic-comments/...  -> "Strategic Comments"
          /research/defence-and-military-analysis/... -> "Defence and Military Analysis"
        """
        parsed = urlparse(url)
        segments = [s for s in parsed.path.strip("/").split("/") if s]
        if len(segments) >= 2:
            return _slug_to_title(segments[1])
        return ""

    # ------------------------------------------------------------------ #
    # Content extraction (BeautifulSoup)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_content(soup):
        """Extract the article body from a BeautifulSoup-parsed page.

        Tries Episerver-specific selectors first, falls back to generic ones.
        Strips navigation, sidebar, and other cruft.
        """
        content = None
        for selector in CONTENT_SELECTORS:
            content = soup.select_one(selector)
            if content and len(content.get_text(strip=True)) > 100:
                break
            content = None

        if content is None:
            return None

        for sel in STRIP_SELECTORS:
            for el in content.select(sel):
                el.decompose()

        return content

    @staticmethod
    def _extract_metadata(soup, url, sitemap_lastmod):
        """Extract title, date, and description from meta tags and page content.

        Priority for date:
          1. article:published_time meta tag
          2. time[datetime] element
          3. Sitemap lastmod
          4. Year/month from URL path
          5. Current time (last resort)

        Priority for title:
          1. og:title meta tag
          2. h1 text
          3. document title
        """
        # Title
        og_title = soup.find("meta", property="og:title")
        title = og_title["content"].strip() if og_title and og_title.get("content") else ""
        if not title:
            h1 = soup.find("h1")
            title = h1.get_text(strip=True) if h1 else ""
        if not title:
            title_tag = soup.find("title")
            title = title_tag.get_text(strip=True) if title_tag else ""
        # Strip site name suffix from title.
        title = re.sub(r"\s*[-|]\s*IISS\s*$", "", title, flags=re.IGNORECASE).strip()

        # Description
        og_desc = soup.find("meta", property="og:description")
        description = og_desc["content"].strip() if og_desc and og_desc.get("content") else ""
        if not description:
            meta_desc = soup.find("meta", attrs={"name": "description"})
            description = (
                meta_desc["content"].strip()
                if meta_desc and meta_desc.get("content")
                else ""
            )

        # Published date
        published = None

        # 1. article:published_time
        pub_meta = soup.find("meta", property="article:published_time")
        if pub_meta and pub_meta.get("content"):
            try:
                dt = datetime.fromisoformat(pub_meta["content"].replace("Z", "+00:00"))
                published = dt.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
            except (ValueError, TypeError):
                pass

        # 2. time[datetime]
        if not published:
            time_el = soup.find("time", attrs={"datetime": True})
            if time_el:
                try:
                    dt = datetime.fromisoformat(
                        time_el["datetime"].replace("Z", "+00:00")
                    )
                    published = dt.astimezone(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S+00:00"
                    )
                except (ValueError, TypeError):
                    pass

        # 3. Sitemap lastmod
        if not published and sitemap_lastmod:
            try:
                dt = datetime.fromisoformat(sitemap_lastmod.replace("Z", "+00:00"))
                published = dt.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
            except (ValueError, TypeError):
                pass

        # 4. URL path date
        if not published:
            published = _extract_date_from_url(url)

        # 5. Fallback
        if not published:
            published = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )

        # Author byline (visible on page, for description, not createdBy)
        author_el = soup.find("meta", property="article:author")
        byline = (
            author_el["content"].strip()
            if author_el and author_el.get("content")
            else ""
        )

        return {
            "title": title,
            "description": description,
            "published": published,
            "byline": byline,
        }

    @staticmethod
    def _is_paywalled(soup):
        """Check for paywall or login-gate indicators in the page."""
        text = soup.get_text(separator=" ").lower()
        for marker in PAYWALL_MARKERS:
            if marker in text:
                # Confirm the marker is prominent, not just a passing mention.
                # Check if it appears in a heading, overlay, or modal.
                for tag in ("h1", "h2", "h3", ".paywall", ".login-gate",
                            ".access-denied", "[class*='paywall']",
                            "[class*='login']", "[class*='subscribe']"):
                    el = soup.select_one(tag)
                    if el and marker in el.get_text(separator=" ").lower():
                        return True
        return False

    # ------------------------------------------------------------------ #
    # Playwright page fetch
    # ------------------------------------------------------------------ #

    def _fetch_and_extract(self, browser, url, lastmod):
        """Navigate to URL with Playwright, extract article content and metadata.

        Returns (content_html_str, metadata_dict) on success,
        (None, "paywall") if paywalled, or (None, None) on failure.
        """
        context = None
        page = None
        try:
            context = browser.new_context(
                viewport={"width": 1280, "height": 1024},
                user_agent=BROWSER_UA,
            )
            page = context.new_page()

            # Retry navigation with exponential backoff.
            delay = self.request_delay
            last_exc = None
            for attempt in range(1, self.render_retries + 1):
                try:
                    page.goto(
                        url, wait_until="networkidle",
                        timeout=self.nav_timeout_ms,
                    )
                    last_exc = None
                    break
                except Exception as exc:
                    last_exc = exc
                    self.helper.log_warning(
                        f"Navigation attempt {attempt}/{self.render_retries} "
                        f"failed for {url}: {exc}"
                    )
                    if attempt < self.render_retries:
                        time.sleep(delay)
                        delay *= 2
            if last_exc is not None:
                raise last_exc

            # Check for WAF challenge in title and page body.
            title = (page.title() or "").lower()
            body_text = (page.inner_text("body") or "").lower()[:2000]
            if any(m in title or m in body_text for m in CHALLENGE_MARKERS):
                raise RuntimeError("WAF challenge interstitial detected")

            # Wait for JS-rendered content.
            page.wait_for_timeout(2000)

            html_content = page.content()
            soup = BeautifulSoup(html_content, "lxml")

            # Paywall check.
            if self._is_paywalled(soup):
                return None, "paywall"

            # Metadata extraction.
            meta = self._extract_metadata(soup, url, lastmod)

            # Content extraction.
            content = self._extract_content(soup)
            if content is None:
                return None, None

            return str(content), meta
        finally:
            try:
                if page is not None:
                    page.close()
            except Exception:
                pass
            try:
                if context is not None:
                    context.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # PDF rendering (WeasyPrint)
    # ------------------------------------------------------------------ #

    def _wp_url_fetcher(self, url):
        """Custom WeasyPrint URL fetcher using the HTTP session for images."""
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

    def _render_pdf(self, url, meta, content_html):
        title = meta.get("title") or ""
        series = self._infer_series(url)

        byline_parts = []
        if meta.get("byline"):
            byline_parts.append(f"By {meta['byline']}")
        if series:
            byline_parts.append(series)
        byline = "  |  ".join(byline_parts)

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

    def _render_with_retry(self, url, meta, content_html):
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._render_pdf(url, meta, content_html)
            except Exception as exc:
                self.helper.log_warning(
                    f"PDF render attempt {attempt}/{self.render_retries} "
                    f"failed for {url}: {exc}"
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

    def _create_report(self, url, meta, pdf_bytes):
        name = meta.get("title") or self._slug_from_url(url)
        series = self._infer_series(url)

        description = meta.get("description", "")
        if series:
            description = f"[{series}] {description}" if description else series
        if meta.get("byline"):
            description = (
                f"By {meta['byline']}. {description}"
                if description
                else f"By {meta['byline']}."
            )

        published = meta.get("published")

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on iiss.org",
        )

        report = self.helper.api.report.create(
            stix_id=self._report_id(url),
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

        slug = self._slug_from_url(url)
        if len(pdf_bytes) > MAX_PDF_BYTES:
            self.helper.log_warning(
                f"Skipping oversized PDF for {url} ({len(pdf_bytes):,} bytes)."
            )
        else:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"iiss-{slug}.pdf",
                data=pdf_bytes,
                mime_type="application/pdf",
            )

        self.helper.log_info(f"Created Report for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        from playwright.sync_api import sync_playwright

        # Step 1: Fetch and filter sitemap URLs.
        urls = self._fetch_sitemap_urls()
        if not urls:
            self.helper.log_warning("No in-scope URLs found in sitemap; skipping run.")
            return

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "IISS enumeration run"
        )
        self.helper.log_info(
            f"Sitemap yielded {len(urls)} in-scope URLs. Starting enumeration."
        )

        processed = 0
        skipped = 0
        failed = 0
        paywalled = 0
        message = "Run did not complete."

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    args=["--no-sandbox", "--disable-dev-shm-usage"]
                )
                try:
                    for url, lastmod in urls:
                        if self.max_reports and processed >= self.max_reports:
                            self.helper.log_info(
                                f"Reached IISS_MAX_REPORTS={self.max_reports}; stopping run."
                            )
                            break

                        # Graph dedup.
                        if self._already_ingested(url):
                            skipped += 1
                            continue

                        # Playwright navigation + content extraction.
                        content_html, meta = self._fetch_and_extract(
                            browser, url, lastmod
                        )

                        if meta == "paywall":
                            paywalled += 1
                            self.helper.log_warning(
                                f"Paywall detected; skipping {url}"
                            )
                            time.sleep(self.request_delay)
                            continue

                        if content_html is None or meta is None:
                            failed += 1
                            self.helper.log_warning(
                                f"Content extraction failed for {url}"
                            )
                            time.sleep(self.request_delay)
                            continue

                        # PDF render.
                        pdf_bytes = self._render_with_retry(url, meta, content_html)
                        if pdf_bytes is None:
                            failed += 1
                            self.helper.log_warning(
                                f"Skipping {url}: PDF render failed after retries."
                            )
                            time.sleep(self.request_delay)
                            continue

                        # Create Report.
                        self._create_report(url, meta, pdf_bytes)
                        processed += 1
                        time.sleep(self.request_delay)

                finally:
                    browser.close()

            message = (
                f"Run complete: {processed} created, {skipped} already present, "
                f"{failed} failed, {paywalled} paywalled."
            )
        finally:
            try:
                self.helper.api.work.to_processed(work_id, message)
            except Exception:
                pass
            self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("IISS connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        IISSConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
