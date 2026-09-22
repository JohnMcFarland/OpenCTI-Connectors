"""
Johns Hopkins Bloomberg School of Public Health OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://publichealth.jhu.edu (Johns Hopkins Bloomberg School of Public
Health) as container-only OpenCTI Reports, one per article, with the
source article attached as a PDF.

Collection model (Sitemap + Playwright hybrid)
----------------------------------------------
The site runs on Drupal 10 (Thunder distribution) behind Cloudflare with
aggressive managed challenges that block plain HTTP clients intermittently.
Playwright is mandatory for fetching article pages.

The sitemap at /sitemap.xml links to 9 sub-sitemaps (?page=1 through
?page=9) totalling ~18,785 URLs.  Only article URLs whose path starts
with /{4-digit-year}/ (possibly preceded by a center slug) are in scope
-- roughly 7,130 news articles from 2000 to present.

Enumeration parses the sitemap index and each sub-sitemap with
requests + lxml (falling back to Playwright if Cloudflare blocks).
For each article URL, Playwright navigates the page, then BeautifulSoup
extracts article content.  WeasyPrint renders the extracted HTML into a
PDF.

Because the corpus is large, graph-dedup (deterministic Report STIX ID
checked before processing) prevents duplicate ingestion across runs.
No cursor is stored -- the full sitemap is re-walked each poll.

Content scope
-------------
IN: News articles at /{year}/... or /{center}/{year}/... paths.

SKIP: Non-article pages (about, faculty, programs, events, etc.),
external links (globalhealthnow.org, etc.).

Design philosophy
-----------------
Container-only.  Creates Report containers and nothing else: no Domain
Objects, no Observables, no Relationships, no Labels.  Entity extraction
is a separate, out-of-scope downstream phase.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (public source).
- Author: the single "Johns Hopkins Bloomberg School of Public Health"
  Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band).
- Deduplication: graph-driven via deterministic Report STIX ID (uuid5 of URL).
- PDF: WeasyPrint (Playwright is for navigation only, not PDF rendering).
- Browser recycling: every ~50 Playwright navigations to prevent memory leaks.
- Cloudflare challenge detection and retry on interstitial pages.

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

# Regex: path starts with /YYYY/ (4-digit year).
ARTICLE_PATH_RE = re.compile(r"^/(\d{4})/")

# Regex: path starts with /{center-slug}/YYYY/ (center then 4-digit year).
CENTER_ARTICLE_PATH_RE = re.compile(r"^/[a-z][a-z0-9-]+/(\d{4})/")

# External domains to skip (articles linking off-site).
EXTERNAL_DOMAINS = (
    "globalhealthnow.org",
    "jhsph.edu",
    "hub.jhu.edu",
    "coronavirus.jhu.edu",
)

BROWSER_RECYCLE_EVERY = 50

CHALLENGE_MARKERS = (
    "just a moment",
    "attention required",
    "cf-browser-verification",
)

# Drupal Thunder content selectors, from most specific to broadest.
CONTENT_SELECTORS = [
    ".field-name--body.field-type--text-with-summary",
    ".field--name-body.field--type-text-with-summary",
    ".field-name--body",
    ".field--name-body",
    "article .content",
    "article .node__content",
    ".node__content",
    ".page-content",
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
    ".related-content",
    ".newsletter-signup",
    ".sidebar",
    "aside",
    "script",
    "style",
    "iframe",
    ".breadcrumb",
    ".breadcrumbs",
    ".field-name--field-tags",
    ".field--name-field-tags",
    ".contextual",
]

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
    "blockquote { border-left: 3px solid #002d72; margin: 1em 0; "
    "padding: 0.5em 1em; color: #555; } "
    "a { color: #002d72; } "
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
        + "  |  OpenCTI JHSPH connector  |  "
        + ingested_at
        + "'; font-size: 7px; color: #888; } } "
        + "</style></head><body>"
        + "<h1>" + safe_title + "</h1>"
        + byline_block
        + content_html
        + "</body></html>"
    )


def _is_article_path(path):
    """Return True if the URL path matches an article pattern.

    Articles live at /{year}/{slug} or /{center}/{year}/{slug}.
    The year must be between 2000 and 2100.
    """
    m = ARTICLE_PATH_RE.match(path)
    if m:
        year = int(m.group(1))
        return 2000 <= year <= 2100

    m = CENTER_ARTICLE_PATH_RE.match(path)
    if m:
        year = int(m.group(1))
        return 2000 <= year <= 2100

    return False


def _extract_year_from_path(path):
    """Extract the 4-digit year from an article path."""
    m = ARTICLE_PATH_RE.search(path)
    if m:
        return int(m.group(1))
    m = CENTER_ARTICLE_PATH_RE.search(path)
    if m:
        return int(m.group(1))
    return None


class JohnsHopkinsPublicHealthConnector:
    """External-import connector that mirrors JHSPH articles into Reports."""

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
            "JOHNS_HOPKINS_PUBLIC_HEALTH_BASE_URL",
            ["johns_hopkins_public_health", "base_url"], config,
            default="https://publichealth.jhu.edu",
        ).rstrip("/")

        self.poll_interval = get_config_variable(
            "JOHNS_HOPKINS_PUBLIC_HEALTH_POLL_INTERVAL",
            ["johns_hopkins_public_health", "poll_interval"], config,
            isNumber=True, default=86400,
        )

        self.request_delay = get_config_variable(
            "JOHNS_HOPKINS_PUBLIC_HEALTH_REQUEST_DELAY",
            ["johns_hopkins_public_health", "request_delay"], config,
            isNumber=True, default=3,
        )

        self.max_reports = get_config_variable(
            "JOHNS_HOPKINS_PUBLIC_HEALTH_MAX_REPORTS",
            ["johns_hopkins_public_health", "max_reports"], config,
            isNumber=True, default=0,
        )

        self.nav_timeout_ms = get_config_variable(
            "JOHNS_HOPKINS_PUBLIC_HEALTH_PLAYWRIGHT_NAV_TIMEOUT",
            ["johns_hopkins_public_health", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )

        self.render_retries = get_config_variable(
            "JOHNS_HOPKINS_PUBLIC_HEALTH_RENDER_RETRIES",
            ["johns_hopkins_public_health", "render_retries"], config,
            isNumber=True, default=3,
        )

        self.confidence = get_config_variable(
            "JOHNS_HOPKINS_PUBLIC_HEALTH_CONFIDENCE",
            ["johns_hopkins_public_health", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "JOHNS_HOPKINS_PUBLIC_HEALTH_REPORT_TYPE",
            ["johns_hopkins_public_health", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "JOHNS_HOPKINS_PUBLIC_HEALTH_TLP",
            ["johns_hopkins_public_health", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "JOHNS_HOPKINS_PUBLIC_HEALTH_AUTHOR_NAME",
            ["johns_hopkins_public_health", "author_name"], config,
            default="Johns Hopkins Bloomberg School of Public Health",
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
                "Johns Hopkins Bloomberg School of Public Health. "
                "Leading public health research and education institution. "
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

    def _fetch_sitemap_urls(self, pw=None):
        """Fetch /sitemap.xml and return filtered (url, lastmod) tuples.

        Handles a <sitemapindex> pointing to sub-sitemaps (?page=1..9).
        Falls back to Playwright for sitemap fetches if Cloudflare blocks
        plain HTTP requests.
        """
        sitemap_url = f"{self.base_url}/sitemap.xml"
        xml_bytes = self._fetch_xml(sitemap_url, pw)
        if not xml_bytes:
            return []

        return self._parse_sitemap_xml(xml_bytes, pw=pw)

    def _fetch_xml(self, url, pw=None):
        """Fetch XML content, falling back to Playwright if requests fails."""
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            # Check for Cloudflare challenge in response body.
            body_lower = resp.text[:2000].lower()
            if any(m in body_lower for m in CHALLENGE_MARKERS):
                raise RuntimeError("Cloudflare challenge in sitemap response")
            return resp.content
        except Exception as exc:
            self.helper.log_warning(
                f"Plain HTTP fetch failed for {url}: {exc}; trying Playwright."
            )

        if pw is None:
            self.helper.log_error(
                f"No Playwright instance for sitemap fallback: {url}"
            )
            return None

        # Playwright fallback for Cloudflare-blocked sitemap.
        browser = None
        context = None
        page = None
        try:
            browser = pw.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 1024},
                user_agent=BROWSER_UA,
            )
            page = context.new_page()
            page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)
            page.wait_for_timeout(3000)
            content = page.content()
            # Extract raw XML from Playwright's rendered page.
            # Browsers wrap XML in an HTML document, so get the pre text.
            soup = BeautifulSoup(content, "lxml")
            # If the browser rendered XML as HTML, try to get the raw text.
            pre = soup.find("pre")
            if pre:
                return pre.get_text().encode("utf-8")
            return content.encode("utf-8")
        except Exception as exc2:
            self.helper.log_error(
                f"Playwright sitemap fallback also failed for {url}: {exc2}"
            )
            return None
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
            try:
                if browser is not None:
                    browser.close()
            except Exception:
                pass

    def _parse_sitemap_xml(self, xml_bytes, depth=3, pw=None):
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
                self.helper.log_warning(
                    "Sitemap recursion depth exceeded; skipping nested sitemaps."
                )
                return []
            results = []
            for sitemap_el in root.findall("sm:sitemap/sm:loc", SITEMAP_NS):
                child_url = (sitemap_el.text or "").strip()
                if not child_url:
                    continue
                child_bytes = self._fetch_xml(child_url, pw)
                if child_bytes:
                    results.extend(
                        self._parse_sitemap_xml(child_bytes, depth=depth - 1, pw=pw)
                    )
                time.sleep(1)
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
            lastmod = (
                (lastmod_el.text or "").strip() if lastmod_el is not None else ""
            )

            if self._url_in_scope(loc):
                results.append((loc, lastmod))

        return results

    def _url_in_scope(self, url):
        """Return True if the URL is an in-scope article."""
        parsed = urlparse(url)

        # Must be on the base domain.
        base_parsed = urlparse(self.base_url)
        if parsed.netloc and parsed.netloc != base_parsed.netloc:
            return False

        # Skip external redirect domains.
        for domain in EXTERNAL_DOMAINS:
            if domain in parsed.netloc:
                return False

        path = parsed.path
        return _is_article_path(path)

    # ------------------------------------------------------------------ #
    # JSON-LD metadata extraction
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_jsonld_metadata(soup):
        """Extract metadata from JSON-LD NewsArticle schema.

        Returns dict with title, description, published, topics, or None
        if no suitable JSON-LD found.
        """
        for script in soup.select('script[type="application/ld+json"]'):
            try:
                data = json.loads(script.string or "")
            except (json.JSONDecodeError, TypeError):
                continue

            # Handle @graph arrays.
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
                    type_match = "NewsArticle" in item_type
                else:
                    type_match = item_type == "NewsArticle"

                if not type_match:
                    continue

                result = {}
                result["title"] = item.get("headline", "")
                result["description"] = item.get("description", "")
                result["published"] = item.get("datePublished", "")
                result["modified"] = item.get("dateModified", "")

                # Extract topics from 'about' field.
                about = item.get("about", [])
                if isinstance(about, dict):
                    about = [about]
                topics = []
                for topic in about:
                    if isinstance(topic, dict):
                        name = topic.get("name", "")
                        if name:
                            topics.append(name)
                    elif isinstance(topic, str):
                        topics.append(topic)
                result["topics"] = topics

                return result

        return None

    # ------------------------------------------------------------------ #
    # CSS selector fallback metadata
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_selector_metadata(soup, url, sitemap_lastmod):
        """Extract metadata from CSS selectors and meta tags as fallback.

        Used when JSON-LD is not available.
        """
        # Title.
        title = ""
        title_el = soup.select_one(".field-name--title")
        if title_el:
            title = title_el.get_text(strip=True)
        if not title:
            og_title = soup.find("meta", property="og:title")
            if og_title and og_title.get("content"):
                title = og_title["content"].strip()
        if not title:
            h1 = soup.find("h1")
            title = h1.get_text(strip=True) if h1 else ""
        if not title:
            title_tag = soup.find("title")
            title = title_tag.get_text(strip=True) if title_tag else ""
        # Strip site name suffix.
        title = re.sub(
            r"\s*[-|]\s*Johns Hopkins.*$", "", title, flags=re.IGNORECASE
        ).strip()

        # Description.
        og_desc = soup.find("meta", property="og:description")
        description = (
            og_desc["content"].strip()
            if og_desc and og_desc.get("content") else ""
        )
        if not description:
            meta_desc = soup.find("meta", attrs={"name": "description"})
            description = (
                meta_desc["content"].strip()
                if meta_desc and meta_desc.get("content") else ""
            )

        # Published date.
        published = None

        # 1. Drupal publish date field.
        date_el = soup.select_one(".field-name--field-publish-date")
        if date_el:
            date_text = date_el.get_text(strip=True)
            try:
                dt = datetime.fromisoformat(date_text.replace("Z", "+00:00"))
                published = dt.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
            except (ValueError, TypeError):
                pass

        # 2. article:published_time meta tag.
        if not published:
            pub_meta = soup.find("meta", property="article:published_time")
            if pub_meta and pub_meta.get("content"):
                try:
                    dt = datetime.fromisoformat(
                        pub_meta["content"].replace("Z", "+00:00")
                    )
                    published = dt.astimezone(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S+00:00"
                    )
                except (ValueError, TypeError):
                    pass

        # 3. time[datetime] element.
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

        # 4. Sitemap lastmod.
        if not published and sitemap_lastmod:
            try:
                dt = datetime.fromisoformat(
                    sitemap_lastmod.replace("Z", "+00:00")
                )
                published = dt.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
            except (ValueError, TypeError):
                pass

        # 5. Year from URL path.
        if not published:
            year = _extract_year_from_path(urlparse(url).path)
            if year:
                published = datetime(year, 1, 1, tzinfo=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )

        # 6. Fallback to now.
        if not published:
            published = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )

        return {
            "title": title,
            "description": description,
            "published": published,
            "topics": [],
        }

    # ------------------------------------------------------------------ #
    # Combined metadata extraction
    # ------------------------------------------------------------------ #

    def _extract_metadata(self, soup, url, sitemap_lastmod):
        """Extract metadata, preferring JSON-LD over CSS selectors."""
        # Try JSON-LD first.
        meta = self._extract_jsonld_metadata(soup)
        if meta and meta.get("title"):
            # Normalise the published date.
            raw_pub = meta.get("published") or meta.get("modified") or ""
            if raw_pub:
                try:
                    dt = datetime.fromisoformat(raw_pub.replace("Z", "+00:00"))
                    meta["published"] = dt.astimezone(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S+00:00"
                    )
                except (ValueError, TypeError):
                    meta["published"] = None

            # Fill in missing published date from sitemap or URL.
            if not meta.get("published"):
                if sitemap_lastmod:
                    try:
                        dt = datetime.fromisoformat(
                            sitemap_lastmod.replace("Z", "+00:00")
                        )
                        meta["published"] = dt.astimezone(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S+00:00"
                        )
                    except (ValueError, TypeError):
                        pass
                if not meta.get("published"):
                    year = _extract_year_from_path(urlparse(url).path)
                    if year:
                        meta["published"] = datetime(
                            year, 1, 1, tzinfo=timezone.utc
                        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
                if not meta.get("published"):
                    meta["published"] = datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S+00:00"
                    )

            # Strip site name from title.
            meta["title"] = re.sub(
                r"\s*[-|]\s*Johns Hopkins.*$", "", meta["title"],
                flags=re.IGNORECASE,
            ).strip()
            return meta

        # Fall back to CSS selectors.
        return self._extract_selector_metadata(soup, url, sitemap_lastmod)

    # ------------------------------------------------------------------ #
    # Content extraction (BeautifulSoup)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_content(soup):
        """Extract the article body from a BeautifulSoup-parsed page.

        Tries Drupal Thunder-specific selectors first, falls back to generic.
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

    # ------------------------------------------------------------------ #
    # Playwright page fetch
    # ------------------------------------------------------------------ #

    def _fetch_and_extract(self, browser, url, lastmod):
        """Navigate to URL with Playwright, extract article content and metadata.

        Returns (content_html_str, metadata_dict) on success,
        or (None, None) on failure.
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

            # Check for Cloudflare challenge in title and page body.
            title = (page.title() or "").lower()
            body_text = (page.inner_text("body") or "").lower()[:2000]
            if any(m in title or m in body_text for m in CHALLENGE_MARKERS):
                raise RuntimeError("Cloudflare challenge interstitial detected")

            # Wait for JS-rendered content.
            page.wait_for_timeout(2000)

            # Check for external redirects.
            current_url = page.url
            current_parsed = urlparse(current_url)
            base_parsed = urlparse(self.base_url)
            if current_parsed.netloc != base_parsed.netloc:
                self.helper.log_warning(
                    f"Page redirected to external domain: {current_url}; skipping."
                )
                return None, None

            html_content = page.content()
            soup = BeautifulSoup(html_content, "lxml")

            # Metadata extraction (JSON-LD preferred, CSS selectors fallback).
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
        topics = meta.get("topics", [])

        byline_parts = []
        if topics:
            byline_parts.append("Topics: " + ", ".join(topics))
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
        topics = meta.get("topics", [])

        description = meta.get("description", "")
        if topics:
            topic_str = ", ".join(topics)
            description = (
                f"[{topic_str}] {description}" if description else topic_str
            )

        published = meta.get("published")

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on publichealth.jhu.edu",
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
                file_name=f"jhsph-{slug}.pdf",
                data=pdf_bytes,
                mime_type="application/pdf",
            )

        self.helper.log_info(f"Created Report for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            # Step 1: Fetch and filter sitemap URLs (may need Playwright
            # fallback if Cloudflare blocks plain HTTP).
            urls = self._fetch_sitemap_urls(pw=pw)
            if not urls:
                self.helper.log_warning(
                    "No in-scope URLs found in sitemap; skipping run."
                )
                return

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "Johns Hopkins Public Health enumeration run",
            )
            self.helper.log_info(
                f"Sitemap yielded {len(urls)} in-scope URLs. Starting enumeration."
            )

            processed = 0
            skipped = 0
            failed = 0
            message = "Run did not complete."

            try:
                browser = pw.chromium.launch(
                    args=["--no-sandbox", "--disable-dev-shm-usage"]
                )
                renders_since_recycle = 0
                try:
                    for url, lastmod in urls:
                        if self.max_reports and processed >= self.max_reports:
                            self.helper.log_info(
                                f"Reached MAX_REPORTS={self.max_reports}; stopping."
                            )
                            break

                        # Graph dedup.
                        if self._already_ingested(url):
                            skipped += 1
                            continue

                        # Browser recycling to prevent memory leaks.
                        if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                            browser.close()
                            browser = pw.chromium.launch(
                                args=["--no-sandbox", "--disable-dev-shm-usage"]
                            )
                            renders_since_recycle = 0

                        # Playwright navigation + content extraction.
                        try:
                            content_html, meta = self._fetch_and_extract(
                                browser, url, lastmod
                            )
                        except Exception as exc:
                            content_html, meta = None, None
                            self.helper.log_warning(
                                f"Fetch/extract raised for {url}: {exc}"
                            )
                        finally:
                            renders_since_recycle += 1

                        if content_html is None or meta is None:
                            failed += 1
                            self.helper.log_warning(
                                f"Content extraction failed for {url}"
                            )
                            time.sleep(self.request_delay)
                            continue

                        # PDF render.
                        pdf_bytes = self._render_with_retry(
                            url, meta, content_html
                        )
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
                    f"{failed} failed."
                )
            finally:
                try:
                    self.helper.api.work.to_processed(work_id, message)
                except Exception:
                    pass
                self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info(
            "Johns Hopkins Public Health connector started."
        )
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        JohnsHopkinsPublicHealthConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
