"""
The Diplomat OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://thediplomat.com as container-only OpenCTI Reports, one per article,
with two PDFs attached per Report:

  1. RSS content PDF (variant "rss-content") -- rendered from the RSS
     description/excerpt via WeasyPrint. This captures the summary as the feed
     provides it: fast, no network fetch beyond embedded images.
  2. Live HTML PDF (variant "live-html") -- Playwright navigates to the article
     URL (bypassing Cloudflare), BeautifulSoup extracts the article body,
     cruft is stripped, and WeasyPrint renders the PDF. This captures the full
     article as a reader sees it.

Collection model (RSS + graph-dedup re-walk)
--------------------------------------------
The Diplomat is a WordPress site behind Cloudflare WAF (~15-25k articles,
2011-present). The WP REST API and sitemaps are blocked (403). The RSS feed at
/feed/ is whitelisted by Cloudflare and supports pagination via ?paged=N with
96 items per page, newest-first.

Enumeration walks the RSS feed from page 1 (newest) forward. There is no
persisted cursor. Each poll re-walks from page 1, relying on graph dedup
(deterministic Report STIX ID from article URL) to skip already-ingested
articles. An early-stop optimisation halts the walk when an entire RSS page
contains only articles already present in the graph, since everything older is
also known.

Article HTML pages are behind Cloudflare JS challenge, so Playwright is
required to access the live page for the second PDF variant. Playwright is
lazy-imported inside _process() so a syntax/import check of this module does
not require the browser stack to be present.

Content filtering
-----------------
Podcasts, videos, and photo essays are skipped. URL-path patterns are checked
during enumeration: /category/podcast/, /category/videos/, /photo-essays/,
/the-pulse/, and similar patterns are filtered out.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id)
and skips if the Report already exists. Because the existence check keys on
the Report id, every sub-write is idempotent and a crash anywhere leaves the
article still "not done"; the next poll re-enters and completes it. The graph
lookup is the correctness backstop; the early-stop on known pages is the
efficiency layer.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels. Named-entity / IOC extraction is
a separate, out-of-scope downstream phase. Keeping this connector
container-only makes it purely additive and prevents it from acting as a
graph-contamination vector.

Key decisions
-------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published source).
- Author: the single "The Diplomat" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band: editorial secondary analysis).
- CR: CR114

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
import feedparser
import weasyprint
import yaml
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper, get_config_variable

logging.getLogger("weasyprint").setLevel(logging.ERROR)

# Playwright is imported lazily inside _process() so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

MAX_RSS_PAGES = 500  # safety cap on pagination depth

BROWSER_RECYCLE_EVERY = 50

CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")

# URL path segments that indicate non-article content to skip.
SKIP_URL_PATTERNS = (
    "/category/podcast",
    "/category/videos",
    "/photo-essays/",
    "/the-pulse/",
    "/category/photo-essay",
    "/category/video",
)

LIVE_CONTENT_SELECTORS = [
    ".entry-content",
    ".post-content",
    "article .content",
    ".td-post-content",
    ".article-content",
    "article .entry-body",
    ".single-post-content",
]

STRIP_SELECTORS = [
    ".ad-container",
    ".advertisement",
    ".social-share",
    ".related-posts",
    ".newsletter-signup",
    ".comments-area",
    "script",
    "style",
    "iframe",
    ".wp-block-embed",
]

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
    "blockquote { border-left: 3px solid #1a3a5c; margin: 1em 0; "
    "padding: 0.5em 1em; color: #555; } "
    "a { color: #1a3a5c; } "
)

PDF_VARIANT_RSS_CONTENT = "rss-content"
PDF_VARIANT_LIVE_HTML = "live-html"

_RE_STRIP_HTML = re.compile(r"<[^>]+>")

MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB


def _strip_html(value):
    if not value:
        return ""
    return html_mod.unescape(_RE_STRIP_HTML.sub("", value)).strip()


def _escape_html(text):
    return html_mod.escape(text, quote=True) if text else ""


def _css_string_escape(s):
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\a ").replace("\r", "")


def _build_pdf_html(title, byline, content_html, source_url, ingested_at,
                     variant=PDF_VARIANT_RSS_CONTENT):
    css_url = _css_string_escape(source_url)
    safe_title = _escape_html(title)
    safe_byline = _escape_html(byline) if byline else ""
    byline_block = f'<div class="byline">{safe_byline}</div>' if safe_byline else ""
    variant_label = variant.upper()
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        + f"<meta name='pdf-variant' content='{variant}'>"
        + f"<meta name='source-url' content='{_escape_html(source_url)}'>"
        + "<style>"
        + _PDF_STYLE
        + "@page { margin: 15mm 12mm 20mm 12mm; "
        + "@bottom-center { content: '"
        + css_url
        + "  |  OpenCTI The Diplomat connector [" + variant_label + "]  |  "
        + ingested_at
        + "'; font-size: 7px; color: #888; } } "
        + "</style></head><body>"
        + "<h1>" + safe_title + "</h1>"
        + byline_block
        + content_html
        + "</body></html>"
    )


def _should_skip(url):
    """Return True if the URL points to non-article content (podcast, video, etc.)."""
    path = urlparse(url).path.lower()
    return any(pattern in path for pattern in SKIP_URL_PATTERNS)


def _parse_rss_date(entry):
    """Extract a publication date from an RSS entry as ISO-8601 string."""
    for attr in ("published_parsed", "updated_parsed"):
        parsed = getattr(entry, attr, None)
        if parsed:
            try:
                dt = datetime(*parsed[:6], tzinfo=timezone.utc)
                if dt.year >= 2000:
                    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            except (TypeError, ValueError):
                continue
    # Fallback: try the raw string
    for attr in ("published", "updated"):
        raw = getattr(entry, attr, None)
        if raw:
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            except (TypeError, ValueError):
                pass
    return None


def _infer_category(url):
    """Attempt to infer a category label from the URL path.

    The Diplomat URL patterns: /category/<topic>/<slug>/ or /<slug>/
    """
    path = urlparse(url).path.strip("/")
    parts = path.split("/")
    if len(parts) >= 2 and parts[0] == "category":
        return parts[1].replace("-", " ").title()
    return None


class TheDiplomatConnector:
    """External-import connector that mirrors The Diplomat articles into Reports."""

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
            "THE_DIPLOMAT_BASE_URL",
            ["the_diplomat", "base_url"], config,
            default="https://thediplomat.com",
        ).rstrip("/")
        self.feed_url = f"{self.base_url}/feed/"

        self.poll_interval = get_config_variable(
            "THE_DIPLOMAT_POLL_INTERVAL",
            ["the_diplomat", "poll_interval"], config,
            isNumber=True, default=86400,
        )

        self.request_delay = get_config_variable(
            "THE_DIPLOMAT_REQUEST_DELAY",
            ["the_diplomat", "request_delay"], config,
            isNumber=True, default=3,
        )

        self.max_reports = get_config_variable(
            "THE_DIPLOMAT_MAX_REPORTS",
            ["the_diplomat", "max_reports"], config,
            isNumber=True, default=0,
        )

        self.render_retries = get_config_variable(
            "THE_DIPLOMAT_RENDER_RETRIES",
            ["the_diplomat", "render_retries"], config,
            isNumber=True, default=3,
        )

        self.nav_timeout_ms = get_config_variable(
            "THE_DIPLOMAT_PLAYWRIGHT_NAV_TIMEOUT",
            ["the_diplomat", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )

        self.confidence = get_config_variable(
            "THE_DIPLOMAT_CONFIDENCE",
            ["the_diplomat", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "THE_DIPLOMAT_REPORT_TYPE",
            ["the_diplomat", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "THE_DIPLOMAT_TLP",
            ["the_diplomat", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "THE_DIPLOMAT_AUTHOR_NAME",
            ["the_diplomat", "author_name"], config,
            default="The Diplomat",
        )

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA})

        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Asia-Pacific current affairs publication covering security, "
                        "diplomacy, politics, economy, environment, and society. "
                        "Source organization for ingested reports.",
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
    # RSS enumeration
    # ------------------------------------------------------------------ #

    def _fetch_rss_page(self, page_num):
        """Fetch and parse one page of the RSS feed. Returns a feedparser feed."""
        url = f"{self.feed_url}?paged={page_num}" if page_num > 1 else self.feed_url
        try:
            resp = self.session.get(url, timeout=60)
            if not resp.ok:
                self.helper.log_warning(
                    f"RSS page {page_num} returned HTTP {resp.status_code}"
                )
                return None
            feed = feedparser.parse(resp.text)
            if feed.bozo and not feed.entries:
                self.helper.log_warning(
                    f"RSS page {page_num} parse error: {feed.bozo_exception}"
                )
                return None
            return feed
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch RSS page {page_num}: {exc}")
            return None

    # ------------------------------------------------------------------ #
    # PDF rendering (WeasyPrint)
    # ------------------------------------------------------------------ #

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

    def _render_rss_pdf(self, entry):
        """Render a PDF from the RSS entry's description/summary content."""
        title = _strip_html(entry.get("title", ""))
        url = entry.get("link", "")

        # RSS description is the excerpt/summary
        content_html = entry.get("summary", "") or entry.get("description", "")
        if not content_html:
            content_html = "<p><em>No content available in RSS feed.</em></p>"

        author = entry.get("author", "")
        category = _infer_category(url)
        byline_parts = []
        if author:
            byline_parts.append(f"By {author}")
        if category:
            byline_parts.append(category)
        byline = "  |  ".join(byline_parts)

        ingested = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        doc_html = _build_pdf_html(
            title, byline, content_html, url, ingested,
            variant=PDF_VARIANT_RSS_CONTENT,
        )

        if len(doc_html.encode("utf-8", errors="replace")) > MAX_CONTENT_BYTES:
            self.helper.log_warning(
                f"Skipping PDF render for {url}: content too large "
                f"({len(doc_html.encode('utf-8', errors='replace')):,} bytes)."
            )
            return None

        return weasyprint.HTML(
            string=doc_html, base_url=url, url_fetcher=self._wp_url_fetcher
        ).write_pdf()

    def _render_rss_with_retry(self, entry):
        url = entry.get("link", "")
        return self._retry(
            lambda: self._render_rss_pdf(entry),
            f"RSS PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Live HTML PDF rendering (Playwright + WeasyPrint)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_live_content(page_html):
        """Extract article body from live HTML using BeautifulSoup."""
        soup = BeautifulSoup(page_html, "lxml")
        content = None
        for selector in LIVE_CONTENT_SELECTORS:
            content = soup.select_one(selector)
            if content:
                break
        if not content:
            return None
        for sel in STRIP_SELECTORS:
            for el in content.select(sel):
                el.decompose()
        return content

    def _render_live_pdf(self, browser, url, title, byline):
        """Navigate to article with Playwright, extract content, render via WeasyPrint."""
        context = browser.new_context(
            viewport={"width": 1280, "height": 1696},
            user_agent=BROWSER_UA,
        )
        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)

            page_title = (page.title() or "").lower()
            if any(marker in page_title for marker in CHALLENGE_MARKERS):
                # Wait for Cloudflare challenge to resolve
                page.wait_for_timeout(5000)
                page_title = (page.title() or "").lower()
                if any(marker in page_title for marker in CHALLENGE_MARKERS):
                    raise RuntimeError("Cloudflare challenge interstitial not resolved")

            page_html = page.content()
        finally:
            page.close()
            context.close()

        content = self._extract_live_content(page_html)
        if content is None:
            raise RuntimeError("No article content container found in live HTML")

        ingested = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        doc_html = _build_pdf_html(
            title, byline, str(content), url, ingested,
            variant=PDF_VARIANT_LIVE_HTML,
        )

        if len(doc_html.encode("utf-8", errors="replace")) > MAX_CONTENT_BYTES:
            self.helper.log_warning(
                f"Skipping PDF render for {url}: content too large "
                f"({len(doc_html.encode('utf-8', errors='replace')):,} bytes)."
            )
            return None

        return weasyprint.HTML(
            string=doc_html, base_url=url, url_fetcher=self._wp_url_fetcher
        ).write_pdf()

    def _render_live_with_retry(self, browser, url, title, byline):
        return self._retry(
            lambda: self._render_live_pdf(browser, url, title, byline),
            f"Live PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, entry, url, published, rss_pdf, live_pdf):
        name = _strip_html(entry.get("title", "")) or url

        description = _strip_html(entry.get("summary", "") or entry.get("description", ""))
        author = entry.get("author", "")
        if author:
            description = f"By {author}. {description}" if description else f"By {author}."

        category = _infer_category(url)
        if category and description:
            description = f"[{category}] {description}"
        elif category:
            description = f"[{category}]"

        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on thediplomat.com",
        )

        report = self.helper.api.report.create(
            stix_id=report_id,
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

        slug = urlparse(url).path.strip("/").rsplit("/", 1)[-1] or "article"

        if len(rss_pdf) > MAX_PDF_BYTES:
            self.helper.log_warning(
                f"Skipping oversized PDF for {url} ({len(rss_pdf):,} bytes)."
            )
        else:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"the-diplomat-{slug}.pdf",
                data=rss_pdf,
                mime_type="application/pdf",
            )

        if live_pdf:
            if len(live_pdf) > MAX_PDF_BYTES:
                self.helper.log_warning(
                    f"Skipping oversized PDF for {url} ({len(live_pdf):,} bytes)."
                )
            else:
                self.helper.api.stix_domain_object.add_file(
                    id=report["id"],
                    file_name=f"the-diplomat-{slug}-live.pdf",
                    data=live_pdf,
                    mime_type="application/pdf",
                )

        live_tag = "+live" if live_pdf else " (live failed)"
        self.helper.log_info(f"Created Report{live_tag} for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        from playwright.sync_api import sync_playwright

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "The Diplomat enumeration run"
        )

        processed = 0
        skipped = 0
        skipped_content_type = 0
        failed = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                for page_num in range(1, MAX_RSS_PAGES + 1):
                    if self.max_reports and processed >= self.max_reports:
                        self.helper.log_info(
                            f"Reached THE_DIPLOMAT_MAX_REPORTS={self.max_reports}; "
                            f"stopping run."
                        )
                        break

                    feed = self._fetch_rss_page(page_num)
                    if feed is None:
                        self.helper.log_warning(
                            f"RSS page {page_num} fetch failed; ending cycle."
                        )
                        break
                    if not feed.entries:
                        self.helper.log_info(
                            f"RSS page {page_num} empty; enumeration complete."
                        )
                        break

                    self.helper.log_info(
                        f"RSS page {page_num}: {len(feed.entries)} entries"
                    )

                    all_known = True
                    for entry in feed.entries:
                        if self.max_reports and processed >= self.max_reports:
                            break

                        url = entry.get("link")
                        if not url:
                            continue

                        # Normalise trailing slash (local var only; don't mutate entry)
                        if not url.endswith("/"):
                            url += "/"

                        # Skip non-article content -- NOT "known", so don't
                        # let a page full of skipped entries trigger early-stop.
                        if _should_skip(url):
                            skipped_content_type += 1
                            all_known = False
                            continue

                        if self._already_ingested(url):
                            skipped += 1
                            continue

                        all_known = False

                        # --- Render RSS content PDF --- #
                        rss_pdf = self._render_rss_with_retry(entry)
                        if rss_pdf is None:
                            failed += 1
                            self.helper.log_warning(
                                f"Skipping {url}: RSS content PDF render failed."
                            )
                            continue

                        # --- Render live HTML PDF via Playwright --- #
                        if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                            browser.close()
                            browser = None
                            browser = pw.chromium.launch(
                                args=["--no-sandbox", "--disable-dev-shm-usage"]
                            )
                            renders_since_recycle = 0

                        title = _strip_html(entry.get("title", ""))
                        author = entry.get("author", "")
                        category = _infer_category(url)
                        byline_parts = []
                        if author:
                            byline_parts.append(f"By {author}")
                        if category:
                            byline_parts.append(category)
                        byline = "  |  ".join(byline_parts)

                        live_pdf = self._render_live_with_retry(
                            browser, url, title, byline
                        )
                        renders_since_recycle += 1
                        if live_pdf is None:
                            self.helper.log_warning(
                                f"Live HTML PDF failed for {url}; "
                                f"attaching RSS content PDF only."
                            )

                        published = _parse_rss_date(entry)
                        if not published:
                            published = datetime.now(timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%S+00:00"
                            )
                            self.helper.log_warning(
                                f"No usable date for {url}; using ingestion time."
                            )

                        self._create_report(entry, url, published, rss_pdf, live_pdf)
                        processed += 1
                        time.sleep(self.request_delay)

                    if all_known and feed.entries:
                        self.helper.log_info(
                            f"All articles on RSS page {page_num} already ingested; "
                            f"stopping walk (early-stop)."
                        )
                        break

                    time.sleep(self.request_delay)
            finally:
                if browser is not None:
                    try:
                        browser.close()
                    except Exception:
                        pass

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{skipped_content_type} skipped (podcast/video/photo), "
            f"{failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("The Diplomat connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        TheDiplomatConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
