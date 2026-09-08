"""
404 Media OpenCTI connector.

Purpose
-------
External-import connector that ingests 404 Media journalism and creates one
OpenCTI Report container per article, with the source article attached as a
full-fidelity PDF.

Collection model
----------------
404 Media runs on Ghost CMS (hosted at 404-media.ghost.io). The Ghost Content
API exists but requires a private key not publicly exposed. Collection therefore
paginates the public front-end listing:

  - Homepage pagination: /page/N/ (1-indexed, ~12 articles per page)
  - Pagination boundary: HTTP 404 on the first page past the end

Article permalinks are extracted from the listing HTML via BeautifulSoup,
targeting the Ghost theme's card-link selectors (a.post-card__image,
.post-card__title a). A generic-link fallback with slug filtering handles
theme changes.

Per-article metadata (title, published date, description) is read from the
article page's Open Graph and JSON-LD meta tags.

PDFs are generated with WeasyPrint from the article's server-rendered HTML
content. No browser automation is needed: Ghost delivers fully rendered HTML
and the site has no WAF or anti-bot protection.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships. Entity extraction is a separate, out-of-scope
phase.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (public source).
- Author: the 404 Media Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band).
- Deduplication: graph-driven via External Reference URL lookup. No state file
  and no cursor; every run re-enumerates listing pages and skips URLs already
  on a Report. An early-stop threshold avoids re-walking the entire archive on
  incremental runs.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import html as html_mod
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
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

MAX_LISTING_PAGES = 500

NON_ARTICLE_SLUGS = frozenset({
    "tag", "author", "page", "ghost", "members", "email",
    "archive", "about", "faq", "contact", "privacy", "subscribe",
    "podcast", "membership", "tips", "signup", "signin", "rss",
    "feed", "sitemap", "r", "webmentions", "404",
})

CONTENT_SELECTORS = [
    ".post__content",
    ".gh-content",
    ".post-content",
    ".post-full-content",
    "article .kg-canvas",
    "article",
]

_PDF_STYLE = (
    "body { font-family: Georgia, serif; max-width: 800px; "
    "margin: 0 auto; padding: 20px; color: #222; line-height: 1.6; } "
    "h1 { font-size: 24px; margin-bottom: 0.5em; } "
    "h2 { font-size: 20px; } "
    "img { max-width: 100%; height: auto; } "
    "pre, code { background: #f4f4f4; padding: 2px 6px; "
    "font-size: 13px; white-space: pre-wrap; word-break: break-all; } "
    "table { border-collapse: collapse; width: 100%; } "
    "td, th { border: 1px solid #ccc; padding: 8px; } "
    "figure { margin: 1em 0; } "
    "figcaption { font-size: 0.85em; color: #666; margin-top: 4px; } "
    "blockquote { border-left: 3px solid #ccc; margin: 1em 0; "
    "padding: 0.5em 1em; color: #555; } "
)


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class _SkipArticle(Exception):
    """Article should be skipped permanently (missing required metadata)."""


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _strip_html(value):
    if not value:
        return ""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", value)).strip()


def _escape_html(text):
    return html_mod.escape(text) if text else ""


def _build_pdf_html(title, content_html, source_url, ingested_at):
    css_url = source_url.replace("'", "").replace("\\", "")
    safe_title = _escape_html(title)
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><style>"
        + _PDF_STYLE
        + "@page { margin: 15mm 12mm 20mm 12mm; "
        + "@bottom-center { content: '"
        + css_url
        + "  |  OpenCTI 404 Media connector  |  "
        + ingested_at
        + "'; font-size: 7px; color: #888; } } "
        + "</style></head><body>"
        + "<h1>" + safe_title + "</h1>"
        + content_html
        + "</body></html>"
    )


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

class FourZeroFourMediaConnector:
    """External-import connector that mirrors 404 Media posts into Reports."""

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
            "FOUR04MEDIA_BASE_URL", ["four04media", "base_url"], config,
            default="https://www.404media.co",
        ).rstrip("/")

        self.poll_interval = get_config_variable(
            "FOUR04MEDIA_POLL_INTERVAL", ["four04media", "poll_interval"], config,
            isNumber=True, default=21600,
        )

        self.request_delay = get_config_variable(
            "FOUR04MEDIA_REQUEST_DELAY", ["four04media", "request_delay"], config,
            isNumber=True, default=3,
        )

        self.max_posts = get_config_variable(
            "FOUR04MEDIA_MAX_POSTS", ["four04media", "max_posts"], config,
            isNumber=True, default=0,
        )

        self.render_retries = get_config_variable(
            "FOUR04MEDIA_RENDER_RETRIES", ["four04media", "render_retries"], config,
            isNumber=True, default=3,
        )

        self.early_stop_skips = get_config_variable(
            "FOUR04MEDIA_EARLY_STOP_SKIPS", ["four04media", "early_stop_skips"],
            config, isNumber=True, default=24,
        )

        self.confidence = get_config_variable(
            "FOUR04MEDIA_CONFIDENCE", ["four04media", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "FOUR04MEDIA_REPORT_TYPE", ["four04media", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "FOUR04MEDIA_TLP", ["four04media", "tlp"], config,
            default="TLP:CLEAR",
        )

        self._host = urlparse(self.base_url).netloc

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
            name="404 Media",
            description="Independent technology and science journalism outlet "
                        "founded in 2023. Source organization for ingested reports.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved 404 Media author identity: {self.author_id}")

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

        resp = self.session.get(self.base_url, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Site unreachable: {self.base_url} returned HTTP {resp.status_code}"
            )
        self.helper.log_info(f"Site reachable: {self.base_url}")

    # ------------------------------------------------------------------ #
    # Listing-page enumeration
    # ------------------------------------------------------------------ #

    def _extract_article_urls(self, page_html):
        soup = BeautifulSoup(page_html, "lxml")
        seen = set()
        ordered = []

        card_links = (
            soup.select("a.post-card__image[href]")
            + soup.select(".post-card__title a[href]")
        )

        targets = card_links if card_links else soup.find_all("a", href=True)

        for a_tag in targets:
            href = a_tag["href"]

            if href.startswith("/") and not href.startswith("//"):
                href = f"{self.base_url}{href}"

            parsed = urlparse(href)
            if parsed.netloc != self._host:
                continue

            path = parsed.path.strip("/")
            if not path or "/" in path:
                continue

            if not card_links and path.lower() in NON_ARTICLE_SLUGS:
                continue

            url = f"{self.base_url}/{path}/"
            if url not in seen:
                seen.add(url)
                ordered.append(url)

        return ordered

    def _walk_listing_pages(self):
        seen = set()
        for page in range(1, MAX_LISTING_PAGES + 1):
            if page == 1:
                url = f"{self.base_url}/"
            else:
                url = f"{self.base_url}/page/{page}/"

            resp = self.session.get(url, timeout=60)
            if resp.status_code == 404:
                break
            resp.raise_for_status()

            urls = self._extract_article_urls(resp.text)
            if not urls:
                if page == 1:
                    self.helper.log_warning(
                        "Homepage returned 200 but no article links found. "
                        "Possible JS-rendered listing or template change."
                    )
                break

            for u in urls:
                if u not in seen:
                    seen.add(u)
                    yield u

            time.sleep(self.request_delay)
        else:
            self.helper.log_warning(
                f"Hit MAX_LISTING_PAGES={MAX_LISTING_PAGES} without a 404 boundary."
            )

    def _already_ingested(self, url):
        existing_ref = self.helper.api.external_reference.read(
            filters={
                "mode": "and",
                "filters": [{"key": "url", "values": [url]}],
                "filterGroups": [],
            }
        )
        return existing_ref is not None

    # ------------------------------------------------------------------ #
    # Metadata + content extraction
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_metadata(soup):
        def _meta(prop):
            tag = soup.find("meta", property=prop)
            return tag["content"].strip() if tag and tag.get("content") else None

        title = _meta("og:title") or (
            soup.title.string if soup.title else None
        )
        description = _meta("og:description") or ""
        published = _meta("article:published_time")

        if not published:
            for script in soup.find_all("script", type="application/ld+json"):
                try:
                    data = json.loads(script.string or "")
                    nodes = (
                        data if isinstance(data, list)
                        else data.get("@graph", [data])
                    )
                    for node in nodes:
                        if isinstance(node, dict) and node.get("datePublished"):
                            published = node["datePublished"]
                            break
                except (json.JSONDecodeError, TypeError):
                    continue
                if published:
                    break

        return {
            "title": _strip_html(title or ""),
            "published": published,
            "description": _strip_html(description),
        }

    @staticmethod
    def _extract_content(soup):
        for selector in CONTENT_SELECTORS:
            content = soup.select_one(selector)
            if content:
                for cta in content.select(".outpost-pub-container"):
                    cta.decompose()
                return content
        raise RuntimeError("No article content container found for PDF")

    # ------------------------------------------------------------------ #
    # PDF rendering (WeasyPrint)
    # ------------------------------------------------------------------ #

    def _wp_url_fetcher(self, url):
        import weasyprint

        if url.startswith("data:"):
            return weasyprint.default_url_fetcher(url)
        try:
            resp = self.session.get(url, timeout=15)
            return {
                "string": resp.content,
                "mime_type": resp.headers.get(
                    "content-type", "application/octet-stream"
                ).split(";")[0],
            }
        except Exception:
            return {"string": b"", "mime_type": "text/plain"}

    def _render_pdf(self, content, url, title):
        ingested = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        doc_html = _build_pdf_html(title, str(content), url, ingested)
        import weasyprint

        return weasyprint.HTML(
            string=doc_html, base_url=url, url_fetcher=self._wp_url_fetcher
        ).write_pdf()

    def _load_article(self, url):
        resp = self.session.get(url, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")
        soup = BeautifulSoup(resp.text, "lxml")
        metadata = self._extract_metadata(soup)
        if not metadata.get("title"):
            raise _SkipArticle("no title in page metadata")
        if not metadata.get("published"):
            raise _SkipArticle("no published date in page metadata")
        content = self._extract_content(soup)
        pdf_bytes = self._render_pdf(content, url, metadata["title"])
        return metadata, pdf_bytes

    def _load_with_retry(self, url):
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._load_article(url)
            except _SkipArticle:
                raise
            except Exception as exc:
                self.helper.log_warning(
                    f"Load attempt {attempt}/{self.render_retries} failed for "
                    f"{url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
        return None, None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    @staticmethod
    def _slug_from_url(url):
        path = urlparse(url).path.strip("/")
        return path.split("/")[-1] if path else "article"

    def _create_report(self, url, meta, pdf_bytes):
        name = meta["title"] or self._slug_from_url(url)
        description = meta.get("description", "")
        published = meta.get("published")

        external_reference = self.helper.api.external_reference.create(
            source_name="404 Media",
            url=url,
            description="Source article on 404media.co",
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

        file_name = f"404media-{self._slug_from_url(url)}.pdf"
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
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "404 Media enumeration run"
        )

        processed = 0
        skipped = 0
        failed = 0
        consecutive_skips = 0

        for url in self._walk_listing_pages():
            if self.max_posts and processed >= self.max_posts:
                self.helper.log_info(
                    f"Reached FOUR04MEDIA_MAX_POSTS={self.max_posts}; stopping run."
                )
                break

            if self._already_ingested(url):
                skipped += 1
                consecutive_skips += 1
                if (
                    self.early_stop_skips
                    and consecutive_skips >= self.early_stop_skips
                ):
                    self.helper.log_info(
                        f"Hit {consecutive_skips} consecutive already-ingested "
                        f"articles; stopping incremental walk."
                    )
                    break
                continue

            try:
                meta, pdf_bytes = self._load_with_retry(url)
            except _SkipArticle as exc:
                failed += 1
                self.helper.log_warning(f"Skipping {url}: {exc}")
                continue

            if pdf_bytes is None:
                failed += 1
                self.helper.log_warning(
                    f"Skipping {url}: load failed after retries."
                )
                continue

            self._create_report(url, meta, pdf_bytes)
            processed += 1
            consecutive_skips = 0
            time.sleep(self.request_delay)

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("404 Media connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        FourZeroFourMediaConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
