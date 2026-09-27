"""
InSight Crime OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://insightcrime.org as container-only OpenCTI Reports, one per
post, with two PDFs attached per Report:

  1. REST API PDF -- rendered from the WP REST `content.rendered` payload via
     WeasyPrint. This is the structured content as WordPress stores it: clean,
     fast, no network fetch beyond embedded images.
  2. Live HTML PDF -- fetched from the article URL, article body extracted from
     the Newspack theme post-content container with BeautifulSoup, cruft stripped,
     rendered via WeasyPrint. This captures the page as a reader sees it and
     serves as the auditor/processor reference.

Collection model (WordPress REST API + ascending-id cursor)
-----------------------------------------------------------
InSight Crime is a WordPress site with Newspack theme (~5-6k posts on organized
crime in Latin America). The WordPress REST API (/wp-json/wp/v2/posts) is fully
open: no WAF gating, no API key, standard pagination. The REST API is the sole
enumeration surface.

Enumeration walks all posts in ascending post-id order (orderby=id&order=asc)
behind a persisted positional {page, index} cursor held in OpenCTI connector state.
Ascending id is used, not date: post ids are monotonic and stable. New posts always
receive the highest ids and land on the last page, so a positional cursor walked
from page 1 is stable for the historical backfill and, once it reaches the tail,
naturally picks up freshly-appended posts on each subsequent poll.

The WordPress REST API caps pagination at 100 pages (10,000 posts with per_page=100).
When the cursor reaches page 100 on a full page, it shifts the query window forward
by adding `after=<date of last processed post>` and resetting to page 1. This
sliding-window approach handles any corpus size.

Article content (title, date, excerpt, full HTML body) is read directly from the
REST payload's `content.rendered` field for the REST API PDF. The live HTML PDF
requires a second HTTP request to the article URL, but both use WeasyPrint (no
browser automation required).

Per-post title, excerpt (description), publication date, link, category ids, and
tag ids are read directly from the REST payload. WP authors are resolved once at
startup via the users endpoint and cached; each post's byline is included in the
Report description but the createdBy field uses the single Organization identity.
WP categories (42, including 20+ country categories) and tags (307, criminal
organizations, crime types, countries) are cached at startup and included in the
Report description.

Content filtering
-----------------
Posts in the "InSight Crime Podcast" or "Audio" categories are skipped during
enumeration (these are podcast/audio content, not articles).

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id) and
skips if the Report already exists. For a new post it creates the External Reference
(upsert-safe), then the Report (with the deterministic stix_id), then attaches the
PDF. Because the existence check keys on the Report id (not on the External
Reference), every sub-write is idempotent and a crash anywhere leaves the post still
"not done"; the next poll re-enters and completes it.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects, no
Observables, no Relationships, no Labels. Named-entity / IOC extraction is a
separate, out-of-scope downstream phase. Keeping this connector container-only makes
it purely additive and prevents it from acting as a graph-contamination vector.

Key decisions
-------------
- Collection requirement: CR94
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published source).
- Author: the single "InSight Crime" Organization identity. Never the connector
  account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (Medium band: editorial secondary analysis).
- Category filtering: skip "InSight Crime Podcast" and "Audio" categories.

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
from pycti import OpenCTIConnectorHelper, get_config_variable

logging.getLogger("weasyprint").setLevel(logging.ERROR)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

MAX_PER_PAGE = 100
MAX_WP_PAGES = 100

MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB

# Categories to skip (podcast/audio content, not articles).
SKIP_CATEGORY_NAMES = {"insight crime podcast", "audio"}

# Newspack theme content selectors (tried in order).
LIVE_CONTENT_SELECTORS = [
    ".entry-content",
    ".post-content",
    "article",
]

STRIP_SELECTORS = [
    ".wp-block-newspack-blocks-donate",
    ".newspack-popup",
    ".above-header-ad",
    ".widget-area",
    ".sharedaddy",
    ".jp-relatedposts",
    "nav",
    ".comments-area",
    "footer",
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


def _strip_html(value):
    if not value:
        return ""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", value)).strip()


def _escape_html(text):
    return html_mod.escape(text, quote=True) if text else ""


def _css_string_escape(s):
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\a ").replace("\r", "")


PDF_VARIANT_REST_API = "rest-api"
PDF_VARIANT_LIVE_HTML = "live-html"


def _build_pdf_html(title, byline, content_html, source_url,
                     variant=PDF_VARIANT_REST_API):
    """Wrap extracted article HTML in a styled document for WeasyPrint."""
    safe_title = _escape_html(title)
    safe_byline = _escape_html(byline) if byline else ""
    byline_block = f'<div class="byline">{safe_byline}</div>' if safe_byline else ""
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        + f"<meta name='pdf-variant' content='{variant}'>"
        + f"<meta name='source-url' content='{_escape_html(source_url)}'>"
        + "<style>"
        + _PDF_STYLE
        + "@page { margin: 15mm 12mm 15mm 12mm; } "
        + "</style></head><body>"
        + "<h1>" + safe_title + "</h1>"
        + byline_block
        + content_html
        + "</body></html>"
    )


class InsightCrimeConnector:
    """External-import connector that mirrors InSight Crime posts into Reports."""

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
            "INSIGHTCRIME_BASE_URL",
            ["insightcrime", "base_url"], config,
            default="https://insightcrime.org",
        ).rstrip("/")
        self.api_url = f"{self.base_url}/wp-json/wp/v2/posts"

        self.per_page = get_config_variable(
            "INSIGHTCRIME_PER_PAGE",
            ["insightcrime", "per_page"], config,
            isNumber=True, default=MAX_PER_PAGE,
        )
        if self.per_page > MAX_PER_PAGE or self.per_page < 1:
            self.per_page = MAX_PER_PAGE

        self.poll_interval = get_config_variable(
            "INSIGHTCRIME_POLL_INTERVAL",
            ["insightcrime", "poll_interval"], config,
            isNumber=True, default=86400,
        )

        self.request_delay = get_config_variable(
            "INSIGHTCRIME_REQUEST_DELAY",
            ["insightcrime", "request_delay"], config,
            isNumber=True, default=2,
        )

        self.max_reports = get_config_variable(
            "INSIGHTCRIME_MAX_REPORTS",
            ["insightcrime", "max_reports"], config,
            isNumber=True, default=0,
        )

        self.render_retries = get_config_variable(
            "INSIGHTCRIME_RENDER_RETRIES",
            ["insightcrime", "render_retries"], config,
            isNumber=True, default=3,
        )

        self.pdf_render_timeout = get_config_variable(
            "INSIGHTCRIME_PDF_RENDER_TIMEOUT",
            ["insightcrime", "pdf_render_timeout"],
            config,
            isNumber=True,
            default=120,
        )

        self.confidence = get_config_variable(
            "INSIGHTCRIME_CONFIDENCE",
            ["insightcrime", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "INSIGHTCRIME_REPORT_TYPE",
            ["insightcrime", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "INSIGHTCRIME_TLP",
            ["insightcrime", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "INSIGHTCRIME_AUTHOR_NAME",
            ["insightcrime", "author_name"], config,
            default="InSight Crime",
        )

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "application/json, */*",
        })

        self.author_id = None
        self.marking_id = None
        self._wp_authors = {}
        self._wp_categories = {}
        self._wp_tags = {}
        self._skip_category_ids = set()

    # ------------------------------------------------------------------ #
    # Cursor helpers
    # ------------------------------------------------------------------ #

    def _scope_sig(self):
        return "all"

    def _save_cursor(self, page, index, window_after=None):
        self.helper.set_state({
            "page": page,
            "index": index,
            "window_after": window_after,
            "scope_sig": self._scope_sig(),
        })

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Investigative journalism organization covering organized crime "
                        "in Latin America and the Caribbean. Source organization for "
                        "ingested reports.",
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

        self._cache_wp_authors()
        self._cache_wp_categories()
        self._cache_wp_tags()

        total = self._probe_total()
        if total is None:
            self.helper.log_error(
                f"REST endpoint {self.api_url} unreachable at startup; entering poll "
                f"loop anyway and retrying next cycle."
            )
        else:
            self.helper.log_info(
                f"REST endpoint reachable: {total} posts reported by API "
                f"(WP caps at 9999; actual count may be higher)."
            )

    def _cache_wp_authors(self):
        page = 1
        while True:
            try:
                resp = self.session.get(
                    f"{self.base_url}/wp-json/wp/v2/users",
                    params={
                        "per_page": MAX_PER_PAGE,
                        "page": page,
                        "_fields": "id,name",
                    },
                    timeout=30,
                )
                if resp.status_code == 400:
                    break
                resp.raise_for_status()
                users = resp.json()
                if not users:
                    break
                for u in users:
                    self._wp_authors[u["id"]] = u.get("name", "")
                if len(users) < MAX_PER_PAGE:
                    break
                page += 1
            except Exception as exc:
                self.helper.log_warning(f"Could not cache WP authors page {page}: {exc}")
                break
        self.helper.log_info(f"Cached {len(self._wp_authors)} WP authors.")

    def _cache_wp_categories(self):
        page = 1
        while True:
            try:
                resp = self.session.get(
                    f"{self.base_url}/wp-json/wp/v2/categories",
                    params={
                        "per_page": MAX_PER_PAGE,
                        "page": page,
                        "_fields": "id,name",
                    },
                    timeout=30,
                )
                if resp.status_code == 400:
                    break
                resp.raise_for_status()
                cats = resp.json()
                if not cats:
                    break
                for cat in cats:
                    cat_name = cat.get("name", "")
                    self._wp_categories[cat["id"]] = cat_name
                    if cat_name.lower() in SKIP_CATEGORY_NAMES:
                        self._skip_category_ids.add(cat["id"])
                if len(cats) < MAX_PER_PAGE:
                    break
                page += 1
            except Exception as exc:
                self.helper.log_warning(
                    f"Could not cache WP categories page {page}: {exc}"
                )
                break
        self.helper.log_info(
            f"Cached {len(self._wp_categories)} WP categories "
            f"(skipping {len(self._skip_category_ids)} podcast/audio categories)."
        )

    def _cache_wp_tags(self):
        page = 1
        while True:
            try:
                resp = self.session.get(
                    f"{self.base_url}/wp-json/wp/v2/tags",
                    params={
                        "per_page": MAX_PER_PAGE,
                        "page": page,
                        "_fields": "id,name",
                    },
                    timeout=30,
                )
                if resp.status_code == 400:
                    break
                resp.raise_for_status()
                tags = resp.json()
                if not tags:
                    break
                for tag in tags:
                    self._wp_tags[tag["id"]] = tag.get("name", "")
                if len(tags) < MAX_PER_PAGE:
                    break
                page += 1
            except Exception as exc:
                self.helper.log_warning(
                    f"Could not cache WP tags page {page}: {exc}"
                )
                break
        self.helper.log_info(f"Cached {len(self._wp_tags)} WP tags.")

    def _probe_total(self):
        try:
            resp = self.session.get(
                self.api_url,
                params={"per_page": 1, "orderby": "id", "order": "asc", "_fields": "id"},
                timeout=60,
            )
            resp.raise_for_status()
            return int(resp.headers.get("X-WP-Total", "0"))
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # REST enumeration
    # ------------------------------------------------------------------ #

    def _fetch_page(self, page, window_after=None):
        params = {
            "per_page": self.per_page,
            "page": page,
            "orderby": "id",
            "order": "asc",
            "_fields": "id,date_gmt,modified_gmt,link,title,excerpt,content,author,categories,tags",
        }
        if window_after:
            params["after"] = window_after
        try:
            resp = self.session.get(self.api_url, params=params, timeout=90)
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch page {page}: {exc}")
            return None
        if resp.status_code == 400:
            return []
        if resp.status_code != 200:
            self.helper.log_error(
                f"Page {page} returned HTTP {resp.status_code}; skipping this cycle."
            )
            return None
        try:
            data = resp.json()
        except ValueError as exc:
            self.helper.log_error(f"Page {page} returned non-JSON body: {exc}")
            return None
        return data if isinstance(data, list) else None

    def _is_podcast_or_audio(self, post):
        """Return True if the post belongs to a skipped category."""
        cat_ids = post.get("categories", [])
        return bool(self._skip_category_ids.intersection(cat_ids))

    @staticmethod
    def _report_id(link):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))

    @staticmethod
    def _published_iso(post):
        for key in ("date_gmt", "modified_gmt"):
            raw = post.get(key)
            if not raw:
                continue
            try:
                dt = datetime.fromisoformat(raw)
            except (TypeError, ValueError):
                continue
            if dt.year >= 2000:
                return dt.replace(tzinfo=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
        return None

    def _author_byline(self, post):
        author_id = post.get("author")
        if author_id and author_id in self._wp_authors:
            return self._wp_authors[author_id]
        return ""

    @staticmethod
    def _post_title(post):
        return _strip_html((post.get("title") or {}).get("rendered", ""))

    def _category_names(self, post):
        cat_ids = post.get("categories", [])
        return [self._wp_categories.get(c, str(c)) for c in cat_ids if c]

    def _tag_names(self, post):
        tag_ids = post.get("tags", [])
        return [self._wp_tags.get(t, str(t)) for t in tag_ids if t]

    def _format_byline(self, post):
        byline = self._author_byline(post)
        cats = self._category_names(post)
        if cats:
            byline = f"{byline}  |  {', '.join(cats)}" if byline else ", ".join(cats)
        return byline

    def _build_description(self, post):
        """Build Report description with byline, categories, and excerpt."""
        parts = []
        byline = self._author_byline(post)
        if byline:
            parts.append(f"By {byline}.")

        cats = self._category_names(post)
        if cats:
            parts.append(f"Categories: {', '.join(cats)}.")

        tags = self._tag_names(post)
        if tags:
            parts.append(f"Tags: {', '.join(tags)}.")

        excerpt = _strip_html((post.get("excerpt") or {}).get("rendered", ""))
        if excerpt:
            parts.append(excerpt)

        return " ".join(parts)

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

    def _render_pdf(self, post):
        """Render REST API content to PDF via WeasyPrint."""
        title = self._post_title(post)
        content_html = (post.get("content") or {}).get("rendered", "")
        url = post.get("link", "")
        byline = self._format_byline(post)

        doc_html = _build_pdf_html(
            title, byline, content_html, url,
            variant=PDF_VARIANT_REST_API,
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

    def _render_with_retry(self, post):
        """Retry REST API PDF rendering with exponential backoff."""
        url = post.get("link", "")
        return self._retry(
            lambda: self._render_pdf_with_timeout(post),
            f"REST PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Live HTML PDF rendering
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_live_content(page_html):
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

    def _render_live_pdf(self, url, title, byline):
        """Fetch live article HTML and render to PDF via WeasyPrint."""
        resp = self.session.get(url, timeout=60, headers={"Accept": "text/html"})
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")

        content = self._extract_live_content(resp.text)
        if content is None:
            raise RuntimeError("No article content container found in live HTML")

        doc_html = _build_pdf_html(
            title, byline, str(content), url,
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

    def _render_live_pdf_with_timeout(self, *args, **kwargs):
        """Wrap _render_live_pdf in a daemon thread with a wall-clock timeout."""
        import threading
        result = [None]
        exc_holder = [None]
        def target():
            """Run _render_live_pdf in a separate thread."""
            try:
                result[0] = self._render_live_pdf(*args, **kwargs)
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

    def _render_live_with_retry(self, url, title, byline):
        """Retry live HTML PDF rendering with exponential backoff."""
        return self._retry(
            lambda: self._render_live_pdf_with_timeout(url, title, byline),
            f"Live PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, post, published, api_pdf, live_pdf):
        url = post.get("link")
        name = self._post_title(post) or url
        description = self._build_description(post)
        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on insightcrime.org",
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

        if len(api_pdf) > MAX_PDF_BYTES:
            self.helper.log_warning(
                f"Skipping oversized PDF for {url} ({len(api_pdf):,} bytes)."
            )
        else:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"insightcrime-{slug}.pdf",
                data=api_pdf,
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
                    file_name=f"insightcrime-{slug}-live.pdf",
                    data=live_pdf,
                    mime_type="application/pdf",
                )

        live_tag = "+live" if live_pdf else " (live failed)"
        self.helper.log_info(f"Created Report{live_tag} for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        state = self.helper.get_state() or {}

        current_sig = self._scope_sig()
        stored_sig = state.get("scope_sig")
        if stored_sig is not None and stored_sig != current_sig:
            self.helper.log_warning(
                f"Collection scope changed; resetting cursor to page 1. "
                f"old={stored_sig!r} new={current_sig!r}."
            )
            state = {}

        cursor_page = max(1, int(state.get("page", 1)))
        cursor_index = max(0, int(state.get("index", 0)))
        window_after = state.get("window_after")

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "InSight Crime enumeration run"
        )
        self.helper.log_info(
            f"Resuming at page={cursor_page}, index={cursor_index}, "
            f"window_after={window_after or 'none'} "
            f"(per_page={self.per_page})."
        )

        processed = 0
        skipped = 0
        filtered = 0
        failed = 0
        stop = False
        last_post_date = None

        page_num = cursor_page
        while not stop:
            posts = self._fetch_page(page_num, window_after)
            if posts is None:
                self.helper.log_warning(
                    f"Page {page_num} fetch failed; ending cycle, cursor preserved."
                )
                break
            if not posts:
                self._save_cursor(page_num, 0, window_after)
                self.helper.log_info(f"Caught up at page {page_num}; nothing new.")
                break

            start = cursor_index if page_num == cursor_page else 0
            self.helper.log_info(
                f"Page {page_num}: {len(posts)} posts; starting at index {start}."
            )

            for idx in range(start, len(posts)):
                post = posts[idx]
                url = post.get("link")
                if not url:
                    self._save_cursor(page_num, idx + 1, window_after)
                    continue

                last_post_date = post.get("date_gmt") or post.get("modified_gmt")

                if self.max_reports and processed >= self.max_reports:
                    self.helper.log_info(
                        f"Reached max_reports={self.max_reports}; stopping run."
                    )
                    stop = True
                    break

                # Skip podcast/audio posts.
                if self._is_podcast_or_audio(post):
                    filtered += 1
                    self._save_cursor(page_num, idx + 1, window_after)
                    continue

                if self.helper.api.report.read(id=self._report_id(url)) is not None:
                    skipped += 1
                    self._save_cursor(page_num, idx + 1, window_after)
                    continue

                api_pdf = self._render_with_retry(post)
                if api_pdf is None:
                    failed += 1
                    self.helper.log_warning(
                        f"Skipping {url}: REST API PDF render failed after retries."
                    )
                    self._save_cursor(page_num, idx + 1, window_after)
                    continue

                title = self._post_title(post)
                byline = self._format_byline(post)
                live_pdf = self._render_live_with_retry(url, title, byline)
                if live_pdf is None:
                    self.helper.log_warning(
                        f"Live HTML PDF failed for {url}; attaching REST API PDF only."
                    )

                published = self._published_iso(post)
                if not published:
                    published = datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S+00:00"
                    )
                    self.helper.log_warning(
                        f"No usable date for {url}; using ingestion time."
                    )

                self._create_report(post, published, api_pdf, live_pdf)
                processed += 1
                self._save_cursor(page_num, idx + 1, window_after)
                time.sleep(self.request_delay)

            if stop:
                break

            if len(posts) < self.per_page:
                self._save_cursor(page_num, len(posts), window_after)
                break

            if page_num >= MAX_WP_PAGES and last_post_date:
                self.helper.log_info(
                    f"Reached WP page limit ({MAX_WP_PAGES}); shifting window "
                    f"forward past {last_post_date}."
                )
                window_after = last_post_date
                page_num = 1
                cursor_index = 0
                self._save_cursor(page_num, 0, window_after)
                time.sleep(self.request_delay)
                continue

            if page_num >= MAX_WP_PAGES and last_post_date is None:
                self.helper.log_warning(
                    f"Reached WP page limit ({MAX_WP_PAGES}) but no post date "
                    f"available for sliding-window shift; stopping to avoid "
                    f"stuck cursor."
                )
                break

            page_num += 1
            cursor_index = 0
            self._save_cursor(page_num, 0, window_after)
            time.sleep(self.request_delay)

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{filtered} filtered (podcast/audio), {failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("InSight Crime connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        InsightCrimeConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
