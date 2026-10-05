"""
QNS OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from https://qns.com (Queens
News) and creates one OpenCTI Report container per article, with the source
page attached as a full-fidelity PDF plus a raw HTML snapshot.

Collection model (WordPress REST API + ascending-id cursor)
-----------------------------------------------------------
QNS is a WordPress site (~163,000 posts since July 2015) covering news, crime,
politics, arts, and neighbourhood life across Queens, New York. The WordPress
REST API (/wp-json/wp/v2/posts) is fully open: no WAF gating, no API key,
standard pagination. The REST API is the sole enumeration surface.

Enumeration walks all posts in ascending post-id order (orderby=id&order=asc)
behind a persisted positional {page, index, window_after} cursor held in
OpenCTI connector state. Ascending id is used, not date: post ids are monotonic
and stable. New posts always receive the highest ids and land on the last page,
so a positional cursor walked from page 1 is stable for the historical backfill
and, once it reaches the tail, naturally picks up freshly-appended posts on each
subsequent poll.

The WordPress REST API caps pagination at 100 pages (10,000 posts with
per_page=100). When the cursor reaches page 100 on a full page, it shifts the
query window forward by adding ``after=<date of last processed post>`` and
resetting to page 1. This sliding-window approach handles any corpus size.

Some QNS articles redirect to the parent amNewYork (amny.com) domain. Both
sites share the same ``article`` container structure, so the render service
handles either transparently. External Reference URLs use the canonical qns.com
link from the REST API.

PDF rendering is delegated to the centralised pdf-renderer microservice via
HTTP POST. The service renders the live page with Playwright and returns both
a PDF and a raw HTML snapshot. The connector uses the ``article`` CSS selector
to isolate article content and strips site chrome (headers, footers, social
sharing, comments).

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id)
and skips if the Report already exists. The graph lookup is the correctness
backstop (idempotent even if the cursor state is lost); the {page, index}
cursor is the efficiency layer that avoids re-reading the whole corpus every
poll.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (free, publicly published source).
- Author: "QNS" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band).
- PDF renderer: centralised pdf-renderer service (Playwright via HTTP).
- No WAF gating on API: plain HTTP requests work for enumeration; the render
  service handles page rendering and any redirects.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import base64
import html as html_mod
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from microservices.classify_report import classify_report


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

MAX_PER_PAGE = 100
MAX_WP_PAGES = 100

STRIP_SELECTORS = [
    ".addthis_inline_share_toolbox",
    ".article-footer",
    "#comments-section",
    ".related-posts",
    ".viafoura-conversation-wrapper",
]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _strip_html(value):
    if not value:
        return ""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", value)).strip()


def _report_id(link):
    return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))


def _slug_from_url(url):
    path = urlparse(url).path.strip("/")
    return path.rsplit("/", 1)[-1] if path else "article"


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

class QnsConnector:
    """External-import connector that mirrors QNS posts into Reports."""

    def __init__(self):
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = {}
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}

        self.helper = OpenCTIConnectorHelper(config)

        self.base_url = get_config_variable(
            "QNS_BASE_URL",
            ["qns", "base_url"], config,
            default="https://qns.com",
        ).rstrip("/")
        self.api_url = f"{self.base_url}/wp-json/wp/v2/posts"

        self.per_page = int(get_config_variable(
            "QNS_PER_PAGE",
            ["qns", "per_page"], config,
            isNumber=True, default=MAX_PER_PAGE,
        ))
        if self.per_page > MAX_PER_PAGE or self.per_page < 1:
            self.per_page = MAX_PER_PAGE

        self.poll_interval = int(get_config_variable(
            "QNS_POLL_INTERVAL",
            ["qns", "poll_interval"], config,
            isNumber=True, default=86400,
        ))

        self.request_delay = int(get_config_variable(
            "QNS_REQUEST_DELAY",
            ["qns", "request_delay"], config,
            isNumber=True, default=2,
        ))

        self.max_reports = int(get_config_variable(
            "QNS_MAX_REPORTS",
            ["qns", "max_reports"], config,
            isNumber=True, default=0,
        ))

        self.render_retries = int(get_config_variable(
            "QNS_RENDER_RETRIES",
            ["qns", "render_retries"], config,
            isNumber=True, default=3,
        ))

        self.render_url = get_config_variable(
            "RENDER_SERVICE_URL",
            ["connector", "render_service_url"], config,
            default="http://pdf-renderer:8080/render",
        )
        self.render_timeout = int(get_config_variable(
            "RENDER_TIMEOUT",
            ["connector", "render_timeout"], config,
            isNumber=True, default=120,
        ))

        self.confidence = int(get_config_variable(
            "QNS_CONFIDENCE",
            ["qns", "confidence"], config,
            isNumber=True, default=50,
        ))
        self.report_type = get_config_variable(
            "QNS_REPORT_TYPE",
            ["qns", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "QNS_TLP",
            ["qns", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "QNS_AUTHOR_NAME",
            ["qns", "author_name"], config,
            default="QNS",
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
            description="QNS — Queens News: local news, crime, politics, arts, and "
                        "community coverage for Queens, New York.",
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

        total = self._probe_total()
        if total is None:
            self.helper.log_error(
                f"REST endpoint {self.api_url} unreachable at startup; entering poll "
                f"loop anyway and retrying next cycle."
            )
        else:
            self.helper.log_info(
                f"REST endpoint reachable: {total} posts reported by API."
            )

    def _paginate_wp_endpoint(self, endpoint):
        """Fetch all items from a paginated WP REST API endpoint."""
        items = {}
        page = 1
        while True:
            try:
                resp = self.session.get(
                    f"{self.base_url}/wp-json/wp/v2/{endpoint}",
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
                rows = resp.json()
                if not rows:
                    break
                for row in rows:
                    items[row["id"]] = html_mod.unescape(row.get("name", ""))
                if len(rows) < MAX_PER_PAGE:
                    break
                page += 1
            except Exception as exc:
                self.helper.log_warning(
                    f"Could not cache WP {endpoint} page {page}: {exc}"
                )
                break
        self.helper.log_info(f"Cached {len(items)} WP {endpoint}.")
        return items

    def _cache_wp_authors(self):
        self._wp_authors = self._paginate_wp_endpoint("users")

    def _cache_wp_categories(self):
        self._wp_categories = self._paginate_wp_endpoint("categories")

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
            "_fields": "id,date_gmt,modified_gmt,link,title,excerpt,author,categories",
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

    # ------------------------------------------------------------------ #
    # PDF rendering (via centralised render service)
    # ------------------------------------------------------------------ #

    def _render_config(self, url):
        return {
            "url": url,
            "content_selector": "article",
            "hide_selectors": STRIP_SELECTORS,
            "timeout_sec": self.render_timeout,
        }

    def _render_via_service(self, url):
        resp = self.session.post(
            self.render_url,
            json=self._render_config(url),
            timeout=self.render_timeout + 30,
        )
        resp.raise_for_status()
        data = resp.json()
        return (
            base64.b64decode(data["pdf"]),
            base64.b64decode(data["html"]),
            data.get("title"),
        )

    def _render_with_retry(self, url):
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._render_via_service(url)
            except Exception as exc:
                self.helper.log_warning(
                    f"Render attempt {attempt}/{self.render_retries} failed for "
                    f"{url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay *= 2
        return None, None, None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, post, published, pdf_bytes, html_bytes):
        url = post.get("link")
        name = self._post_title(post) or url
        description = _strip_html((post.get("excerpt") or {}).get("rendered", ""))

        byline = self._author_byline(post)
        if byline:
            description = f"By {byline}. {description}" if description else f"By {byline}."

        cats = self._category_names(post)
        if cats:
            cat_tag = f"[{', '.join(cats)}]"
            description = f"{description} {cat_tag}" if description else cat_tag

        report_stix_id = _report_id(url)
        slug = _slug_from_url(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on qns.com",
        )

        _report_types = classify_report(
            title=name, description=description, content=description or "",
            source="QNS", source_url=url,
            default_types=[self.report_type],
        )

        report = self.helper.api.report.create(
            stix_id=report_stix_id,
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

        self.helper.api.stix_domain_object.add_file(
            id=report["id"],
            file_name=f"qns-{slug}.pdf",
            data=pdf_bytes,
            mime_type="application/pdf",
        )

        if html_bytes:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"qns-raw-{slug}.html",
                data=html_bytes,
                mime_type="text/html",
            )

        self.helper.log_info(f"Created Report for {url} ({name[:80]})")

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
            self.helper.connect_id, "QNS enumeration run"
        )
        self.helper.log_info(
            f"Resuming at page={cursor_page}, index={cursor_index}, "
            f"window_after={window_after or 'none'} "
            f"(per_page={self.per_page})."
        )

        processed = 0
        skipped = 0
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

                if self.helper.api.report.read(id=_report_id(url)) is not None:
                    skipped += 1
                    self._save_cursor(page_num, idx + 1, window_after)
                    continue

                pdf_bytes, html_bytes, _ = self._render_with_retry(url)
                if pdf_bytes is None:
                    failed += 1
                    self.helper.log_warning(
                        f"Skipping {url}: render failed after retries."
                    )
                    self._save_cursor(page_num, idx + 1, window_after)
                    continue

                published = self._published_iso(post)
                if not published:
                    published = datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S+00:00"
                    )
                    self.helper.log_warning(
                        f"No usable date for {url}; using ingestion time."
                    )

                self._create_report(post, published, pdf_bytes, html_bytes)
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

            page_num += 1
            cursor_index = 0
            self._save_cursor(page_num, 0, window_after)
            time.sleep(self.request_delay)

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("QNS connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        QnsConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
