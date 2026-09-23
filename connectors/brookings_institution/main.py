"""
Brookings Institution Foreign Policy OpenCTI connector.

Purpose
-------
External-import connector that ingests foreign-policy articles from
https://www.brookings.edu as container-only OpenCTI Reports, one per
article, with a WeasyPrint PDF attached per Report.

Collection model (WordPress VIP REST API + ascending-id cursor)
---------------------------------------------------------------
Brookings runs on WordPress VIP with Yoast SEO. The WordPress REST API
exposes a custom post type ``article`` at /wp-json/wp/v2/article. The
site carries ~54,488 articles total, but only ~6,636 belong to the
foreign-policy topic (topic ID 69).

Server-side topic filtering is broken (``?topics=69`` is silently
ignored), so enumeration walks ALL articles in ascending post-id order
and filters client-side: an article is kept only when ``69`` is present
in its ``topics`` array.

Enumeration uses a lightweight listing pass with ``_fields`` to minimise
bandwidth for the ~88% of articles that will be discarded. Matched
articles are re-fetched individually for full ACF content.

Article content is NOT in ``content.rendered`` (which is empty). The body
lives in ``acf.page_layout``: an array of layout blocks where blocks of
type ``layout_wysiwyg`` carry the HTML in
``component_wysiwyg.content``.

The cursor is a persisted positional {page, index} held in OpenCTI
connector state. Ascending id order means the cursor walks from page 1
and naturally picks up freshly-appended posts on each subsequent poll.
A sliding-window shift (via WP ``after`` parameter) handles the 100-page
cap.

Content filtering
-----------------
- Only articles with topic ID 69 (foreign policy) are processed.
- Articles where ``acf.details.article_parent_type`` is ``podcast`` are
  skipped.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article
URL (uuid5 over the URL). Before rendering, the connector checks
report.read(id) and skips if the Report already exists. Sub-writes are
idempotent; a crash anywhere leaves the article "not done" and the next
poll re-enters and completes it.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain
Objects, no Observables, no Relationships, no Labels. Named-entity / IOC
extraction is a separate, out-of-scope downstream phase.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (free, publicly published source).
- Author: the single "Brookings Institution" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band: editorial secondary analysis).

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

FOREIGN_POLICY_TOPIC_ID = 69

# Fields for the lightweight listing pass (no ACF content).
LISTING_FIELDS = "id,title,link,date_gmt,modified_gmt,topics,excerpt"

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
    "blockquote { border-left: 3px solid #003A70; margin: 1em 0; "
    "padding: 0.5em 1em; color: #555; } "
    "a { color: #003A70; } "
)


def _strip_html(value):
    if not value:
        return ""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", value)).strip()


def _escape_html(text):
    return html_mod.escape(text, quote=True) if text else ""


def _css_string_escape(s):
    return (
        s.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\a ")
        .replace("\r", "")
    )


def _build_pdf_html(title, content_html, source_url, ingested_at):
    css_url = _css_string_escape(source_url)
    safe_title = _escape_html(title)
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        + f"<meta name='source-url' content='{_escape_html(source_url)}'>"
        + "<style>"
        + _PDF_STYLE
        + "@page { margin: 15mm 12mm 20mm 12mm; "
        + "@bottom-center { content: '"
        + css_url
        + "  |  OpenCTI Brookings Institution connector  |  "
        + ingested_at
        + "'; font-size: 7px; color: #888; } } "
        + "</style></head><body>"
        + "<h1>"
        + safe_title
        + "</h1>"
        + content_html
        + "</body></html>"
    )


class BrookingsInstitutionConnector:
    """External-import connector that mirrors Brookings foreign-policy articles into Reports."""

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
            "BROOKINGS_INSTITUTION_BASE_URL",
            ["brookings_institution", "base_url"],
            config,
            default="https://www.brookings.edu",
        ).rstrip("/")
        self.api_url = f"{self.base_url}/wp-json/wp/v2/article"

        self.per_page = get_config_variable(
            "BROOKINGS_INSTITUTION_PER_PAGE",
            ["brookings_institution", "per_page"],
            config,
            isNumber=True,
            default=MAX_PER_PAGE,
        )
        if self.per_page > MAX_PER_PAGE or self.per_page < 1:
            self.per_page = MAX_PER_PAGE

        self.poll_interval = get_config_variable(
            "BROOKINGS_INSTITUTION_POLL_INTERVAL",
            ["brookings_institution", "poll_interval"],
            config,
            isNumber=True,
            default=86400,
        )

        self.request_delay = get_config_variable(
            "BROOKINGS_INSTITUTION_REQUEST_DELAY",
            ["brookings_institution", "request_delay"],
            config,
            isNumber=True,
            default=2,
        )

        self.max_reports = get_config_variable(
            "BROOKINGS_INSTITUTION_MAX_REPORTS",
            ["brookings_institution", "max_reports"],
            config,
            isNumber=True,
            default=0,
        )

        self.render_retries = get_config_variable(
            "BROOKINGS_INSTITUTION_RENDER_RETRIES",
            ["brookings_institution", "render_retries"],
            config,
            isNumber=True,
            default=3,
        )

        self.confidence = get_config_variable(
            "BROOKINGS_INSTITUTION_CONFIDENCE",
            ["brookings_institution", "confidence"],
            config,
            isNumber=True,
            default=50,
        )
        self.report_type = get_config_variable(
            "BROOKINGS_INSTITUTION_REPORT_TYPE",
            ["brookings_institution", "report_type"],
            config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "BROOKINGS_INSTITUTION_TLP",
            ["brookings_institution", "tlp"],
            config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "BROOKINGS_INSTITUTION_AUTHOR_NAME",
            ["brookings_institution", "author_name"],
            config,
            default="Brookings Institution",
        )

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": BROWSER_UA,
                "Accept": "application/json, */*",
            }
        )

        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Cursor helpers
    # ------------------------------------------------------------------ #

    def _scope_sig(self):
        return "foreign_policy"

    def _save_cursor(self, page, index, window_after=None):
        self.helper.set_state(
            {
                "page": page,
                "index": index,
                "window_after": window_after,
                "scope_sig": self._scope_sig(),
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
                "American research group and think tank founded in 1916. "
                "Source organization for ingested foreign-policy reports."
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

        total = self._probe_total()
        if total is None:
            self.helper.log_error(
                f"REST endpoint {self.api_url} unreachable at startup; entering poll "
                f"loop anyway and retrying next cycle."
            )
        else:
            self.helper.log_info(
                f"REST endpoint reachable: {total} articles reported by API "
                f"(topic filtering is client-side; ~12% are foreign policy)."
            )

    def _probe_total(self):
        try:
            resp = self.session.get(
                self.api_url,
                params={
                    "per_page": 1,
                    "orderby": "id",
                    "order": "asc",
                    "_fields": "id",
                },
                timeout=60,
            )
            resp.raise_for_status()
            return int(resp.headers.get("X-WP-Total", "0"))
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # REST enumeration
    # ------------------------------------------------------------------ #

    def _fetch_listing_page(self, page, window_after=None):
        """Fetch a lightweight listing page for enumeration and topic filtering."""
        params = {
            "per_page": self.per_page,
            "page": page,
            "orderby": "id",
            "order": "asc",
            "_fields": LISTING_FIELDS,
        }
        if window_after:
            params["after"] = window_after
        try:
            resp = self.session.get(self.api_url, params=params, timeout=90)
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch listing page {page}: {exc}")
            return None
        if resp.status_code == 400:
            return []
        if resp.status_code != 200:
            self.helper.log_error(
                f"Listing page {page} returned HTTP {resp.status_code}; "
                f"skipping this cycle."
            )
            return None
        try:
            data = resp.json()
        except ValueError as exc:
            self.helper.log_error(
                f"Listing page {page} returned non-JSON body: {exc}"
            )
            return None
        return data if isinstance(data, list) else None

    def _fetch_full_article(self, article_id):
        """Re-fetch a single article with full ACF content."""
        try:
            resp = self.session.get(
                f"{self.api_url}/{article_id}", timeout=90
            )
        except Exception as exc:
            self.helper.log_error(
                f"Failed to fetch full article {article_id}: {exc}"
            )
            return None
        if resp.status_code != 200:
            self.helper.log_error(
                f"Full article {article_id} returned HTTP {resp.status_code}."
            )
            return None
        try:
            data = resp.json()
        except ValueError as exc:
            self.helper.log_error(
                f"Full article {article_id} returned non-JSON body: {exc}"
            )
            return None
        return data if isinstance(data, dict) else None

    # ------------------------------------------------------------------ #
    # Filtering helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_foreign_policy(article):
        """Return True if the article belongs to the foreign-policy topic."""
        topics = article.get("topics")
        if not topics or not isinstance(topics, list):
            return False
        return FOREIGN_POLICY_TOPIC_ID in topics

    @staticmethod
    def _is_podcast(article):
        """Return True if the article is a podcast (skip these)."""
        details = (article.get("acf") or {}).get("details") or {}
        parent_type = details.get("article_parent_type", "")
        if isinstance(parent_type, str) and parent_type.lower() == "podcast":
            return True
        return False

    # ------------------------------------------------------------------ #
    # Content extraction
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_content(article):
        """Extract HTML body from ACF page_layout wysiwyg blocks."""
        page_layout = (article.get("acf") or {}).get("page_layout") or []
        if not isinstance(page_layout, list):
            return ""
        body_parts = []
        for block in page_layout:
            if not isinstance(block, dict):
                continue
            if block.get("acf_fc_layout") == "layout_wysiwyg":
                html = (block.get("component_wysiwyg") or {}).get("content", "")
                if html:
                    body_parts.append(html)
        return "\n".join(body_parts)

    @staticmethod
    def _report_id(link):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))

    @staticmethod
    def _published_iso(article):
        for key in ("date_gmt", "modified_gmt"):
            raw = article.get(key)
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

    @staticmethod
    def _post_title(article):
        return _strip_html((article.get("title") or {}).get("rendered", ""))

    @staticmethod
    def _build_description(article):
        """Build Report description from excerpt."""
        excerpt = _strip_html((article.get("excerpt") or {}).get("rendered", ""))
        return excerpt or ""

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
                return {"string": b"", "mime_type": "text/plain"}
            return {
                "string": resp.content,
                "mime_type": resp.headers.get(
                    "content-type", "application/octet-stream"
                ).split(";")[0],
            }
        except Exception:
            return {"string": b"", "mime_type": "text/plain"}

    def _render_pdf(self, title, content_html, url):
        ingested = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        doc_html = _build_pdf_html(title, content_html, url, ingested)

        content_bytes = len(doc_html.encode("utf-8", errors="replace"))
        if content_bytes > MAX_CONTENT_BYTES:
            self.helper.log_warning(
                f"Content too large for PDF render ({content_bytes:,} bytes)."
            )
            return None

        return weasyprint.HTML(
            string=doc_html, base_url=url, url_fetcher=self._wp_url_fetcher
        ).write_pdf()

    def _render_with_retry(self, title, content_html, url):
        return self._retry(
            lambda: self._render_pdf(title, content_html, url),
            f"PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, article, published, pdf):
        url = article.get("link")
        name = self._post_title(article) or url
        description = self._build_description(article)
        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on brookings.edu",
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

        if len(pdf) > MAX_PDF_BYTES:
            self.helper.log_warning(
                f"Skipping oversized PDF for {url} ({len(pdf):,} bytes)."
            )
        else:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"brookings-{slug}.pdf",
                data=pdf,
                mime_type="application/pdf",
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
            self.helper.connect_id, "Brookings Institution enumeration run"
        )
        self.helper.log_info(
            f"Resuming at page={cursor_page}, index={cursor_index}, "
            f"window_after={window_after or 'none'} "
            f"(per_page={self.per_page})."
        )

        processed = 0
        skipped = 0
        non_fp = 0
        filtered_podcast = 0
        no_content = 0
        failed = 0
        stop = False
        last_post_date = None
        try:

            page_num = cursor_page
            while not stop:
                articles = self._fetch_listing_page(page_num, window_after)
                if articles is None:
                    self.helper.log_warning(
                        f"Page {page_num} fetch failed; ending cycle, cursor preserved."
                    )
                    break
                if not articles:
                    self._save_cursor(page_num, 0, window_after)
                    self.helper.log_info(
                        f"Caught up at page {page_num}; nothing new."
                    )
                    break

                start = cursor_index if page_num == cursor_page else 0
                self.helper.log_info(
                    f"Page {page_num}: {len(articles)} articles; "
                    f"starting at index {start}."
                )

                for idx in range(start, len(articles)):
                    listing = articles[idx]
                    last_post_date = (
                        listing.get("date_gmt") or listing.get("modified_gmt")
                    )

                    if self.max_reports and processed >= self.max_reports:
                        self.helper.log_info(
                            f"Reached max_reports={self.max_reports}; stopping run."
                        )
                        stop = True
                        break

                    # Client-side topic filter: keep only foreign-policy articles.
                    if not self._is_foreign_policy(listing):
                        non_fp += 1
                        self._save_cursor(page_num, idx + 1, window_after)
                        continue

                    url = listing.get("link", "")
                    if not url:
                        self._save_cursor(page_num, idx + 1, window_after)
                        continue

                    # Graph dedup: skip if Report already exists.
                    if (
                        self.helper.api.report.read(id=self._report_id(url))
                        is not None
                    ):
                        skipped += 1
                        self._save_cursor(page_num, idx + 1, window_after)
                        continue

                    # Fetch full article for ACF content.
                    full = self._fetch_full_article(listing["id"])
                    if full is None:
                        failed += 1
                        self.helper.log_warning(
                            f"Skipping article {listing['id']}: full fetch failed."
                        )
                        self._save_cursor(page_num, idx + 1, window_after)
                        continue

                    # Skip podcasts.
                    if self._is_podcast(full):
                        filtered_podcast += 1
                        self._save_cursor(page_num, idx + 1, window_after)
                        continue

                    # Extract HTML body from ACF layout blocks.
                    content_html = self._extract_content(full)
                    if not content_html:
                        no_content += 1
                        self.helper.log_warning(
                            f"No ACF content for {url}; skipping."
                        )
                        self._save_cursor(page_num, idx + 1, window_after)
                        continue

                    title = self._post_title(full)

                    # Render PDF via WeasyPrint.
                    pdf = self._render_with_retry(title, content_html, url)
                    if pdf is None:
                        failed += 1
                        self.helper.log_warning(
                            f"Skipping {url}: PDF render failed after retries."
                        )
                        self._save_cursor(page_num, idx + 1, window_after)
                        continue

                    published = self._published_iso(full)
                    if not published:
                        published = datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S+00:00"
                        )
                        self.helper.log_warning(
                            f"No usable date for {url}; using ingestion time."
                        )

                    try:
                        self._create_report(full, published, pdf)
                        processed += 1
                    except Exception as exc:
                        failed += 1
                        self.helper.log_warning(
                            f"Report creation failed for {url}: {exc}"
                        )
                    self._save_cursor(page_num, idx + 1, window_after)
                    time.sleep(self.request_delay)

                if stop:
                    break

                if len(articles) < self.per_page:
                    self._save_cursor(page_num, len(articles), window_after)
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

        finally:
            message = (
                f"Run complete: {processed} created, {skipped} already present, "
                f"{non_fp} filtered (non-foreign-policy), "
                f"{filtered_podcast} filtered (podcast), "
                f"{no_content} skipped (no ACF content), {failed} failed."
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("Brookings Institution connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        BrookingsInstitutionConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
