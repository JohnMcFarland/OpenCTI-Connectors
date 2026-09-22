"""
World Health Organization OpenCTI connector.

Purpose
-------
External-import connector that ingests news articles from
https://www.who.int/news as container-only OpenCTI Reports, one per
article, with a PDF attachment rendered from the fetched article HTML
via WeasyPrint.

Collection model (Sitefinity OData API + ascending datetime cursor)
-------------------------------------------------------------------
The WHO website is built on Sitefinity CMS and exposes an OData REST API
at /api/news/newsitems. The API returns metadata only (title, slug,
publication date) -- not article body content. Full article HTML must be
fetched from the article page URL.

Enumeration walks all items in ascending PublicationDateAndTime order
behind a persisted datetime cursor held in OpenCTI connector state.
The cursor stores the last processed item's PublicationDateAndTime;
on the next run, the query adds $filter=PublicationDateAndTime gt {cursor}
to resume where it left off. Within a single run, $skip pagination
advances through the filtered result set.

The OData API supports $count, $top, $skip, $select, $orderby, and $filter.
Default page size is 50 items. Total corpus: ~6,493 items (1996-present).

Article URL pattern: /news/item/{slug} where the API returns
ItemDefaultUrl as /{slug} and the connector prepends /news/item.

Content fetch and PDF render
-----------------------------
Each article page is server-side rendered and responds to plain HTTP GET
requests (no Playwright needed). BeautifulSoup extracts the article body
from the page, and WeasyPrint renders it to PDF.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id)
and skips if the Report already exists. For a new article it creates the
External Reference (upsert-safe), then the Report (with the deterministic
stix_id), then attaches the PDF. Because the existence check keys on the
Report id (not on the External Reference), every sub-write is idempotent
and a crash anywhere leaves the article still "not done"; the next poll
re-enters and completes it.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels. Named-entity / IOC extraction is
a separate, out-of-scope downstream phase. Keeping this connector container-only
makes it purely additive and prevents it from acting as a graph-contamination
vector.

Key decisions
-------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published source).
- Author: the single "World Health Organization" Organization identity.
  Never the connector account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (Medium band).

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

ODATA_PAGE_SIZE = 50

MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB

# Article content selectors (tried in order).
ARTICLE_CONTENT_SELECTORS = [
    ".sf-detail-body-wrapper",
    ".article-body",
    ".content-area",
    "[itemprop='articleBody']",
    "article",
    "main",
]

STRIP_SELECTORS = [
    ".sf-share-block",
    ".social-share",
    ".related-posts",
    ".sidebar",
    "nav",
    "footer",
    ".comments",
    "script",
    "style",
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
    "blockquote { border-left: 3px solid #009ADE; margin: 1em 0; "
    "padding: 0.5em 1em; color: #555; } "
    "a { color: #009ADE; } "
)


def _strip_html(value):
    if not value:
        return ""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", value)).strip()


def _escape_html(text):
    return html_mod.escape(text, quote=True) if text else ""


def _css_string_escape(s):
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\a ").replace("\r", "")


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
        + "  |  OpenCTI WHO connector  |  "
        + ingested_at
        + "'; font-size: 7px; color: #888; } } "
        + "</style></head><body>"
        + "<h1>" + safe_title + "</h1>"
        + byline_block
        + content_html
        + "</body></html>"
    )


class WorldHealthOrganizationConnector:
    """External-import connector that mirrors WHO news articles into Reports."""

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
            "WORLD_HEALTH_ORGANIZATION_BASE_URL",
            ["world_health_organization", "base_url"], config,
            default="https://www.who.int",
        ).rstrip("/")
        self.api_url = f"{self.base_url}/api/news/newsitems"

        self.poll_interval = get_config_variable(
            "WORLD_HEALTH_ORGANIZATION_POLL_INTERVAL",
            ["world_health_organization", "poll_interval"], config,
            isNumber=True, default=86400,
        )

        self.request_delay = get_config_variable(
            "WORLD_HEALTH_ORGANIZATION_REQUEST_DELAY",
            ["world_health_organization", "request_delay"], config,
            isNumber=True, default=2,
        )

        self.max_reports = get_config_variable(
            "WORLD_HEALTH_ORGANIZATION_MAX_REPORTS",
            ["world_health_organization", "max_reports"], config,
            isNumber=True, default=0,
        )

        self.render_retries = get_config_variable(
            "WORLD_HEALTH_ORGANIZATION_RENDER_RETRIES",
            ["world_health_organization", "render_retries"], config,
            isNumber=True, default=3,
        )

        self.confidence = get_config_variable(
            "WORLD_HEALTH_ORGANIZATION_CONFIDENCE",
            ["world_health_organization", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "WORLD_HEALTH_ORGANIZATION_REPORT_TYPE",
            ["world_health_organization", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "WORLD_HEALTH_ORGANIZATION_TLP",
            ["world_health_organization", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "WORLD_HEALTH_ORGANIZATION_AUTHOR_NAME",
            ["world_health_organization", "author_name"], config,
            default="World Health Organization",
        )

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "application/json, */*",
        })

        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Cursor helpers
    # ------------------------------------------------------------------ #

    def _save_cursor(self, last_date, skip):
        self.helper.set_state({
            "last_publication_date": last_date,
            "skip": skip,
        })

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="The World Health Organization (WHO) is a specialized agency "
                        "of the United Nations responsible for international public "
                        "health. Source organization for ingested reports.",
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
                f"OData endpoint {self.api_url} unreachable at startup; entering poll "
                f"loop anyway and retrying next cycle."
            )
        else:
            self.helper.log_info(
                f"OData endpoint reachable: {total} news items reported by API."
            )

    def _probe_total(self):
        try:
            resp = self.session.get(
                self.api_url,
                params={"$count": "true", "$top": "1"},
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("@odata.count", data.get("totalCount"))
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # OData enumeration
    # ------------------------------------------------------------------ #

    def _fetch_page(self, skip, cursor_date=None):
        params = {
            "$orderby": "PublicationDateAndTime asc",
            "$top": str(ODATA_PAGE_SIZE),
            "$skip": str(skip),
            "$select": "Title,ItemDefaultUrl,PublicationDateAndTime,Summary",
        }
        if cursor_date:
            params["$filter"] = f"PublicationDateAndTime ge {cursor_date}"
        try:
            resp = self.session.get(self.api_url, params=params, timeout=90)
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch skip={skip}: {exc}")
            return None
        if resp.status_code != 200:
            self.helper.log_error(
                f"Skip={skip} returned HTTP {resp.status_code}; skipping this cycle."
            )
            return None
        try:
            data = resp.json()
        except ValueError as exc:
            self.helper.log_error(f"Skip={skip} returned non-JSON body: {exc}")
            return None
        return data.get("value", []) if isinstance(data, dict) else None

    @staticmethod
    def _item_url(base_url, item):
        slug = item.get("ItemDefaultUrl", "")
        if not slug:
            return None
        if not slug.startswith("/"):
            slug = "/" + slug
        return f"{base_url}/news/item{slug}"

    @staticmethod
    def _report_id(article_url):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, article_url))

    @staticmethod
    def _published_iso(item):
        raw = item.get("PublicationDateAndTime")
        if not raw:
            return None
        try:
            # OData dates may include timezone or be naive UTC
            raw_clean = raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(raw_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _item_title(item):
        return _strip_html(item.get("Title", ""))

    @staticmethod
    def _item_summary(item):
        return _strip_html(item.get("Summary", ""))

    # ------------------------------------------------------------------ #
    # Article HTML fetch + content extraction
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_article_content(page_html):
        soup = BeautifulSoup(page_html, "lxml")
        content = None
        for selector in ARTICLE_CONTENT_SELECTORS:
            content = soup.select_one(selector)
            if content:
                break
        if not content:
            return None
        for sel in STRIP_SELECTORS:
            for el in content.select(sel):
                el.decompose()
        return content

    def _fetch_article_html(self, article_url):
        resp = self.session.get(
            article_url, timeout=60,
            headers={"Accept": "text/html"},
        )
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {article_url}")
        return resp.text

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

    def _url_fetcher(self, url):
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

    def _render_pdf(self, article_url, title, summary):
        page_html = self._fetch_article_html(article_url)
        content = self._extract_article_content(page_html)
        if content is None:
            raise RuntimeError("No article content container found in HTML")

        ingested = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        byline = f"World Health Organization  |  {summary[:200]}" if summary else "World Health Organization"
        doc_html = _build_pdf_html(
            title, byline, str(content), article_url, ingested,
        )

        if len(doc_html.encode("utf-8", errors="replace")) > MAX_CONTENT_BYTES:
            self.helper.log_warning(
                f"Skipping PDF render for {article_url}: content too large "
                f"({len(doc_html.encode('utf-8', errors='replace')):,} bytes)."
            )
            return None

        return weasyprint.HTML(
            string=doc_html, base_url=article_url,
            url_fetcher=self._url_fetcher,
        ).write_pdf()

    def _render_with_retry(self, article_url, title, summary):
        return self._retry(
            lambda: self._render_pdf(article_url, title, summary),
            f"PDF render for {article_url}",
        )

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, article_url, title, summary, published, pdf_bytes):
        name = title or article_url
        description = summary or ""
        report_id = self._report_id(article_url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=article_url,
            description="Source article on who.int",
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

        slug = urlparse(article_url).path.strip("/").rsplit("/", 1)[-1] or "article"

        if len(pdf_bytes) > MAX_PDF_BYTES:
            self.helper.log_warning(
                f"Skipping oversized PDF for {article_url} ({len(pdf_bytes):,} bytes)."
            )
        else:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"who-{slug}.pdf",
                data=pdf_bytes,
                mime_type="application/pdf",
            )

        self.helper.log_info(f"Created Report for {article_url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        state = self.helper.get_state() or {}

        cursor_date = state.get("last_publication_date")
        cursor_skip = max(0, int(state.get("skip", 0)))

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "WHO news enumeration run"
        )
        self.helper.log_info(
            f"Resuming with cursor_date={cursor_date or 'none'}, "
            f"skip={cursor_skip}."
        )

        processed = 0
        skipped = 0
        failed = 0
        stop = False
        last_date = cursor_date

        skip = cursor_skip
        while not stop:
            items = self._fetch_page(skip, cursor_date)
            if items is None:
                self.helper.log_warning(
                    f"Fetch at skip={skip} failed; ending cycle, cursor preserved."
                )
                break
            if not items:
                self._save_cursor(last_date, 0)
                self.helper.log_info(f"Caught up at skip={skip}; nothing new.")
                break

            self.helper.log_info(
                f"Skip={skip}: {len(items)} items."
            )

            for item in items:
                article_url = self._item_url(self.base_url, item)
                if not article_url:
                    skip += 1
                    self._save_cursor(last_date, skip)
                    continue

                item_date = item.get("PublicationDateAndTime")

                if self.max_reports and processed >= self.max_reports:
                    self.helper.log_info(
                        f"Reached max_reports={self.max_reports}; stopping run."
                    )
                    stop = True
                    break

                if self.helper.api.report.read(id=self._report_id(article_url)) is not None:
                    skipped += 1
                    if item_date:
                        if last_date != item_date:
                            last_date = item_date
                            skip = 0
                        else:
                            skip += 1
                    else:
                        skip += 1
                    self._save_cursor(last_date, skip)
                    continue

                title = self._item_title(item)
                summary = self._item_summary(item)

                pdf_bytes = self._render_with_retry(article_url, title, summary)
                if pdf_bytes is None:
                    failed += 1
                    self.helper.log_warning(
                        f"Skipping {article_url}: PDF render failed after retries."
                    )
                    if item_date:
                        if last_date != item_date:
                            last_date = item_date
                            skip = 0
                        else:
                            skip += 1
                    else:
                        skip += 1
                    self._save_cursor(last_date, skip)
                    continue

                published = self._published_iso(item)
                if not published:
                    published = datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S+00:00"
                    )
                    self.helper.log_warning(
                        f"No usable date for {article_url}; using ingestion time."
                    )

                self._create_report(article_url, title, summary, published, pdf_bytes)
                processed += 1
                if item_date:
                    if last_date != item_date:
                        last_date = item_date
                        skip = 0
                    else:
                        skip += 1
                else:
                    skip += 1
                self._save_cursor(last_date, skip)
                time.sleep(self.request_delay)

            if stop:
                break

            if len(items) < ODATA_PAGE_SIZE:
                # Last page reached; reset skip for next run
                self._save_cursor(last_date, 0)
                break

            time.sleep(self.request_delay)

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("World Health Organization connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        WorldHealthOrganizationConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
