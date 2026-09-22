"""
Defense One OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://www.defenseone.com as container-only OpenCTI Reports, one per
article, with two PDFs attached per Report:

  1. RSS Content PDF (variant "rss-content") -- rendered from the RSS
     content:encoded payload via WeasyPrint. This is the full article text
     as the RSS feed delivers it: clean, structured, no extra network fetch.
  2. Live HTML PDF (variant "live-html") -- fetched from the article URL
     with requests, article body extracted from the .content-body container
     with BeautifulSoup, cruft stripped, rendered via WeasyPrint. This
     captures the page as a reader sees it and serves as the
     auditor/processor reference.

Collection model (RSS feed + graph-dedup re-walk)
-------------------------------------------------
Defense One is a US defense/national security journalism site published by
Government Media Group (Atlantic Media). The RSS feed at /rss/all/ is
RSS 2.0 with content:encoded providing the full article text. The feed
returns the ~21 most recent articles in newest-first order with no
pagination support.

Because the feed is newest-first and non-paginated, there is no stable
positional cursor. Instead the connector re-walks the entire feed on each
poll cycle and relies on graph deduplication: before processing each item,
it checks report.read(id) against a deterministic STIX id derived from the
article URL (uuid5). If the Report already exists, the item is skipped.
If all items in the feed are already known, the run finishes immediately.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id)
and skips if the Report already exists. For a new article it creates the
External Reference (upsert-safe), then the Report (with the deterministic
stix_id), then attaches the PDFs. Because the existence check keys on the
Report id (not on the External Reference), every sub-write is idempotent
a crash after report.create but before the add_file calls will leave the
Report permanently orphaned without its PDF attachments.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain
Objects, no Observables, no Relationships, no Labels. Named-entity / IOC
extraction is a separate, out-of-scope downstream phase. Keeping this
connector container-only makes it purely additive and prevents it from
acting as a graph-contamination vector.

Key decisions
-------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published source).
- Author: the single "Defense One" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band: editorial secondary analysis).
- No content filtering: all site categories are substantive editorial content.
- Crawl-delay: 1 second (per robots.txt).

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

import feedparser
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

LIVE_CONTENT_SELECTORS = [
    ".content-body",
    ".wysiwyg-article",
]

STRIP_SELECTORS = [
    ".ad-container", ".comments-area", ".related-stories",
    ".newsletter-module", ".social-share", "nav", "footer",
    "iframe", "script", "style",
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
    "blockquote { border-left: 3px solid #1a3c6b; margin: 1em 0; "
    "padding: 0.5em 1em; color: #555; } "
    "a { color: #1a3c6b; } "
)

PDF_VARIANT_RSS_CONTENT = "rss-content"
PDF_VARIANT_LIVE_HTML = "live-html"

MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB


def _strip_html(value):
    if not value:
        return ""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", value)).strip()


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
        + "  |  OpenCTI Defense One connector [" + variant_label + "]  |  "
        + ingested_at
        + "'; font-size: 7px; color: #888; } } "
        + "</style></head><body>"
        + "<h1>" + safe_title + "</h1>"
        + byline_block
        + content_html
        + "</body></html>"
    )


class DefenseOneConnector:
    """External-import connector that mirrors Defense One articles into Reports."""

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
            "DEFENSE_ONE_BASE_URL",
            ["defense_one", "base_url"], config,
            default="https://www.defenseone.com",
        ).rstrip("/")
        self.rss_url = get_config_variable(
            "DEFENSE_ONE_RSS_URL",
            ["defense_one", "rss_url"], config,
            default=f"{self.base_url}/rss/all/",
        )

        self.poll_interval = get_config_variable(
            "DEFENSE_ONE_POLL_INTERVAL",
            ["defense_one", "poll_interval"], config,
            isNumber=True, default=86400,
        )

        self.request_delay = get_config_variable(
            "DEFENSE_ONE_REQUEST_DELAY",
            ["defense_one", "request_delay"], config,
            isNumber=True, default=1,
        )

        self.max_reports = get_config_variable(
            "DEFENSE_ONE_MAX_REPORTS",
            ["defense_one", "max_reports"], config,
            isNumber=True, default=0,
        )

        self.render_retries = get_config_variable(
            "DEFENSE_ONE_RENDER_RETRIES",
            ["defense_one", "render_retries"], config,
            isNumber=True, default=3,
        )

        self.confidence = get_config_variable(
            "DEFENSE_ONE_CONFIDENCE",
            ["defense_one", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "DEFENSE_ONE_REPORT_TYPE",
            ["defense_one", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "DEFENSE_ONE_TLP",
            ["defense_one", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "DEFENSE_ONE_AUTHOR_NAME",
            ["defense_one", "author_name"], config,
            default="Defense One",
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
            description="US defense and national security news outlet "
                        "(Government Media Group). Source organization "
                        "for ingested reports.",
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
    # RSS enumeration
    # ------------------------------------------------------------------ #

    def _fetch_feed(self):
        """Fetch and parse the RSS feed. Returns list of entries or None on failure."""
        try:
            resp = self.session.get(self.rss_url, timeout=60)
            if resp.status_code != 200:
                self.helper.log_error(
                    f"RSS feed returned HTTP {resp.status_code}; skipping this cycle."
                )
                return None
            feed = feedparser.parse(resp.text)
            if feed.bozo and not feed.entries:
                self.helper.log_error(
                    f"RSS feed parse error: {feed.bozo_exception}; skipping this cycle."
                )
                return None
            return feed.entries
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch RSS feed: {exc}")
            return None

    @staticmethod
    def _report_id(link):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))

    @staticmethod
    def _entry_link(entry):
        """Extract the article URL from an RSS entry."""
        return entry.get("link", "").strip()

    @staticmethod
    def _entry_title(entry):
        """Extract and clean the title from an RSS entry."""
        return _strip_html(entry.get("title", ""))

    @staticmethod
    def _entry_description(entry):
        """Extract the description/summary from an RSS entry."""
        return _strip_html(entry.get("description", "") or entry.get("summary", ""))

    @staticmethod
    def _entry_author(entry):
        """Extract the author name from dc:creator."""
        # feedparser normalizes dc:creator to 'author'
        return (entry.get("author") or "").strip()

    @staticmethod
    def _entry_category(entry):
        """Extract categories from an RSS entry."""
        tags = entry.get("tags", [])
        return [t.get("term", "") for t in tags if t.get("term")]

    @staticmethod
    def _entry_content(entry):
        """Extract content:encoded HTML from an RSS entry."""
        # feedparser normalizes content:encoded into 'content' list
        content_list = entry.get("content", [])
        if content_list:
            return content_list[0].get("value", "")
        return ""

    @staticmethod
    def _entry_published_iso(entry):
        """Extract publication date as ISO string."""
        # feedparser normalizes pubDate into 'published_parsed'
        parsed = entry.get("published_parsed")
        if parsed:
            try:
                dt = datetime(*parsed[:6], tzinfo=timezone.utc)
                if dt.year >= 2000:
                    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            except (TypeError, ValueError):
                pass
        # Fallback: try the raw string
        raw = entry.get("published", "")
        if raw:
            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(raw).astimezone(timezone.utc)
                if dt.year >= 2000:
                    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            except Exception:
                pass
        return None

    def _format_byline(self, entry):
        """Build a byline string from author and categories."""
        author = self._entry_author(entry)
        cats = self._entry_category(entry)
        if cats:
            return f"{author}  |  {', '.join(cats)}" if author else ", ".join(cats)
        return author

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
        """Render a PDF from the RSS content:encoded payload."""
        title = self._entry_title(entry)
        content_html = self._entry_content(entry)
        url = self._entry_link(entry)
        byline = self._format_byline(entry)

        if not content_html:
            raise RuntimeError("No content:encoded in RSS entry")

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
        url = self._entry_link(entry)
        return self._retry(
            lambda: self._render_rss_pdf(entry),
            f"RSS PDF render for {url}",
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
        resp = self.session.get(url, timeout=60, headers={"Accept": "text/html"})
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")

        content = self._extract_live_content(resp.text)
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

    def _render_live_with_retry(self, url, title, byline):
        return self._retry(
            lambda: self._render_live_pdf(url, title, byline),
            f"Live PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, entry, published, rss_pdf, live_pdf):
        url = self._entry_link(entry)
        name = self._entry_title(entry) or url
        description = self._entry_description(entry)

        byline = self._entry_author(entry)
        if byline:
            description = f"By {byline}. {description}" if description else f"By {byline}."

        cats = self._entry_category(entry)
        if cats:
            description = f"{description} [{', '.join(cats)}]" if description else f"[{', '.join(cats)}]"

        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on defenseone.com",
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
                file_name=f"defense-one-{slug}.pdf",
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
                    file_name=f"defense-one-{slug}-live.pdf",
                    data=live_pdf,
                    mime_type="application/pdf",
                )

        live_tag = "+live" if live_pdf else " (live failed)"
        self.helper.log_info(f"Created Report{live_tag} for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        entries = self._fetch_feed()
        if entries is None:
            return
        if not entries:
            self.helper.log_info("RSS feed returned no entries.")
            return

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Defense One enumeration run"
        )
        self.helper.log_info(
            f"RSS feed returned {len(entries)} entries; starting graph-dedup re-walk."
        )

        processed = 0
        skipped = 0
        failed = 0

        for entry in entries:
            url = self._entry_link(entry)
            if not url:
                continue

            if self.max_reports and processed >= self.max_reports:
                self.helper.log_info(
                    f"Reached max_reports={self.max_reports}; stopping run."
                )
                break

            if self.helper.api.report.read(id=self._report_id(url)) is not None:
                skipped += 1
                continue

            rss_pdf = self._render_rss_with_retry(entry)
            if rss_pdf is None:
                failed += 1
                self.helper.log_warning(
                    f"Skipping {url}: RSS content PDF render failed after retries."
                )
                continue

            title = self._entry_title(entry)
            byline = self._format_byline(entry)
            live_pdf = self._render_live_with_retry(url, title, byline)
            if live_pdf is None:
                self.helper.log_warning(
                    f"Live HTML PDF failed for {url}; attaching RSS content PDF only."
                )

            published = self._entry_published_iso(entry)
            if not published:
                published = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
                self.helper.log_warning(
                    f"No usable date for {url}; using ingestion time."
                )

            self._create_report(entry, published, rss_pdf, live_pdf)
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
        self.helper.log_info("Defense One connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        DefenseOneConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
