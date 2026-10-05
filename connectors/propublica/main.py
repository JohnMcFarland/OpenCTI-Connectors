"""
ProPublica OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://www.propublica.org as container-only OpenCTI Reports, one per article,
with two PDFs attached per Report:

  1. RSS content PDF (variant "rss-content") -- rendered from the RSS entry's
     description/content field via WeasyPrint. This is the structured summary
     as the feed delivers it: clean, fast, no network fetch beyond embedded
     images.
  2. Live HTML PDF (variant "live-html") -- fetched from the article URL,
     article body extracted with BeautifulSoup, cruft stripped, rendered via
     WeasyPrint. This captures the full article as a reader sees it.

Collection model (RSS feed + graph-dedup re-walk)
-------------------------------------------------
ProPublica is a WordPress 6.9.8 site with ~3-5k investigative articles. The
RSS feed at /feed/ is standard WordPress RSS 2.0, returning the most recent
items in reverse-chronological order.

Because the feed is newest-first and shifts as new articles are published,
no positional cursor is used. Instead, the connector re-walks the feed on
each poll cycle and relies on graph dedup (report.read by deterministic
STIX id) to skip already-ingested articles. An early-stop counter halts the
walk after N consecutive already-known articles, avoiding re-scanning the
entire feed on each cycle.

Feed entries carry category tags for topics (Criminal Justice, Immigration,
Health Care, etc.) which are included in the Report description.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id)
and skips if the Report already exists. For a new article it creates the
External Reference (upsert-safe), then the Report (with the deterministic
stix_id), then attaches the PDFs. A crash before report.create is fully safe:
the next poll re-renders and creates from scratch. However, a crash after
report.create but before add_file leaves an orphaned Report (exists in graph
but has no PDF attachments); the dedup check will then skip it on subsequent
polls. This is a narrow window and the Report is still usable (it carries
the external reference), but the PDFs will not be attached automatically.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels. Named-entity / IOC extraction is
a separate, out-of-scope downstream phase.

Key decisions
-------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published source).
- Author: the single "ProPublica" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band: editorial investigative journalism).
- Skip podcasts: entries with "podcast" category or podcast URLs are filtered.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import html as html_mod
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import feedparser
import requests
import yaml
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper, get_config_variable

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from microservices.classify_report import classify_report
from microservices.make_pdf import render_html_to_pdf


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

LIVE_CONTENT_SELECTORS = [
    ".article-body",
    ".entry-content",
    ".post-content",
    "article .body",
    "article",
]

STRIP_SELECTORS = [
    ".newsletter-signup",
    ".donation-banner",
    ".ad-container",
    ".sidebar",
    "nav",
    "footer",
    ".related-stories",
    ".share-tools",
    "script",
    "style",
    "iframe",
]

SKIP_CATEGORIES = frozenset({
    "podcast",
    "podcasts",
})

PDF_VARIANT_RSS_CONTENT = "rss-content"
PDF_VARIANT_LIVE_HTML = "live-html"

MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB

def _strip_html(value):
    if not value:
        return ""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", value)).strip()


class ProPublicaConnector:
    """External-import connector that mirrors ProPublica articles into Reports."""

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
            "PROPUBLICA_BASE_URL",
            ["propublica", "base_url"], config,
            default="https://www.propublica.org",
        ).rstrip("/")

        self.feed_path = get_config_variable(
            "PROPUBLICA_FEED_PATH",
            ["propublica", "feed_path"], config,
            default="/feed/",
        )

        self.poll_interval = get_config_variable(
            "PROPUBLICA_POLL_INTERVAL",
            ["propublica", "poll_interval"], config,
            isNumber=True, default=86400,
        )

        self.request_delay = get_config_variable(
            "PROPUBLICA_REQUEST_DELAY",
            ["propublica", "request_delay"], config,
            isNumber=True, default=2,
        )

        self.max_reports = get_config_variable(
            "PROPUBLICA_MAX_REPORTS",
            ["propublica", "max_reports"], config,
            isNumber=True, default=0,
        )

        self.early_stop = get_config_variable(
            "PROPUBLICA_EARLY_STOP",
            ["propublica", "early_stop"], config,
            isNumber=True, default=20,
        )

        self.render_retries = get_config_variable(
            "PROPUBLICA_RENDER_RETRIES",
            ["propublica", "render_retries"], config,
            isNumber=True, default=3,
        )
        self.pdf_render_timeout = get_config_variable(
            "PROPUBLICA_PDF_RENDER_TIMEOUT",
            ["propublica", "pdf_render_timeout"],
            config,
            isNumber=True,
            default=120,
        )

        self.confidence = get_config_variable(
            "PROPUBLICA_CONFIDENCE",
            ["propublica", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "PROPUBLICA_REPORT_TYPE",
            ["propublica", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "PROPUBLICA_TLP",
            ["propublica", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "PROPUBLICA_AUTHOR_NAME",
            ["propublica", "author_name"], config,
            default="ProPublica",
        )

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
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
            description="ProPublica: independent, nonprofit investigative journalism "
                        "in the public interest. Source organization for ingested reports.",
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
    # RSS feed parsing
    # ------------------------------------------------------------------ #

    def _fetch_feed(self):
        feed_url = f"{self.base_url}{self.feed_path}"
        try:
            resp = self.session.get(feed_url, timeout=60)
            resp.raise_for_status()
            feed = feedparser.parse(resp.text)
            if feed.bozo and not feed.entries:
                self.helper.log_error(
                    f"RSS feed parse error with no entries: {feed.bozo_exception}"
                )
                return None
            return feed.entries
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch RSS feed: {exc}")
            return None

    @staticmethod
    def _is_podcast(entry):
        tags = entry.get("tags", [])
        for tag in tags:
            term = (tag.get("term") or "").lower().strip()
            if term in SKIP_CATEGORIES:
                return True
        link = entry.get("link", "").lower()
        if "/podcast" in link:
            return True
        return False

    @staticmethod
    def _entry_url(entry):
        return entry.get("link", "").strip()

    @staticmethod
    def _entry_title(entry):
        return _strip_html(entry.get("title", ""))

    @staticmethod
    def _entry_categories(entry):
        tags = entry.get("tags", [])
        return [tag.get("term", "").strip() for tag in tags if tag.get("term", "").strip()]

    @staticmethod
    def _entry_author(entry):
        return entry.get("author", "").strip()

    @staticmethod
    def _entry_content_html(entry):
        """Extract the richest content field from the RSS entry."""
        # feedparser puts content:encoded into entry.content
        if entry.get("content"):
            for c in entry["content"]:
                if c.get("value"):
                    return c["value"]
        # Fall back to summary/description
        return entry.get("summary", "") or entry.get("description", "")

    @staticmethod
    def _entry_published_iso(entry):
        for key in ("published_parsed", "updated_parsed"):
            parsed = entry.get(key)
            if parsed:
                try:
                    dt = datetime(*parsed[:6], tzinfo=timezone.utc)
                    if dt.year >= 2000:
                        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
                except (TypeError, ValueError):
                    continue
        # Fall back to string parsing
        for key in ("published", "updated"):
            raw = entry.get(key)
            if raw:
                try:
                    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    if dt.year >= 2000:
                        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
                except (TypeError, ValueError):
                    continue
        return None

    # ------------------------------------------------------------------ #
    # Deterministic ID and dedup
    # ------------------------------------------------------------------ #

    @staticmethod
    def _report_id(url):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))

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

    def _render_rss_pdf(self, entry):
        """Render the RSS entry content to PDF via the shared microservice."""
        title = self._entry_title(entry)
        content_html = self._entry_content_html(entry)
        url = self._entry_url(entry)
        return render_html_to_pdf(
            title, str(content_html), url,
            session=self.session, timeout=self.pdf_render_timeout,
        )

    def _render_rss_with_retry(self, entry):
        """Retry RSS PDF rendering with exponential backoff."""
        url = self._entry_url(entry)
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
        """Fetch a live article page, extract content, and render to PDF."""
        resp = self.session.get(url, timeout=60, headers={"Accept": "text/html"})
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")

        content = self._extract_live_content(resp.text)
        if content is None:
            raise RuntimeError("No article content container found in live HTML")

        return render_html_to_pdf(
            title, str(content), url,
            session=self.session, timeout=self.pdf_render_timeout,
        )

    def _render_live_with_retry(self, url, title, byline):
        """Retry live HTML PDF rendering with exponential backoff."""
        return self._retry(
            lambda: self._render_live_pdf(url, title, byline),
            f"Live PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _build_description(self, entry):
        summary = _strip_html(entry.get("summary", "") or entry.get("description", ""))
        author = self._entry_author(entry)
        categories = self._entry_categories(entry)

        parts = []
        if author:
            parts.append(f"By {author}.")
        if categories:
            parts.append(f"Topics: {', '.join(categories)}.")
        if summary:
            parts.append(summary)
        return " ".join(parts)

    def _build_byline(self, entry):
        author = self._entry_author(entry)
        categories = self._entry_categories(entry)
        byline_parts = []
        if author:
            byline_parts.append(f"By {author}")
        if categories:
            byline_parts.append(", ".join(categories))
        return "  |  ".join(byline_parts)

    def _create_report(self, entry, published, rss_pdf, live_pdf):
        url = self._entry_url(entry)
        name = self._entry_title(entry) or url
        description = self._build_description(entry)
        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on propublica.org",
        )

        # -- Crucible report classification --
        _report_types = classify_report(
            title=name, description=description, content=description or "",
            source="ProPublica", source_url=url,
            default_types=[self.report_type],
        )

        report = self.helper.api.report.create(
            stix_id=report_id,
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

        slug = urlparse(url).path.strip("/").rsplit("/", 1)[-1] or "article"

        if len(rss_pdf) > MAX_PDF_BYTES:
            self.helper.log_warning(
                f"Skipping oversized PDF for {url} ({len(rss_pdf):,} bytes)."
            )
        else:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"propublica-{slug}.pdf",
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
                    file_name=f"propublica-{slug}-live.pdf",
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
            self.helper.log_warning("Feed fetch failed; skipping this cycle.")
            return

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "ProPublica RSS enumeration run"
        )
        self.helper.log_info(f"Feed returned {len(entries)} entries.")

        processed = 0
        skipped = 0
        failed = 0
        consecutive_known = 0
        podcasts_skipped = 0

        for entry in entries:
            url = self._entry_url(entry)
            if not url:
                continue

            if self._is_podcast(entry):
                podcasts_skipped += 1
                consecutive_known = 0
                continue

            if self.max_reports and processed >= self.max_reports:
                self.helper.log_info(
                    f"Reached max_reports={self.max_reports}; stopping run."
                )
                break

            # Graph dedup check
            if self.helper.api.report.read(id=self._report_id(url)) is not None:
                skipped += 1
                consecutive_known += 1
                if self.early_stop and consecutive_known >= self.early_stop:
                    self.helper.log_info(
                        f"Early stop: {consecutive_known} consecutive known articles; "
                        f"remaining entries assumed already ingested."
                    )
                    break
                continue

            consecutive_known = 0

            # Render RSS content PDF
            rss_pdf = self._render_rss_with_retry(entry)
            if rss_pdf is None:
                failed += 1
                self.helper.log_warning(
                    f"Skipping {url}: RSS content PDF render failed after retries."
                )
                continue

            # Render live HTML PDF
            title = self._entry_title(entry)
            byline = self._build_byline(entry)
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
            f"{failed} failed (render), {podcasts_skipped} podcasts skipped."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("ProPublica connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        ProPublicaConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
