"""
Chalkbeat OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://www.chalkbeat.org as container-only OpenCTI Reports, one per
article, with a WeasyPrint-rendered PDF attached per Report.

Collection model (Queryly Search API + offset cursor)
------------------------------------------------------
Chalkbeat runs on Arc Publishing (the Washington Post platform). There is
no WordPress REST API, no usable full-corpus RSS, and the sitemap is a
rolling recent-week window. The Queryly Search API is the sole viable
enumeration surface for the full ~33,000+ article corpus (2003-present).

Enumeration queries all articles in ascending chronological order via
``sort=oldestfirst``, paginated by offset (``endindex`` parameter,
``batchsize=100``). The offset is persisted in OpenCTI connector state.
On restart the connector resumes from the saved offset. When the offset
reaches or exceeds the reported total, the connector waits for the next
poll interval.

For each article the connector fetches the full HTML page via
``requests.get()``, extracts article content with BeautifulSoup (Arc
Publishing selectors: ``.article-body-wrapper``, ``.body-paragraph``),
and renders a PDF via WeasyPrint. Metadata (title, published date,
description) is read from the article page's meta tags (``og:title``,
``article:published_time``) and JSON-LD.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks
report.read(id) and skips if the Report already exists. For a new article
it creates the External Reference (upsert-safe), then the Report (with the
deterministic stix_id), then attaches the PDF. Because the existence check
keys on the Report id (not on the External Reference), every sub-write is
idempotent and a crash anywhere leaves the article still "not done"; the
next poll re-enters and completes it.

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
- Author: the single "Chalkbeat" Organization identity. Never the
  connector account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (Medium band: editorial journalism).
- Enumeration: Queryly Search API, sorted oldest-first, offset cursor.
- Content fetch: plain HTTP requests (no Playwright/browser needed).
- PDF: WeasyPrint from extracted article body HTML.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import html as html_mod
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

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

QUERYLY_ENDPOINT = "https://api.queryly.com/json.aspx"
QUERYLY_BATCH_SIZE = 100

MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB

# Arc Publishing content selectors (tried in order).
ARTICLE_CONTENT_SELECTORS = [
    ".article-body-wrapper",
    ".body-paragraph",
    "article",
]

STRIP_SELECTORS = [
    ".ad-container",
    ".newsletter-signup",
    ".related-stories",
    ".social-share",
    ".comments-section",
    "nav",
    "footer",
    "aside",
]

def _strip_html(value):
    """Remove HTML tags and unescape entities from a string."""
    if not value:
        return ""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", value)).strip()


class ChalkbeatConnector:
    """External-import connector that mirrors Chalkbeat articles into Reports."""

    def __init__(self):
        """Initialize connector configuration and HTTP session."""
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = {}
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}

        self.helper = OpenCTIConnectorHelper(config)

        self.base_url = get_config_variable(
            "CHALKBEAT_BASE_URL",
            ["chalkbeat", "base_url"], config,
            default="https://www.chalkbeat.org",
        ).rstrip("/")

        self.queryly_key = get_config_variable(
            "CHALKBEAT_QUERYLY_KEY",
            ["chalkbeat", "queryly_key"], config,
            default="12a8b884283a4e73",
        )

        self.poll_interval = get_config_variable(
            "CHALKBEAT_POLL_INTERVAL",
            ["chalkbeat", "poll_interval"], config,
            isNumber=True, default=86400,
        )

        self.request_delay = get_config_variable(
            "CHALKBEAT_REQUEST_DELAY",
            ["chalkbeat", "request_delay"], config,
            isNumber=True, default=2,
        )

        self.max_reports = get_config_variable(
            "CHALKBEAT_MAX_REPORTS",
            ["chalkbeat", "max_reports"], config,
            isNumber=True, default=0,
        )

        self.render_retries = get_config_variable(
            "CHALKBEAT_RENDER_RETRIES",
            ["chalkbeat", "render_retries"], config,
            isNumber=True, default=3,
        )

        self.pdf_render_timeout = get_config_variable(
            "CHALKBEAT_PDF_RENDER_TIMEOUT",
            ["chalkbeat", "pdf_render_timeout"],
            config,
            isNumber=True,
            default=120,
        )

        self.confidence = get_config_variable(
            "CHALKBEAT_CONFIDENCE",
            ["chalkbeat", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "CHALKBEAT_REPORT_TYPE",
            ["chalkbeat", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "CHALKBEAT_TLP",
            ["chalkbeat", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "CHALKBEAT_AUTHOR_NAME",
            ["chalkbeat", "author_name"], config,
            default="Chalkbeat",
        )

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "text/html, application/json, */*",
        })

        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Cursor helpers
    # ------------------------------------------------------------------ #

    def _save_cursor(self, endindex):
        """Persist the enumeration offset to connector state."""
        self.helper.set_state({
            "endindex": endindex,
        })

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Resolve or create author identity, marking, and vocabulary."""
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Nonprofit education news organization covering schools "
                        "and education policy across the United States. Source "
                        "organization for ingested reports.",
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
                "Queryly API unreachable at startup; entering poll "
                "loop anyway and retrying next cycle."
            )
        else:
            self.helper.log_info(
                f"Queryly API reachable: {total} articles reported."
            )

    def _probe_total(self):
        """Query the Queryly API for the total article count."""
        try:
            resp = self.session.get(
                QUERYLY_ENDPOINT,
                params={
                    "queryly_key": self.queryly_key,
                    "query": "*",
                    "endindex": 0,
                    "batchsize": 1,
                    "sort": "oldestfirst",
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("metadata", {}).get("total", 0)
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # Queryly enumeration
    # ------------------------------------------------------------------ #

    def _fetch_batch(self, endindex):
        """Fetch a batch of article stubs from the Queryly API."""
        params = {
            "queryly_key": self.queryly_key,
            "query": "*",
            "endindex": endindex,
            "batchsize": QUERYLY_BATCH_SIZE,
            "sort": "oldestfirst",
        }
        try:
            resp = self.session.get(QUERYLY_ENDPOINT, params=params, timeout=90)
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch batch at offset {endindex}: {exc}")
            return None, 0
        if resp.status_code != 200:
            self.helper.log_error(
                f"Queryly returned HTTP {resp.status_code} at offset {endindex}; "
                f"skipping this cycle."
            )
            return None, 0
        try:
            data = resp.json()
        except ValueError as exc:
            self.helper.log_error(
                f"Queryly returned non-JSON body at offset {endindex}: {exc}"
            )
            return None, 0
        items = data.get("items", [])
        total = data.get("metadata", {}).get("total", 0)
        return items, total

    # ------------------------------------------------------------------ #
    # Article content extraction
    # ------------------------------------------------------------------ #

    def _fetch_article(self, url):
        """Fetch a single article page and return the raw HTML."""
        resp = self.session.get(url, timeout=60, headers={"Accept": "text/html"})
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")
        return resp.text

    @staticmethod
    def _extract_metadata(soup):
        """Extract title, description, published date, and byline from page metadata."""
        meta = {}

        og_title = soup.find("meta", property="og:title")
        if og_title and og_title.get("content"):
            meta["title"] = og_title["content"].strip()

        og_desc = soup.find("meta", property="og:description")
        if og_desc and og_desc.get("content"):
            meta["description"] = og_desc["content"].strip()

        pub_time = soup.find("meta", property="article:published_time")
        if pub_time and pub_time.get("content"):
            meta["published"] = pub_time["content"].strip()

        # Try JSON-LD for additional metadata.
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                ld = json.loads(script.string or "")
                if isinstance(ld, list):
                    ld = ld[0] if ld else {}
                if isinstance(ld, dict):
                    if not meta.get("title") and ld.get("headline"):
                        meta["title"] = ld["headline"]
                    if not meta.get("published") and ld.get("datePublished"):
                        meta["published"] = ld["datePublished"]
                    if not meta.get("description") and ld.get("description"):
                        meta["description"] = ld["description"]
                    # Extract author from JSON-LD.
                    author = ld.get("author")
                    if isinstance(author, dict):
                        meta["byline"] = author.get("name", "")
                    elif isinstance(author, list) and author:
                        names = [a.get("name", "") for a in author if isinstance(a, dict)]
                        meta["byline"] = ", ".join(n for n in names if n)
            except (json.JSONDecodeError, TypeError, AttributeError):
                continue

        # Fallback: headline selector.
        if not meta.get("title"):
            headline = soup.select_one(".b-headline")
            if headline:
                meta["title"] = headline.get_text(strip=True)

        return meta

    @staticmethod
    def _extract_content(soup):
        """Extract the article body element from the parsed HTML."""
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

    # ------------------------------------------------------------------ #
    # STIX helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _report_id(link):
        """Derive a deterministic STIX Report id from the article URL."""
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))

    @staticmethod
    def _parse_published(raw):
        """Parse a date string into an ISO 8601 timestamp."""
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt.year >= 2000:
            dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        return None

    # ------------------------------------------------------------------ #
    # PDF rendering (WeasyPrint)
    # ------------------------------------------------------------------ #

    def _retry(self, fn, label):
        """Retry a callable with exponential backoff."""
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

    def _render_with_retry(self, url, title, byline, content_html):
        """Render a PDF with retries, using render_html_to_pdf."""
        return self._retry(
            lambda: render_html_to_pdf(title, str(content_html), url, session=self.session, timeout=self.pdf_render_timeout),
            f"PDF render for {url}",
        )

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, url, title, description, published, pdf_bytes):
        """Create an OpenCTI Report with attached PDF for a single article."""
        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on chalkbeat.org",
        )

        _report_types = classify_report(
            title=title, description=description, content=description,
            source="Chalkbeat", source_url=url,
            default_types=[self.report_type],
        )

        report = self.helper.api.report.create(
            stix_id=report_id,
            name=title,
            description=description,
            published=published,
            report_types=_report_types,
            confidence=self.confidence,
            createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[external_reference["id"]],
            update=True,
        )

        parsed = urlparse(url)
        slug = parsed.path.strip("/").rsplit("/", 1)[-1] or "article"

        if len(pdf_bytes) > MAX_PDF_BYTES:
            self.helper.log_warning(
                f"Skipping oversized PDF for {url} ({len(pdf_bytes):,} bytes)."
            )
        else:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"chalkbeat-{slug}.pdf",
                data=pdf_bytes,
                mime_type="application/pdf",
            )

        self.helper.log_info(f"Created Report for {url} ({title[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        """Run a single enumeration cycle over the Queryly article index."""
        state = self.helper.get_state() or {}
        cursor_offset = max(0, int(state.get("endindex", 0)))

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Chalkbeat enumeration run"
        )
        self.helper.log_info(
            f"Resuming at endindex={cursor_offset}."
        )

        processed = 0
        skipped = 0
        failed = 0
        offset = cursor_offset
        stop = False
        try:

            while not stop:
                items, total = self._fetch_batch(offset)
                if items is None:
                    self.helper.log_warning(
                        f"Batch fetch failed at offset {offset}; ending cycle, "
                        f"cursor preserved."
                    )
                    break
                if not items:
                    self.helper.log_info(
                        f"No items returned at offset {offset} (total={total}); "
                        f"caught up."
                    )
                    break

                self.helper.log_info(
                    f"Batch at offset {offset}: {len(items)} items "
                    f"(total={total})."
                )

                for item in items:
                    url = item.get("link")
                    if not url:
                        offset += 1
                        self._save_cursor(offset)
                        continue

                    # Ensure absolute URL.
                    if url.startswith("/"):
                        url = self.base_url + url

                    if self.max_reports and processed >= self.max_reports:
                        self.helper.log_info(
                            f"Reached max_reports={self.max_reports}; stopping run."
                        )
                        self._save_cursor(offset)
                        stop = True
                        break

                    report_id = self._report_id(url)

                    # Graph dedup: skip if Report already exists.
                    try:
                        if self.helper.api.report.read(id=report_id) is not None:
                            skipped += 1
                            offset += 1
                            self._save_cursor(offset)
                            continue
                    except Exception as exc:
                        self.helper.log_warning(
                            f"Dedup check failed for {url}: {exc}"
                        )

                    # Fetch the article page.
                    try:
                        page_html = self._fetch_article(url)
                    except Exception as exc:
                        failed += 1
                        self.helper.log_warning(
                            f"Skipping {url}: article fetch failed: {exc}"
                        )
                        offset += 1
                        self._save_cursor(offset)
                        time.sleep(self.request_delay)
                        continue

                    # Extract metadata and content.
                    soup = BeautifulSoup(page_html, "lxml")
                    meta = self._extract_metadata(soup)
                    content = self._extract_content(soup)

                    title = (
                        meta.get("title")
                        or _strip_html(item.get("title", ""))
                        or url
                    )
                    byline = meta.get("byline", "")
                    description = meta.get("description") or _strip_html(
                        item.get("description", "")
                    )

                    published_raw = (
                        meta.get("published")
                        or item.get("pubdate")
                    )
                    published = self._parse_published(published_raw)
                    if not published:
                        published = datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S+00:00"
                        )
                        self.helper.log_warning(
                            f"No usable date for {url}; using ingestion time."
                        )

                    if content is None:
                        failed += 1
                        self.helper.log_warning(
                            f"Skipping {url}: no article content found in HTML."
                        )
                        offset += 1
                        self._save_cursor(offset)
                        time.sleep(self.request_delay)
                        continue

                    content_html = str(content)

                    # Render PDF with retry.
                    pdf_bytes = self._render_with_retry(url, title, byline, content_html)
                    if pdf_bytes is None:
                        failed += 1
                        self.helper.log_warning(
                            f"Skipping {url}: PDF render failed after retries."
                        )
                        offset += 1
                        self._save_cursor(offset)
                        time.sleep(self.request_delay)
                        continue

                    # Create the Report.
                    try:
                        self._create_report(url, title, description, published, pdf_bytes)
                        processed += 1
                    except Exception as exc:
                        failed += 1
                        self.helper.log_warning(
                            f"Report creation failed for {url}: {exc}"
                        )
                    offset += 1
                    self._save_cursor(offset)
                    time.sleep(self.request_delay)

                # If fewer items than batch size, we've reached the end.
                if len(items) < QUERYLY_BATCH_SIZE:
                    self.helper.log_info(
                        f"Reached end of results at offset {offset} "
                        f"(batch had {len(items)} items)."
                    )
                    break

        finally:
            message = (
                f"Run complete: {processed} created, {skipped} already present, "
                f"{failed} failed."
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)

    def run(self):
        """Start the connector and enter the main poll loop."""
        self._resolve_graph_references()
        self.helper.log_info("Chalkbeat connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        ChalkbeatConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
