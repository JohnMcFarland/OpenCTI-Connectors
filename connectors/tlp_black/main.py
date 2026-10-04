"""
TLPBLACK OpenCTI connector.

Purpose
-------
External-import connector that ingests cybersecurity research articles from the
TLPBLACK blog (https://tlpblack.net/blog) and creates one OpenCTI Report
container per article, with the source page attached as a full-fidelity PDF
plus a raw HTML snapshot.

Collection model
----------------
The TLPBLACK blog is a Next.js site that publishes an RSS feed at /rss.xml
containing all posts (~9 as of September 2026). The feed provides title,
description, and publication date for each item.

Enumeration reads the full RSS feed on each poll cycle. Because the corpus is
small and the feed is newest-first (no stable ascending cursor), the connector
uses graph-dedup re-walk: it checks the OpenCTI graph for each article's
deterministic STIX id before rendering, skipping items already ingested.

PDF rendering is delegated to the centralised pdf-renderer microservice via
HTTP POST. The service renders the live page with Playwright and returns both
a PDF and a raw HTML snapshot. The connector uses the ``article`` CSS selector
to isolate blog content.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id)
and skips if the Report already exists. Since there is no cursor to save,
crashes simply restart the re-walk from the top of the feed on the next cycle.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (free, publicly published source).
- Author: "TLPBLACK" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band).
- PDF renderer: centralised pdf-renderer service (Playwright via HTTP).
- No WAF gating: plain HTTP requests work for RSS; the render service handles
  page rendering.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import base64
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from xml.etree import ElementTree

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

STRIP_SELECTORS = []


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _report_id(link):
    """Return a deterministic STIX Report id derived from the article URL."""
    return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))


def _slug_from_url(url):
    """Return the last path segment of a URL, or 'report' for root URLs."""
    path = urlparse(url).path.strip("/")
    return path.rsplit("/", 1)[-1] if path else "report"


def _parse_rfc2822(date_str):
    """Parse an RFC 2822 date string and return an ISO-8601 UTC string."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

class TlpBlackConnector:
    """External-import connector that mirrors TLPBLACK blog posts into Reports."""

    def __init__(self):
        """Load configuration and initialise the HTTP session."""
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = {}
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                config = yaml.load(fh, Loader=yaml.FullLoader) or {}

        self.helper = OpenCTIConnectorHelper(config)

        self.base_url = get_config_variable(
            "TLP_BLACK_BASE_URL",
            ["tlp_black", "base_url"],
            config,
            default="https://tlpblack.net",
        ).rstrip("/")

        self.rss_url = f"{self.base_url}/rss.xml"

        self.poll_interval = int(get_config_variable(
            "TLP_BLACK_POLL_INTERVAL",
            ["tlp_black", "poll_interval"],
            config,
            isNumber=True,
            default=86400,
        ))

        self.request_delay = int(get_config_variable(
            "TLP_BLACK_REQUEST_DELAY",
            ["tlp_black", "request_delay"],
            config,
            isNumber=True,
            default=3,
        ))

        self.max_reports = int(get_config_variable(
            "TLP_BLACK_MAX_REPORTS",
            ["tlp_black", "max_reports"],
            config,
            isNumber=True,
            default=0,
        ))

        self.render_retries = int(get_config_variable(
            "TLP_BLACK_RENDER_RETRIES",
            ["tlp_black", "render_retries"],
            config,
            isNumber=True,
            default=3,
        ))

        self.render_url = get_config_variable(
            "RENDER_SERVICE_URL",
            ["connector", "render_service_url"],
            config,
            default="http://pdf-renderer:8080/render",
        )
        self.render_timeout = int(get_config_variable(
            "RENDER_TIMEOUT",
            ["connector", "render_timeout"],
            config,
            isNumber=True,
            default=120,
        ))

        self.confidence = int(get_config_variable(
            "TLP_BLACK_CONFIDENCE",
            ["tlp_black", "confidence"],
            config,
            isNumber=True,
            default=50,
        ))
        self.report_type = get_config_variable(
            "TLP_BLACK_REPORT_TYPE",
            ["tlp_black", "report_type"],
            config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "TLP_BLACK_TLP",
            ["tlp_black", "tlp"],
            config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "TLP_BLACK_AUTHOR_NAME",
            ["tlp_black", "author_name"],
            config,
            default="TLPBLACK",
        )

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA})

        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Create or look up the author identity, marking, and vocabulary."""
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="TLPBLACK — cyber threat intelligence services, data feeds, "
                        "training, tools, and cybersecurity research.",
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

    def _fetch_rss(self):
        """Fetch and parse the RSS feed, returning a list of item dicts."""
        try:
            resp = self.session.get(self.rss_url, timeout=60)
            resp.raise_for_status()
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch RSS feed: {exc}")
            return None

        try:
            root = ElementTree.fromstring(resp.content)
        except ElementTree.ParseError as exc:
            self.helper.log_error(f"Failed to parse RSS XML: {exc}")
            return None

        items = []
        for item_el in root.iter("item"):
            link = (item_el.findtext("link") or "").strip()
            if not link:
                continue

            items.append({
                "title": (item_el.findtext("title") or "").strip(),
                "link": link,
                "description": (item_el.findtext("description") or "").strip(),
                "pub_date": (item_el.findtext("pubDate") or "").strip(),
            })

        return items

    # ------------------------------------------------------------------ #
    # PDF rendering (via centralised render service)
    # ------------------------------------------------------------------ #

    def _render_config(self, url):
        """Build the JSON payload for the render service."""
        return {
            "url": url,
            "content_selector": "article",
            "hide_selectors": STRIP_SELECTORS,
            "timeout_sec": self.render_timeout,
        }

    def _render_via_service(self, url):
        """POST to the render service and return (pdf_bytes, html_bytes, title)."""
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
        """Attempt rendering with exponential backoff."""
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

    def _create_report(self, item, published, pdf_bytes, html_bytes):
        """Create the External Reference, Report, and attach PDF + HTML."""
        url = item["link"]
        name = item["title"] or url
        description = item["description"]
        stix_id = _report_id(url)
        slug = _slug_from_url(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on the TLPBLACK blog",
        )

        report = self.helper.api.report.create(
            stix_id=stix_id,
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

        self.helper.api.stix_domain_object.add_file(
            id=report["id"],
            file_name=f"tlpblack-{slug}.pdf",
            data=pdf_bytes,
            mime_type="application/pdf",
        )

        if html_bytes:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"tlpblack-raw-{slug}.html",
                data=html_bytes,
                mime_type="text/html",
            )

        self.helper.log_info(f"Created Report for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Per-item ingestion
    # ------------------------------------------------------------------ #

    def _ingest_item(self, item):
        """Ingest one RSS item. Returns 'created', 'skipped', or 'failed'."""
        url = item["link"]

        if self.helper.api.report.read(id=_report_id(url)) is not None:
            return "skipped"

        pdf_bytes, html_bytes, _ = self._render_with_retry(url)
        if pdf_bytes is None:
            self.helper.log_warning(
                f"Skipping {url}: render failed after retries."
            )
            return "failed"

        published = _parse_rfc2822(item["pub_date"])
        if not published:
            published = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            self.helper.log_warning(
                f"No usable date for {url}; using ingestion time."
            )

        self._create_report(item, published, pdf_bytes, html_bytes)
        return "created"

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        """Run one full enumeration cycle over the RSS feed."""
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "TLPBLACK blog enumeration run"
        )

        items = self._fetch_rss()
        if items is None:
            self.helper.api.work.to_processed(
                work_id, "RSS fetch failed; will retry next cycle.", in_error=True
            )
            return

        self.helper.log_info(f"RSS feed returned {len(items)} items.")

        processed = 0
        skipped = 0
        failed = 0

        for item in items:
            if self.max_reports and processed >= self.max_reports:
                self.helper.log_info(
                    f"Reached max_reports={self.max_reports}; stopping run."
                )
                break

            outcome = self._ingest_item(item)

            if outcome == "created":
                processed += 1
                time.sleep(self.request_delay)
            elif outcome == "skipped":
                skipped += 1
            elif outcome == "failed":
                failed += 1

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        """Resolve graph references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info("TLPBLACK connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        TlpBlackConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
