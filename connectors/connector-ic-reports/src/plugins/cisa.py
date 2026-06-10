"""
plugins/cisa.py
CISA (Cybersecurity and Infrastructure Security Agency) plugin.

Discovery:  RSS/Atom feeds (CISA provides several structured feeds)
Content:    Advisories, alerts, ICS advisories — PDF or HTML
Author:     Cybersecurity and Infrastructure Security Agency

CISA feeds:
  - Advisories: https://www.cisa.gov/cybersecurity-advisories/all.xml
  - ICS:        https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml
  - Alerts:     https://www.cisa.gov/cybersecurity-advisories/alerts.xml

PDF filtering rules:
  - Only download PDFs hosted on cisa.gov (skip external partner domains)
  - Skip PDFs under /sites/default/files/publications/ (CISA's static reference
    document library — these are generic background docs, not advisory content)
  - Advisory PDFs are typically under date-structured paths e.g. /files/2026-/
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

import feedparser
from bs4 import BeautifulSoup

from base_plugin import BasePlugin, EnrichedReport, RawReport
from http_client import build_session, fetch_pdf, safe_get

logger = logging.getLogger(__name__)

DEFAULT_FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
]

CISA_BASE = "https://www.cisa.gov"

# PDF paths that indicate generic reference/background documents rather than
# primary advisory content. These appear as supplementary links on many pages.
EXCLUDED_PDF_PATHS = [
    "/sites/default/files/publications/",  # Static reference document library
    "/sites/default/files/resources/",     # Generic resource documents
]


class CISAPlugin(BasePlugin):
    name = "CISA"
    author_name = "Cybersecurity and Infrastructure Security Agency"
    default_marking = "TLP:CLEAR"
    report_type = "industry-alert"
    confidence = 85

    def __init__(self, config: dict, logger: logging.Logger):
        super().__init__(config, logger)
        self.session = build_session()
        self.feeds = self.get_config("feeds", DEFAULT_FEEDS)
        self.max_per_run = self.get_config("max_per_run", 20)

    def fetch_new_reports(self) -> list[RawReport]:
        """
        Parse RSS feeds and return reports up to max_per_run.
        Deduplication is handled by report_builder via graph lookup —
        all discovered reports are returned regardless of prior runs.
        """
        discovered = []

        for feed_url in self.feeds:
            self.log.info("Polling CISA feed: %s", feed_url)
            try:
                resp = safe_get(self.session, feed_url)
                if resp is None:
                    continue
                feed = feedparser.parse(resp.text)
            except Exception as e:
                self.log.warning("Failed to parse CISA feed %s: %s", feed_url, e)
                continue

            for entry in feed.entries:
                raw = self._entry_to_raw(entry)
                if raw is None:
                    continue
                discovered.append(raw)

        return discovered[: self.max_per_run]

    def enrich_report(self, raw: RawReport) -> Optional[EnrichedReport]:
        """
        Fetch the advisory page, attempt PDF download from cisa.gov only,
        applying path exclusions to avoid attaching generic reference docs.
        Falls back gracefully if no suitable PDF is found.
        """
        resp = safe_get(self.session, raw.url)
        if resp is None:
            self.log.warning("Could not fetch CISA advisory: %s", raw.url)
            return None

        soup = BeautifulSoup(resp.text, "html.parser")
        pdf_bytes, pdf_filename = self._find_and_download_pdf(soup, raw.url)
        summary = self._extract_summary(soup) or raw.summary
        published = self._resolve_date(soup) or raw.published
        labels = self._extract_labels(soup, raw)

        return EnrichedReport(
            raw=raw,
            pdf_bytes=pdf_bytes,
            pdf_filename=pdf_filename,
            html_content=resp.text if not pdf_bytes else None,
            author_name=self.author_name,
            marking=self.default_marking,
            report_type=self.report_type,
            labels=labels,
            resolved_published=published,
        )

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _entry_to_raw(self, entry) -> Optional[RawReport]:
        """Convert a feedparser entry into a RawReport."""
        try:
            url = entry.get("link", "")
            if not url:
                return None
            title = entry.get("title", "Untitled CISA Advisory").strip()
            summary = entry.get("summary", "")
            # Strip HTML tags from RSS summary field
            summary = BeautifulSoup(summary, "html.parser").get_text(separator=" ").strip()

            published = None
            if hasattr(entry, "published"):
                try:
                    published = parsedate_to_datetime(entry.published)
                    if published.tzinfo is None:
                        published = published.replace(tzinfo=timezone.utc)
                except Exception:
                    pass

            return RawReport(
                url=url,
                title=title,
                published=published,
                summary=summary[:500] if summary else None,
                meta={"tags": [t.term for t in getattr(entry, "tags", [])]},
            )
        except Exception as e:
            self.log.debug("Failed to parse feed entry: %s", e)
            return None

    def _find_and_download_pdf(
        self, soup: BeautifulSoup, page_url: str
    ) -> tuple[Optional[bytes], Optional[str]]:
        """
        Locate and download the primary advisory PDF from the page.

        Filtering rules applied in order:
        1. Only cisa.gov hosted PDFs (skip external partner domains)
        2. Skip paths matching EXCLUDED_PDF_PATHS (generic reference docs)

        Advisory PDFs are typically under date-structured paths like
        /sites/default/files/2026-02/ rather than /publications/.
        """
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if not href.lower().endswith(".pdf"):
                continue

            pdf_url = urljoin(page_url, href)
            parsed = urlparse(pdf_url)

            # Rule 1: only download from cisa.gov
            if not parsed.netloc.endswith("cisa.gov"):
                self.log.debug("Skipping external PDF domain: %s", parsed.netloc)
                continue

            # Rule 2: skip generic reference document paths
            path_lower = parsed.path.lower()
            if any(excl in path_lower for excl in EXCLUDED_PDF_PATHS):
                self.log.debug("Skipping reference document PDF: %s", pdf_url)
                continue

            # This looks like a primary advisory PDF — attempt download
            self.log.debug("Found advisory PDF link: %s", pdf_url)
            pdf_bytes = fetch_pdf(self.session, pdf_url)
            if pdf_bytes:
                filename = pdf_url.split("/")[-1]
                return pdf_bytes, filename

        return None, None

    def _extract_summary(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract a clean text summary from the advisory page body."""
        content_div = soup.find(
            "div",
            class_=re.compile(r"(field--body|advisory-body|views-field-body)", re.I)
        )
        if content_div:
            return content_div.get_text(separator=" ").strip()[:1000]
        # Fallback to meta description tag
        meta = soup.find("meta", {"name": "description"})
        if meta and meta.get("content"):
            return meta["content"].strip()
        return None

    def _resolve_date(self, soup: BeautifulSoup) -> Optional[datetime]:
        """
        Extract publication date from the advisory page.
        Tries structured <time> element first, falls back to text pattern matching.
        """
        # Prefer machine-readable <time datetime="..."> element
        time_tag = soup.find("time", {"datetime": True})
        if time_tag:
            try:
                dt = datetime.fromisoformat(time_tag["datetime"].replace("Z", "+00:00"))
                return dt
            except ValueError:
                pass

        # Fall back to common date text patterns in page body
        date_patterns = [
            r"(\w+ \d{1,2},\s*\d{4})",   # e.g. "February 20, 2026"
            r"(\d{4}-\d{2}-\d{2})",       # e.g. "2026-02-20"
        ]
        page_text = soup.get_text()
        for pattern in date_patterns:
            match = re.search(pattern, page_text)
            if match:
                try:
                    return datetime.strptime(
                        match.group(1), "%B %d, %Y"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    try:
                        return datetime.strptime(
                            match.group(1), "%Y-%m-%d"
                        ).replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue
        return None

    def _extract_labels(self, soup: BeautifulSoup, raw: RawReport) -> list[str]:
        """
        Derive OpenCTI labels from URL structure and RSS tags.
        Labels help analysts filter by advisory type in the UI.
        """
        labels = ["CISA"]
        url_lower = raw.url.lower()
        if "ics" in url_lower:
            labels.append("ICS")
        if "alert" in url_lower:
            labels.append("Alert")
        if "advisory" in url_lower:
            labels.append("Advisory")
        # Include up to 3 RSS tags to avoid label explosion
        tags = raw.meta.get("tags", [])
        labels.extend(tags[:3])
        return list(set(labels))
