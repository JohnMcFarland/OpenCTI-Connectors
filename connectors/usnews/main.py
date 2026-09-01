"""
U.S. News & World Report OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from U.S. News & World Report
(https://www.usnews.com) as container-only OpenCTI Reports, one per article,
with the live source page attached as a full-fidelity Playwright-rendered PDF.

The connector polls multiple RSS feeds across the Money, Health, Education, and
Opinion sections. Content provides economic intelligence, geopolitical context,
and business-world insight relevant to threat motivation analysis and
prediction-market (Kalshi) signal tracking.

Collection model (multi-feed RSS + graph-dedup re-walk)
-------------------------------------------------------
US News publishes per-section RSS feeds at www.usnews.com/rss/{key}. Each feed
is a rolling window of recent articles (100 items), newest-first, with no
pagination. The connector re-walks every configured feed each poll cycle and
relies entirely on graph-driven deduplication to avoid re-ingesting articles:
each article maps to a deterministic Report STIX id (uuid5 over the article
URL), and the connector skips any article whose Report already exists before
rendering.

The origin's CDN (Akamai) aggressively blocks non-browser HTTP clients: both
plain requests and curl time out at the TLS layer with zero bytes received. The
RSS feeds load successfully in a real browser, however, so the connector uses
Playwright for everything — feed fetching and article PDF rendering. The RSS
fetch uses a same-origin JavaScript fetch() from a page already parked on
www.usnews.com, avoiding a full page navigation for each feed.

Article metadata (title, description, publication date, author) comes entirely
from the RSS feed items. Playwright is used purely to render article pages to
PDF; no DOM metadata extraction is needed.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels, no Indicators. This mirrors the
house pattern established by the Unit 42, Trellix, Hellenic Shipping News,
Jamestown, ScienceDaily, and DFIR Report connectors.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (free, publicly published editorial content).
- Author: the single "US News" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band), matching the other OSINT-publisher connectors.
- Feeds: money, health, education, opinion by default; operator-configurable.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import time
import html
import traceback
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside the renderer so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

BROWSER_RECYCLE_EVERY = 50

CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")

MIN_VALID_YEAR = 1990

# Known RSS feed endpoints keyed by short slug.
FEED_MAP = {
    "money": "https://www.usnews.com/rss/money",
    "news": "https://www.usnews.com/rss/news",
    "health": "https://www.usnews.com/rss/health",
    "education": "https://www.usnews.com/rss/education",
    "opinion": "https://www.usnews.com/rss/opinion",
    "travel": "https://www.usnews.com/rss/travel-editorial",
}

# Same-origin fetch evaluated inside a Playwright page already on usnews.com.
_SAME_ORIGIN_FETCH_JS = """
(url) => fetch(url, {credentials: 'same-origin'})
    .then((r) => (r.ok ? r.text() : null))
    .catch(() => null)
"""

# DC namespace used in the feeds.
_DC_NS = "http://purl.org/dc/elements/1.1/"

# Pre-compiled patterns.
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_AUTHOR_PAREN_RE = re.compile(r"\(([^)]+)\)")


# --------------------------------------------------------------------------- #
# Pure helpers (independently testable)
# --------------------------------------------------------------------------- #

def _strip_html(value):
    """Strip HTML tags and decode entities from a text fragment."""
    if not value:
        return ""
    return html.unescape(_HTML_TAG_RE.sub("", value)).strip()


def _parse_author(item):
    """Extract a human-readable author name from an RSS item element.

    The feeds use two formats:
      <author>email@usnews.com (Full Name)</author>
      <dc:creator>Full Name</dc:creator>
    """
    author_el = item.find("author")
    if author_el is not None and author_el.text:
        text = author_el.text.strip()
        match = _AUTHOR_PAREN_RE.search(text)
        if match:
            return match.group(1).strip()
        return text
    creator_el = item.find(f"{{{_DC_NS}}}creator")
    if creator_el is not None and creator_el.text:
        return creator_el.text.strip()
    return None


def _published_iso(raw):
    """Parse an RFC-822 <pubDate> to ISO 8601 UTC, or None.

    RSS dates look like "Fri, 31 Jul 2026 10:00:18 +0000".
    """
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None or dt.year < MIN_VALID_YEAR:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _report_id(link):
    """Deterministic Report STIX id derived from the article URL."""
    return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))


def _parse_feed_xml(xml_text, feed_key):
    """Parse RSS XML into a list of item dicts.

    Args:
        xml_text: raw RSS XML string.
        feed_key: feed slug (e.g. "money") attached to each item for provenance.

    Returns:
        list[dict]: parsed items, each with keys link, title, description,
        published, author, feed.

    Raises:
        ET.ParseError: if the XML is malformed.
    """
    root = ET.fromstring(xml_text)
    items = []
    for item in root.iter("item"):
        link_el = item.find("link")
        link = (link_el.text or "").strip() if link_el is not None else ""
        if not link:
            continue
        title_el = item.find("title")
        desc_el = item.find("description")
        date_el = item.find("pubDate")
        items.append({
            "link": link,
            "title": _strip_html(title_el.text if title_el is not None else "") or link,
            "description": _strip_html(desc_el.text if desc_el is not None else ""),
            "published": _published_iso(date_el.text if date_el is not None else None),
            "author": _parse_author(item),
            "feed": feed_key,
        })
    return items


class USNewsConnector:
    """External-import connector that mirrors US News articles into Reports."""

    def __init__(self):
        config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        # --- Feed configuration ------------------------------------------- #
        feeds_raw = get_config_variable(
            "USNEWS_FEEDS", ["usnews", "feeds"], config,
            default="money,health,education,opinion",
        )
        self.feeds = [
            key.strip().lower()
            for key in str(feeds_raw).split(",")
            if key.strip().lower() in FEED_MAP
        ]
        if not self.feeds:
            raise ValueError(
                f"USNEWS_FEEDS resolved to no valid feed keys; "
                f"available: {', '.join(sorted(FEED_MAP))}."
            )

        self.poll_interval = get_config_variable(
            "USNEWS_POLL_INTERVAL", ["usnews", "poll_interval"], config,
            isNumber=True, default=86400,
        )
        self.request_delay = get_config_variable(
            "USNEWS_REQUEST_DELAY", ["usnews", "request_delay"], config,
            isNumber=True, default=3,
        )
        self.max_reports = get_config_variable(
            "USNEWS_MAX_REPORTS", ["usnews", "max_reports"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ----------------------------------------- #
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["usnews", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "USNEWS_RENDER_RETRIES", ["usnews", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ----------------------------------- #
        self.confidence = get_config_variable(
            "USNEWS_CONFIDENCE", ["usnews", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "USNEWS_REPORT_TYPE", ["usnews", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "USNEWS_TLP", ["usnews", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "USNEWS_AUTHOR_NAME", ["usnews", "author_name"], config,
            default="US News",
        )

        # HTTP session for optimistic RSS fetch (usually CDN-blocked; the
        # browser path is the real workhorse).
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "application/rss+xml, application/xml, text/xml, */*",
        })

        self.author_id = None
        self.marking_id = None
        self._work_id = None

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="U.S. News & World Report. Source organization for "
                        "ingested economic, geopolitical, and editorial reports.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved author identity '{self.author_name}': {self.author_id}")

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
            self.helper.log_info(f"Ensured report_type vocabulary value: {self.report_type}")
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc}). "
                f"Add it under Settings -> Taxonomies -> Report types if missing."
            )

    # ------------------------------------------------------------------ #
    # RSS feed enumeration
    # ------------------------------------------------------------------ #

    def _fetch_feed(self, page, feed_key):
        """Fetch and parse one RSS feed into a list of item dicts.

        Tries a direct HTTP GET first (cheap); falls back to a same-origin
        fetch() evaluated inside the supplied Playwright page when the CDN
        blocks the programmatic client.

        Args:
            page: a Playwright page already navigated to www.usnews.com.
            feed_key: key into FEED_MAP (e.g. "money").

        Returns:
            list[dict]: parsed items. Returns [] on failure.
        """
        feed_url = FEED_MAP[feed_key]
        xml_text = None

        try:
            resp = self.session.get(feed_url, timeout=10)
            if resp.status_code == 200 and resp.content.strip():
                xml_text = resp.text
            else:
                self.helper.log_info(
                    f"Direct fetch of {feed_key} feed returned HTTP "
                    f"{resp.status_code}; falling back to browser."
                )
        except Exception as exc:  # noqa: BLE001
            self.helper.log_info(
                f"Direct fetch of {feed_key} feed failed ({type(exc).__name__}); "
                f"falling back to browser."
            )

        if xml_text is None:
            try:
                xml_text = page.evaluate(_SAME_ORIGIN_FETCH_JS, feed_url)
            except Exception as exc:  # noqa: BLE001
                self.helper.log_error(f"Browser fetch of {feed_key} feed raised: {exc}")
                return []
            if not xml_text:
                self.helper.log_error(f"Browser fetch of {feed_key} feed returned no body.")
                return []
            self.helper.log_info(f"Feed '{feed_key}' retrieved via browser fallback.")

        try:
            return _parse_feed_xml(xml_text, feed_key)
        except ET.ParseError as exc:
            self.helper.log_error(f"Feed {feed_key} returned unparseable XML: {exc}")
            return []

    def _collect_items(self, page):
        """Collect items across all configured feeds, deduplicating by URL.

        Args:
            page: Playwright page for same-origin feed fetches.

        Returns:
            list[dict]: deduplicated items across all feeds.
        """
        seen = set()
        all_items = []
        for feed_key in self.feeds:
            items = self._fetch_feed(page, feed_key)
            self.helper.log_info(f"Feed '{feed_key}': {len(items)} items.")
            for item in items:
                if item["link"] not in seen:
                    seen.add(item["link"])
                    all_items.append(item)
        return all_items

    # ------------------------------------------------------------------ #
    # PDF rendering (Playwright)
    # ------------------------------------------------------------------ #

    def _auto_scroll(self, page):
        """Scroll to the page bottom to trigger lazy-loaded media before render.

        Guards against infinite-scroll pages with both a pixel cap (maxScroll)
        and a wall-clock cap (maxTimeMs). Whichever fires first stops the scroll
        and resets to the top.
        """
        page.evaluate(
            """
            async () => {
              await new Promise((resolve) => {
                let total = 0;
                const step = 400;
                const maxScroll = 100000;
                const maxTimeMs = 15000;
                const start = Date.now();
                const timer = setInterval(() => {
                  window.scrollBy(0, step);
                  total += step;
                  if (total >= document.body.scrollHeight
                      || total >= maxScroll
                      || Date.now() - start > maxTimeMs) {
                    clearInterval(timer);
                    window.scrollTo(0, 0);
                    resolve();
                  }
                }, 100);
              });
            }
            """
        )

    def _render_pdf(self, browser, url):
        """Render an article page to PDF.

        Mirrors the Trellix connector render path: fresh context per page,
        networkidle wait, challenge/block detection, auto-scroll, settle, PDF.
        No footer is rendered.
        """
        context = browser.new_context(
            viewport={"width": 1280, "height": 1696},
            user_agent=BROWSER_UA,
        )
        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)

            title = (page.title() or "").lower()
            if any(marker in title for marker in CHALLENGE_MARKERS):
                raise RuntimeError("Edge challenge interstitial detected")

            if "blocked" in title:
                raise RuntimeError("Bot detection block page detected")

            self._auto_scroll(page)
            page.wait_for_timeout(1500)

            return page.pdf(
                print_background=True,
                margin={"top": "10mm", "bottom": "10mm", "left": "8mm", "right": "8mm"},
                format="A4",
            )
        finally:
            page.close()
            context.close()

    def _render_with_retry(self, browser, url):
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._render_pdf(browser, url)
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(
                    f"Render attempt {attempt}/{self.render_retries} failed for {url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
        return None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, item, pdf_bytes):
        url = item["link"]
        name = item["title"] or url
        description = item["description"]
        if item.get("author"):
            description = f"By {item['author']}. {description}" if description else f"By {item['author']}."
        published = item["published"]
        if not published:
            published = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
            self.helper.log_warning(f"No usable pubDate for {url}; using ingestion time.")

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description=f"Source article on usnews.com ({item['feed']} section)",
        )

        report = self.helper.api.report.create(
            stix_id=_report_id(url),
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

        path = url.rstrip("/").rsplit("/", 1)[-1] or "article"
        file_name = f"usnews-{item['feed']}-{path}.pdf"
        if len(file_name) > 200:
            file_name = file_name[:196] + ".pdf"

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
        from playwright.sync_api import sync_playwright  # lazy import

        self._work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "US News enumeration run"
        )
        self.helper.log_info(
            f"Starting feed walk (feeds={','.join(self.feeds)}, "
            f"request_delay={self.request_delay}s, "
            f"max_reports={self.max_reports or 'unlimited'})."
        )

        processed = 0
        skipped = 0
        failed = 0
        items = []

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                bootstrap_ctx = browser.new_context(user_agent=BROWSER_UA)
                try:
                    bootstrap_page = bootstrap_ctx.new_page()
                    try:
                        bootstrap_page.goto(
                            "https://www.usnews.com/",
                            wait_until="domcontentloaded",
                            timeout=self.nav_timeout_ms,
                        )
                    except Exception as exc:  # noqa: BLE001
                        self.helper.log_warning(
                            f"Could not park a page on usnews.com ({exc}); "
                            f"same-origin feed fetch may be unavailable this cycle."
                        )
                    items = self._collect_items(bootstrap_page)
                finally:
                    bootstrap_ctx.close()

                self.helper.log_info(
                    f"Collected {len(items)} unique articles across "
                    f"{len(self.feeds)} feeds."
                )

                for item in items:
                    url = item["link"]

                    if self.max_reports and processed >= self.max_reports:
                        self.helper.log_info(
                            f"Reached USNEWS_MAX_REPORTS={self.max_reports}; stopping run."
                        )
                        break

                    if self.helper.api.report.read(id=_report_id(url)) is not None:
                        skipped += 1
                        continue

                    if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                        browser.close()
                        browser = pw.chromium.launch(
                            args=["--no-sandbox", "--disable-dev-shm-usage"]
                        )
                        renders_since_recycle = 0

                    pdf_bytes = self._render_with_retry(browser, url)
                    renders_since_recycle += 1

                    if pdf_bytes is None:
                        failed += 1
                        self.helper.log_warning(f"Skipping {url}: render failed after retries.")
                        continue

                    self._create_report(item, pdf_bytes)
                    processed += 1
                    time.sleep(self.request_delay)
            finally:
                browser.close()

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render), out of {len(items)} unique articles."
        )
        self.helper.api.work.to_processed(self._work_id, message)
        self.helper.log_info(message)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info(
            f"US News connector started (feeds={','.join(self.feeds)})."
        )
        while True:
            self._work_id = None
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001
                self.helper.log_error(
                    f"Unhandled error during run: {exc}\n{traceback.format_exc()}"
                )
                if self._work_id:
                    try:
                        self.helper.api.work.to_processed(
                            self._work_id,
                            f"Run failed with unhandled error: {exc}",
                        )
                    except Exception:  # noqa: BLE001
                        pass
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        USNewsConnector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
