"""
MERICS (Mercator Institute for China Studies) OpenCTI connector.

Purpose
-------
External-import connector that ingests Reports and Briefs from MERICS
(https://merics.org/en/) and creates one OpenCTI Report container per
article. Each Report carries a rendered PDF and raw HTML snapshot of the
article page (via the centralised pdf-renderer service) plus the native
publication PDF that MERICS attaches to the article.

Collection model
----------------
MERICS runs on Drupal 11 behind Cloudflare (CDN-only, no bot challenge).
The English sitemap at /en/sitemap.xml is a single <urlset>. The connector
keeps only article URLs under:
  - /en/report/<slug>         -> Reports (~182)
  - /en/merics-briefs/<slug>  -> Briefs (~261 across 3 sub-series)

No cursor is persisted. The corpus is small (~443) and Drupal rewrites
<lastmod> whenever a node is edited, so a lastmod cursor would be both
unstable and able to skip past failed articles. Every poll re-walks the
sitemap and dedups against the graph.

Deduplication
-------------
Dedup keys on a deterministic Report STIX id (uuid5 over the article URL).
report.read(id) runs before any page fetch; anything already present is
skipped, and anything that failed is retried automatically next poll.

Failure handling
----------------
Permanent failures (404/410, missing title, missing publication date)
raise _SkipArticle and are never retried. Transient failures (HTTP
errors, render-service errors, native PDF download errors) are retried
with exponential backoff; if all attempts fail, nothing is written so the
article is picked up again on the next poll.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain
Objects, no Observables, no Relationships, no Labels.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (free, publicly published source).
- Author: "MERICS" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band).
- Published: the article's own date-published field; never ingestion time.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import base64
import os
import re
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from urllib.parse import unquote, urljoin, urlparse
from xml.etree import ElementTree as ET

import requests
import yaml
from bs4 import BeautifulSoup
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

_ARTICLE_PATH_RE = re.compile(
    r"^/en/(?P<type>report|merics-briefs)/(?P<slug>[^/]+)/?$",
    re.IGNORECASE,
)

CONTENT_SELECTOR = "article.content--type-microsite"
DATE_SELECTOR = ".block-field-blocknodemicrositefield-date-published time[datetime]"
NATIVE_PDF_SELECTOR = ".block-field-blocknodemicrositefield-download a.file-download-pdf"

STRIP_SELECTORS = [
    ".block-mrcs-common-node-share-block",
    ".block-chinaupdatenewsletter",
    ".sub-button.block-mrcs-common-subscribe-newsletter-block",
    ".block-mericschinabriefing",
    ".block-newpaperonchina",
    ".block-new-paper-on-china-mobile",
    ".block-extra-field-blocknodemicrositerelated-content-about-term-entity-view-1",
    ".view-table-of-content-block",
    ".block-extra-field-blocknodemicrositereading-time",
    ".block-social-media-links",
    ".footer-wrapper",
    ".content-bottom",
    "header.header",
]

MAX_DESCRIPTION_CHARS = 2000

# MERICS was founded in 2013; anything earlier is a parsing artefact.
MIN_VALID_YEAR = 2013


class _SkipArticle(Exception):
    """Permanent failure: retrying will not help."""


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _report_id(url):
    return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))


def _article_match(url, host):
    """Return the path match for an in-scope article URL on `host`, else None."""
    parsed = urlparse(url)
    if parsed.netloc.lower() != host:
        return None
    return _ARTICLE_PATH_RE.match(parsed.path)


def _local_name(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _parse_iso_datetime(text):
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if dt.year < MIN_VALID_YEAR:
        return None
    return dt.astimezone(timezone.utc)


def _truncate(text, limit=MAX_DESCRIPTION_CHARS):
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "..."


def _meta_content(soup, selector):
    tag = soup.select_one(selector)
    if tag and tag.get("content"):
        return tag["content"].strip()
    return None


def _extract_metadata(page_html, url):
    """Parse title, description, publication date and native PDF link."""
    soup = BeautifulSoup(page_html, "html.parser")

    title = _meta_content(soup, 'meta[property="og:title"]')
    if not title:
        h1 = soup.select_one("h1")
        title = h1.get_text(strip=True) if h1 else None

    description = (
        _meta_content(soup, 'meta[name="description"]')
        or _meta_content(soup, 'meta[property="og:description"]')
        or ""
    )

    time_tag = soup.select_one(DATE_SELECTOR)
    published = _parse_iso_datetime(time_tag.get("datetime")) if time_tag else None

    pdf_link = soup.select_one(NATIVE_PDF_SELECTOR)
    pdf_url = urljoin(url, pdf_link["href"]) if pdf_link and pdf_link.get("href") else None

    return {
        "title": title,
        "description": _truncate(description),
        "published": published,
        "pdf_url": pdf_url,
    }


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

class MericsConnector:

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
            "MERICS_BASE_URL", ["merics", "base_url"], config,
            default="https://merics.org",
        ).rstrip("/")
        self.host = urlparse(self.base_url).netloc.lower()

        self.sitemap_url = get_config_variable(
            "MERICS_SITEMAP_URL", ["merics", "sitemap_url"], config,
            default="",
        ) or f"{self.base_url}/en/sitemap.xml"

        self.poll_interval = get_config_variable(
            "MERICS_POLL_INTERVAL", ["merics", "poll_interval"], config,
            isNumber=True, default=86400,
        )
        self.request_delay = get_config_variable(
            "MERICS_REQUEST_DELAY", ["merics", "request_delay"], config,
            isNumber=True, default=3,
        )
        self.max_reports = get_config_variable(
            "MERICS_MAX_REPORTS", ["merics", "max_reports"], config,
            isNumber=True, default=0,
        )
        self.render_retries = get_config_variable(
            "MERICS_RENDER_RETRIES", ["merics", "render_retries"], config,
            isNumber=True, default=3,
        )
        self.confidence = get_config_variable(
            "MERICS_CONFIDENCE", ["merics", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "MERICS_REPORT_TYPE", ["merics", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "MERICS_TLP", ["merics", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "MERICS_AUTHOR_NAME", ["merics", "author_name"], config,
            default="MERICS",
        )

        self.render_url = get_config_variable(
            "RENDER_SERVICE_URL", ["connector", "render_service_url"], config,
            default="http://pdf-renderer:8080/render",
        )
        self.render_timeout = int(get_config_variable(
            "RENDER_TIMEOUT", ["connector", "render_timeout"], config,
            isNumber=True, default=120,
        ))

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA})

        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Init
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description=(
                "Mercator Institute for China Studies (MERICS). Independent "
                "German research institute providing analysis and policy advice "
                "on China for European audiences."
            ),
        )
        self.author_id = author["id"]
        self.helper.log_info(
            f"Resolved author '{self.author_name}': {self.author_id}"
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
                f"Could not resolve marking '{self.tlp_name}'. Refusing to "
                f"create Reports without a resolved marking UUID."
            )
        self.marking_id = marking["id"]
        self.helper.log_info(f"Resolved marking {self.tlp_name}: {self.marking_id}")

        try:
            self.helper.api.vocabulary.create(
                name=self.report_type,
                category="report_types_ov",
                description="Open-source reporting from public OSINT publishers.",
            )
        except Exception as exc:
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc})."
            )

    # ------------------------------------------------------------------ #
    # Sitemap
    # ------------------------------------------------------------------ #

    def _enumerate_posts(self):
        """Return in-scope article URLs in sitemap order, or None on failure."""
        try:
            resp = self.session.get(
                self.sitemap_url, timeout=90,
                headers={"Accept": "application/xml, text/xml, */*"},
            )
            resp.raise_for_status()
            root = ET.fromstring(resp.content)
        except Exception as exc:
            self.helper.log_error(f"Sitemap unavailable ({self.sitemap_url}): {exc}")
            return None

        urls = []
        seen = set()
        for el in root.iter():
            if _local_name(el.tag) != "loc":
                continue
            loc = (el.text or "").strip()
            if loc in seen or not _article_match(loc, self.host):
                continue
            seen.add(loc)
            urls.append(loc)
        return urls

    # ------------------------------------------------------------------ #
    # PDF acquisition
    # ------------------------------------------------------------------ #

    def _render_config(self, url):
        return {
            "url": url,
            "content_selector": CONTENT_SELECTOR,
            "hide_selectors": STRIP_SELECTORS,
            "timeout_sec": self.render_timeout,
        }

    def _render_via_service(self, url):
        """POST to the render service and return (pdf_bytes, html_bytes)."""
        resp = self.session.post(
            self.render_url,
            json=self._render_config(url),
            timeout=self.render_timeout + 30,
        )
        resp.raise_for_status()
        data = resp.json()
        return base64.b64decode(data["pdf"]), base64.b64decode(data["html"])

    def _download_native_pdf(self, pdf_url):
        """Return native PDF bytes, or None when MERICS links a dead file."""
        resp = self.session.get(pdf_url, timeout=120)
        if resp.status_code in (404, 410):
            self.helper.log_warning(
                f"Native PDF link is dead (HTTP {resp.status_code}): {pdf_url}"
            )
            return None
        resp.raise_for_status()
        if not resp.content.startswith(b"%PDF"):
            raise RuntimeError(f"Native PDF at {pdf_url} is not a PDF")
        return resp.content

    # ------------------------------------------------------------------ #
    # Article loading
    # ------------------------------------------------------------------ #

    def _load_article(self, url):
        """Fetch, validate and acquire all attachments for one article."""
        resp = self.session.get(url, timeout=60)
        if resp.status_code in (404, 410):
            raise _SkipArticle(f"HTTP {resp.status_code}")
        resp.raise_for_status()

        metadata = _extract_metadata(resp.text, url)
        if not metadata["title"]:
            raise _SkipArticle("no title on page")
        if metadata["published"] is None:
            raise _SkipArticle("no date-published field on page")

        # Native download first: it is far cheaper than a render, so a
        # transient native failure doesn't burn a render on every retry.
        metadata["native_pdf"] = (
            self._download_native_pdf(metadata["pdf_url"])
            if metadata["pdf_url"] else None
        )
        metadata["pdf"], metadata["html"] = self._render_via_service(url)
        return metadata

    def _load_with_retry(self, url):
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._load_article(url)
            except _SkipArticle:
                raise
            except Exception as exc:
                self.helper.log_warning(
                    f"Attempt {attempt}/{self.render_retries} failed for "
                    f"{url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
        return None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, url, article):
        name = article["title"]
        description = article["description"]
        published = article["published"].strftime("%Y-%m-%dT%H:%M:%S+00:00")

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on merics.org",
        )

        report_types = classify_report(
            title=name, description=description, content=description,
            source="MERICS", source_url=url,
            default_types=[self.report_type],
        )

        report = self.helper.api.report.create(
            stix_id=_report_id(url),
            name=name,
            description=description,
            published=published,
            report_types=report_types,
            confidence=self.confidence,
            createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[external_reference["id"]],
            update=True,
        )

        match = _article_match(url, self.host)
        prefix = f"merics-{match.group('type').lower()}"
        slug = match.group("slug")

        attachments = [
            (f"{prefix}-rendered-{slug}.pdf", article["pdf"], "application/pdf"),
            (f"{prefix}-raw-{slug}.html", article["html"], "text/html"),
        ]
        if article["native_pdf"]:
            native_name = unquote(urlparse(article["pdf_url"]).path.rsplit("/", 1)[-1])
            attachments.append((native_name, article["native_pdf"], "application/pdf"))

        for file_name, data, mime_type in attachments:
            if data:
                self.helper.api.stix_domain_object.add_file(
                    id=report["id"], file_name=file_name,
                    data=data, mime_type=mime_type,
                )

        self.helper.log_info(
            f"Created Report for {url} ({name[:80]}) published {published[:10]}"
        )

    # ------------------------------------------------------------------ #
    # Per-article ingestion
    # ------------------------------------------------------------------ #

    def _ingest_post(self, url):
        """Return 'created', 'skipped', 'invalid' or 'failed'."""
        if self.helper.api.report.read(id=_report_id(url)) is not None:
            return "skipped"

        try:
            article = self._load_with_retry(url)
        except _SkipArticle as exc:
            self.helper.log_warning(f"Skipping {url} permanently: {exc}")
            return "invalid"

        if article is None:
            self.helper.log_warning(f"Skipping {url}: load failed after retries.")
            return "failed"

        self._create_report(url, article)
        return "created"

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        self._work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "MERICS enumeration run"
        )

        urls = self._enumerate_posts()
        if urls is None:
            self.helper.api.work.to_processed(
                self._work_id, "Sitemap unavailable; retrying next poll.",
                in_error=True,
            )
            return

        self.helper.log_info(f"Sitemap yielded {len(urls)} in-scope posts.")

        counts = {"created": 0, "skipped": 0, "invalid": 0, "failed": 0}
        for url in urls:
            if self.max_reports and counts["created"] >= self.max_reports:
                self.helper.log_info(
                    f"Reached MERICS_MAX_REPORTS={self.max_reports}; stopping."
                )
                break
            outcome = self._ingest_post(url)
            counts[outcome] += 1
            if outcome != "skipped":
                time.sleep(self.request_delay)

        msg = (
            f"Run complete: {counts['created']} created, "
            f"{counts['skipped']} already present, {counts['invalid']} invalid, "
            f"{counts['failed']} failed, out of {len(urls)} in-scope posts."
        )
        self.helper.api.work.to_processed(self._work_id, msg)
        self.helper.log_info(msg)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("MERICS connector started.")
        while True:
            self._work_id = None
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(
                    f"Unhandled error: {exc}\n{traceback.format_exc()}"
                )
                if self._work_id:
                    try:
                        self.helper.api.work.to_processed(
                            self._work_id, f"Run failed: {exc}", in_error=True
                        )
                    except Exception:
                        pass
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        MericsConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
