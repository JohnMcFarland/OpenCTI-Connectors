"""Trellix blog OpenCTI connector (curl_cffi + BS4 + WeasyPrint, no Playwright)."""

import os
import re
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from bs4 import BeautifulSoup
from curl_cffi import requests as cfreq
import weasyprint
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

MIN_VALID_YEAR = 2000

_POST_URL_RE = re.compile(
    r"^https?://[^/]+/blogs/(?P<category>[a-z0-9][a-z0-9-]*)/(?P<slug>[^/]+)/?$",
    re.IGNORECASE,
)

_DATELINE_DATE_RE = re.compile(r"\b([A-Za-z]{3,9})\.?\s+(\d{1,2}),\s*(\d{4})(?!\d)")
_UPDATED_PREFIX_RE = re.compile(r"updated\W*$", re.IGNORECASE)

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def _escape_html(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _local_name(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _date_from_dateline(dateline):
    if not dateline:
        return None
    for match in _DATELINE_DATE_RE.finditer(dateline):
        month = _MONTHS.get(match.group(1)[:3].lower())
        if month is None:
            continue
        preceding = dateline[max(0, match.start() - 14):match.start()]
        if _UPDATED_PREFIX_RE.search(preceding):
            continue
        day, year = int(match.group(2)), int(match.group(3))
        if not MIN_VALID_YEAR <= year <= datetime.now(timezone.utc).year + 1:
            continue
        try:
            return datetime(year, month, day, tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _date_from_release_meta(raw):
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed.year < MIN_VALID_YEAR:
        return None
    return parsed.astimezone(timezone.utc)


class TrellixBlogConnector:

    def __init__(self):
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.base_url = (
            get_config_variable(
                "TRELLIX_BASE_URL", ["trellix_blog", "base_url"], config,
                default="https://www.trellix.com",
            ) or "https://www.trellix.com"
        ).rstrip("/")

        self.sitemap_url = get_config_variable(
            "TRELLIX_SITEMAP_URL", ["trellix_blog", "sitemap_url"], config,
            default="",
        ) or f"{self.base_url}/en-us.sitemap.xml"

        categories_raw = get_config_variable(
            "TRELLIX_CATEGORIES", ["trellix_blog", "categories"], config,
            default="research,platform",
        )
        self.categories = [
            slug.strip().strip("/").lower()
            for slug in str(categories_raw).split(",")
            if slug.strip().strip("/")
        ]
        if not self.categories:
            raise ValueError("TRELLIX_CATEGORIES resolved to an empty list")

        self.poll_interval = get_config_variable(
            "TRELLIX_POLL_INTERVAL", ["trellix_blog", "poll_interval"], config,
            isNumber=True, default=86400,
        )
        self.request_delay = get_config_variable(
            "TRELLIX_REQUEST_DELAY", ["trellix_blog", "request_delay"], config,
            isNumber=True, default=3,
        )
        self.max_reports = get_config_variable(
            "TRELLIX_MAX_REPORTS", ["trellix_blog", "max_reports"], config,
            isNumber=True, default=0,
        )
        self.render_retries = get_config_variable(
            "TRELLIX_RENDER_RETRIES", ["trellix_blog", "render_retries"], config,
            isNumber=True, default=3,
        )
        self.confidence = get_config_variable(
            "TRELLIX_CONFIDENCE", ["trellix_blog", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "TRELLIX_REPORT_TYPE", ["trellix_blog", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "TRELLIX_TLP", ["trellix_blog", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "TRELLIX_AUTHOR_NAME", ["trellix_blog", "author_name"], config,
            default="Trellix",
        )

        self.session = cfreq.Session(impersonate="chrome")
        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Init
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization", name=self.author_name,
            description="Trellix threat intelligence and research.",
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
            raise RuntimeError(f"Could not resolve marking '{self.tlp_name}'")
        self.marking_id = marking["id"]
        self.helper.log_info(f"Resolved marking {self.tlp_name}: {self.marking_id}")

        try:
            self.helper.api.vocabulary.create(
                name=self.report_type, category="report_types_ov",
                description="Open-source reporting from public OSINT publishers.",
            )
        except Exception as exc:
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc})."
            )

    # ------------------------------------------------------------------ #
    # Sitemap
    # ------------------------------------------------------------------ #

    def _fetch_sitemap(self):
        try:
            resp = self.session.get(
                self.sitemap_url, timeout=90,
                headers={"Accept": "application/xml, text/xml, */*"},
            )
            if resp.status_code == 200 and resp.content.strip():
                return resp.text
            self.helper.log_error(
                f"Sitemap returned HTTP {resp.status_code}"
            )
        except Exception as exc:
            self.helper.log_error(f"Sitemap fetch failed: {exc}")
        return None

    def _enumerate_posts(self):
        xml = self._fetch_sitemap()
        if xml is None:
            return None
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            self.helper.log_error(f"Sitemap XML parse error: {exc}")
            return None

        entries = []
        seen = set()
        for url_el in root.iter():
            if _local_name(url_el.tag) != "url":
                continue
            loc = lastmod = ""
            for child in url_el:
                name = _local_name(child.tag)
                if name == "loc":
                    loc = (child.text or "").strip()
                elif name == "lastmod":
                    lastmod = (child.text or "").strip()
            if not loc or loc in seen:
                continue
            match = _POST_URL_RE.match(loc)
            if not match or match.group("category").lower() not in self.categories:
                continue
            seen.add(loc)
            entries.append((lastmod, loc))

        entries.sort(key=lambda e: (e[0], e[1]), reverse=True)
        return [loc for _, loc in entries]

    @staticmethod
    def _report_id(url):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))

    @staticmethod
    def _canonical_url(metadata, fallback_url):
        canonical = (metadata.get("canonical") or "").strip()
        if canonical and _POST_URL_RE.match(canonical):
            return canonical
        return fallback_url

    # ------------------------------------------------------------------ #
    # Article loading (curl_cffi + BS4 + WeasyPrint)
    # ------------------------------------------------------------------ #

    def _extract_metadata(self, html):
        soup = BeautifulSoup(html, "html.parser")
        article = soup.select_one(".stories-category")

        canonical_tag = soup.select_one('link[rel="canonical"]')
        canonical = (
            canonical_tag["href"]
            if canonical_tag and canonical_tag.get("href")
            else None
        )

        og_title = soup.select_one('meta[property="og:title"]')
        title = (
            og_title["content"].strip()
            if og_title and og_title.get("content")
            else None
        )

        heading = None
        if article:
            h1 = article.select_one("h1")
            heading = h1.get_text(strip=True) if h1 else None

        desc_tag = soup.select_one(
            'meta[name="description"]'
        ) or soup.select_one('meta[property="og:description"]')
        description = (
            desc_tag["content"].strip()
            if desc_tag and desc_tag.get("content")
            else None
        )

        release_tag = soup.select_one('meta[name="releaseDate"]')
        release_date = (
            release_tag["content"].strip()
            if release_tag and release_tag.get("content")
            else None
        )

        dateline = None
        if article:
            dl = article.select_one("p.dateline")
            if dl:
                dateline = " ".join(dl.get_text().split())

        return {
            "article_present": article is not None,
            "canonical": canonical,
            "title": title,
            "heading": heading,
            "description": description,
            "release_date": release_date,
            "dateline": dateline,
        }

    def _wp_url_fetcher(self, url):
        if url.startswith("data:"):
            return weasyprint.default_url_fetcher(url)
        try:
            resp = self.session.get(url, timeout=15)
            return {
                "string": resp.content,
                "mime_type": resp.headers.get(
                    "content-type", "application/octet-stream"
                ).split(";")[0],
            }
        except Exception:
            return {"string": b"", "mime_type": "text/plain"}

    def _render_pdf(self, html, url):
        soup = BeautifulSoup(html, "html.parser")
        article = soup.select_one(".stories-category")
        if not article:
            raise RuntimeError("No .stories-category container for PDF")

        ingested = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        safe_url = _escape_html(url)
        clean_html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><style>"
            "body { font-family: Georgia, serif; max-width: 800px; "
            "margin: 0 auto; padding: 20px; color: #222; line-height: 1.6; } "
            "h1 { font-size: 24px; } h2 { font-size: 20px; } "
            "img { max-width: 100%; height: auto; } "
            "pre, code { background: #f4f4f4; padding: 2px 6px; "
            "font-size: 13px; white-space: pre-wrap; word-break: break-all; } "
            "table { border-collapse: collapse; width: 100%; } "
            "td, th { border: 1px solid #ccc; padding: 8px; } "
            "@page { margin: 15mm 12mm 20mm 12mm; "
            "@bottom-center { content: '"
            + safe_url
            + "  |  OpenCTI Trellix connector  |  "
            + ingested
            + "'; font-size: 7px; color: #888; } } "
            "</style></head><body>"
            + str(article)
            + "</body></html>"
        )

        return weasyprint.HTML(
            string=clean_html, base_url=url, url_fetcher=self._wp_url_fetcher
        ).write_pdf()

    def _load_article(self, url):
        resp = self.session.get(url, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")
        html = resp.text
        metadata = self._extract_metadata(html)
        if not metadata.get("article_present"):
            raise RuntimeError("Article container absent")
        if not (metadata.get("title") or metadata.get("heading")):
            raise RuntimeError("Article carries no title")
        pdf_bytes = self._render_pdf(html, url)
        return metadata, pdf_bytes

    def _load_with_retry(self, url):
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                metadata, pdf_bytes = self._load_article(url)
                return metadata, pdf_bytes, attempt
            except Exception as exc:
                self.helper.log_warning(
                    f"Attempt {attempt}/{self.render_retries} failed for "
                    f"{url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
        return None, None, self.render_retries

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _resolve_published(self, metadata, url):
        published = _date_from_dateline(metadata.get("dateline"))
        if published is None:
            published = _date_from_release_meta(metadata.get("release_date"))
        if published is None:
            self.helper.log_warning(f"No usable date for {url}; using now.")
            published = datetime.now(timezone.utc)
        return published.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def _create_report(self, url, metadata, pdf_bytes):
        name = metadata.get("title") or metadata.get("heading") or url
        description = metadata.get("description") or ""
        published = self._resolve_published(metadata, url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name, url=url,
            description="Source article on www.trellix.com",
        )

        report = self.helper.api.report.create(
            stix_id=self._report_id(url), name=name, description=description,
            published=published, report_types=[self.report_type],
            confidence=self.confidence, createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[external_reference["id"]], update=True,
        )

        match = _POST_URL_RE.match(url)
        category = match.group("category").lower() if match else "blog"
        slug = match.group("slug") if match else "report"
        self.helper.api.stix_domain_object.add_file(
            id=report["id"],
            file_name=f"trellix-{category}-{slug}.pdf",
            data=pdf_bytes, mime_type="application/pdf",
        )
        self.helper.log_info(
            f"Created Report for {url} ({name[:80]}) published {published[:10]}"
        )

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        self._work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Trellix blog enumeration run"
        )

        urls = self._enumerate_posts()
        if urls is None:
            msg = "Run aborted: sitemap unavailable; retrying next poll."
            self.helper.log_error(msg)
            self.helper.api.work.to_processed(self._work_id, msg)
            return

        self.helper.log_info(
            f"Sitemap yielded {len(urls)} in-scope posts "
            f"(categories={','.join(self.categories)}, "
            f"max_reports={self.max_reports or 'unlimited'})."
        )

        processed = skipped = failed = 0
        for url in urls:
            if self.max_reports and processed >= self.max_reports:
                self.helper.log_info(
                    f"Reached TRELLIX_MAX_REPORTS={self.max_reports}; stopping."
                )
                break

            if self.helper.api.report.read(id=self._report_id(url)) is not None:
                skipped += 1
                continue

            metadata, pdf_bytes, _attempts = self._load_with_retry(url)
            if metadata is None:
                failed += 1
                self.helper.log_warning(
                    f"Skipping {url}: load failed after retries."
                )
                continue

            canonical = self._canonical_url(metadata, url)
            if canonical != url and self.helper.api.report.read(
                id=self._report_id(canonical)
            ) is not None:
                skipped += 1
                self.helper.log_info(
                    f"Skipping {url}: already ingested as {canonical}."
                )
                time.sleep(self.request_delay)
                continue

            self._create_report(canonical, metadata, pdf_bytes)
            processed += 1
            time.sleep(self.request_delay)

        msg = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed, out of {len(urls)} in-scope posts."
        )
        self.helper.api.work.to_processed(self._work_id, msg)
        self.helper.log_info(msg)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info(
            f"Trellix blog connector started "
            f"(categories={','.join(self.categories)})."
        )
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
                            self._work_id, f"Run failed: {exc}"
                        )
                    except Exception:
                        pass
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        TrellixBlogConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
