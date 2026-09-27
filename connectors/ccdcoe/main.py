"""CCDCOE OpenCTI connector — NATO CCDCOE news + publications (requests + WeasyPrint)."""

import html
import os
import re
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests as req
from bs4 import BeautifulSoup
import weasyprint
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

NEWS_YEAR_START = 2008

NEWS_DATE_RE = re.compile(r"(\d{2})\.(\d{2})\.(\d{4})")


def _escape_html(value):
    return html.escape(str(value))


def _canonical(base, href):
    url = urljoin(base, href).rstrip("/")
    return url


def _slug_from_url(url):
    path = urlparse(url).path.rstrip("/")
    return path.rsplit("/", 1)[-1] or "article"


class CcdcoeConnector:

    def __init__(self):
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = {}
        if os.path.isfile(config_path):
            with open(config_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}

        self.helper = OpenCTIConnectorHelper(config)

        self.base_url = (
            get_config_variable(
                "CCDCOE_BASE_URL", ["ccdcoe", "base_url"], config,
                default="https://ccdcoe.org",
            ) or "https://ccdcoe.org"
        ).rstrip("/")

        self.poll_interval = get_config_variable(
            "CCDCOE_POLL_INTERVAL", ["ccdcoe", "poll_interval"], config,
            isNumber=True, default=86400,
        )
        self.request_delay = get_config_variable(
            "CCDCOE_REQUEST_DELAY", ["ccdcoe", "request_delay"], config,
            isNumber=True, default=3,
        )
        self.max_reports = get_config_variable(
            "CCDCOE_MAX_REPORTS", ["ccdcoe", "max_reports"], config,
            isNumber=True, default=0,
        )
        self.render_retries = get_config_variable(
            "CCDCOE_RENDER_RETRIES", ["ccdcoe", "render_retries"], config,
            isNumber=True, default=3,
        )
        self.confidence = get_config_variable(
            "CCDCOE_CONFIDENCE", ["ccdcoe", "confidence"], config,
            isNumber=True, default=60,
        )
        self.report_type = get_config_variable(
            "CCDCOE_REPORT_TYPE", ["ccdcoe", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "CCDCOE_TLP", ["ccdcoe", "tlp"], config, default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "CCDCOE_AUTHOR_NAME", ["ccdcoe", "author_name"], config,
            default="CCDCOE",
        )

        self.session = req.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA})
        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Graph bootstrap
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization", name=self.author_name,
            description=(
                "NATO Cooperative Cyber Defence Centre of Excellence — "
                "multinational cyber defence research, training and exercises."
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
    # Enumeration — news
    # ------------------------------------------------------------------ #

    def _enumerate_news(self):
        current_year = datetime.now(timezone.utc).year
        articles = []
        seen = set()
        for year in range(NEWS_YEAR_START, current_year + 1):
            url = f"{self.base_url}/news/{year}"
            try:
                resp = self.session.get(url, timeout=60)
            except Exception as exc:
                self.helper.log_warning(f"Failed to fetch {url}: {exc}")
                continue
            if resp.status_code != 200:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            for card in soup.select("a.common-item__link"):
                href = card.get("href", "")
                if "/news/" not in href or href.rstrip("/").count("/") < 3:
                    continue
                full_url = _canonical(self.base_url, href)
                if full_url in seen:
                    continue
                seen.add(full_url)

                title_el = card.select_one(".common-item__title")
                desc_el = card.select_one(".common-item__description")
                time_el = card.select_one("time.common-item__time")

                published = datetime(year, 1, 1, tzinfo=timezone.utc)
                if time_el:
                    m = NEWS_DATE_RE.search(time_el.text)
                    if m:
                        try:
                            published = datetime(
                                int(m.group(3)), int(m.group(2)), int(m.group(1)),
                                tzinfo=timezone.utc,
                            )
                        except ValueError:
                            pass

                articles.append({
                    "url": full_url,
                    "title": title_el.text.strip() if title_el else _slug_from_url(full_url),
                    "description": desc_el.text.strip() if desc_el else "",
                    "published": published,
                    "kind": "news",
                })
            time.sleep(self.request_delay)

        self.helper.log_info(
            f"Enumerated {len(articles)} news articles "
            f"({NEWS_YEAR_START}–{current_year})."
        )
        return articles

    # ------------------------------------------------------------------ #
    # Enumeration — publications
    # ------------------------------------------------------------------ #

    def _enumerate_publications(self):
        url = f"{self.base_url}/library/publications"
        try:
            resp = self.session.get(url, timeout=120)
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch publications list: {exc}")
            return []
        if resp.status_code != 200:
            self.helper.log_error(
                f"Publications list returned HTTP {resp.status_code}"
            )
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        pubs = []
        seen = set()

        for item in soup.select(".research-items-item"):
            link_el = item.select_one("a.research-items-item__link")
            if not link_el:
                continue
            href = link_el.get("href", "")
            if not href:
                continue
            full_url = _canonical(self.base_url, href)
            if full_url in seen:
                continue
            seen.add(full_url)

            title_el = item.select_one("h3.research-items-item__title")
            desc_el = item.select_one(".research-items-item__excerpt")
            year_el = item.select_one(".research-items-item__year h6")

            year = datetime.now(timezone.utc).year
            if year_el:
                try:
                    year = int(year_el.text.strip())
                except ValueError:
                    pass

            pdf_url = None
            for file_link in item.select(
                ".research-items-item__files-list a.tag-item--file"
            ):
                fhref = file_link.get("href", "")
                if fhref.lower().endswith(".pdf"):
                    pdf_url = _canonical(self.base_url, fhref)
                    break

            pub_month = 6
            if pdf_url:
                m = re.search(r"/uploads/\d{4}/(\d{2})/", pdf_url)
                if m:
                    try:
                        pub_month = max(1, min(12, int(m.group(1))))
                    except ValueError:
                        pass

            focus_areas = []
            for tag in item.select(".tag-item--tags"):
                inner = tag.select_one("span")
                if inner and inner.text.strip():
                    focus_areas.append(inner.text.strip())

            authors = []
            for tag in item.select(".tag-item--authors"):
                inner = tag.select_one("span")
                if inner and inner.text.strip():
                    authors.append(inner.text.strip())

            pubs.append({
                "url": full_url,
                "title": title_el.text.strip() if title_el else _slug_from_url(full_url),
                "description": desc_el.text.strip() if desc_el else "",
                "published": datetime(year, pub_month, 1, tzinfo=timezone.utc),
                "kind": "publication",
                "pdf_url": pdf_url,
                "focus_areas": focus_areas,
                "authors": authors,
            })

        self.helper.log_info(
            f"Enumerated {len(pubs)} publications "
            f"({sum(1 for p in pubs if p['pdf_url'])} with native PDF)."
        )
        return pubs

    # ------------------------------------------------------------------ #
    # Dedup
    # ------------------------------------------------------------------ #

    @staticmethod
    def _report_id(url):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))

    # ------------------------------------------------------------------ #
    # Content fetching
    # ------------------------------------------------------------------ #

    def _fetch_article_body(self, url):
        resp = self.session.get(url, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} for {url}")
        soup = BeautifulSoup(resp.text, "html.parser")

        h1 = soup.select_one("h1")
        title = h1.text.strip() if h1 else ""

        article = soup.select_one("article.content-block__wrapper")
        body_html = str(article) if article else ""

        return title, body_html

    # ------------------------------------------------------------------ #
    # PDF rendering (WeasyPrint)
    # ------------------------------------------------------------------ #

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

    def _render_pdf(self, url, title, body_html):
        ingested = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        safe_url = _escape_html(url)
        page_html = (
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
            + "  |  OpenCTI CCDCOE connector  |  "
            + ingested
            + "'; font-size: 7px; color: #888; } } "
            "</style></head><body>"
            "<h1>" + _escape_html(title) + "</h1>"
            + body_html
            + "</body></html>"
        )
        return weasyprint.HTML(
            string=page_html, base_url=url,
            url_fetcher=self._wp_url_fetcher,
        ).write_pdf()

    def _download_pdf(self, pdf_url):
        resp = self.session.get(pdf_url, timeout=120)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} downloading {pdf_url}")
        if not resp.content:
            raise RuntimeError(f"Empty response from {pdf_url}")
        return resp.content

    def _acquire_pdf(self, item):
        url = item["url"]
        kind = item["kind"]

        if kind == "publication" and item.get("pdf_url"):
            pdf_bytes = self._download_pdf(item["pdf_url"])
            pdf_name = urlparse(item["pdf_url"]).path.rsplit("/", 1)[-1]
            return pdf_bytes, pdf_name

        title, body_html = self._fetch_article_body(url)
        if not body_html:
            raise RuntimeError(f"No article content at {url}")
        if title:
            item["_detail_title"] = title
        pdf_bytes = self._render_pdf(url, title or item["title"], body_html)
        prefix = "ccdcoe-pub" if kind == "publication" else "ccdcoe-news"
        pdf_name = f"{prefix}-{_slug_from_url(url)}.pdf"
        return pdf_bytes, pdf_name

    def _acquire_with_retry(self, item):
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._acquire_pdf(item)
            except Exception as exc:
                self.helper.log_warning(
                    f"Attempt {attempt}/{self.render_retries} failed for "
                    f"{item['url']}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
        return None, None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, item, pdf_bytes, pdf_name):
        url = item["url"]
        name = item.get("_detail_title") or item["title"]
        description = item["description"]
        if item.get("authors"):
            description += f"\n\nAuthors: {', '.join(item['authors'])}"
        if item.get("focus_areas"):
            description += f"\n\nFocus areas: {', '.join(item['focus_areas'])}"
        published = item["published"].strftime("%Y-%m-%dT%H:%M:%S+00:00")

        ext_ref = self.helper.api.external_reference.create(
            source_name=self.author_name, url=url,
            description="Source article on ccdcoe.org",
        )

        report = self.helper.api.report.create(
            stix_id=self._report_id(url), name=name,
            description=description, published=published,
            report_types=[self.report_type],
            confidence=self.confidence, createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[ext_ref["id"]], update=True,
        )

        if pdf_bytes:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"], file_name=pdf_name,
                data=pdf_bytes, mime_type="application/pdf",
            )

        self.helper.log_info(
            f"Created {item['kind']} Report: {name[:80]} "
            f"[{item['published'].strftime('%Y-%m-%d')}]"
        )

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "CCDCOE enumeration run"
        )
        try:
            items = self._enumerate_news() + self._enumerate_publications()
            self.helper.log_info(f"Total enumerated: {len(items)} items.")

            processed = skipped = failed = 0
            for item in items:
                if self.max_reports and processed >= self.max_reports:
                    self.helper.log_info(
                        f"Reached max_reports={self.max_reports}; stopping."
                    )
                    break

                url = item["url"]
                if self.helper.api.report.read(id=self._report_id(url)) is not None:
                    skipped += 1
                    continue

                try:
                    pdf_bytes, pdf_name = self._acquire_with_retry(item)
                    if pdf_bytes is None:
                        failed += 1
                        continue
                    self._create_report(item, pdf_bytes, pdf_name)
                    processed += 1
                except Exception as exc:
                    self.helper.log_warning(
                        f"Failed to process {url}: {exc}"
                    )
                    failed += 1

                time.sleep(self.request_delay)

            msg = (
                f"Run complete: {processed} created, {skipped} already present, "
                f"{failed} failed, out of {len(items)} items."
            )
            self.helper.api.work.to_processed(work_id, msg)
            self.helper.log_info(msg)
        except Exception:
            try:
                self.helper.api.work.to_processed(
                    work_id, f"Run failed: {traceback.format_exc()}"
                )
            except Exception:
                pass
            raise

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("CCDCOE connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(
                    f"Unhandled error: {exc}\n{traceback.format_exc()}"
                )
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        CcdcoeConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
