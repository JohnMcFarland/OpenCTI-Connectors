"""NATO CCDCOE OpenCTI connector -- news, publications, and strategy database (Playwright + WeasyPrint)."""

import html
import os
import re
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests as req
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import weasyprint
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)  # type: str

NEWS_YEAR_START = 2008  # type: int

NEWS_DATE_RE = re.compile(r"(\d{2})\.(\d{2})\.(\d{4})")


def _escape_html(value):
    """Escape a value for safe inclusion in HTML attributes and content."""
    return html.escape(str(value))


def _canonical(base, href):
    """Resolve *href* against *base* and strip the trailing slash."""
    return urljoin(base, href).rstrip("/")


def _slug_from_url(url):
    """Return the last path segment of *url*, falling back to ``article``."""
    path = urlparse(url).path.rstrip("/")  # type: str
    return path.rsplit("/", 1)[-1] or "article"


def _slugify(text):
    """Turn free text into a lowercase ASCII slug for URL fragments and filenames."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


class CcdcoeConnector:
    """NATO CCDCOE external-import connector for OpenCTI."""

    def __init__(self):
        """Load YAML and env-var configuration, create HTTP session."""
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )  # type: str
        config = {}  # type: dict
        if os.path.isfile(config_path):
            with open(config_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}

        self.helper = OpenCTIConnectorHelper(config)

        self.base_url = (
            get_config_variable(
                "CCDCOE_BASE_URL", ["ccdcoe", "base_url"], config,
                default="https://ccdcoe.org",
            ) or "https://ccdcoe.org"
        ).rstrip("/")  # type: str

        self.poll_interval = get_config_variable(
            "CCDCOE_POLL_INTERVAL", ["ccdcoe", "poll_interval"], config,
            isNumber=True, default=86400,
        )  # type: int
        self.request_delay = get_config_variable(
            "CCDCOE_REQUEST_DELAY", ["ccdcoe", "request_delay"], config,
            isNumber=True, default=3,
        )  # type: int
        self.max_reports = get_config_variable(
            "CCDCOE_MAX_REPORTS", ["ccdcoe", "max_reports"], config,
            isNumber=True, default=0,
        )  # type: int
        self.render_retries = get_config_variable(
            "CCDCOE_RENDER_RETRIES", ["ccdcoe", "render_retries"], config,
            isNumber=True, default=3,
        )  # type: int
        self.confidence = get_config_variable(
            "CCDCOE_CONFIDENCE", ["ccdcoe", "confidence"], config,
            isNumber=True, default=75,
        )  # type: int
        self.report_type = get_config_variable(
            "CCDCOE_REPORT_TYPE", ["ccdcoe", "report_type"], config,
            default="open-source-reporting",
        )  # type: str
        self.tlp_name = get_config_variable(
            "CCDCOE_TLP", ["ccdcoe", "tlp"], config, default="TLP:CLEAR",
        )  # type: str
        self.author_name = get_config_variable(
            "CCDCOE_AUTHOR_NAME", ["ccdcoe", "author_name"], config,
            default="NATO CCDCOE",
        )  # type: str
        self.pdf_render_timeout = get_config_variable(
            "CCDCOE_PDF_RENDER_TIMEOUT", ["ccdcoe", "pdf_render_timeout"],
            config, isNumber=True, default=120,
        )  # type: int

        self.session = req.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA})
        self.author_id = None  # type: str | None
        self.marking_id = None  # type: str | None
        self._pw_page = None  # Playwright page, set during _process()

    # ------------------------------------------------------------------ #
    # Graph bootstrap
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Create author identity, resolve TLP marking, register report vocabulary."""
        author = self.helper.api.identity.create(
            type="Organization", name=self.author_name,
            description=(
                "NATO Cooperative Cyber Defence Centre of Excellence -- "
                "multinational cyber defence research, training and exercises."
            ),
        )
        self.author_id = author["id"]  # type: str
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
        self.marking_id = marking["id"]  # type: str
        self.helper.log_info(
            f"Resolved marking {self.tlp_name}: {self.marking_id}"
        )

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
    # Playwright helpers
    # ------------------------------------------------------------------ #

    def _pw_navigate(self, url):
        """Navigate the Playwright page to *url*, wait for idle, return True on HTTP 200."""
        resp = self._pw_page.goto(url, timeout=120000, wait_until="networkidle")
        time.sleep(self.request_delay)
        return resp is not None and resp.status == 200

    def _pw_soup(self):
        """Return a BeautifulSoup parse tree of the current Playwright page."""
        return BeautifulSoup(self._pw_page.content(), "html.parser")

    # ------------------------------------------------------------------ #
    # Enumeration -- news
    # ------------------------------------------------------------------ #

    def _enumerate_news(self):
        """Walk per-year news listing pages via Playwright and extract article cards."""
        current_year = datetime.now(timezone.utc).year  # type: int
        articles = []  # type: list[dict]
        seen = set()  # type: set[str]
        for year in range(NEWS_YEAR_START, current_year + 1):
            url = f"{self.base_url}/news/{year}"  # type: str
            try:
                if not self._pw_navigate(url):
                    continue
            except Exception as exc:
                self.helper.log_warning(f"Failed to load {url}: {exc}")
                continue

            soup = self._pw_soup()
            for card in soup.select("a.common-item__link"):
                href = card.get("href", "")  # type: str
                if "/news/" not in href or href.rstrip("/").count("/") < 3:
                    continue
                full_url = _canonical(self.base_url, href)  # type: str
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
                                int(m.group(3)), int(m.group(2)),
                                int(m.group(1)), tzinfo=timezone.utc,
                            )
                        except ValueError:
                            pass

                articles.append({
                    "url": full_url,
                    "title": (
                        title_el.text.strip()
                        if title_el
                        else _slug_from_url(full_url)
                    ),
                    "description": desc_el.text.strip() if desc_el else "",
                    "published": published,
                    "kind": "news",
                })

        self.helper.log_info(
            f"Enumerated {len(articles)} news articles "
            f"({NEWS_YEAR_START}--{current_year})."
        )
        return articles

    # ------------------------------------------------------------------ #
    # Enumeration -- publications
    # ------------------------------------------------------------------ #

    def _enumerate_publications(self):
        """Parse the publications listing page via Playwright and extract metadata."""
        url = f"{self.base_url}/library/publications"  # type: str
        try:
            if not self._pw_navigate(url):
                self.helper.log_error(
                    "Publications page returned non-200 status"
                )
                return []
        except Exception as exc:
            self.helper.log_error(f"Failed to load publications list: {exc}")
            return []

        soup = self._pw_soup()
        pubs = []  # type: list[dict]
        seen = set()  # type: set[str]

        for item in soup.select(".research-items-item"):
            link_el = item.select_one("a.research-items-item__link")
            if not link_el:
                continue
            href = link_el.get("href", "")  # type: str
            if not href:
                continue
            full_url = _canonical(self.base_url, href)  # type: str
            if full_url in seen:
                continue
            seen.add(full_url)

            title_el = item.select_one("h3.research-items-item__title")
            desc_el = item.select_one(".research-items-item__excerpt")
            year_el = item.select_one(".research-items-item__year h6")

            year = datetime.now(timezone.utc).year  # type: int
            if year_el:
                try:
                    year = int(year_el.text.strip())
                except ValueError:
                    pass

            pdf_url = None  # type: str | None
            for file_link in item.select(
                ".research-items-item__files-list a.tag-item--file"
            ):
                fhref = file_link.get("href", "")  # type: str
                if fhref.lower().endswith(".pdf"):
                    pdf_url = _canonical(self.base_url, fhref)
                    break

            pub_month = 6  # type: int
            if pdf_url:
                m = re.search(r"/uploads/\d{4}/(\d{2})/", pdf_url)
                if m:
                    try:
                        pub_month = max(1, min(12, int(m.group(1))))
                    except ValueError:
                        pass

            focus_areas = []  # type: list[str]
            for tag in item.select(".tag-item--tags"):
                inner = tag.select_one("span")
                if inner and inner.text.strip():
                    focus_areas.append(inner.text.strip())

            authors = []  # type: list[str]
            for tag in item.select(".tag-item--authors"):
                inner = tag.select_one("span")
                if inner and inner.text.strip():
                    authors.append(inner.text.strip())

            pubs.append({
                "url": full_url,
                "title": (
                    title_el.text.strip()
                    if title_el
                    else _slug_from_url(full_url)
                ),
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
    # Enumeration -- strategy & governance
    # ------------------------------------------------------------------ #

    def _enumerate_strategies(self):
        """Parse the Strategy and Governance page for per-country strategy items."""
        url = f"{self.base_url}/library/strategy-and-governance"  # type: str
        try:
            if not self._pw_navigate(url):
                self.helper.log_error(
                    "Strategy page returned non-200 status"
                )
                return []
        except Exception as exc:
            self.helper.log_error(f"Failed to load strategy database: {exc}")
            return []

        soup = self._pw_soup()
        strategies = []  # type: list[dict]
        seen = set()  # type: set[str]

        for item in soup.select(
            ".research-items-item--strategy-documents"
        ):
            title_el = item.select_one("h3.research-items-item__title")
            if not title_el:
                continue
            country = title_el.text.strip()  # type: str
            if not country:
                continue

            slug = _slugify(country)  # type: str
            item_url = f"{url}#{slug}"  # type: str
            if item_url in seen:
                continue
            seen.add(item_url)

            orgs = []  # type: list[str]
            for tag_span in item.select(".tag-item span"):
                tag_text = tag_span.text.strip()  # type: str
                if tag_text:
                    orgs.append(tag_text)

            doc_count = 0  # type: int
            max_year = 0  # type: int
            doc_names = []  # type: list[str]
            for doc_item in item.select(
                ".strategy-documents-files__document-item"
            ):
                doc_count += 1
                year_el = doc_item.select_one(
                    "time.strategy-documents-files__document-year"
                )
                name_el = doc_item.select_one(
                    "p.strategy-documents-files__document-name"
                )
                if year_el:
                    try:
                        yr = int(year_el.text.strip())  # type: int
                        if yr > max_year:
                            max_year = yr
                    except ValueError:
                        pass
                if name_el and name_el.text.strip():
                    doc_names.append(name_el.text.strip())

            pub_year = max_year or datetime.now(timezone.utc).year  # type: int
            body_html = str(item)  # type: str

            desc_parts = []  # type: list[str]
            if orgs:
                desc_parts.append(f"Memberships: {', '.join(orgs)}")
            desc_parts.append(
                f"{doc_count} strategy and policy document"
                f"{'s' if doc_count != 1 else ''}."
            )
            for dn in doc_names[:10]:
                desc_parts.append(f"- {dn}")

            strategies.append({
                "url": item_url,
                "title": f"National Cyber Strategy: {country}",
                "description": "\n".join(desc_parts),
                "published": datetime(pub_year, 1, 1, tzinfo=timezone.utc),
                "kind": "strategy",
                "body_html": body_html,
                "country": country,
            })

        self.helper.log_info(
            f"Enumerated {len(strategies)} strategy country sections."
        )
        return strategies

    # ------------------------------------------------------------------ #
    # Dedup
    # ------------------------------------------------------------------ #

    @staticmethod
    def _report_id(url):
        """Generate a deterministic STIX Report ID from a URL via UUID5."""
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))

    # ------------------------------------------------------------------ #
    # Content fetching
    # ------------------------------------------------------------------ #

    def _fetch_article_body(self, url):
        """Fetch an article detail page via requests and extract title and body HTML."""
        resp = self.session.get(url, timeout=60)  # type: req.Response
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} for {url}")
        soup = BeautifulSoup(resp.text, "html.parser")

        h1 = soup.select_one("h1")
        title = h1.text.strip() if h1 else ""  # type: str

        article = soup.select_one("article.content-block__wrapper")
        body_html = str(article) if article else ""  # type: str

        return title, body_html

    # ------------------------------------------------------------------ #
    # PDF rendering (WeasyPrint)
    # ------------------------------------------------------------------ #

    def _wp_url_fetcher(self, url):
        """WeasyPrint URL fetcher using the connector HTTP session."""
        if url.startswith("data:"):
            return weasyprint.default_url_fetcher(url)
        try:
            resp = self.session.get(url, timeout=15)  # type: req.Response
            return {
                "string": resp.content,
                "mime_type": resp.headers.get(
                    "content-type", "application/octet-stream"
                ).split(";")[0],
            }
        except Exception:
            return {"string": b"", "mime_type": "text/plain"}

    def _render_pdf(self, url, title, body_html):
        """Render HTML content to an A4 PDF via WeasyPrint."""
        ingested = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )  # type: str
        safe_url = _escape_html(url)  # type: str
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
            + "  |  OpenCTI NATO CCDCOE connector  |  "
            + ingested
            + "'; font-size: 7px; color: #888; } } "
            "</style></head><body>"
            "<h1>" + _escape_html(title) + "</h1>"
            + body_html
            + "</body></html>"
        )  # type: str
        return weasyprint.HTML(
            string=page_html, base_url=url,
            url_fetcher=self._wp_url_fetcher,
        ).write_pdf()

    def _render_pdf_with_timeout(self, url, title, body_html):
        """Render PDF with a configurable wall-clock timeout via daemon thread."""
        result = [None]  # type: list
        error = [None]  # type: list

        def _target():
            """Execute the WeasyPrint render in a background thread."""
            try:
                result[0] = self._render_pdf(url, title, body_html)
            except Exception as exc:
                error[0] = exc

        t = threading.Thread(target=_target, daemon=True)
        t.start()
        t.join(timeout=self.pdf_render_timeout)
        if t.is_alive():
            self.helper.log_warning(
                f"PDF render timed out after {self.pdf_render_timeout}s "
                f"for {url}"
            )
            return None
        if error[0] is not None:
            raise error[0]
        return result[0]

    def _download_pdf(self, pdf_url):
        """Download a native PDF file from the given URL."""
        resp = self.session.get(pdf_url, timeout=120)  # type: req.Response
        if resp.status_code != 200:
            raise RuntimeError(
                f"HTTP {resp.status_code} downloading {pdf_url}"
            )
        if not resp.content:
            raise RuntimeError(f"Empty response from {pdf_url}")
        return resp.content

    # ------------------------------------------------------------------ #
    # PDF acquisition
    # ------------------------------------------------------------------ #

    def _acquire_pdfs(self, item):
        """Acquire all PDFs: rendered always, native PDF for publications when available."""
        url = item["url"]  # type: str
        kind = item["kind"]  # type: str
        pdfs = []  # type: list[tuple[bytes, str]]

        if kind == "strategy":
            body_html = item.get("body_html", "")  # type: str
            title = item["title"]  # type: str
        else:
            title, body_html = self._fetch_article_body(url)
            if title:
                item["_detail_title"] = title
            title = title or item["title"]

        if body_html:
            rendered = self._render_pdf_with_timeout(
                url, title, body_html
            )  # type: bytes | None
            if rendered:
                if kind == "strategy":
                    slug = _slugify(
                        item.get("country", "country")
                    )  # type: str
                else:
                    slug = _slug_from_url(url)  # type: str
                pdfs.append((rendered, f"nato-ccdcoe-rendered-{slug}.pdf"))

        if kind == "publication" and item.get("pdf_url"):
            try:
                native_bytes = self._download_pdf(
                    item["pdf_url"]
                )  # type: bytes
                native_name = urlparse(
                    item["pdf_url"]
                ).path.rsplit("/", 1)[-1]  # type: str
                pdfs.append((native_bytes, native_name))
            except Exception as exc:
                self.helper.log_warning(
                    f"Native PDF download failed for "
                    f"{item['pdf_url']}: {exc}"
                )

        if not pdfs:
            raise RuntimeError(f"No PDFs acquired for {url}")

        return pdfs

    def _acquire_with_retry(self, item):
        """Attempt PDF acquisition with bounded exponential backoff."""
        delay = self.request_delay  # type: int
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._acquire_pdfs(item)
            except Exception as exc:
                self.helper.log_warning(
                    f"Attempt {attempt}/{self.render_retries} failed for "
                    f"{item['url']}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
        return []

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, item, pdf_list):
        """Create an OpenCTI Report with external reference and attach all PDFs."""
        url = item["url"]  # type: str
        name = item.get("_detail_title") or item["title"]  # type: str
        description = item["description"]  # type: str
        if item.get("authors"):
            description += "\n\nAuthors: " + ", ".join(item["authors"])
        if item.get("focus_areas"):
            description += "\n\nFocus areas: " + ", ".join(item["focus_areas"])
        published = item["published"].strftime(
            "%Y-%m-%dT%H:%M:%S+00:00"
        )  # type: str

        ext_ref = self.helper.api.external_reference.create(
            source_name=self.author_name, url=url,
            description="Source page on ccdcoe.org",
        )

        report = self.helper.api.report.create(
            stix_id=self._report_id(url), name=name,
            description=description, published=published,
            report_types=[self.report_type],
            confidence=self.confidence, createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[ext_ref["id"]], update=True,
        )

        for pdf_bytes, pdf_name in pdf_list:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"], file_name=pdf_name,
                data=pdf_bytes, mime_type="application/pdf",
            )

        self.helper.log_info(
            f"Created {item['kind']} Report ({len(pdf_list)} PDF"
            f"{'s' if len(pdf_list) != 1 else ''}): "
            f"{name[:80]} [{item['published'].strftime('%Y-%m-%d')}]"
        )

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        """Run one full enumeration-and-ingest cycle with Playwright browser."""
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "NATO CCDCOE enumeration run"
        )  # type: str
        pw_instance = None
        browser = None
        try:
            pw_instance = sync_playwright().start()
            browser = pw_instance.chromium.launch(headless=True)
            context = browser.new_context(user_agent=BROWSER_UA)
            self._pw_page = context.new_page()

            items = (
                self._enumerate_news()
                + self._enumerate_publications()
                + self._enumerate_strategies()
            )  # type: list[dict]

            browser.close()
            pw_instance.stop()
            browser = None
            pw_instance = None
            self._pw_page = None

            self.helper.log_info(f"Total enumerated: {len(items)} items.")

            processed = 0  # type: int
            skipped = 0  # type: int
            failed = 0  # type: int
            for item in items:
                if self.max_reports and processed >= self.max_reports:
                    self.helper.log_info(
                        f"Reached max_reports={self.max_reports}; stopping."
                    )
                    break

                url = item["url"]  # type: str
                if self.helper.api.report.read(
                    id=self._report_id(url)
                ) is not None:
                    skipped += 1
                    continue

                try:
                    pdf_list = self._acquire_with_retry(item)  # type: list
                    if not pdf_list:
                        failed += 1
                        continue
                    self._create_report(item, pdf_list)
                    processed += 1
                except Exception as exc:
                    self.helper.log_warning(
                        f"Failed to process {url}: {exc}"
                    )
                    failed += 1

                time.sleep(self.request_delay)

            msg = (
                f"Run complete: {processed} created, "
                f"{skipped} already present, "
                f"{failed} failed, out of {len(items)} items."
            )  # type: str
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
        finally:
            self._pw_page = None
            if browser:
                browser.close()
            if pw_instance:
                pw_instance.stop()

    def run(self):
        """Resolve graph references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info("NATO CCDCOE connector started.")
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
