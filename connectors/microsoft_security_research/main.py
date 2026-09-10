"""
Microsoft Security Research OpenCTI connector.

Purpose
-------
External-import connector that ingests research articles from the Microsoft
Security Blog (https://www.microsoft.com/en-us/security/blog/content-type/research/)
and creates one OpenCTI Report container per article, with the source page
attached as a full-fidelity PDF.

Collection model
----------------
The Microsoft Security Blog runs on WordPress 6.x. The WP REST API is open and
unrestricted (no WAF gating, no API key). Research articles are identified by
the custom taxonomy ``content-type`` with term id 3663 ("Research", ~501 posts
as of September 2026, dating back to 2006).

Enumeration walks the filtered posts in ascending post-id order
(orderby=id&order=asc) behind a persisted positional {page, index} cursor held
in OpenCTI connector state. Ascending id ordering is used rather than date: post
ids are monotonic and yield a perfectly stable sort (no ties), whereas two posts
can share a timestamp. New posts always receive the highest ids and land on the
last page, so one uniform code path covers both backfill and steady state.

Per-post title, excerpt (description), publication date, and link are read
directly from the REST payload. Playwright navigates to the article URL and
prints the rendered page to PDF: enumeration never goes through Playwright.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id)
and skips if the Report already exists. For a new post it creates the External
Reference (upsert-safe), then the Report (with the deterministic stix_id), then
attaches the PDF. The graph lookup is the correctness backstop; the {page, index}
cursor is the efficiency layer.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships, no Labels. Named-entity / IOC extraction is a
separate, out-of-scope downstream phase.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (free, publicly published source).
- Author: "Microsoft Security Research" Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band).
- PDF renderer: Playwright (full-fidelity live-page print).

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import html
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

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

MAX_PER_PAGE = 100

BROWSER_RECYCLE_EVERY = 50

MAX_SCROLL_PX = 100_000


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _strip_html(value):
    if not value:
        return ""
    return html.unescape(re.sub(r"<[^>]+>", "", value)).strip()


def _report_id(link):
    return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))


def _published_iso(post):
    for key in ("date_gmt", "modified_gmt"):
        raw = post.get(key)
        if not raw:
            continue
        try:
            dt = datetime.fromisoformat(raw)
        except (TypeError, ValueError):
            continue
        if dt.year >= 2000:
            return dt.replace(tzinfo=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
    return None


def _slug_from_url(url):
    path = urlparse(url).path.strip("/")
    return path.rsplit("/", 1)[-1] if path else "report"


def _post_title(post):
    return _strip_html((post.get("title") or {}).get("rendered", ""))


def _post_description(post):
    return _strip_html((post.get("excerpt") or {}).get("rendered", ""))


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

class MicrosoftSecurityResearchConnector:
    """External-import connector that mirrors Microsoft Security Research posts into Reports."""

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
            "MICROSOFT_SECURITY_RESEARCH_BASE_URL",
            ["microsoft_security_research", "base_url"],
            config,
            default="https://www.microsoft.com/en-us/security/blog",
        ).rstrip("/")
        self.api_url = f"{self.base_url}/wp-json/wp/v2/posts"

        self.content_type_id = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_CONTENT_TYPE_ID",
            ["microsoft_security_research", "content_type_id"],
            config,
            isNumber=True,
            default=3663,
        )

        self.per_page = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_PER_PAGE",
            ["microsoft_security_research", "per_page"],
            config,
            isNumber=True,
            default=MAX_PER_PAGE,
        )
        if self.per_page > MAX_PER_PAGE or self.per_page < 1:
            self.per_page = MAX_PER_PAGE

        self.poll_interval = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_POLL_INTERVAL",
            ["microsoft_security_research", "poll_interval"],
            config,
            isNumber=True,
            default=86400,
        )

        self.request_delay = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_REQUEST_DELAY",
            ["microsoft_security_research", "request_delay"],
            config,
            isNumber=True,
            default=3,
        )

        self.max_reports = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_MAX_REPORTS",
            ["microsoft_security_research", "max_reports"],
            config,
            isNumber=True,
            default=0,
        )

        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT",
            ["microsoft_security_research", "playwright_nav_timeout"],
            config,
            isNumber=True,
            default=60000,
        )
        self.render_retries = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_RENDER_RETRIES",
            ["microsoft_security_research", "render_retries"],
            config,
            isNumber=True,
            default=3,
        )

        self.confidence = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_CONFIDENCE",
            ["microsoft_security_research", "confidence"],
            config,
            isNumber=True,
            default=50,
        )
        self.report_type = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_REPORT_TYPE",
            ["microsoft_security_research", "report_type"],
            config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_TLP",
            ["microsoft_security_research", "tlp"],
            config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "MICROSOFT_SECURITY_RESEARCH_AUTHOR_NAME",
            ["microsoft_security_research", "author_name"],
            config,
            default="Microsoft Security Research",
        )

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "application/json, */*",
        })

        self.author_id = None
        self.marking_id = None

    def _scope_sig(self):
        return str(self.content_type_id)

    def _save_cursor(self, page, index):
        self.helper.set_state(
            {"page": page, "index": index, "scope_sig": self._scope_sig()}
        )

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Microsoft's security research division. Publishes threat "
                        "intelligence, vulnerability research, and defense strategies "
                        "on the Microsoft Security Blog.",
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
                f"REST endpoint {self.api_url} unreachable at startup; entering poll "
                f"loop anyway and retrying next cycle."
            )
        else:
            self.helper.log_info(
                f"REST endpoint reachable: {total} research posts "
                f"(content-type={self.content_type_id})."
            )

    def _probe_total(self):
        params = {
            "content-type": self.content_type_id,
            "per_page": 1,
            "orderby": "id",
            "order": "asc",
            "_fields": "id",
        }
        try:
            resp = self.session.get(self.api_url, params=params, timeout=60)
            resp.raise_for_status()
        except Exception:
            return None
        try:
            return int(resp.headers.get("X-WP-Total", "0"))
        except (TypeError, ValueError):
            return None

    # ------------------------------------------------------------------ #
    # REST enumeration
    # ------------------------------------------------------------------ #

    def _fetch_page(self, page):
        params = {
            "content-type": self.content_type_id,
            "per_page": self.per_page,
            "page": page,
            "orderby": "id",
            "order": "asc",
            "_fields": "id,date_gmt,modified_gmt,link,title,excerpt",
        }
        try:
            resp = self.session.get(self.api_url, params=params, timeout=90)
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch page {page}: {exc}")
            return None
        if resp.status_code == 400:
            return []
        if resp.status_code != 200:
            self.helper.log_error(
                f"Page {page} returned HTTP {resp.status_code}; skipping this cycle."
            )
            return None
        try:
            data = resp.json()
        except ValueError as exc:
            self.helper.log_error(f"Page {page} returned non-JSON body: {exc}")
            return None
        return data if isinstance(data, list) else None

    # ------------------------------------------------------------------ #
    # PDF rendering (Playwright)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _auto_scroll(page):
        page.evaluate(
            """
            async () => {
              await new Promise((resolve) => {
                let total = 0;
                const step = 400;
                const maxScroll = %d;
                const timer = setInterval(() => {
                  window.scrollBy(0, step);
                  total += step;
                  if (total >= document.body.scrollHeight || total >= maxScroll) {
                    clearInterval(timer);
                    window.scrollTo(0, 0);
                    resolve();
                  }
                }, 100);
              });
            }
            """
            % MAX_SCROLL_PX
        )

    def _render_pdf(self, browser, url):
        context = browser.new_context(
            viewport={"width": 1280, "height": 1696},
            user_agent=BROWSER_UA,
        )
        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)

            self._auto_scroll(page)
            page.wait_for_timeout(1500)

            ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            footer = (
                "<div style='font-size:8px; width:100%; padding:0 12px; "
                "color:#444; display:flex; justify-content:space-between;'>"
                f"<span>{html.escape(url)}</span>"
                f"<span>OpenCTI Microsoft Security Research connector &middot; "
                f"ingested {ingested_at} &middot; page "
                "<span class='pageNumber'></span>/"
                "<span class='totalPages'></span></span></div>"
            )
            return page.pdf(
                print_background=True,
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=footer,
                margin={
                    "top": "10mm",
                    "bottom": "16mm",
                    "left": "8mm",
                    "right": "8mm",
                },
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
            except Exception as exc:
                self.helper.log_warning(
                    f"Render attempt {attempt}/{self.render_retries} failed for "
                    f"{url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay *= 2
        return None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, post, published, pdf_bytes):
        url = post.get("link")
        name = _post_title(post) or url
        description = _post_description(post)
        stix_id = _report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on the Microsoft Security Blog",
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

        file_name = f"msft-research-{_slug_from_url(url)}.pdf"
        self.helper.api.stix_domain_object.add_file(
            id=report["id"],
            file_name=file_name,
            data=pdf_bytes,
            mime_type="application/pdf",
        )
        self.helper.log_info(f"Created Report for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Per-post ingestion
    # ------------------------------------------------------------------ #

    def _ingest_post(self, browser, post):
        """Attempt to ingest a single post.

        Returns:
            str: "created", "skipped", "failed", or "no_url".
                 Only "created" means a Playwright render was used.
        """
        url = post.get("link")
        if not url:
            return "no_url"

        if self.helper.api.report.read(id=_report_id(url)) is not None:
            return "skipped"

        pdf_bytes = self._render_with_retry(browser, url)
        if pdf_bytes is None:
            self.helper.log_warning(
                f"Skipping {url}: render failed after retries."
            )
            return "failed"

        published = _published_iso(post)
        if not published:
            published = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            self.helper.log_warning(
                f"No usable date for {url}; using ingestion time."
            )

        self._create_report(post, published, pdf_bytes)
        return "created"

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        from playwright.sync_api import sync_playwright

        state = self.helper.get_state() or {}
        current_sig = self._scope_sig()
        stored_sig = state.get("scope_sig")
        if stored_sig is not None and stored_sig != current_sig:
            self.helper.log_warning(
                f"Collection scope changed; resetting cursor to page 1. "
                f"old={stored_sig!r} new={current_sig!r}."
            )
            state = {}
        cursor_page = max(1, int(state.get("page", 1)))
        cursor_index = max(0, int(state.get("index", 0)))

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Microsoft Security Research enumeration run"
        )
        self.helper.log_info(
            f"Resuming at page={cursor_page}, index={cursor_index} "
            f"(per_page={self.per_page}, content-type={self.content_type_id})."
        )

        processed = 0
        skipped = 0
        failed = 0
        stop = False

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    args=["--no-sandbox", "--disable-dev-shm-usage"]
                )
                renders_since_recycle = 0
                try:
                    page_num = cursor_page
                    while not stop:
                        posts = self._fetch_page(page_num)
                        if posts is None:
                            self.helper.log_warning(
                                f"Page {page_num} fetch failed; ending cycle, "
                                f"cursor preserved."
                            )
                            break
                        if not posts:
                            self._save_cursor(page_num, 0)
                            self.helper.log_info(
                                f"Caught up at page {page_num}; nothing new."
                            )
                            break

                        start = cursor_index if page_num == cursor_page else 0
                        self.helper.log_info(
                            f"Page {page_num}: {len(posts)} posts; "
                            f"starting at index {start}."
                        )

                        for idx in range(start, len(posts)):
                            if self.max_reports and processed >= self.max_reports:
                                self.helper.log_info(
                                    f"Reached max_reports={self.max_reports}; "
                                    f"stopping run."
                                )
                                stop = True
                                break

                            if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                                browser.close()
                                browser = pw.chromium.launch(
                                    args=["--no-sandbox",
                                          "--disable-dev-shm-usage"]
                                )
                                renders_since_recycle = 0

                            outcome = self._ingest_post(browser, posts[idx])

                            if outcome == "created":
                                processed += 1
                                renders_since_recycle += 1
                                time.sleep(self.request_delay)
                            elif outcome == "skipped":
                                skipped += 1
                            elif outcome == "failed":
                                failed += 1

                            self._save_cursor(page_num, idx + 1)

                        if stop:
                            break

                        if len(posts) < self.per_page:
                            self._save_cursor(page_num, len(posts))
                            break

                        page_num += 1
                        cursor_index = 0
                        self._save_cursor(page_num, 0)
                        time.sleep(self.request_delay)
                finally:
                    browser.close()

            message = (
                f"Run complete: {processed} created, {skipped} already present, "
                f"{failed} failed (render)."
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)
        except Exception as exc:
            self.helper.log_error(f"Error during processing: {exc}")
            self.helper.api.work.to_processed(work_id, str(exc), in_error=True)
            raise

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("Microsoft Security Research connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        MicrosoftSecurityResearchConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
