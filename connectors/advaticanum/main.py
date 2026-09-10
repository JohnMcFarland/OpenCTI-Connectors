"""
AdVaticanum OpenCTI connector.

Purpose
-------
External-import connector that ingests AdVaticanum Catholic news articles and
creates one OpenCTI Report container per article, with the source article
attached as a full-fidelity PDF.

Collection model
----------------
AdVaticanum is a Next.js site with Cloudflare bot protection. There is no
public API, RSS feed, or XML sitemap. Non-browser HTTP clients receive 403.
Collection therefore uses Playwright for both enumeration and rendering:

  - Listing pages: /category/latest/page/{n}/ (newest-first, ~6 articles/page)
  - Article pages: /article/{slug}/

Enumeration walks the "Latest" category listing from page 1 (newest) forward.
An early-stop optimisation halts the walk when an entire listing page contains
only articles already present in the graph, since everything older is also
known.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships. Entity extraction is a separate phase.

Key decisions
-------------
- Container type: Report (external intelligence).
- TLP: CLEAR (public source).
- Author: the AdVaticanum Organization identity.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: 50 (Medium band, general news source).
- Deduplication: graph-driven via deterministic Report STIX ID
  (uuid5 of article URL). No cursor/state; every poll re-walks the listing
  with early-stop, which makes an interrupted backfill inherently resumable.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import time
import html
import uuid
from datetime import datetime, timezone

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside _process() so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

MAX_LISTING_PAGES = 200

BROWSER_RECYCLE_EVERY = 50

CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")


def _strip_html(value: str) -> str:
    if not value:
        return ""
    no_tags = re.sub(r"<[^>]+>", "", value)
    return html.unescape(no_tags).strip()


def _parse_date(date_text: str) -> str | None:
    """Parse AdVaticanum date text (e.g. 'Sep. 8, 2026') into ISO-8601."""
    if not date_text:
        return None
    cleaned = date_text.replace(".", "").strip()
    for fmt in ("%b %d, %Y", "%B %d, %Y", "%b %d %Y"):
        try:
            dt = datetime.strptime(cleaned, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


class AdVaticanumConnector:
    """External-import connector that mirrors AdVaticanum articles into Reports."""

    def __init__(self):
        config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as f:
                config = yaml.safe_load(f)
        else:
            config = {}

        self.helper = OpenCTIConnectorHelper(config)

        # --- Source configuration ------------------------------------------ #
        self.base_url = get_config_variable(
            "ADVATICANUM_BASE_URL", ["advaticanum", "base_url"], config,
            default="https://advaticanum.com",
        ).rstrip("/")

        self.poll_interval = get_config_variable(
            "ADVATICANUM_POLL_INTERVAL", ["advaticanum", "poll_interval"], config,
            isNumber=True, default=21600,
        )

        self.request_delay = get_config_variable(
            "ADVATICANUM_REQUEST_DELAY", ["advaticanum", "request_delay"], config,
            isNumber=True, default=3,
        )

        self.max_reports = get_config_variable(
            "ADVATICANUM_MAX_REPORTS", ["advaticanum", "max_reports"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ------------------------------------------ #
        self.nav_timeout_ms = get_config_variable(
            "ADVATICANUM_PLAYWRIGHT_NAV_TIMEOUT", ["advaticanum", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "ADVATICANUM_RENDER_RETRIES", ["advaticanum", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        self.confidence = get_config_variable(
            "ADVATICANUM_CONFIDENCE", ["advaticanum", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "ADVATICANUM_REPORT_TYPE", ["advaticanum", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "ADVATICANUM_TLP", ["advaticanum", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "ADVATICANUM_AUTHOR_NAME", ["advaticanum", "author_name"], config,
            default="AdVaticanum",
        )

        self.author_id = None
        self.marking_id = None

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Catholic news and analysis site covering the Vatican and the "
                        "wider Church. Source organization for ingested reports.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved author identity: {self.author_id}")

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
        except Exception as exc:
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc}). "
                f"Add it under Settings -> Taxonomies -> Report types if missing."
            )

    # ------------------------------------------------------------------ #
    # Deduplication
    # ------------------------------------------------------------------ #

    def _report_id(self, url):
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))

    def _already_ingested(self, url):
        return self.helper.api.report.read(id=self._report_id(url)) is not None

    # ------------------------------------------------------------------ #
    # Listing-page enumeration (Playwright)
    # ------------------------------------------------------------------ #

    def _scrape_listing_page(self, page, page_num):
        """Navigate to a listing page and return unique article URLs.

        Returns an empty list if the page is out of range (redirect to
        homepage) or contains no article links.
        """
        url = f"{self.base_url}/category/latest/page/{page_num}/"
        page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)

        title = (page.title() or "").lower()
        if any(marker in title for marker in CHALLENGE_MARKERS):
            self.helper.log_warning(f"Cloudflare challenge on listing page {page_num}")
            return []

        if "latest" not in title:
            return []

        article_urls = page.evaluate(
            """
            () => {
              const links = document.querySelectorAll('a[href*="/article/"]');
              const seen = new Set();
              const urls = [];
              for (const a of links) {
                let href = a.href;
                if (!href.endsWith('/')) href += '/';
                if (!seen.has(href)) {
                  seen.add(href);
                  urls.push(href);
                }
              }
              return urls;
            }
            """
        )
        return article_urls or []

    # ------------------------------------------------------------------ #
    # PDF rendering + metadata extraction (Playwright)
    # ------------------------------------------------------------------ #

    def _auto_scroll(self, page):
        page.evaluate(
            """
            async () => {
              await new Promise((resolve) => {
                let total = 0;
                const step = 400;
                const timer = setInterval(() => {
                  window.scrollBy(0, step);
                  total += step;
                  if (total >= document.body.scrollHeight) {
                    clearInterval(timer);
                    window.scrollTo(0, 0);
                    resolve();
                  }
                }, 100);
              });
            }
            """
        )

    def _extract_metadata(self, page):
        """Read title, published date, and description from the article page.

        AdVaticanum has no JSON-LD or article:published_time meta. The date is
        in a visible span near the h1 (format 'Sep. 8, 2026'). The description
        comes from og:description or the first paragraph.
        """
        return page.evaluate(
            """
            () => {
              const h1 = document.querySelector('h1');
              const title = h1 ? h1.textContent.trim() : document.title;

              // Date: look for a span sibling of the author containing a date pattern
              const headerDiv = h1 ? h1.parentElement : null;
              let dateText = null;
              if (headerDiv) {
                const spans = headerDiv.querySelectorAll('span');
                for (const s of spans) {
                  const t = s.textContent.trim();
                  if (/^[A-Z][a-z]+\\.?\\s+\\d{1,2},?\\s+\\d{4}$/.test(t)) {
                    dateText = t;
                    break;
                  }
                }
              }

              // Description: og:description or first paragraph
              const ogDesc = document.querySelector('meta[property="og:description"]');
              let description = ogDesc ? ogDesc.getAttribute('content') : '';
              if (!description) {
                const firstP = document.querySelector('main p');
                description = firstP ? firstP.textContent.trim().substring(0, 500) : '';
              }

              // Author byline (for external reference description, not createdBy)
              const authorEl = headerDiv ? headerDiv.querySelector('h2') : null;
              const author = authorEl ? authorEl.textContent.trim() : null;

              return { title, dateText, description, author };
            }
            """
        )

    def _render_and_extract(self, browser, url):
        context = browser.new_context(
            viewport={"width": 1280, "height": 1696},
            user_agent=BROWSER_UA,
        )
        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)

            title = (page.title() or "").lower()
            if any(marker in title for marker in CHALLENGE_MARKERS):
                raise RuntimeError("Cloudflare challenge interstitial detected")

            self._auto_scroll(page)
            page.wait_for_timeout(1500)

            meta = self._extract_metadata(page)

            ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            footer = (
                "<div style='font-size:8px; width:100%; padding:0 12px; "
                "color:#444; display:flex; justify-content:space-between;'>"
                f"<span>{html.escape(url)}</span>"
                f"<span>OpenCTI AdVaticanum connector &middot; ingested {ingested_at} "
                "&middot; page <span class='pageNumber'></span>/"
                "<span class='totalPages'></span></span></div>"
            )
            pdf_bytes = page.pdf(
                print_background=True,
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=footer,
                margin={"top": "10mm", "bottom": "16mm", "left": "8mm", "right": "8mm"},
                format="A4",
            )
            return pdf_bytes, meta
        finally:
            page.close()
            context.close()

    def _render_with_retry(self, browser, url):
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._render_and_extract(browser, url)
            except Exception as exc:
                self.helper.log_warning(
                    f"Render attempt {attempt}/{self.render_retries} failed for {url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay *= 2
        return None, None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _slug_from_url(self, url):
        return url.rstrip("/").split("/")[-1] or "article"

    def _create_report(self, url, meta, pdf_bytes):
        name = _strip_html(meta.get("title") or "")
        name = re.sub(r"\s*[-|]\s*[Aa]dvaticanum\s*$", "", name).strip()
        if not name:
            name = self._slug_from_url(url)

        description = _strip_html(meta.get("description") or "")
        published = _parse_date(meta.get("dateText"))

        ref_desc = "Source article on advaticanum.com"
        byline = meta.get("author")
        if byline:
            ref_desc = f"By {byline}. {ref_desc}"

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description=ref_desc,
        )

        report = self.helper.api.report.create(
            name=name,
            description=description,
            published=published,
            report_types=[self.report_type],
            confidence=self.confidence,
            createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[external_reference["id"]],
            stix_id=self._report_id(url),
            update=True,
        )

        file_name = f"advaticanum-{self._slug_from_url(url)}.pdf"
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
        from playwright.sync_api import sync_playwright

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "AdVaticanum enumeration run"
        )
        try:

            processed = 0
            skipped = 0
            failed = 0

            with sync_playwright() as pw:
                browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
                renders_since_recycle = 0
                try:
                    listing_ctx = browser.new_context(user_agent=BROWSER_UA)
                    listing_page = listing_ctx.new_page()

                    for page_num in range(1, MAX_LISTING_PAGES + 1):
                        if self.max_reports and processed >= self.max_reports:
                            self.helper.log_info(
                                f"Reached ADVATICANUM_MAX_REPORTS={self.max_reports}; stopping run."
                            )
                            break

                        article_urls = self._scrape_listing_page(listing_page, page_num)
                        if not article_urls:
                            self.helper.log_info(
                                f"Listing page {page_num} empty or out of range; enumeration complete."
                            )
                            break

                        self.helper.log_info(
                            f"Listing page {page_num}: {len(article_urls)} articles"
                        )

                        all_known = True
                        for url in article_urls:
                            if self.max_reports and processed >= self.max_reports:
                                break

                            if self._already_ingested(url):
                                skipped += 1
                                continue

                            all_known = False

                            if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                                listing_page.close()
                                listing_ctx.close()
                                browser.close()
                                browser = pw.chromium.launch(
                                    args=["--no-sandbox", "--disable-dev-shm-usage"]
                                )
                                renders_since_recycle = 0
                                listing_ctx = browser.new_context(user_agent=BROWSER_UA)
                                listing_page = listing_ctx.new_page()

                            pdf_bytes, meta = self._render_with_retry(browser, url)
                            renders_since_recycle += 1

                            if pdf_bytes is None:
                                failed += 1
                                self.helper.log_warning(f"Skipping {url}: render failed after retries.")
                                continue

                            if not meta or not meta.get("dateText"):
                                failed += 1
                                self.helper.log_warning(
                                    f"Skipping {url}: no published date in page metadata."
                                )
                                continue

                            parsed_date = _parse_date(meta["dateText"])
                            if not parsed_date:
                                failed += 1
                                self.helper.log_warning(
                                    f"Skipping {url}: could not parse date '{meta['dateText']}'."
                                )
                                continue

                            self._create_report(url, meta, pdf_bytes)
                            processed += 1
                            time.sleep(self.request_delay)

                        if all_known and article_urls:
                            self.helper.log_info(
                                f"All articles on page {page_num} already ingested; stopping walk."
                            )
                            break

                        time.sleep(self.request_delay)

                    listing_page.close()
                    listing_ctx.close()
                finally:
                    browser.close()

            message = (
                f"Run complete: {processed} created, {skipped} already present, "
                f"{failed} failed (render or missing date)."
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)
        except Exception as e:
            self.helper.log_error(f"Error processing: {e}")
            self.helper.api.work.to_processed(work_id, str(e), in_error=True)
            raise

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info("AdVaticanum connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        AdVaticanumConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
