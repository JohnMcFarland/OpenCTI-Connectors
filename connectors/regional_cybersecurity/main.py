import io
import os
import time
import traceback
from datetime import datetime, timezone

import feedparser
import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from sources import SOURCES, AgencySource
from scrapers import (
    enrich_from_page,
    make_pdf_filename,
    parse_published,
    truncate_summary,
    SCRAPER_REGISTRY,
)


class RegionalCybersecurity:

    EARLY_STOP_THRESHOLD = 5
    BROWSER_RECYCLE_EVERY = 50
    BROWSER_UA = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(self):
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = {}
        if os.path.isfile(config_path):
            with open(config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}

        self.helper = OpenCTIConnectorHelper(config)

        self.poll_interval = int(
            get_config_variable(
                "REGIONAL_CYBERSECURITY_POLL_INTERVAL",
                ["regional_cybersecurity", "poll_interval"],
                config,
                isNumber=True,
                default=21600,
            )
        )
        self.request_delay = float(
            get_config_variable(
                "REGIONAL_CYBERSECURITY_REQUEST_DELAY",
                ["regional_cybersecurity", "request_delay"],
                config,
                isNumber=True,
                default=2,
            )
        )
        self.confidence = int(
            get_config_variable(
                "REGIONAL_CYBERSECURITY_CONFIDENCE",
                ["regional_cybersecurity", "confidence"],
                config,
                isNumber=True,
                default=85,
            )
        )
        self.report_type = get_config_variable(
            "REGIONAL_CYBERSECURITY_REPORT_TYPE",
            ["regional_cybersecurity", "report_type"],
            config,
            default="industry-alert",
        )
        self.tlp_name = get_config_variable(
            "REGIONAL_CYBERSECURITY_TLP",
            ["regional_cybersecurity", "tlp"],
            config,
            default="TLP:CLEAR",
        )
        self.max_per_source = int(
            get_config_variable(
                "REGIONAL_CYBERSECURITY_MAX_PER_SOURCE",
                ["regional_cybersecurity", "max_per_source"],
                config,
                isNumber=True,
                default=20,
            )
        )
        enabled_raw = get_config_variable(
            "REGIONAL_CYBERSECURITY_ENABLED_SOURCES",
            ["regional_cybersecurity", "enabled_sources"],
            config,
            default="",
        )
        if enabled_raw:
            self.enabled_keys = {
                k.strip() for k in enabled_raw.split(",") if k.strip()
            }
        else:
            self.enabled_keys = {s.key for s in SOURCES}

        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "OpenCTI-RegionalCybersecurity/1.0"}
        )

        self.marking_id: str | None = None
        self.author_ids: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Graph reference setup
    # ------------------------------------------------------------------

    def _resolve_graph_references(self):
        marking = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [self.tlp_name]}],
                "filterGroups": [],
            }
        )
        if not marking:
            raise RuntimeError(f"Marking '{self.tlp_name}' not found on platform")
        self.marking_id = marking["id"]

        self.helper.api.vocabulary.create(
            name=self.report_type, category="report_types_ov"
        )

        for source in SOURCES:
            if source.key not in self.enabled_keys:
                continue
            identity = self.helper.api.identity.create(
                type="Organization",
                name=source.name,
                description=f"Regional cybersecurity agency — {source.country}",
            )
            self.author_ids[source.key] = identity["id"]

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _already_ingested(self, url: str) -> bool:
        ref = self.helper.api.external_reference.read(
            filters={
                "mode": "and",
                "filters": [{"key": "url", "values": [url]}],
                "filterGroups": [],
            }
        )
        return ref is not None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, url: str, timeout: int = 30) -> requests.Response | None:
        try:
            resp = self.session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp
        except Exception as e:
            self.helper.log_error(f"HTTP GET failed: {url} — {e}")
            return None

    # ------------------------------------------------------------------
    # Feed fetching
    # ------------------------------------------------------------------

    def _fetch_feed(self, feed_url: str) -> list:
        resp = self._get(feed_url)
        if not resp:
            return []
        parsed = feedparser.parse(resp.content)
        return parsed.entries

    # ------------------------------------------------------------------
    # Browser & PDF acquisition
    # ------------------------------------------------------------------

    @staticmethod
    def _auto_scroll(page):
        page.evaluate("""async () => {
            await new Promise(resolve => {
                let total = 0;
                const dist = 300;
                const timer = setInterval(() => {
                    window.scrollBy(0, dist);
                    total += dist;
                    if (total >= document.body.scrollHeight) {
                        clearInterval(timer);
                        resolve();
                    }
                }, 100);
            });
        }""")

    def _maybe_recycle_browser(self):
        if self._renders_since_recycle >= self.BROWSER_RECYCLE_EVERY:
            self._browser.close()
            self._browser = self._pw.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            self._renders_since_recycle = 0

    def _render_pdf(self, url: str) -> bytes | None:
        self._maybe_recycle_browser()
        context = self._browser.new_context(
            viewport={"width": 1280, "height": 1696},
            user_agent=self.BROWSER_UA,
        )
        page = context.new_page()
        try:
            response = page.goto(url, wait_until="networkidle", timeout=60000)

            if response and "application/pdf" in (
                response.headers.get("content-type") or ""
            ):
                return response.body()

            self._auto_scroll(page)
            page.wait_for_timeout(1500)
            return page.pdf(
                print_background=True,
                format="A4",
                margin={
                    "top": "10mm",
                    "bottom": "10mm",
                    "left": "8mm",
                    "right": "8mm",
                },
            )
        except Exception as e:
            self.helper.log_warning(f"PDF render failed: {url} — {e}")
            return None
        finally:
            page.close()
            context.close()

    def _acquire_pdf(self, url: str, pdf_url: str | None = None) -> bytes | None:
        if pdf_url:
            try:
                resp = self.session.get(pdf_url, timeout=30)
                resp.raise_for_status()
                if "application/pdf" in resp.headers.get("Content-Type", ""):
                    return resp.content
            except Exception as e:
                self.helper.log_warning(f"PDF download failed: {pdf_url} — {e}")

        return self._render_pdf(url)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _hit_limit(self, ingested: int) -> bool:
        return self.max_per_source > 0 and ingested >= self.max_per_source

    # ------------------------------------------------------------------
    # Shared report ingestion
    # ------------------------------------------------------------------

    def _ingest_report(
        self,
        source: AgencySource,
        url: str,
        title: str,
        published: datetime,
        summary: str,
        pdf_bytes: bytes | None = None,
        pdf_url: str | None = None,
    ) -> dict:
        ext_ref = self.helper.api.external_reference.create(
            source_name=source.name,
            url=url,
            description=f"Advisory published by {source.name}",
        )

        report_type = source.report_type or self.report_type
        confidence = source.confidence or self.confidence

        report = self.helper.api.report.create(
            name=title,
            description=summary,
            published=published.strftime("%Y-%m-%dT%H:%M:%SZ"),
            report_types=[report_type],
            confidence=confidence,
            createdBy=self.author_ids[source.key],
            objectMarking=[self.marking_id],
            externalReferences=[ext_ref["id"]],
            update=True,
        )

        if pdf_bytes is None:
            time.sleep(self.request_delay)
            pdf_bytes = self._acquire_pdf(url, pdf_url=pdf_url)

        if pdf_bytes:
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=make_pdf_filename(url),
                data=io.BytesIO(pdf_bytes),
                mime_type="application/pdf",
            )

        return report

    # ------------------------------------------------------------------
    # Source processing — feed-based
    # ------------------------------------------------------------------

    def _process_feed_source(
        self, source: AgencySource, seen: set[str]
    ) -> tuple[int, int, int]:
        ingested = 0
        skipped = 0
        errors = 0

        for feed in source.feeds:
            if self._hit_limit(ingested):
                break

            entries = self._fetch_feed(feed.url)
            self.helper.log_info(
                f"[{source.key}] {feed.label}: {len(entries)} entries"
            )

            for entry in entries:
                if not getattr(entry, "link", None):
                    continue

                if entry.link in seen or self._already_ingested(entry.link):
                    skipped += 1
                    continue

                if self._hit_limit(ingested):
                    self.helper.log_info(
                        f"[{source.key}] Hit max_per_source ({self.max_per_source})"
                    )
                    break

                try:
                    title = entry.get("title", "Untitled Advisory")
                    published = parse_published(entry)
                    summary = truncate_summary(entry.get("summary", "") or "")

                    self._ingest_report(source, entry.link, title, published, summary)
                    seen.add(entry.link)
                    ingested += 1
                    self.helper.log_info(f"[{source.key}] Ingested: {title}")
                    time.sleep(self.request_delay)
                except Exception as e:
                    errors += 1
                    self.helper.log_error(
                        f"[{source.key}] Failed: {entry.link} — {e}"
                    )

        return ingested, skipped, errors

    # ------------------------------------------------------------------
    # Source processing — scraper-based (with early-stop dedup)
    # ------------------------------------------------------------------

    def _process_scraper_source(
        self, source: AgencySource, seen: set[str]
    ) -> tuple[int, int, int]:
        scraper_fn = SCRAPER_REGISTRY.get(source.scraper)
        if not scraper_fn:
            self.helper.log_error(
                f"[{source.key}] Unknown scraper: {source.scraper}"
            )
            return 0, 0, 1

        entries = scraper_fn(self._get, self.request_delay, self.helper.log_info)

        ingested = 0
        skipped = 0
        errors = 0
        consecutive_skips = 0

        for entry in entries:
            if not entry.url:
                continue

            if entry.url in seen or self._already_ingested(entry.url):
                skipped += 1
                consecutive_skips += 1
                if consecutive_skips >= self.EARLY_STOP_THRESHOLD:
                    self.helper.log_info(
                        f"[{source.key}] Early stop: {self.EARLY_STOP_THRESHOLD} "
                        f"consecutive already-ingested"
                    )
                    break
                continue

            consecutive_skips = 0

            if self._hit_limit(ingested):
                self.helper.log_info(
                    f"[{source.key}] Hit max_per_source ({self.max_per_source})"
                )
                break

            try:
                time.sleep(self.request_delay)
                resp = self._get(entry.url)
                html = resp.text if resp else None

                pdf_url = None
                if html:
                    pdf_url = enrich_from_page(entry, html)

                published = entry.published or datetime.now(tz=timezone.utc)
                title = entry.title or "Untitled Advisory"
                summary = truncate_summary(entry.summary or "")

                self._ingest_report(
                    source,
                    entry.url,
                    title,
                    published,
                    summary,
                    pdf_url=pdf_url,
                )
                seen.add(entry.url)
                ingested += 1
                self.helper.log_info(f"[{source.key}] Ingested: {title}")
            except Exception as e:
                errors += 1
                self.helper.log_error(
                    f"[{source.key}] Failed: {entry.url} — {e}"
                )

        return ingested, skipped, errors

    # ------------------------------------------------------------------
    # Source processing — dispatch
    # ------------------------------------------------------------------

    def _process_source(
        self, source: AgencySource, seen: set[str]
    ) -> tuple[int, int, int]:
        if source.scraper:
            return self._process_scraper_source(source, seen)
        return self._process_feed_source(source, seen)

    # ------------------------------------------------------------------
    # Main run cycle
    # ------------------------------------------------------------------

    def _process(self):
        from playwright.sync_api import sync_playwright

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Regional Cybersecurity run"
        )

        total_ingested = 0
        total_skipped = 0
        total_errors = 0
        seen: set[str] = set()

        with sync_playwright() as pw:
            self._pw = pw
            self._browser = pw.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            self._renders_since_recycle = 0

            try:
                for source in SOURCES:
                    if source.key not in self.enabled_keys:
                        continue
                    self.helper.log_info(
                        f"Processing {source.name} ({source.country})"
                    )
                    ingested, skipped, errors = self._process_source(source, seen)
                    total_ingested += ingested
                    total_skipped += skipped
                    total_errors += errors
                    self.helper.log_info(
                        f"[{source.key}] Done: {ingested} new, {skipped} existing, "
                        f"{errors} errors"
                    )
            finally:
                self._browser.close()

        msg = (
            f"Complete: {total_ingested} ingested, "
            f"{total_skipped} already present, {total_errors} errors"
        )
        self.helper.api.work.to_processed(work_id, msg)
        self.helper.log_info(msg)

    def run(self):
        self._resolve_graph_references()
        self.helper.log_info(
            f"Started with {len(self.enabled_keys)} sources enabled: "
            f"{', '.join(sorted(self.enabled_keys))}"
        )
        while True:
            try:
                self._process()
            except Exception:
                self.helper.log_error(traceback.format_exc())
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    RegionalCybersecurity().run()
