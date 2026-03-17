print("[BOOT] connector.py starting...", flush=True)

import hashlib
import io
import json
import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import logging
import requests
import weasyprint
from dateutil import parser as dtparser
from pycti import OpenCTIConnectorHelper

STATE_FILE = "/opt/connector/state/state.json"
SEEN_TTL_DAYS = 7


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def load_state() -> dict:
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state: dict) -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, separators=(",", ":"))
    os.replace(tmp, STATE_FILE)


def read_lines_file(path: str) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


def read_json_file(path: str, default):
    if not path or not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_host(host: str) -> str:
    host = (host or "").strip().lower()
    return host[4:] if host.startswith("www.") else host


def domain_of(url: str) -> str:
    try:
        return normalize_host(urlparse(url).hostname or "")
    except Exception:
        return ""


def article_key(article: dict) -> str:
    """Stable 16-char local dedup key: URL-based, falling back to source+title+date."""
    url = (article.get("url") or "").strip()
    if url:
        basis = url
    else:
        src = ((article.get("source") or {}).get("name") or "").strip()
        title = (article.get("title") or "").strip()
        published = (article.get("publishedAt") or "").strip()
        basis = f"{src}|{title}|{published}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def safe_filename(name: str) -> str:
    keepchars = frozenset(" .-_")
    cleaned = "".join(c if (c.isalnum() or c in keepchars) else "_" for c in name)
    return cleaned[:120].strip()


def md_from_article(article: dict, technical_creator: str, profile_name: str) -> str:
    src = (article.get("source") or {}).get("name") or "Unknown source"
    title = article.get("title") or ""
    desc = article.get("description") or ""
    content = article.get("content") or ""
    url = article.get("url") or ""
    published = article.get("publishedAt") or ""

    return "\n".join([
        f"# {title}", "",
        f"**Profile:** {profile_name}",
        f"**Source:** {src}",
        f"**Published:** {published}",
        f"**URL:** {url}", "",
        "## Description", desc, "",
        "## Content (snippet)", content, "",
        "---",
        f"Technical Creator: {technical_creator}", "",
    ])


# ---------------------------------------------------------------------------
# Seen cache (local performance layer — graph is the authoritative dedup)
# ---------------------------------------------------------------------------

def load_seen(state: dict) -> dict[str, int]:
    raw = state.get("seen", {})
    if not isinstance(raw, dict):
        return {}
    now = int(time.time())
    return {k: v for k, v in raw.items() if isinstance(v, int) and v > now}


def seen_add(seen: dict[str, int], key: str) -> None:
    seen[key] = int(time.time()) + SEEN_TTL_DAYS * 86400


# ---------------------------------------------------------------------------
# NewsAPI HTTP client
# ---------------------------------------------------------------------------

class NewsApiClient:
    BASE = "https://newsapi.org"

    def __init__(self, api_key: str, min_gap: int, max_retries: int):
        self.api_key = api_key
        self.min_gap = max(0, min_gap)
        self.max_retries = max(0, max_retries)
        self._last_ts = 0.0

    def get(self, path: str, params: dict) -> dict:
        headers = {"X-Api-Key": self.api_key}

        gap = (self._last_ts + self.min_gap) - time.time()
        if gap > 0:
            time.sleep(gap)

        for attempt in range(1, self.max_retries + 2):
            self._last_ts = time.time()
            r = requests.get(f"{self.BASE}{path}", params=params, headers=headers, timeout=60)
            if r.status_code != 429:
                r.raise_for_status()
                return r.json()
            if attempt > self.max_retries:
                r.raise_for_status()
            try:
                delay = int(r.headers.get("Retry-After", 0)) or 2 ** min(attempt, 6)
            except (ValueError, TypeError):
                delay = 2 ** min(attempt, 6)
            time.sleep(delay)


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class NewsAPIConnector:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

        self.api_key = os.getenv("NEWSAPI_API_KEY", "").strip()
        if not self.api_key:
            raise ValueError("NEWSAPI_API_KEY is required")

        self.language       = os.getenv("NEWSAPI_LANGUAGE", "").strip()
        self.sort_by        = os.getenv("NEWSAPI_SORT_BY", "publishedAt").strip()
        self.page_size      = int(os.getenv("NEWSAPI_PAGE_SIZE", "50"))
        self.lookback_hours = int(os.getenv("NEWSAPI_LOOKBACK_HOURS", "24"))
        self.max_pages      = int(os.getenv("NEWSAPI_MAX_PAGES_PER_RUN", "1"))

        self.daily_budget   = int(os.getenv("NEWSAPI_DAILY_REQUEST_BUDGET", "90"))
        self.min_gap        = int(os.getenv("NEWSAPI_MIN_SECONDS_BETWEEN_REQUESTS", "2"))
        self.max_retries    = int(os.getenv("NEWSAPI_MAX_RETRIES", "5"))

        self.report_type        = os.getenv("NEWSAPI_REPORT_TYPE", "Open Source Report").strip()
        self.marking            = os.getenv("NEWSAPI_MARKING", "TLP:CLEAR").strip()
        self.confidence         = int(os.getenv("NEWSAPI_CONFIDENCE", "15"))
        self.cr_labels          = [x.strip() for x in os.getenv("NEWSAPI_CR_LABELS", "").split(",") if x.strip()]
        self.technical_creator  = os.getenv("NEWSAPI_TECHNICAL_CREATOR", "[C]NewsAPI").strip()

        self.attach_pdf     = os.getenv("NEWSAPI_ATTACH_PDF", "true").strip().lower() == "true"
        self.pdf_timeout    = int(os.getenv("NEWSAPI_PDF_TIMEOUT", "30"))
        self.pdf_max_bytes  = int(os.getenv("NEWSAPI_PDF_MAX_MB", "12")) * 1024 * 1024
        self.pdf_ua         = os.getenv(
            "NEWSAPI_PDF_USER_AGENT",
            "Mozilla/5.0 (compatible; NewsAPI-OpenCTI/1.0)"
        ).strip()

        # Pre-normalize allowlist into a frozenset at init — not on every article
        raw_domains = read_lines_file(os.getenv("NEWSAPI_DOMAINS_ALLOWLIST_FILE", "").strip())
        self.allowed_domains: frozenset[str] = frozenset(normalize_host(d) for d in raw_domains)

        self.query_profiles = read_json_file(
            os.getenv("NEWSAPI_QUERY_PROFILES_FILE", "").strip(), default=[]
        )
        if not self.query_profiles:
            self.query_profiles = [
                {"name": "default", "query": "diplomacy OR sanctions OR military OR ceasefire OR missile OR drone"}
            ]

        # Suppress weasyprint CSS noise — non-fatal warnings flood the log
        logging.getLogger("weasyprint").setLevel(logging.ERROR)
        logging.getLogger("weasyprint.css").setLevel(logging.ERROR)
        logging.getLogger("fontTools").setLevel(logging.ERROR)

        self.client = NewsApiClient(self.api_key, self.min_gap, self.max_retries)
        self._author_cache: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Domain filtering  (O(1) frozenset lookup)
    # ------------------------------------------------------------------

    def _domain_allowed(self, url: str) -> bool:
        if not self.allowed_domains:
            return True
        d = domain_of(url)
        if not d:
            return False
        if d in self.allowed_domains:
            return True
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in self.allowed_domains:
                return True
        return False

    # ------------------------------------------------------------------
    # Graph-based dedup (authoritative — state cache is a performance layer on top)
    # ------------------------------------------------------------------

    def _url_already_ingested(self, url: str) -> bool:
        """Return True if an External Reference with this URL already exists in the graph."""
        if not url:
            return False
        try:
            results = self.helper.api.external_reference.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "url", "values": [url]}],
                    "filterGroups": [],
                },
                first=1,
            )
            if isinstance(results, list):
                return len(results) > 0
            if isinstance(results, dict):
                return len(results.get("edges") or []) > 0
            return False
        except Exception as e:
            self.helper.log_warning(f"Graph dedup check failed (non-fatal): {e}")
            return False

    # ------------------------------------------------------------------
    # Work tracking
    # ------------------------------------------------------------------

    def _work_begin(self, title: str) -> str | None:
        try:
            return self.helper.api.work.initiate_work(self.helper.connect_id, title)
        except Exception as e:
            self.helper.log_warning(f"Work begin failed (non-fatal): {e}")
            return None

    def _work_end(self, work_id: str | None, message: str = "") -> None:
        if not work_id:
            return
        try:
            self.helper.api.work.to_processed(work_id, message)
        except Exception as e:
            self.helper.log_warning(f"Work end failed (non-fatal): {e}")

    def _work_fail(self, work_id: str | None, message: str) -> None:
        if not work_id:
            return
        try:
            self.helper.api.work.to_failure(work_id, message)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Marking resolution
    # ------------------------------------------------------------------

    def _resolve_marking(self) -> list[str]:
        if self.marking.startswith("marking-definition--"):
            return [self.marking]
        md = self.helper.api.marking_definition.read(filters={
            "mode": "and",
            "filters": [{"key": "definition", "values": [self.marking]}],
            "filterGroups": [],
        })
        if md:
            return [md["id"]]
        self.helper.log_warning(f"Marking '{self.marking}' not found; continuing without markings.")
        return []

    # ------------------------------------------------------------------
    # Author identity (filter-only lookup, cached)
    # ------------------------------------------------------------------

    def _ensure_org_author(self, name: str) -> str:
        name = (name or "Unknown source").strip()
        if name in self._author_cache:
            return self._author_cache[name]

        try:
            res = self.helper.api.identity.list(
                first=1,
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "name", "values": [name]},
                        {"key": "entity_type", "values": ["Organization"]},
                    ],
                    "filterGroups": [],
                },
            )
            entities = []
            if isinstance(res, dict):
                entities = res.get("entities") or [
                    e["node"] for e in (res.get("edges") or []) if e.get("node")
                ]
            elif isinstance(res, list):
                entities = res

            if entities:
                self._author_cache[name] = entities[0]["id"]
                return self._author_cache[name]
        except Exception as e:
            self.helper.log_warning(f"Author lookup failed, will create: {e}")

        created = self.helper.api.identity.create(type="Organization", name=name)
        self._author_cache[name] = created["id"]
        return self._author_cache[name]

    # ------------------------------------------------------------------
    # PDF rendering (matches feedly connector pattern)
    # ------------------------------------------------------------------

    def _render_pdf(self, url: str) -> bytes:
        """Fetch article and render to PDF bytes via weasyprint (pure Python, no X11)."""
        headers = {"User-Agent": self.pdf_ua}
        response = requests.get(url, headers=headers, timeout=self.pdf_timeout)
        response.raise_for_status()
        return weasyprint.HTML(string=response.text, base_url=url).write_pdf()

    def _attach_pdf(self, report_id: str, report_name: str, url: str) -> None:
        try:
            pdf_bytes = self._render_pdf(url)
        except Exception as e:
            self.helper.log_warning(f"PDF render failed for '{report_name}' ({url}): {e}")
            return

        if len(pdf_bytes) > self.pdf_max_bytes:
            self.helper.log_warning(
                f"PDF for '{report_name}' exceeds {self.pdf_max_bytes // (1024*1024)}MB limit, skipping upload"
            )
            return

        try:
            self.helper.api.stix_domain_object.add_file(
                id=report_id,
                file_name=safe_filename(report_name) + ".pdf",
                data=io.BytesIO(pdf_bytes),
                mime_type="application/pdf",
            )
            self.helper.log_info(f"Attached PDF to report '{report_name}'")
        except Exception as e:
            self.helper.log_warning(f"PDF upload failed for '{report_name}': {e}")

    # ------------------------------------------------------------------
    # Markdown attachment
    # ------------------------------------------------------------------

    def _attach_markdown(self, report_id: str, key: str, profile_name: str, article: dict) -> None:
        md = md_from_article(article, self.technical_creator, profile_name)
        fname = f"newsapi_{safe_filename(profile_name)}_{key}.md"
        try:
            self.helper.api.stix_domain_object.add_file(
                id=report_id,
                file_name=fname,
                data=md.encode("utf-8"),
                mime_type="text/markdown",
            )
        except Exception as e:
            self.helper.log_warning(f"Markdown attachment failed (non-fatal): {e}")

    # ------------------------------------------------------------------
    # Report creation
    # ------------------------------------------------------------------

    def _ingest_article(self, article: dict, marking_ids: list[str], profile_name: str, key: str) -> str:
        src_name = ((article.get("source") or {}).get("name") or "Unknown source").strip()
        title    = (article.get("title") or "").strip()
        url      = (article.get("url") or "").strip()
        desc     = (article.get("description") or "").strip()
        content  = (article.get("content") or "").strip()

        try:
            published_dt = dtparser.parse(article.get("publishedAt") or "").astimezone(timezone.utc)
        except Exception:
            published_dt = utc_now()

        report_name = title or f"News Article ({src_name})"
        author_id   = self._ensure_org_author(src_name)

        ext_ref = self.helper.api.external_reference.create(
            source_name=src_name,
            url=url or None,
            description=desc[:1000] if desc else None,
        )

        report = self.helper.api.report.create(
            name=report_name,
            description=desc or content[:280],
            report_types=[self.report_type],
            published=published_dt.isoformat(),
            createdBy=author_id,
            confidence=self.confidence,
            objectMarking=marking_ids,
            externalReferences=[ext_ref["id"]],
        )
        report_id = report["id"]

        for lab in self.cr_labels:
            try:
                self.helper.api.label.add(object_id=report_id, value=lab)
            except Exception:
                pass

        self._attach_markdown(report_id, key, profile_name, article)

        if self.attach_pdf and url:
            self._attach_pdf(report_id, report_name, url)

        return report_id

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run_once(self) -> None:
        work_id = self._work_begin(f"NewsAPI ingestion ({len(self.query_profiles)} profiles)")
        state   = load_state()

        today  = utc_now().strftime("%Y-%m-%d")
        budget = state.get("budget", {})
        if budget.get("day") != today:
            budget = {"day": today, "requests": 0}

        seen    = load_seen(state)
        cursors = state.get("cursors") if isinstance(state.get("cursors"), dict) else {}

        marking_ids       = self._resolve_marking()
        ingested          = 0
        skipped_allowlist = 0
        skipped_dedup     = 0
        errors            = 0
        skipped_domains   = Counter()

        try:
            for profile in self.query_profiles:
                if budget["requests"] >= self.daily_budget:
                    self.helper.log_info("Daily budget reached; stopping run.")
                    break

                pname  = (profile.get("name") or "default").strip()
                pquery = (profile.get("query") or "").strip()

                if not pquery:
                    self.helper.log_warning(f"Skipping empty query profile: {pname}")
                    continue

                try:
                    from_dt = dtparser.parse(cursors[pname]).astimezone(timezone.utc)
                except Exception:
                    from_dt = utc_now() - timedelta(hours=self.lookback_hours)

                newest_seen = from_dt

                for page in range(1, self.max_pages + 1):
                    if budget["requests"] >= self.daily_budget:
                        break

                    params = {
                        "q":        pquery,
                        "pageSize": self.page_size,
                        "page":     page,
                        "sortBy":   self.sort_by,
                        "from":     from_dt.isoformat(),
                    }
                    if self.language:
                        params["language"] = self.language

                    budget["requests"] += 1
                    data     = self.client.get("/v2/everything", params)
                    articles = data.get("articles") or []

                    self.helper.log_info(
                        f"profile={pname} page={page} total={data.get('totalResults')} "
                        f"on_page={len(articles)} from={from_dt.date()}"
                    )

                    if not articles:
                        break

                    for a in articles:
                        try:
                            url = (a.get("url") or "").strip()

                            if not self._domain_allowed(url):
                                skipped_allowlist += 1
                                skipped_domains[domain_of(url) or "NO_DOMAIN"] += 1
                                continue

                            key = article_key(a)

                            # Local cache check (fast path)
                            if key in seen:
                                skipped_dedup += 1
                                continue

                            # Graph check (authoritative dedup — survives state loss)
                            if self._url_already_ingested(url):
                                seen_add(seen, key)  # backfill local cache
                                skipped_dedup += 1
                                continue

                            self._ingest_article(a, marking_ids, pname, key)
                            seen_add(seen, key)
                            ingested += 1

                            try:
                                pub_dt = dtparser.parse(a.get("publishedAt") or "").astimezone(timezone.utc)
                                if pub_dt > newest_seen:
                                    newest_seen = pub_dt
                            except Exception:
                                pass

                        except Exception as e:
                            errors += 1
                            self.helper.log_error(f"Article ingest failed (non-fatal): {e}")

                cursors[pname] = newest_seen.isoformat()

            state["seen"]    = seen
            state["cursors"] = cursors
            state["budget"]  = budget
            save_state(state)

            if skipped_domains:
                top = ", ".join(f"{d}:{c}" for d, c in skipped_domains.most_common(20))
                self.helper.log_info(f"Top allowlist-skipped domains: {top}")

            msg = (
                f"Run complete. ingested={ingested} skipped_dedup={skipped_dedup} "
                f"skipped_allowlist={skipped_allowlist} errors={errors} "
                f"budget={budget['requests']}/{self.daily_budget}"
            )
            self.helper.log_info(msg)
            self._work_end(work_id, msg)

        except Exception as e:
            self._work_fail(work_id, f"Run failed: {e}")
            raise

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def start(self) -> None:
        self.helper.log_info("Starting NewsAPI connector...")
        while True:
            try:
                self.run_once()
            except Exception as e:
                self.helper.log_error(str(e))
            time.sleep(int(os.getenv("CONNECTOR_REFRESH_INTERVAL", "3600")))


if __name__ == "__main__":
    try:
        NewsAPIConnector().start()
    except Exception:
        import traceback
        print("[FATAL] connector crashed:", flush=True)
        traceback.print_exc()
        raise
