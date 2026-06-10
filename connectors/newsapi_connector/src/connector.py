print("[BOOT] connector.py starting...", flush=True)

import logging
logging.getLogger("weasyprint").setLevel(logging.CRITICAL)
logging.getLogger("weasyprint.css").setLevel(logging.CRITICAL)
logging.getLogger("fontTools").setLevel(logging.ERROR)
logging.getLogger("fontTools.subset").setLevel(logging.ERROR)
logging.getLogger("fontTools.ttLib").setLevel(logging.ERROR)

import hashlib
import io
import json
import os
import re
import threading
import multiprocessing
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
import trafilatura
import weasyprint
from dateutil import parser as dtparser
from pycti import OpenCTIConnectorHelper

CONNECTOR_VERSION   = "2.0.0"
CONFIDENCE          = 15
SEEN_TTL_DAYS       = 7
AUTHOR_CACHE_TTL    = 7 * 86400
STATE_FILE          = "/opt/connector/state/state.json"

DEFAULT_SECTOR_MAP: dict[str, list[str]] = {
    "Energy": [
        "energy", "oil", "gas", "pipeline", "lng", "petroleum", "power grid",
        "electricity", "nuclear", "refinery", "opec", "offshore drilling",
        "natural gas", "coal", "hydropower", "renewable energy",
    ],
    "Financial Services": [
        "bank", "finance", "fintech", "payment", "trading", "stock exchange",
        "cryptocurrency", "bitcoin", "blockchain", "insurance", "hedge fund",
        "central bank", "federal reserve", "imf", "world bank",
    ],
    "Defense": [
        "military", "defense", "missile", "nato", "armed forces", "pentagon",
        "air force", "navy", "army", "drone strike", "warship", "nuclear weapon",
        "ballistic", "hypersonic", "special forces",
    ],
    "Telecommunications": [
        "telecom", "telecommunications", "5g", "broadband", "internet provider",
        "satellite", "undersea cable", "fiber optic", "mobile network",
    ],
    "Government": [
        "government", "ministry", "parliament", "congress", "senate",
        "intelligence agency", "election", "diplomat", "embassy", "sanction",
        "foreign policy", "state department",
    ],
    "Healthcare": [
        "hospital", "healthcare", "pharmaceutical", "vaccine", "medical device",
        "health ministry", "pandemic", "biotech", "clinical trial",
    ],
    "Transportation": [
        "airport", "airline", "shipping", "port", "railway", "logistics",
        "supply chain", "cargo", "maritime", "aviation",
    ],
    "Critical Infrastructure": [
        "critical infrastructure", "scada", "ics", "water treatment",
        "power plant", "dam", "sewage", "grid", "operational technology",
    ],
}

ISO2_TO_COUNTRY: dict[str, str] = {
    "us": "United States of America", "gb": "United Kingdom",
    "cn": "China", "ru": "Russia", "ir": "Iran", "kp": "North Korea",
    "ua": "Ukraine", "il": "Israel", "sa": "Saudi Arabia", "ae": "United Arab Emirates",
    "de": "Germany", "fr": "France", "in": "India", "pk": "Pakistan",
    "tr": "Turkey", "au": "Australia", "ca": "Canada", "jp": "Japan",
    "kr": "South Korea", "br": "Brazil", "mx": "Mexico", "ng": "Nigeria",
    "za": "South Africa", "eg": "Egypt", "iq": "Iraq", "sy": "Syria",
    "af": "Afghanistan", "by": "Belarus", "ge": "Georgia", "md": "Moldova",
    "pl": "Poland", "fi": "Finland", "se": "Sweden", "no": "Norway",
    "tw": "Taiwan", "sg": "Singapore", "my": "Malaysia", "id": "Indonesia",
    "th": "Thailand", "vn": "Vietnam", "ph": "Philippines",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def load_state() -> dict:
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: dict) -> None:
    tmp = STATE_FILE + ".tmp"
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, separators=(",", ":"))
    os.replace(tmp, STATE_FILE)


def read_lines_file(path: str) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


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
    url = (article.get("url") or "").strip()
    if url:
        basis = url
    else:
        src   = ((article.get("source") or {}).get("name") or "").strip()
        title = (article.get("title") or "").strip()
        pub   = (article.get("publishedAt") or "").strip()
        basis = f"{src}|{title}|{pub}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def safe_filename(name: str) -> str:
    keepchars = frozenset(" .-_")
    cleaned = "".join(c if (c.isalnum() or c in keepchars) else "_" for c in name)
    return cleaned[:120].strip()


def normalize_for_index(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().strip())


def load_seen(state: dict) -> dict[str, int]:
    raw = state.get("seen", {})
    if not isinstance(raw, dict):
        return {}
    now = int(time.time())
    return {k: v for k, v in raw.items() if isinstance(v, int) and v > now}


def seen_add(seen: dict[str, int], key: str) -> None:
    seen[key] = int(time.time()) + SEEN_TTL_DAYS * 86400


def load_author_cache(state: dict) -> dict[str, tuple[str, int]]:
    raw = state.get("author_cache", {})
    if not isinstance(raw, dict):
        return {}
    now = int(time.time())
    return {
        k: (v[0], v[1]) for k, v in raw.items()
        if isinstance(v, list) and len(v) == 2 and v[1] > now
    }


def save_author_cache(state: dict, cache: dict[str, tuple[str, int]]) -> None:
    state["author_cache"] = {k: list(v) for k, v in cache.items()}


def _weasyprint_worker(html: str, url: str, queue) -> None:
    """Module-level worker for subprocess-isolated weasyprint rendering.
    Runs in a child process so all weasyprint/Cairo/Pango heap is fully
    released when the process exits, preventing memory accumulation.
    """
    import weasyprint
    try:
        pdf = weasyprint.HTML(string=html, base_url=url).write_pdf()
        queue.put(("ok", pdf))
    except Exception as exc:
        queue.put(("error", str(exc)))


class NewsApiClient:
    BASE = "https://newsapi.org"

    def __init__(self, api_key: str, min_gap: int, max_retries: int):
        self.api_key     = api_key
        self.min_gap     = max(0, min_gap)
        self.max_retries = max(0, max_retries)
        self._last_ts    = 0.0

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

        self.report_type       = os.getenv("NEWSAPI_REPORT_TYPE", "osint").strip()
        self.default_marking   = os.getenv("NEWSAPI_MARKING", "TLP:CLEAR").strip()
        self.confidence        = CONFIDENCE
        self.cr_labels         = [
            x.strip() for x in os.getenv("NEWSAPI_CR_LABELS", "").split(",") if x.strip()
        ]
        self.technical_creator = os.getenv("NEWSAPI_TECHNICAL_CREATOR", "[C]NewsAPI").strip()

        self.attach_pdf    = os.getenv("NEWSAPI_ATTACH_PDF", "true").strip().lower() == "true"
        self.pdf_timeout   = int(os.getenv("NEWSAPI_PDF_TIMEOUT", "120"))
        self.pdf_max_bytes = int(os.getenv("NEWSAPI_PDF_MAX_MB", "12")) * 1024 * 1024
        self.pdf_ua        = os.getenv(
            "NEWSAPI_PDF_USER_AGENT",
            "Mozilla/5.0 (compatible; NewsAPI-OpenCTI/2.0)"
        ).strip()
        self.fetch_timeout = int(os.getenv("NEWSAPI_FETCH_TIMEOUT", "30"))

        raw_domains = read_lines_file(os.getenv("NEWSAPI_DOMAINS_ALLOWLIST_FILE", "").strip())
        self.allowed_domains: frozenset[str] = frozenset(normalize_host(d) for d in raw_domains)

        self.query_profiles: list[dict] = read_json_file(
            os.getenv("NEWSAPI_QUERY_PROFILES_FILE", "").strip(), default=[]
        )
        if not self.query_profiles:
            self.query_profiles = [{
                "name": "default",
                "query": "diplomacy OR sanctions OR military OR ceasefire OR missile OR drone"
            }]

        sectors_file = os.getenv("NEWSAPI_SECTORS_MAP_FILE", "").strip()
        self.sector_map: dict[str, list[str]] = (
            read_json_file(sectors_file, default=DEFAULT_SECTOR_MAP)
            if sectors_file else DEFAULT_SECTOR_MAP
        )

        self.client = NewsApiClient(self.api_key, self.min_gap, self.max_retries)
        self._marking_cache: dict[str, str] = {}
        self._author_cache:  dict[str, tuple[str, int]] = {}
        self._sector_cache:  dict[str, str] = {}
        self._country_cache: dict[str, str] = {}
        self._entity_index:  dict[str, str] = {}

    def _resolve_markings(self) -> None:
        try:
            all_markings = self.helper.api.marking_definition.list()
            if isinstance(all_markings, list):
                for m in all_markings:
                    defn = (m.get("definition") or "").strip()
                    if defn:
                        self._marking_cache[defn] = m["id"]
            self.helper.log_info(f"Resolved {len(self._marking_cache)} marking definitions")
        except Exception as e:
            self.helper.log_warning(f"Marking resolution failed: {e}")

    def _get_marking_id(self, name: str) -> str | None:
        return self._marking_cache.get(name)

    def _resolve_entity_index(self) -> None:
        index: dict[str, str] = {}
        for entity_type, api_obj in [
            ("Intrusion Set", self.helper.api.intrusion_set),
            ("Threat Actor Group", self.helper.api.threat_actor_group),
        ]:
            try:
                after = None
                while True:
                    kwargs = {"first": 200}
                    if after:
                        kwargs["after"] = after
                    page = api_obj.list(**kwargs)
                    if not page:
                        break
                    entities = page if isinstance(page, list) else [
                        e["node"] for e in page.get("edges", [])
                    ]
                    for e in entities:
                        eid = e.get("id")
                        if not eid:
                            continue
                        name = (e.get("name") or "").strip()
                        if name:
                            index[normalize_for_index(name)] = eid
                        for alias in (e.get("aliases") or []):
                            if alias:
                                index[normalize_for_index(alias)] = eid
                    if isinstance(page, list) or not page.get("pageInfo", {}).get("hasNextPage"):
                        break
                    after = page["pageInfo"]["endCursor"]
            except Exception as ex:
                self.helper.log_warning(f"Entity index build failed for {entity_type}: {ex}")
        self._entity_index = index
        self.helper.log_info(f"Entity index built: {len(index)} name/alias entries")

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

    def _url_already_ingested(self, url: str) -> bool:
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
            self.helper.log_warning(f"Graph dedup check failed: {e}")
            return False

    def _work_begin(self, title: str) -> str | None:
        try:
            return self.helper.api.work.initiate_work(self.helper.connect_id, title)
        except Exception as e:
            self.helper.log_warning(f"Work begin failed: {e}")
            return None

    def _work_end(self, work_id: str | None, message: str = "") -> None:
        if not work_id:
            return
        try:
            self.helper.api.work.to_processed(work_id, message)
        except Exception:
            pass

    def _work_fail(self, work_id: str | None, message: str) -> None:
        if not work_id:
            return
        try:
            self.helper.api.work.to_failure(work_id, message)
        except Exception:
            pass

    def _ensure_org_author(self, name: str) -> str:
        name = (name or "Unknown source").strip()
        now  = int(time.time())
        if name in self._author_cache:
            cached_id, expires = self._author_cache[name]
            if expires > now:
                return cached_id
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
                eid = entities[0]["id"]
                self._author_cache[name] = (eid, now + AUTHOR_CACHE_TTL)
                return eid
        except Exception as e:
            self.helper.log_warning(f"Author lookup failed, will create: {e}")
        created = self.helper.api.identity.create(type="Organization", name=name)
        self._author_cache[name] = (created["id"], now + AUTHOR_CACHE_TTL)
        return created["id"]

    def _match_sectors(self, title: str, description: str) -> list[str]:
        text = normalize_for_index(f"{title} {description}")
        matched = []
        for sector_name, keywords in self.sector_map.items():
            for kw in keywords:
                if kw.lower() in text:
                    matched.append(sector_name)
                    break
        return matched

    def _get_or_create_sector(self, name: str) -> str | None:
        if name in self._sector_cache:
            return self._sector_cache[name]
        try:
            res = self.helper.api.sector.list(
                first=1,
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [name]}],
                    "filterGroups": [],
                }
            )
            entities = res if isinstance(res, list) else [
                e["node"] for e in (res or {}).get("edges", [])
            ]
            if entities:
                self._sector_cache[name] = entities[0]["id"]
                return entities[0]["id"]
            created = self.helper.api.sector.create(name=name)
            self._sector_cache[name] = created["id"]
            return created["id"]
        except Exception as e:
            self.helper.log_warning(f"Sector resolution failed for '{name}': {e}")
            return None

    def _get_country_id(self, name: str) -> str | None:
        if name in self._country_cache:
            return self._country_cache[name]
        try:
            res = self.helper.api.location.list(
                first=1,
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "name", "values": [name]},
                        {"key": "entity_type", "values": ["Country"]},
                    ],
                    "filterGroups": [],
                }
            )
            entities = res if isinstance(res, list) else [
                e["node"] for e in (res or {}).get("edges", [])
            ]
            if entities:
                self._country_cache[name] = entities[0]["id"]
                return entities[0]["id"]
        except Exception as e:
            self.helper.log_warning(f"Country lookup failed for '{name}': {e}")
        return None

    def _resolve_geography(self, profile: dict, article: dict) -> list[str]:
        country_ids: list[str] = []
        seen_names: set[str] = set()
        for country_name in (profile.get("geography") or []):
            if country_name not in seen_names:
                cid = self._get_country_id(country_name)
                if cid:
                    country_ids.append(cid)
                    seen_names.add(country_name)
        iso2 = ((article.get("source") or {}).get("country") or "").strip().lower()
        if iso2 and iso2 in ISO2_TO_COUNTRY:
            country_name = ISO2_TO_COUNTRY[iso2]
            if country_name not in seen_names:
                cid = self._get_country_id(country_name)
                if cid:
                    country_ids.append(cid)
        return country_ids

    def _scan_entity_mentions(self, title: str, description: str) -> list[str]:
        text = normalize_for_index(f"{title} {description}")
        matched_ids: list[str] = []
        seen_ids: set[str] = set()
        for normalized_name, entity_id in self._entity_index.items():
            if len(normalized_name) >= 4 and normalized_name in text:
                if entity_id not in seen_ids:
                    matched_ids.append(entity_id)
                    seen_ids.add(entity_id)
        return matched_ids

    def _create_targeting_relationships(
        self,
        entity_ids: list[str],
        country_ids: list[str],
        marking_ids: list[str],
        report_id: str,
    ) -> None:
        for entity_id in entity_ids:
            for country_id in country_ids:
                try:
                    rel = self.helper.api.stix_core_relationship.create(
                        fromId=entity_id,
                        toId=country_id,
                        relationship_type="targets",
                        confidence=self.confidence,
                        objectMarking=marking_ids,
                    )
                    if rel and rel.get("id"):
                        self.helper.api.report.add_stix_object_or_stix_relationship(
                            id=report_id,
                            stixObjectOrStixRelationshipId=rel["id"],
                        )
                except Exception as e:
                    self.helper.log_warning(
                        f"Targeting relationship failed (entity={entity_id} country={country_id}): {e}"
                    )

    def _fetch_full_text(self, url: str) -> str:
        try:
            headers  = {"User-Agent": self.pdf_ua}
            response = requests.get(url, headers=headers, timeout=self.fetch_timeout)
            response.raise_for_status()
            extracted = trafilatura.extract(
                response.text,
                include_comments=False,
                include_tables=True,
                no_fallback=False,
                favor_recall=True,
            )
            return extracted or ""
        except Exception as e:
            self.helper.log_warning(f"Full text fetch failed for {url}: {e}")
            return ""

    def _build_markdown(self, article: dict, full_text: str, profile_name: str) -> str:
        src       = (article.get("source") or {}).get("name") or "Unknown source"
        title     = article.get("title") or ""
        desc      = article.get("description") or ""
        url       = article.get("url") or ""
        published = article.get("publishedAt") or ""
        body      = full_text or desc or "(No content extracted)"
        return "\n".join([
            f"# {title}", "",
            f"**Profile:** {profile_name}",
            f"**Source:** {src}",
            f"**Published:** {published}",
            f"**URL:** {url}", "",
            "## Description", desc, "",
            "## Full Text", body, "",
            "---",
            f"Technical Creator: {self.technical_creator}",
        ])

    def _render_pdf_with_timeout(self, url: str) -> bytes | None:
        """Fetch article and render to PDF bytes via weasyprint.
        Runs weasyprint in a child process so all C-level heap (Cairo, Pango,
        fontTools) is unconditionally released when the process exits,
        preventing memory accumulation in the parent process.
        """
        try:
            headers = {"User-Agent": self.pdf_ua}
            response = requests.get(url, headers=headers, timeout=self.fetch_timeout)
            response.raise_for_status()
            html = response.text
        except Exception as e:
            self.helper.log_warning(f"PDF fetch failed for {url}: {e}")
            return None
        queue = multiprocessing.Queue()
        proc = multiprocessing.Process(target=_weasyprint_worker, args=(html, url, queue))
        proc.start()
        proc.join(timeout=self.pdf_timeout)
        if proc.is_alive():
            proc.kill()
            proc.join()
            self.helper.log_warning(f"PDF render timed out after {self.pdf_timeout}s for {url}")
            return None
        if queue.empty():
            self.helper.log_warning(f"PDF render returned no result for {url}")
            return None
        status, payload = queue.get()
        if status == "error":
            self.helper.log_warning(f"PDF render failed for {url}: {payload}")
            return None
        return payload

    def _attach_pdf(self, report_id: str, report_name: str, url: str) -> None:
        if not self.attach_pdf or not url:
            return
        pdf_bytes = self._render_pdf_with_timeout(url)
        if pdf_bytes is None:
            return
        if len(pdf_bytes) > self.pdf_max_bytes:
            self.helper.log_warning(f"PDF for '{report_name}' exceeds size limit, skipping")
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

    def _attach_markdown(
        self, report_id: str, key: str, profile_name: str,
        article: dict, full_text: str
    ) -> None:
        md    = self._build_markdown(article, full_text, profile_name)
        fname = f"newsapi_{safe_filename(profile_name)}_{key}.md"
        try:
            self.helper.api.stix_domain_object.add_file(
                id=report_id,
                file_name=fname,
                data=md.encode("utf-8"),
                mime_type="text/markdown",
            )
        except Exception as e:
            self.helper.log_warning(f"Markdown attachment failed: {e}")

    def _ingest_article(self, article: dict, profile: dict, key: str) -> str:
        src_name = ((article.get("source") or {}).get("name") or "Unknown source").strip()
        title    = (article.get("title") or "").strip()
        url      = (article.get("url") or "").strip()
        desc     = (article.get("description") or "").strip()

        marking_name = (profile.get("marking") or self.default_marking).strip()
        marking_id   = self._get_marking_id(marking_name)
        marking_ids  = [marking_id] if marking_id else []

        try:
            published_dt = dtparser.parse(article.get("publishedAt") or "").astimezone(timezone.utc)
        except Exception:
            published_dt = utc_now()

        report_name = title or f"News Article ({src_name})"
        author_id   = self._ensure_org_author(src_name)
        full_text   = self._fetch_full_text(url) if url else ""

        ext_ref = self.helper.api.external_reference.create(
            source_name=src_name,
            url=url or None,
            description=desc[:1000] if desc else None,
        )

        report = self.helper.api.report.create(
            name=report_name,
            description=desc or (full_text[:280] if full_text else ""),
            report_types=[self.report_type],
            published=published_dt.isoformat(),
            createdBy=author_id,
            confidence=self.confidence,
            objectMarking=marking_ids,
            externalReferences=[ext_ref["id"]],
        )
        report_id = report["id"]

        cr_labels = profile.get("cr_labels") or self.cr_labels
        for lab in cr_labels:
            try:
                self.helper.api.label.add(object_id=report_id, value=lab)
            except Exception:
                pass

        matched_sectors = self._match_sectors(title, desc)
        for sector_name in matched_sectors:
            sector_id = self._get_or_create_sector(sector_name)
            if sector_id:
                try:
                    self.helper.api.report.add_stix_object_or_stix_relationship(
                        id=report_id, stixObjectOrStixRelationshipId=sector_id,
                    )
                except Exception:
                    pass

        country_ids = self._resolve_geography(profile, article)
        for country_id in country_ids:
            try:
                self.helper.api.report.add_stix_object_or_stix_relationship(
                    id=report_id, stixObjectOrStixRelationshipId=country_id,
                )
            except Exception:
                pass

        if country_ids:
            entity_ids = self._scan_entity_mentions(title, desc)
            if entity_ids:
                self._create_targeting_relationships(entity_ids, country_ids, marking_ids, report_id)

        self._attach_markdown(report_id, key, profile.get("name", "default"), article, full_text)
        self._attach_pdf(report_id, report_name, url)

        return report_id

    def run_once(self) -> None:
        self._resolve_markings()
        self._resolve_entity_index()

        work_id = self._work_begin(f"NewsAPI ingestion ({len(self.query_profiles)} profiles)")
        state   = load_state()

        today  = utc_now().strftime("%Y-%m-%d")
        budget = state.get("budget", {})
        if budget.get("day") != today:
            budget = {"day": today, "requests": 0}

        seen    = load_seen(state)
        cursors = state.get("cursors") if isinstance(state.get("cursors"), dict) else {}
        self._author_cache = load_author_cache(state)

        ingested = skipped_allowlist = skipped_dedup = errors = 0
        skipped_domains: Counter = Counter()

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

                    params: dict = {
                        "q": pquery, "pageSize": self.page_size,
                        "page": page, "sortBy": self.sort_by,
                        "from": from_dt.isoformat(),
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
                            if key in seen:
                                skipped_dedup += 1
                                continue
                            if self._url_already_ingested(url):
                                seen_add(seen, key)
                                skipped_dedup += 1
                                continue
                            self._ingest_article(a, profile, key)
                            seen_add(seen, key)
                            ingested += 1
                            try:
                                pub_dt = dtparser.parse(
                                    a.get("publishedAt") or ""
                                ).astimezone(timezone.utc)
                                if pub_dt > newest_seen:
                                    newest_seen = pub_dt
                            except Exception:
                                pass
                        except Exception as e:
                            errors += 1
                            self.helper.log_error(f"Article ingest failed: {e}")

                cursors[pname] = newest_seen.isoformat()

            state["seen"]    = seen
            state["cursors"] = cursors
            state["budget"]  = budget
            save_author_cache(state, self._author_cache)
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
            save_state(state)
            self._work_fail(work_id, f"Run failed: {e}")
            raise

    def start(self) -> None:
        self.helper.log_info(f"Starting NewsAPI connector v{CONNECTOR_VERSION}...")
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
