"""
NewsAPI OpenCTI connector.

Purpose
-------
External-import connector that queries NewsAPI.org across a set of configurable
query profiles and creates one OpenCTI Report container per article, with the
source article attached as a full-fidelity PDF rendered via Playwright/Chromium.

Collection model
----------------
For each query profile the connector calls the NewsAPI ``/v2/everything``
endpoint with a per-profile time cursor, walks up to ``max_pages_per_run`` pages,
and ingests every article that (a) passes the domain allow-list, (b) is not
already in the graph, and (c) renders to a PDF. NewsAPI's free tier caps usage
at ~100 requests/day, so a persistent daily request budget is enforced across
runs; cursors and a short dedup cache also persist in the state file.

PDF rendering (Playwright)
--------------------------
Every Report gets a PDF. The connector first renders the *live* publisher page
to PDF (high fidelity, lazy media triggered by an auto-scroll). If the live
render fails after retries -- paywall, Cloudflare interstitial, JS-only page,
timeout -- it falls back to rendering a self-contained HTML page built from the
NewsAPI-provided title/description. The fallback has no network dependency, so a
Report is never created without a PDF. This replaces the previous
weasyprint + multiprocessing renderer.

Graph output
------------
Container-first, but not container-only: each Report is enriched with matched
Sector and Country objects, and -- when a known Intrusion Set / Threat Actor
Group is co-mentioned with a resolved country -- a low-confidence ``targets``
relationship (permitted by the data-model allow-list). No Indicators or
Observables are ever created.

Key decisions
-------------
- Container type: Report (external intelligence / "what the world says").
- TLP: CLEAR (public news). report_type: open-source-reporting.
- Author: an Organization identity named after the publishing outlet, created
  on demand. Never the byline, never the connector service account.
- Deduplication: graph-driven via External Reference URL lookup, backed by a
  short TTL seen-cache for speed.
- Confidence: a single low blanket value (unverified OSINT).

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import io
import re
import sys
import html
import time
import json
import hashlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
import trafilatura
import yaml
from dateutil import parser as dtparser
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside the renderer so a syntax/import check of
# this module does not require the browser stack to be present.


class PaywallDetected(Exception):
    """Raised when a live page render is a subscription/paywall wall rather than
    article content, so the caller can fall back to a metadata-only PDF instead
    of archiving a useless 'subscribe to continue' screenshot. Not retried."""


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Browser User-Agent for the article HTTP fetch and the Playwright context.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Recycle the Chromium browser after this many renders to cap memory growth on
# a host that co-locates Elasticsearch.
BROWSER_RECYCLE_EVERY = 50

# Substrings indicating a Cloudflare interstitial rather than article content.
CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")

# Phrases that, when prominent on a rendered page, indicate a paywall/subscribe
# wall rather than the article body. Conservative (specific multi-word phrases)
# to avoid false positives on articles that merely mention subscriptions.
PAYWALL_MARKERS = (
    "subscribe to continue reading", "subscribe to read", "subscribe for full access",
    "to continue reading", "this article is for subscribers", "already a subscriber",
    "create an account to continue", "become a subscriber", "subscribe to keep reading",
    "register to continue reading",
)

# Domains rendered straight to the metadata fallback because their live pages are
# hard paywalls (the rendered PDF would otherwise capture a subscribe wall).
# Operator-extendable via NEWSAPI_PAYWALL_DOMAINS_FILE.
DEFAULT_PAYWALL_DOMAINS = frozenset({
    "wsj.com", "ft.com", "nytimes.com", "washingtonpost.com", "economist.com",
    "bloomberg.com", "nikkei.com", "businessinsider.com", "barrons.com",
    "newyorker.com", "telegraph.co.uk", "foreignpolicy.com", "seekingalpha.com",
})

# Cap on article text written into the Report description (full text also lives
# in the attached PDF). Generous enough for a long feature, bounded to avoid bloat.
MAX_DESCRIPTION_CHARS = 30000

# How long a successfully-ingested article key is remembered in the fast-path
# dedup cache (graph dedup remains the source of truth).
SEEN_TTL_DAYS = 7

# How long a resolved outlet Organization id is cached in state.
AUTHOR_CACHE_TTL = 7 * 86400

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


# --------------------------------------------------------------------------- #
# Module helpers
# --------------------------------------------------------------------------- #

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


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
    """Stable 16-hex dedup key for an article (URL, else source|title|date)."""
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


def strip_html(value: str) -> str:
    """Strip tags and decode HTML entities from a text fragment."""
    if not value:
        return ""
    no_tags = re.sub(r"<[^>]+>", "", value)
    return html.unescape(no_tags).strip()


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


# --------------------------------------------------------------------------- #
# NewsAPI HTTP client
# --------------------------------------------------------------------------- #

class NewsApiClient:
    """Minimal NewsAPI.org client with rate-limit floor and 429 backoff."""

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


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

class NewsAPIConnector:
    """External-import connector that mirrors NewsAPI articles into Reports."""

    def __init__(self):
        """Load configuration, build the OpenCTI helper, and prepare runtime
        config (query profiles, allow-list, sector map). Fixed graph references
        (markings, entity index) are resolved later in run().
        """
        # Classic config bootstrap: optional config.yml so the module runs both
        # in-container (env only) and locally (yaml) unchanged. Environment
        # variables take precedence over config.yml.
        config_file_path = os.path.join(BASE_DIR, "config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        # --- NewsAPI credentials / query behaviour -------------------------- #
        self.api_key = get_config_variable(
            "NEWSAPI_API_KEY", ["newsapi", "api_key"], config, default=""
        ).strip()
        if not self.api_key:
            raise ValueError("NEWSAPI_API_KEY is required")

        self.language = get_config_variable(
            "NEWSAPI_LANGUAGE", ["newsapi", "language"], config, default="en"
        ).strip()
        self.sort_by = get_config_variable(
            "NEWSAPI_SORT_BY", ["newsapi", "sort_by"], config, default="publishedAt"
        ).strip()
        self.page_size = get_config_variable(
            "NEWSAPI_PAGE_SIZE", ["newsapi", "page_size"], config, isNumber=True, default=50
        )
        self.lookback_hours = get_config_variable(
            "NEWSAPI_LOOKBACK_HOURS", ["newsapi", "lookback_hours"], config,
            isNumber=True, default=24,
        )
        self.max_pages = get_config_variable(
            "NEWSAPI_MAX_PAGES_PER_RUN", ["newsapi", "max_pages_per_run"], config,
            isNumber=True, default=1,
        )
        self.daily_budget = get_config_variable(
            "NEWSAPI_DAILY_REQUEST_BUDGET", ["newsapi", "daily_request_budget"], config,
            isNumber=True, default=90,
        )
        self.min_gap = get_config_variable(
            "NEWSAPI_MIN_SECONDS_BETWEEN_REQUESTS", ["newsapi", "min_seconds_between_requests"],
            config, isNumber=True, default=2,
        )
        self.max_retries = get_config_variable(
            "NEWSAPI_MAX_RETRIES", ["newsapi", "max_retries"], config, isNumber=True, default=5,
        )
        # 0 == unlimited. Set small (e.g. 3) for a bounded test before a backfill.
        self.max_posts = get_config_variable(
            "NEWSAPI_MAX_POSTS", ["newsapi", "max_posts"], config, isNumber=True, default=0,
        )

        # --- Report field configuration ------------------------------------ #
        self.report_type = get_config_variable(
            "NEWSAPI_REPORT_TYPE", ["newsapi", "report_type"], config,
            default="open-source-reporting",
        ).strip()
        self.default_marking = get_config_variable(
            "NEWSAPI_MARKING", ["newsapi", "marking"], config, default="TLP:CLEAR"
        ).strip()
        self.confidence = get_config_variable(
            "NEWSAPI_CONFIDENCE", ["newsapi", "confidence"], config, isNumber=True, default=15,
        )
        self.cr_labels = [
            x.strip()
            for x in (get_config_variable(
                "NEWSAPI_CR_LABELS", ["newsapi", "cr_labels"], config, default="") or "").split(",")
            if x.strip()
        ]

        # --- Render configuration (Playwright) ------------------------------ #
        self.poll_interval = get_config_variable(
            "NEWSAPI_POLL_INTERVAL", ["newsapi", "poll_interval"], config,
            isNumber=True, default=3600,
        )
        self.request_delay = get_config_variable(
            "NEWSAPI_REQUEST_DELAY", ["newsapi", "request_delay"], config,
            isNumber=True, default=3,
        )
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["newsapi", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "NEWSAPI_RENDER_RETRIES", ["newsapi", "render_retries"], config,
            isNumber=True, default=3,
        )
        self.pdf_max_bytes = get_config_variable(
            "NEWSAPI_PDF_MAX_MB", ["newsapi", "pdf_max_mb"], config, isNumber=True, default=12,
        ) * 1024 * 1024

        # --- Runtime config files / state ----------------------------------- #
        # Path configs fall back to files next to main.py. The trailing `or`
        # also covers an empty-string config.yml value (which get_config_variable
        # returns verbatim rather than substituting the default).
        self.state_file = get_config_variable(
            "NEWSAPI_STATE_FILE", ["newsapi", "state_file"], config, default=""
        ) or os.path.join(BASE_DIR, "state", "state.json")

        domains_file = get_config_variable(
            "NEWSAPI_DOMAINS_ALLOWLIST_FILE", ["newsapi", "domains_allowlist_file"], config,
            default="",
        ) or os.path.join(BASE_DIR, "domains_allowlist.txt")
        raw_domains = read_lines_file(domains_file.strip())
        self.allowed_domains: frozenset[str] = frozenset(normalize_host(d) for d in raw_domains)

        # Paywalled domains: a provided file replaces the built-in defaults; an
        # absent/empty file keeps the defaults.
        paywall_file = get_config_variable(
            "NEWSAPI_PAYWALL_DOMAINS_FILE", ["newsapi", "paywall_domains_file"], config,
            default="",
        )
        raw_paywall = read_lines_file((paywall_file or "").strip())
        self.paywalled_domains: frozenset[str] = (
            frozenset(normalize_host(d) for d in raw_paywall)
            if raw_paywall else DEFAULT_PAYWALL_DOMAINS
        )

        profiles_file = get_config_variable(
            "NEWSAPI_QUERY_PROFILES_FILE", ["newsapi", "query_profiles_file"], config,
            default="",
        ) or os.path.join(BASE_DIR, "query_profiles.json")
        self.query_profiles: list[dict] = read_json_file(profiles_file.strip(), default=[])
        if not self.query_profiles:
            self.query_profiles = [{
                "name": "default",
                "query": "diplomacy OR sanctions OR military OR ceasefire OR missile OR drone",
            }]

        sectors_file = get_config_variable(
            "NEWSAPI_SECTORS_MAP_FILE", ["newsapi", "sectors_map_file"], config, default=""
        )
        self.sector_map: dict[str, list[str]] = (
            read_json_file((sectors_file or "").strip(), default=DEFAULT_SECTOR_MAP)
            if sectors_file else DEFAULT_SECTOR_MAP
        )

        self.client = NewsApiClient(self.api_key, self.min_gap, self.max_retries)
        self._marking_cache: dict[str, str] = {}
        self._author_cache:  dict[str, tuple[str, int]] = {}
        self._sector_cache:  dict[str, str] = {}
        self._country_cache: dict[str, str] = {}
        self._entity_index:  dict[str, str] = {}

    # ------------------------------------------------------------------ #
    # State
    # ------------------------------------------------------------------ #

    def _load_state(self) -> dict:
        if not os.path.exists(self.state_file):
            return {}
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_state(self, state: dict) -> None:
        tmp = self.state_file + ".tmp"
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, separators=(",", ":"))
        os.replace(tmp, self.state_file)

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self) -> None:
        """Resolve marking definitions, register the report_type vocabulary, and
        build the Intrusion Set / Threat Actor Group name index used to detect
        co-mentions for targeting relationships. Called once at startup.
        """
        # Markings: name -> internal UUID. Profiles may override the default.
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
        if self.default_marking not in self._marking_cache:
            self.helper.log_warning(
                f"Default marking '{self.default_marking}' did not resolve; reports may be "
                f"created without a marking. Verify the marking name in your instance."
            )

        # Open-vocabulary registration (idempotent; harmless if locked). The
        # report_type categorises each Report; the 'assessment' note_type is used
        # for the inference notes attached to co-mention targeting relationships.
        for name, category, desc in [
            (self.report_type, "report_types_ov",
             "Open-source reporting ingested from public news publishers."),
            ("assessment", "note_types_ov",
             "Analyst/automated assessment note (inference or judgement)."),
        ]:
            try:
                self.helper.api.vocabulary.create(name=name, category=category, description=desc)
                self.helper.log_info(f"Ensured {category} value: {name}")
            except Exception as exc:
                self.helper.log_warning(
                    f"Could not register {category} value '{name}' ({exc}). "
                    f"Add it under Settings -> Taxonomies if missing."
                )

        self._build_entity_index()

    def _build_entity_index(self) -> None:
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

    def _get_marking_id(self, name: str) -> str | None:
        return self._marking_cache.get(name)

    # ------------------------------------------------------------------ #
    # Dedup / domain gating
    # ------------------------------------------------------------------ #

    @staticmethod
    def _domain_in_set(url: str, domain_set: frozenset[str]) -> bool:
        """True if the URL's host exactly matches, or is a subdomain of, any
        entry in domain_set (e.g. www.bbc.com matches bbc.com)."""
        d = domain_of(url)
        if not d:
            return False
        if d in domain_set:
            return True
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in domain_set:
                return True
        return False

    def _domain_allowed(self, url: str) -> bool:
        if not self.allowed_domains:
            return True
        return self._domain_in_set(url, self.allowed_domains)

    def _is_paywalled(self, url: str) -> bool:
        return self._domain_in_set(url, self.paywalled_domains)

    def _url_already_ingested(self, url: str) -> bool:
        """Graph-driven dedup: True if an External Reference with this url exists."""
        if not url:
            return False
        try:
            existing = self.helper.api.external_reference.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "url", "values": [url]}],
                    "filterGroups": [],
                }
            )
            return existing is not None
        except Exception as e:
            self.helper.log_warning(f"Graph dedup check failed: {e}")
            return False

    # ------------------------------------------------------------------ #
    # Identity / enrichment lookups
    # ------------------------------------------------------------------ #

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
            if len(normalized_name) >= 4 and re.search(
                r"\b" + re.escape(normalized_name) + r"\b", text
            ):
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
        published_iso: str,
        author_id: str,
        context_title: str,
        context_source: str,
    ) -> None:
        """Create low-confidence Intrusion Set / Threat Actor `targets` Country
        edges for entities co-mentioned with a country in the article. Permitted
        by the data-model allow-list (intrusion-set/threat-actor-group targets
        country). Each edge carries an Assessment Note recording that it is an
        article-co-mention inference, not a confirmed assertion, per the CTI
        Ingestion Manual's requirement for implied/attribution relationships.
        """
        for entity_id in entity_ids:
            for country_id in country_ids:
                try:
                    rel = self.helper.api.stix_core_relationship.create(
                        fromId=entity_id,
                        toId=country_id,
                        relationship_type="targets",
                        description=(
                            "Inferred from co-mention of this actor and country in a source "
                            "news article. Low-confidence; not a confirmed targeting assertion."
                        ),
                        start_time=published_iso,
                        confidence=self.confidence,
                        objectMarking=marking_ids,
                    )
                    if rel and rel.get("id"):
                        self.helper.api.report.add_stix_object_or_stix_relationship(
                            id=report_id,
                            stixObjectOrStixRelationshipId=rel["id"],
                        )
                        self._create_assessment_note(
                            rel["id"], report_id, marking_ids, author_id,
                            context_title, context_source,
                        )
                except Exception as e:
                    self.helper.log_warning(
                        f"Targeting relationship failed (entity={entity_id} country={country_id}): {e}"
                    )

    def _create_assessment_note(
        self, rel_id: str, report_id: str, marking_ids: list[str],
        author_id: str, title: str, source: str,
    ) -> None:
        """Attach an Assessment-type Note to a co-mention `targets` relationship,
        documenting that it is a machine-generated, unverified inference. Required
        by the manual for every implied/attribution relationship."""
        try:
            note = self.helper.api.note.create(
                abstract="Automated co-mention inference (unverified)",
                content=(
                    f"This `targets` relationship was generated automatically from the "
                    f"co-occurrence of the threat actor and the country in the source news "
                    f"article \"{title}\" ({source}). It is a low-confidence assessment that "
                    f"has not been analyst-verified; co-mention in an article does not "
                    f"establish actual targeting."
                ),
                note_types=["assessment"],
                confidence=self.confidence,
                createdBy=author_id,
                objects=[rel_id],
                objectMarking=marking_ids,
            )
            if note and note.get("id"):
                self.helper.api.report.add_stix_object_or_stix_relationship(
                    id=report_id, stixObjectOrStixRelationshipId=note["id"],
                )
        except Exception as e:
            self.helper.log_warning(f"Assessment note creation failed for {rel_id}: {e}")

    # ------------------------------------------------------------------ #
    # PDF rendering (Playwright)
    # ------------------------------------------------------------------ #

    def _auto_scroll(self, page) -> None:
        """Scroll to the page bottom to trigger lazy-loaded media."""
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

    def _pdf_footer(self, url: str) -> str:
        ingested_at = utc_now().strftime("%Y-%m-%d %H:%M UTC")
        return (
            "<div style='font-size:8px; width:100%; padding:0 12px; "
            "color:#444; display:flex; justify-content:space-between;'>"
            f"<span>{html.escape(url)}</span>"
            f"<span>OpenCTI NewsAPI connector &middot; ingested {ingested_at} "
            "&middot; page <span class='pageNumber'></span>/"
            "<span class='totalPages'></span></span></div>"
        )

    def _extract_text(self, page) -> str:
        """Extract the main article text from the already-rendered DOM via
        trafilatura. Reuses page.content(), so there is no second network fetch."""
        try:
            extracted = trafilatura.extract(
                page.content(),
                include_comments=False, include_tables=True,
                no_fallback=False, favor_recall=True,
            )
            return (extracted or "").strip()
        except Exception:
            return ""

    def _looks_paywalled(self, page) -> bool:
        """True if the rendered body text carries a prominent paywall phrase."""
        try:
            body = (page.inner_text("body") or "").lower()
        except Exception:
            return False
        return any(marker in body for marker in PAYWALL_MARKERS)

    def _render_live(self, browser, url: str) -> tuple[bytes, str]:
        """Render the live publisher page to (pdf_bytes, full_text).

        Raises PaywallDetected if the page is a subscribe wall (caller falls back
        to a metadata PDF without retrying), or other exceptions on transient
        failure for the retry handler.
        """
        context = browser.new_context(
            viewport={"width": 1280, "height": 1696}, user_agent=BROWSER_UA
        )
        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)
            title = (page.title() or "").lower()
            if any(marker in title for marker in CHALLENGE_MARKERS):
                raise RuntimeError("Cloudflare challenge interstitial detected")
            self._auto_scroll(page)
            page.wait_for_timeout(1500)  # final settle for post-scroll loads
            if self._looks_paywalled(page):
                raise PaywallDetected(url)
            full_text = self._extract_text(page)
            pdf = page.pdf(
                print_background=True,
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=self._pdf_footer(url),
                margin={"top": "10mm", "bottom": "16mm", "left": "8mm", "right": "8mm"},
                format="A4",
            )
            return pdf, full_text
        finally:
            page.close()
            context.close()

    def _render_live_with_retry(self, browser, url: str) -> tuple[bytes, str] | None:
        """Render the live page with bounded exponential backoff. Returns
        (pdf_bytes, full_text), or None to signal 'use the metadata fallback'
        (paywall detected, or all attempts exhausted). Paywalls are not retried."""
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._render_live(browser, url)
            except PaywallDetected:
                self.helper.log_info(f"Paywall detected at {url}; using metadata fallback.")
                return None
            except Exception as exc:
                self.helper.log_warning(
                    f"Live render attempt {attempt}/{self.render_retries} failed for {url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay *= 2
        return None

    def _build_fallback_html(self, article: dict, profile_name: str) -> str:
        """Self-contained HTML built from NewsAPI metadata (no network needed)."""
        src       = html.escape((article.get("source") or {}).get("name") or "Unknown source")
        title     = html.escape(article.get("title") or "Untitled")
        desc      = html.escape(article.get("description") or "(No description provided by NewsAPI.)")
        url       = html.escape(article.get("url") or "")
        published = html.escape(article.get("publishedAt") or "")
        return f"""<!doctype html><html><head><meta charset="utf-8"><style>
            body {{ font-family: Georgia, 'Times New Roman', serif; margin: 48px; color: #1a1a1a; line-height: 1.5; }}
            .meta {{ color: #555; font-size: 12px; margin-bottom: 24px; }}
            .meta div {{ margin: 2px 0; }}
            h1 {{ font-size: 22px; line-height: 1.25; margin: 0 0 16px; }}
            .desc {{ font-size: 15px; }}
            .note {{ margin-top: 40px; padding-top: 12px; border-top: 1px solid #ccc; color: #888; font-size: 11px; }}
            a {{ color: #1a5276; word-break: break-all; }}
        </style></head><body>
            <h1>{title}</h1>
            <div class="meta">
              <div><strong>Source:</strong> {src}</div>
              <div><strong>Published:</strong> {published}</div>
              <div><strong>Profile:</strong> {html.escape(profile_name)}</div>
              <div><strong>URL:</strong> <a href="{url}">{url}</a></div>
            </div>
            <div class="desc">{desc}</div>
            <div class="note">Live article page could not be rendered; this fallback was generated
            from NewsAPI metadata by the OpenCTI NewsAPI connector.</div>
        </body></html>"""

    def _render_fallback_pdf(self, browser, article: dict, profile_name: str) -> bytes:
        """Render the metadata-only fallback page to PDF. Raises on failure."""
        context = browser.new_context(
            viewport={"width": 1280, "height": 1696}, user_agent=BROWSER_UA
        )
        page = context.new_page()
        try:
            page.set_content(
                self._build_fallback_html(article, profile_name),
                wait_until="load", timeout=self.nav_timeout_ms,
            )
            return page.pdf(
                print_background=True,
                margin={"top": "10mm", "bottom": "12mm", "left": "8mm", "right": "8mm"},
                format="A4",
            )
        finally:
            page.close()
            context.close()

    def _acquire(self, browser, article: dict, profile_name: str) -> tuple[bytes | None, str]:
        """Produce (pdf_bytes, full_text) for an article, guaranteeing a PDF where
        possible.

        Known-paywalled domains skip straight to the metadata fallback (their live
        render would only capture a subscribe wall). Otherwise the live page is
        rendered and its article text extracted; on paywall/failure/oversize the
        metadata fallback is used. Returns (None, "") only if even the fallback
        fails. full_text is empty when the metadata fallback is used.
        """
        url = (article.get("url") or "").strip()
        if url and self._is_paywalled(url):
            self.helper.log_info(
                f"{domain_of(url)} is on the paywall list; using metadata fallback for {url}"
            )
        elif url:
            result = self._render_live_with_retry(browser, url)
            if result is not None:
                pdf, full_text = result
                if pdf is not None and len(pdf) > self.pdf_max_bytes:
                    self.helper.log_warning(
                        f"Live PDF for {url} exceeds {self.pdf_max_bytes} bytes; using metadata fallback."
                    )
                else:
                    return pdf, full_text
        try:
            pdf = self._render_fallback_pdf(browser, article, profile_name)
            self.helper.log_info(f"Used metadata fallback PDF for {url or '(no url)'}")
            return pdf, ""
        except Exception as exc:
            self.helper.log_warning(f"Fallback PDF render failed for {url}: {exc}")
            return None, ""

    def _attach_pdf(self, report_id: str, report_name: str, key: str, pdf_bytes: bytes) -> None:
        base = safe_filename(report_name) or f"newsapi-{key}"
        try:
            self.helper.api.stix_domain_object.add_file(
                id=report_id,
                file_name=f"{base}.pdf",
                data=io.BytesIO(pdf_bytes),
                mime_type="application/pdf",
            )
            self.helper.log_info(f"Attached PDF to report '{report_name[:80]}'")
        except Exception as e:
            self.helper.log_warning(f"PDF upload failed for '{report_name}': {e}")

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _ingest_article(
        self, article: dict, profile: dict, key: str, pdf_bytes: bytes, full_text: str
    ) -> str:
        src_name = ((article.get("source") or {}).get("name") or "Unknown source").strip()
        title    = (article.get("title") or "").strip()
        url      = (article.get("url") or "").strip()
        desc     = (article.get("description") or "").strip()
        # Prefer the extracted article body (searchable in the graph); fall back
        # to NewsAPI's snippet when the live page wasn't rendered (paywall/failure).
        body = (full_text or "").strip()[:MAX_DESCRIPTION_CHARS]
        report_description = body or desc

        marking_name = (profile.get("marking") or self.default_marking).strip()
        marking_id   = self._get_marking_id(marking_name)
        marking_ids  = [marking_id] if marking_id else []

        try:
            published_dt = dtparser.parse(article.get("publishedAt") or "").astimezone(timezone.utc)
        except Exception:
            published_dt = utc_now()
        published_iso = published_dt.isoformat()

        report_name = title or f"News Article ({src_name})"
        author_id   = self._ensure_org_author(src_name)

        ext_ref = self.helper.api.external_reference.create(
            source_name=src_name,
            url=url or None,
            description=desc[:1000] if desc else None,
        )

        report = self.helper.api.report.create(
            name=report_name,
            description=report_description,
            report_types=[self.report_type],
            published=published_iso,
            createdBy=author_id,
            confidence=self.confidence,
            objectMarking=marking_ids,
            externalReferences=[ext_ref["id"]],
            update=True,
        )
        report_id = report["id"]

        cr_labels = profile.get("cr_labels") or self.cr_labels
        for lab in cr_labels:
            try:
                self.helper.api.label.add(object_id=report_id, value=lab)
            except Exception:
                pass

        for sector_name in self._match_sectors(title, desc):
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
                self._create_targeting_relationships(
                    entity_ids, country_ids, marking_ids, report_id, published_iso,
                    author_id, title, src_name,
                )

        self._attach_pdf(report_id, report_name, key, pdf_bytes)
        return report_id

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self) -> None:
        """Execute one full enumeration-and-ingest pass over all query profiles."""
        from playwright.sync_api import sync_playwright  # lazy import

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, f"NewsAPI ingestion ({len(self.query_profiles)} profiles)"
        )
        state = self._load_state()

        today  = utc_now().strftime("%Y-%m-%d")
        budget = state.get("budget", {})
        if budget.get("day") != today:
            budget = {"day": today, "requests": 0}

        seen    = load_seen(state)
        cursors = state.get("cursors") if isinstance(state.get("cursors"), dict) else {}
        self._author_cache = load_author_cache(state)

        # Wire the live sub-objects back into `state` so any mid-run _save_state()
        # writes a consistent snapshot — notably the API request budget, which is
        # flushed after every request so a crash/restart cannot blow the daily quota.
        state["budget"]  = budget
        state["seen"]    = seen
        state["cursors"] = cursors

        ingested = skipped_allowlist = skipped_dedup = errors = 0
        skipped_domains: Counter = Counter()

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                for profile in self.query_profiles:
                    if budget["requests"] >= self.daily_budget:
                        self.helper.log_info("Daily budget reached; stopping run.")
                        break
                    if self.max_posts and ingested >= self.max_posts:
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
                        if self.max_posts and ingested >= self.max_posts:
                            break

                        params: dict = {
                            "q": pquery, "pageSize": self.page_size,
                            "page": page, "sortBy": self.sort_by,
                            "from": from_dt.isoformat(),
                        }
                        if self.language:
                            params["language"] = self.language

                        budget["requests"] += 1
                        self._save_state(state)  # durable budget before the call
                        try:
                            data = self.client.get("/v2/everything", params)
                        except Exception as e:
                            # One bad request should not abort the remaining profiles.
                            errors += 1
                            self.helper.log_error(f"NewsAPI request failed (profile={pname}): {e}")
                            break
                        articles = data.get("articles") or []

                        self.helper.log_info(
                            f"profile={pname} page={page} total={data.get('totalResults')} "
                            f"on_page={len(articles)} from={from_dt.date()}"
                        )

                        if not articles:
                            break

                        for a in articles:
                            if self.max_posts and ingested >= self.max_posts:
                                break
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

                                if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                                    browser.close()
                                    browser = pw.chromium.launch(
                                        args=["--no-sandbox", "--disable-dev-shm-usage"]
                                    )
                                    renders_since_recycle = 0

                                pdf_bytes, full_text = self._acquire(browser, a, pname)
                                renders_since_recycle += 1
                                if pdf_bytes is None:
                                    errors += 1
                                    self.helper.log_warning(
                                        f"Skipping {url}: no PDF could be produced."
                                    )
                                    continue

                                self._ingest_article(a, profile, key, pdf_bytes, full_text)
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
                                time.sleep(self.request_delay)
                            except Exception as e:
                                errors += 1
                                self.helper.log_error(f"Article ingest failed: {e}")

                    cursors[pname] = newest_seen.isoformat()
                    self._save_state(state)  # persist cursor progress per profile

                state["seen"]    = seen
                state["cursors"] = cursors
                state["budget"]  = budget
                save_author_cache(state, self._author_cache)
                self._save_state(state)

                if skipped_domains:
                    top = ", ".join(f"{d}:{c}" for d, c in skipped_domains.most_common(20))
                    self.helper.log_info(f"Top allowlist-skipped domains: {top}")

                msg = (
                    f"Run complete. ingested={ingested} skipped_dedup={skipped_dedup} "
                    f"skipped_allowlist={skipped_allowlist} errors={errors} "
                    f"budget={budget['requests']}/{self.daily_budget}"
                )
                self.helper.log_info(msg)
                self.helper.api.work.to_processed(work_id, msg)

            except Exception as e:
                self._save_state(state)
                self.helper.api.work.to_processed(work_id, f"Run failed: {e}", in_error=True)
                raise
            finally:
                browser.close()

    def run(self) -> None:
        """Connector entrypoint: resolve references once, then poll forever."""
        self.helper.log_info("NewsAPI connector started.")
        self._resolve_graph_references()
        while True:
            try:
                self._process()
            except Exception as e:
                self.helper.log_error(f"Unhandled error during run: {e}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        NewsAPIConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
