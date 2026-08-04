# URLHaus OpenCTI Connector

A custom external-import connector for [OpenCTI](https://www.opencti.io/) that ingests active malware-distribution URLs and associated payload hashes from [URLHaus](https://urlhaus.abuse.ch/) (abuse.ch) and converts them to STIX 2.1 objects inside a daily Report container.

---

## Overview

On a configurable interval (default 24 h) the connector pulls two URLHaus API v1 feeds — recent URLs and recent payloads — and folds each entry into a single daily **`observable-feed`** Report. It is **Indicator-free** (`createIndicator=False` on every observable), non-destructive, and idempotent: the daily report is reused by name, so intra-day re-runs merge into the same container rather than duplicating it.

Scope is deliberately tight on the URL side: only entries whose `url_status == "online"` at fetch time are ingested — the URL was actively serving malicious content at last check. Payload hashes are ingested unconditionally, since a hash stays analytically useful for detection and retrospective analysis after its hosting URL goes offline.

---

## Requirements

- OpenCTI 6.x (pinned to `pycti==6.9.13`)
- Docker and Docker Compose
- A URLHaus API auth key ([get one free](https://auth.abuse.ch/))
- An OpenCTI user token for the connector identity

---

## Configuration

Configuration is resolved by `pycti.get_config_variable`, which reads (in order) an optional `config.yml` beside `src/` and then the process environment. Standard `OPENCTI_*` / `CONNECTOR_*` variables are consumed by `OpenCTIConnectorHelper`; connector-specific variables are below.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENCTI_URL` | Yes | — | OpenCTI instance URL |
| `OPENCTI_TOKEN` | Yes | — | API token for the connector user |
| `CONNECTOR_ID` | Yes | — | Stable UUID for this connector instance |
| `URLHAUS_API_KEY` | Yes | — | URLHaus API auth key (sent as `Auth-Key` header) |
| `URLHAUS_INTERVAL_HOURS` | No | `24` | Hours between ingestion cycles |
| `URLHAUS_RUN_ON_STARTUP` | No | `false` | If `true`, run immediately on boot; otherwise sleep one interval first |

Secrets belong in `docker-compose.override.yml` (never committed). Work with the env-var **names** above, not their values.

---

## Data Model

### What the connector produces

| STIX Type | Source | Notes |
|-----------|--------|-------|
| `url` | URL feed `url` field | Scored `85`; described as active distribution URL |
| `domain-name` / `ipv4-addr` / `ipv6-addr` | URL feed `host` field | Type auto-classified from the value (`classify_host`) |
| `file` | Payload feed | SHA-256 (required) + MD5 (if present) + `size`; scored `85` |
| `software` | Sensor/framework tags | e.g. `Cowrie` honeypot — observable, not an SDO |
| `malware` | URL threat tags + payload `signature` | `is_family: true`; default route for unrecognized family tags |
| `tool` | Abused-tool tags | e.g. `ConnectWise`, `GitHub`, `wget`, generic RMM |
| `identity` | Static | `URLHaus` Organization — authors the report and every object |
| `report` | Per run | Title: `URLHaus Feed — YYYY-MM-DD`, type `observable-feed` |

### Relationships produced

All edges are `related-to` STIX core relationships, validated against the Data Model Relationship Guide allowlist. `start_time` is set from the entry's `date_added` / `firstseen` when available.

| Source | Type | Target |
|--------|------|--------|
| `url` | `related-to` | `URLHaus` identity |
| `url` | `related-to` | host observable (domain / IPv4 / IPv6) |
| host observable | `related-to` | `URLHaus` identity |
| `url` / host | `related-to` | Malware / Tool / Software (per tag) |
| `file` | `related-to` | `URLHaus` identity |
| `file` | `related-to` | Malware (from payload `signature`) |
| `file` | `related-to` | parent `url` (via `urls_from_same_payload`) |

### What the connector does NOT produce

- **Indicators** — `createIndicator=False` everywhere; OpenCTI generates them downstream if configured
- Infrastructure, Attack Pattern, or Sighting objects
- Any relationship outside the `related-to` allowlist

---

## Tag Routing

Each URLHaus threat tag on a URL entry passes through a four-step pipeline (`_ingest_url_entry`):

1. **`normalize_tag()`** — underscores/hyphens to spaces, title-case, then drop if empty, in `TAG_BLOCKLIST`, or matching a `_BLOCKLIST_PREFIXES` pattern (`Pw *`, `Dropped By *`). The blocklist suppresses file extensions, CPU architectures, encoding descriptors, and generic category labels that are not malware-family names.
2. **`TAG_TOOL_MAP`** — known legitimate-but-abused software → **Tool** SDO (`ConnectWise`, generic `RMM`, `GitHub`, `wget`).
3. **`TAG_SOFTWARE_MAP`** — detection infrastructure observed in the submission context → **Software** observable (`Cowrie`).
4. **Fallback** — anything surviving the above → **Malware** SDO (`is_family: true`).

Payload `signature` values bypass this pipeline and route straight to Malware — they are abuse.ch pipeline classifications, not user-submitted tags.

Tags in `TAG_TOOL_MAP` / `TAG_SOFTWARE_MAP` must **not** also appear in `TAG_BLOCKLIST`; the maps and blocklist are mutually exclusive by design.

---

## Report Container

Each run produces (or reuses) a `report` SDO titled `URLHaus Feed — YYYY-MM-DD`. The report:
- Is typed `report_types: ["observable-feed"]` — the house value distinguishing automated abuse.ch feeds from analyst-authored `threat-report` products
- Is authored by the `URLHaus` Organization identity, resolved-or-created once at startup
- `published` is set to `YYYY-MM-DDT00:00:00Z`
- Is marked **TLP:CLEAR** (resolved from the platform by name — never a hardcoded marking ID)
- Objects are attached individually via `report.add_stix_object_or_stix_relationship()` rather than `send_stix2_bundle`, so large daily object sets don't overflow a single bundle push

---

## Deduplication & Idempotency

No state file is kept — deduplication is graph-driven:

- **Report** — looked up by exact name before creation; same-day re-runs return the existing container and re-attach objects (attachment is a merge, not a duplicate).
- **Observables** — keyed by STIX namespace + value inside OpenCTI; identical URLs/hosts/files from this or any other feed merge automatically.
- **Malware / Tool / Software** — resolved by name through a per-type, TTL-aware in-process cache (`MALWARE_CACHE_TTL_SECONDS = 86400`) backed by a graph lookup, then create-if-absent. The cache spares repeated graph reads within a run; the graph lookup guarantees cross-run reuse.

---

## API Client

`URLHausClient` is a thin wrapper over URLHaus API v1 (`https://urlhaus-api.abuse.ch/v1`):

- Auth-Key header on every request; `GET` method (the current API returns 405 on POST)
- 60 s per-request timeout
- Exponential backoff (2 s / 4 s / 8 s) on connection errors, timeouts, and retryable status codes (`429, 500, 502, 503, 504`); up to 3 retries
- Non-retryable 4xx (e.g. `401` bad key) raise immediately — retrying a config error is pointless
- `get_recent_urls()` filters to `url_status == "online"`; `get_recent_payloads()` returns all payloads
- A non-`ok` `query_status` from either endpoint raises `URLHausAPIError`

---

## Run Lifecycle

1. **Startup** — load config, build the helper, resolve TLP:CLEAR and the `URLHaus` identity, initialize per-type caches, log active tag routing.
2. **Schedule** — if `URLHAUS_RUN_ON_STARTUP` is false, sleep one interval before the first cycle.
3. **Each cycle** (`_run_once`) — initiate a Work, fetch both feeds, get-or-create the daily report, process URL entries then payload entries, link every produced object to the report, and mark the Work processed with an object/link-failure summary.
4. **Resilience** — a single bad entry is logged and skipped, not fatal; an API error fails the Work and re-raises; the outer loop catches any unhandled exception so the connector survives to the next interval.

---

## Project Structure
```
urlhaus/
├── src/
│   ├── main.py        # Entry point — instantiate and run
│   ├── connector.py   # Connector class, run loop, tag routing, entity/report helpers
│   └── client.py      # URLHaus API v1 client with backoff retry
├── Dockerfile         # python:3.11-slim, libmagic1 before pip
└── requirements.txt   # pycti==6.9.13 pinned
```

---

## Build & Run
```bash
docker compose -f docker-compose.yml -f docker-compose.override.yml build --no-cache
docker compose -f docker-compose.yml -f docker-compose.override.yml up -d
docker compose -f docker-compose.yml -f docker-compose.override.yml logs -f
```

---

## Notes

- **Authoring identity migration (2026-06):** the report author was moved from a shared `abuse.ch` identity to a per-product `URLHaus` Organization. Existing reports were re-authored via `scripts/migrate_report_author_type.py`. Known residue: pre-migration observables/SDOs remain `created_by` `abuse.ch`; remapping those objects is a separate, larger operation and has not been performed.
- The connector was already TLP-correct and correctly pinned at review time — do not "fix" it to match the older ThreatFox pattern.

---

## License

MIT
