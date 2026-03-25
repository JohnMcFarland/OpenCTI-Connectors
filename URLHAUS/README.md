# OpenCTI URLHaus Connector

An external import connector for [OpenCTI](https://www.opencti.io/) that ingests active malware distribution URLs and payload hashes from [abuse.ch URLHaus](https://urlhaus.abuse.ch/) into the knowledge graph as daily-scoped threat report containers.

---

## Design Philosophy

This connector is built around four principles that govern every architectural decision:

**Observable-only output.** URLHaus provides threat indicators, not intelligence assessments. The connector produces observables — URLs, IP addresses, domain names, and file hashes — and never creates Indicator objects. Indicators carry an analytical assertion ("this is malicious") that belongs to the analyst, not to an automated feed ingestor. The sole exception in this codebase is the VirusTotal connector, which imports crowdsourced YARA rules as Indicators under explicit policy authorization.

**Container-first containment.** Every object created by this connector is explicitly linked to its daily Report container. No entity or observable exists in the graph without provenance. This enforces the Four Cs data model (Containment, Contextualization, Completeness, Categorization) and ensures data is traceable, scopeable, and manageable over time.

**Graph-native deduplication.** The connector maintains no local state files. Deduplication is handled entirely by the OpenCTI graph: `pycti` create calls are idempotent on observable values and file hashes, returning existing objects when they match. Same-day reruns append to the existing daily container without creating duplicates.

**Analytical integrity over volume.** Data quality gates are applied before any graph write. The tag filtering pipeline — static blocklist, prefix pattern matching, and entity-type routing — prevents non-family tags from producing incorrect entity types. A smaller graph with high analytical confidence is more valuable than a larger graph contaminated with spurious entities.

---

## Functionality

### Data Sources

Two URLHaus API v1 endpoints are consumed per run:

| Endpoint | Scope | Filter |
|---|---|---|
| `/urls/recent/` | Last 1,000 submitted URLs | `url_status == 'online'` only |
| `/payloads/recent/` | Last 1,000 submitted payloads | None — all payloads retained |

The online-status filter on URLs is intentional. Ingesting offline URLs would flood the graph with stale, low-value observables. Payloads have no equivalent filter because file hashes remain analytically relevant for detection and retrospective analysis regardless of whether their hosting URL is still active.

### Container Strategy

The connector creates one Report container per calendar day (UTC), named `URLHaus Feed — YYYY-MM-DD`. Containers are idempotent on name — if the connector is restarted on the same day, it finds the existing container and appends new objects to it rather than creating a duplicate.

### Tag Routing Pipeline

URLHaus threat tags pass through a four-stage pipeline before any entity is created or looked up:

**Stage 1 — Normalization and suppression.** The raw tag is title-cased after replacing underscores and hyphens with spaces. The result is checked against `TAG_BLOCKLIST` (static frozenset) and `_BLOCKLIST_PREFIXES` (regex patterns). Tags that match are dropped silently — no entity is created. This stage blocks file type extensions, CPU architecture names, encoding descriptors, hosting pattern labels, and open-ended tag families (`Pw *`, `Dropped By *`).

**Stage 2 — Tool routing.** If the normalized name appears in `TAG_TOOL_MAP`, a Tool SDO is resolved (looked up or created). Tool entities represent legitimate software abused by threat actors. Current mappings:

| URLHaus Tag | Canonical Tool Name |
|---|---|
| `connectwise` | ConnectWise |
| `rmm` | Remote Monitoring and Management (RMM) |
| `github` | GitHub |
| `ua_wget` | wget |

**Stage 3 — Software routing.** If the normalized name appears in `TAG_SOFTWARE_MAP`, a Software observable is resolved. Software entities represent specific tools or frameworks observed in the threat context that are not themselves malicious. Current mappings:

| URLHaus Tag | Canonical Software Name |
|---|---|
| `cowrie` | Cowrie |

**Stage 4 — Malware SDO (default).** Any tag that passes all filters and is not in the Tool or Software maps produces a Malware SDO with `is_family=True`.

All resolved entity IDs — Malware, Tool, or Software — receive `related-to` relationships from the URL and host observables, and are linked into the daily Report container.

### Object Model

For each online URL entry:

```
URL observable
  └─ related-to → abuse.ch (Organization)
  └─ related-to → Host observable (IPv4-Addr, IPv6-Addr, or Domain-Name)
  └─ related-to → Malware SDO  (per malware family tag)
  └─ related-to → Tool SDO     (per abused-tool tag)
  └─ related-to → Software     (per sensor/framework tag)

Host observable
  └─ related-to → abuse.ch (Organization)
  └─ related-to → Malware SDO  (per malware family tag)
  └─ related-to → Tool SDO     (per abused-tool tag)
  └─ related-to → Software     (per sensor/framework tag)
```

For each payload entry:

```
File observable (StixFile, SHA-256 + MD5)
  └─ related-to → abuse.ch (Organization)
  └─ related-to → Malware SDO (from signature field, if accepted)
  └─ related-to → URL observable (same-run only)
```

Payload signatures are always routed to Malware SDOs. URLHaus payload signatures are assigned by the abuse.ch classification pipeline, not user-submitted tags, so Tool/Software routing does not apply.

### File→URL Scoping

The `File → related-to → URL` link is created only when both the URL and its payload appear in the same run. The URL must have had `url_status == 'online'` at ingestion time. This prevents creating relationships between payloads and URLs that were offline at ingestion time.

### Identity Sharing

Both URLHaus and ThreatFox attribute their data to `abuse.ch`. The connector resolves the `abuse.ch` Organization identity by name lookup at startup, reusing any entity already created by the ThreatFox connector or by manual ingestion. Exactly one `abuse.ch` Organization exists in the graph regardless of deployment order.

---

## Core Components

### `src/connector.py`

The main connector class. Key responsibilities:

- **Startup resolution** — resolves `TLP:CLEAR` and `abuse.ch` identity. Logs the full tag routing configuration (tool tags, software tags, blocked tags, prefix patterns) at startup for production auditability.
- **Tag routing pipeline** — `normalize_tag()` applies normalization, blocklist, and prefix filters. `_ingest_url_entry()` routes accepted tags through `TAG_TOOL_MAP`, `TAG_SOFTWARE_MAP`, then falls through to Malware.
- **Entity resolution** — `_get_or_create_tool()`, `_get_or_create_software()`, and `_get_or_create_malware()` share the same TTL-aware cache and graph-lookup-then-create pattern.
- **Run loop** — polls on a configurable interval. Respects `URLHAUS_RUN_ON_STARTUP` to avoid redundant same-day runs on container restart.
- **Report linking** — links all created object IDs to the daily Report container via `add_stix_object_or_stix_relationship()`.

### `src/client.py`

Thin HTTP client for the URLHaus API v1. Sends `Auth-Key` as an HTTP header on GET requests. Wraps all requests in an exponential backoff retry loop: up to 3 retries with 2s/4s/8s delays on connection errors, timeouts, and 5xx/429 responses. Non-retryable 4xx errors raise immediately.

### Tag Filtering

**`TAG_BLOCKLIST`** — a `frozenset` of title-cased strings. Tags matching any entry are dropped before any entity lookup or creation. Covers file type extensions, CPU architecture names (ARM, MIPS, x86, SPARC, etc.), encoding descriptors, scripting language names, hosting pattern labels, and generic category labels.

**`_BLOCKLIST_PREFIXES`** — compiled regex patterns for open-ended tag families:
- `Pw *` — URLHaus internal tracking artifacts with arbitrary suffixes
- `Dropped By *` — dropper chain provenance labels, not family names

**`TAG_TOOL_MAP`** — maps normalized tag names to canonical Tool entity names for known abused legitimate tools.

**`TAG_SOFTWARE_MAP`** — maps normalized tag names to canonical Software observable names for known sensor/framework tags.

The full routing configuration is logged at every connector startup under `"URLHaus tag routing active"`.

### `classify_host()`

Determines the correct STIX observable type for a URLHaus host field value. Handles IPv4 addresses (`IPv4-Addr`), IPv6 addresses (`IPv6-Addr`), and domain names (`Domain-Name`) explicitly.

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | Yes | — | OpenCTI base URL (internal Docker network) |
| `OPENCTI_TOKEN` | Yes | — | Connector service account API token |
| `CONNECTOR_ID` | Yes | — | Connector UUID — must be unique per OpenCTI instance |
| `CONNECTOR_NAME` | No | `URLHaus` | Display name in the OpenCTI connector panel |
| `CONNECTOR_LOG_LEVEL` | No | `info` | Logging verbosity: `debug`, `info`, `warning`, `error` |
| `URLHAUS_API_KEY` | Yes | — | URLHaus API key from [https://urlhaus.abuse.ch/api/](https://urlhaus.abuse.ch/api/) |
| `URLHAUS_INTERVAL_HOURS` | No | `24` | Poll interval in hours |
| `URLHAUS_RUN_ON_STARTUP` | No | `false` | Execute a run immediately on startup. Set `true` for development or forced runs. |

---

## Deployment

### Prerequisites

- OpenCTI 6.9.13
- A dedicated connector user in **Settings → Security → Users** with the **Connector** role
- A URLHaus API key from [https://urlhaus.abuse.ch/api/](https://urlhaus.abuse.ch/api/) with account email verification completed

### Installation

**1. Copy connector source to the host:**
```bash
cp -r ./urlhaus /path/to/opencti-docker/connectors/custom/
```

**2. Add environment variables to `.env`:**
```bash
URLHAUS_CONNECTOR_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
URLHAUS_OPENCTI_TOKEN=<token from OpenCTI Settings>
URLHAUS_API_KEY=<your URLHaus API key>
URLHAUS_INTERVAL_HOURS=24
URLHAUS_RUN_ON_STARTUP=false
```

**3. Add the service to `docker-compose.override.yml`:**
```yaml
connector-urlhaus:
  build:
    context: ./connectors/custom/urlhaus
    dockerfile: Dockerfile
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${URLHAUS_OPENCTI_TOKEN}
    - CONNECTOR_ID=${URLHAUS_CONNECTOR_ID}
    - CONNECTOR_TYPE=EXTERNAL_IMPORT
    - CONNECTOR_NAME=URLHaus
    - CONNECTOR_SCOPE=urlhaus
    - CONNECTOR_AUTO=true
    - CONNECTOR_LOG_LEVEL=info
    - URLHAUS_API_KEY=${URLHAUS_API_KEY}
    - URLHAUS_INTERVAL_HOURS=${URLHAUS_INTERVAL_HOURS}
    - URLHAUS_RUN_ON_STARTUP=${URLHAUS_RUN_ON_STARTUP}
  restart: unless-stopped
  depends_on:
    - opencti
```

**4. Build and start:**
```bash
sudo docker compose build --no-cache connector-urlhaus
sudo docker compose up -d connector-urlhaus
sudo docker compose logs -f connector-urlhaus
```

### Verifying Startup

A successful startup produces the following log sequence:

```
Resolved TLP:CLEAR marking definition
Resolved existing abuse.ch identity
URLHaus tag routing active  {"tool_tags": [...], "software_tags": [...], "blocked_tags": [...], "prefix_patterns": [...]}
URLHaus connector starting  {"version": "1.0.3", "run_on_startup": false}
RUN_ON_STARTUP is false — sleeping until next scheduled run  {"next_run_utc": "..."}
```

---

## Operational Notes

**Volume.** On a typical day, 50–300 of the 1,000 most recent URLs have `online` status. The payload endpoint always returns up to 1,000 entries. Expect 500–3,000 objects per run after relationships are counted.

**Extending the tag maps.** To add a new Tool or Software mapping, add an entry to `TAG_TOOL_MAP` or `TAG_SOFTWARE_MAP` in `connector.py` and rebuild. The key must be the title-cased normalized form of the URLHaus tag (underscores and hyphens replaced with spaces). The value is the canonical entity name to look up or create.

**Extending the blocklist.** When new non-family tags appear in production logs under `"Created Malware entity"`, add them to `TAG_BLOCKLIST` and rebuild. All entries must be title-cased.

**Periodic Malware entity review.** Run the following query periodically to audit all Malware entities attributed to abuse.ch:

```bash
sudo docker exec -it opencti-docker-opencti-1 wget -qO- \
  --header="Authorization: Bearer <admin_token>" \
  --header="Content-Type: application/json" \
  --post-data='{"query":"{ malwares(filters: {mode: and, filters: [{key: \"createdBy\", values: [\"<abuse_ch_id>\"]}], filterGroups: []}, first: 200) { edges { node { id name created_at } } } }"}' \
  http://localhost:8080/graphql | python3 -m json.tool
```

Review the output for: CPU architecture names, file type extensions, encoding descriptors, garbled `Pw *` tags, `Dropped By *` labels, and generic category names. Delete confirmed garbage entities via `Arsenal → Malware` in the UI and add their normalized forms to `TAG_BLOCKLIST` before the next run.

**Tag normalization edge cases.** Tags with non-standard capitalizations (`njRAT`, `AsyncRAT`) normalize to `Njrat` and `Asyncrat`. Review `Arsenal → Malware` after initial ingestion for entities that may need merging with canonically named graph entities.

**Identity sharing with ThreatFox.** Both URLHaus and ThreatFox use the `abuse.ch` Organization identity. Name-based lookup at startup ensures exactly one entity exists regardless of connector start order.

---

## Requirements

- Python 3.11
- `pycti==6.9.13`
- `requests>=2.28.0`
- `pyyaml>=6.0`
- `libmagic1` (system package — installed in Dockerfile, required by `pycti` via `python-magic`)

> **Note:** `pycti` must match the OpenCTI instance version exactly. A version mismatch produces GraphQL schema errors at runtime.

---

## Changelog

| Version | Changes |
|---|---|
| 1.0.3 | Added `TAG_TOOL_MAP` and `TAG_SOFTWARE_MAP`. Tags for known abused tools (ConnectWise, RMM, GitHub, wget) now produce Tool SDOs with `related-to` relationships to URL and host observables. Cowrie tag produces a Software observable. All Tool and Software entities linked into the daily Report container. Payload signature routing unchanged (Malware SDOs only). |
| 1.0.2 | Expanded `TAG_BLOCKLIST` with CPU architecture tags (ARM, MIPS, x86, SPARC, SuperH, M68K, PowerPC), encoding descriptors (Base64, Ascii, Encoded, Encrypted), scripting language tags (Lua), and operational/sensor descriptors (Rat, Rmm, Honeypot, Github, Cowrie, Ua Wget, Botnetdomain). Added `_BLOCKLIST_PREFIXES` regex patterns for `Pw *` and `Dropped By *` tag families. |
| 1.0.1 | Added `RUN_ON_STARTUP` guard, Malware cache TTL (24h), startup tag audit log, IPv6-Addr observable support, exponential backoff retry in API client (`client.py`). |
| 1.0.0 | Initial release. URL and payload ingestion, online-status filter, daily Report containers, Malware SDOs from tags, `TAG_BLOCKLIST` for file type extensions and hosting descriptors. |
