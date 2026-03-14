# connector-udm

An [OpenCTI](https://www.opencti.io) external import connector that ingests blocked network flow telemetry from a [UniFi Dream Machine Pro](https://ui.com/dreammachine) into an OpenCTI knowledge graph.

---

## Overview

`connector-udm` polls the UDM Pro's local traffic flow API for blocked connection attempts and transforms them into a structured, STIX 2.1-aligned graph of observables, incidents, sightings, and relationships — all scoped to per-day Incident Response containers.

This is not a traditional threat intelligence ingestion pipeline. Its purpose is **internal observability**: producing a durable, analytically traceable record of blocked perimeter events, contextualized against your internal host topology and the external source geography of blocked traffic.

---

## Features

- **Blocked flow ingestion** via the UDM Pro local traffic-flows API
- **Per-day Incident Response containers** — one Case Incident per UTC day with blocked flows
- **Full STIX 2.1 entity coverage** — Incidents, IPv4 addresses, Countries, Systems, MAC addresses, OUI organizations, Software observables, and their relationships
- **Sighting upsert** — existing sightings are updated (count + last\_seen) rather than duplicated across runs
- **Lazy containment** — all entities are created and scoped to their day container at the point of first use; no orphaned objects
- **pycountry resolution** — ISO 3166-1 alpha-2 region codes resolved to full country names before graph entry
- **Graph-driven deduplication** — no local state files or Redis; all dedup via OpenCTI API lookup
- **Configurable backfill** — on first run, ingests a configurable window of historical flows
- **8-hour overlap window** — incremental runs use an 8-hour lookback to absorb late-arriving flow records across PT6H cadence
- **Schema-safe relationships** — relationship types validated against the OpenCTI schema; blocked-traffic SROs use `related-to`, not `communicates-with`

---

## Requirements

- OpenCTI 6.9.13 or compatible
- UniFi Dream Machine Pro with local API access enabled
- Docker + Docker Compose
- Python 3.11 (handled by Docker image)

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/connector-udm.git
cd connector-udm
```

### 2. Generate a connector UUID

```bash
python3 -c "import uuid; print(uuid.uuid4())"
```

### 3. Get your OpenCTI marking definition UUID

In OpenCTI: **Settings → Marking Definitions** — copy the UUID of the TLP marking definition you want applied to all ingested objects.

### 4. Configure

Copy `docker-compose.yml` and populate the environment variables with your values. See [Configuration Reference](#configuration-reference) below.

If integrating into an existing OpenCTI Docker Compose stack, add the connector block to your `docker-compose.override.yml` and reference secrets via environment variable substitution.

### 5. Build and run

```bash
docker compose build connector-udm
docker compose up -d connector-udm
```

### 6. Verify

```bash
docker compose logs -f connector-udm
```

A successful first run will log:

```
[CONNECTOR] UDM Connector starting.
[CONNECTOR] UDM Connector execute triggered.
[STARTUP] Client discovery complete: N hosts cached.
[CONNECTOR] First run — backfill 30 days.
[UDM] fetch complete: N flows in window
[DAY] N flows for YYYY-MM-DD. Creating container...
[CONNECTOR] Run complete | days=N flows=N incidents=N ...
```

---

## Configuration Reference

All configuration is via environment variables. No values are hardcoded in source.

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | Yes | — | OpenCTI instance URL. Use internal Docker service name if co-deployed (e.g. `http://opencti:8080`). |
| `OPENCTI_TOKEN` | Yes | — | API token for a user with the **Connector** role in OpenCTI. |
| `CONNECTOR_ID` | Yes | — | Stable UUID for this connector instance. Generate once and keep fixed. |
| `CONNECTOR_NAME` | No | `UDM Connector` | Display name in the OpenCTI connector list. |
| `CONNECTOR_LOG_LEVEL` | No | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `CONNECTOR_INTERVAL` | No | `PT6H` | ISO 8601 duration between scheduled runs. |
| `TLP_AMBER_STRICT_ID` | Yes | — | Instance-specific UUID of the TLP marking definition to apply to all created objects. Connector aborts at startup if absent. |
| `UDM_HOST` | Yes | — | IP address or hostname of the UDM Pro. |
| `UDM_API_KEY` | Yes | — | UDM Pro API key. Generate in the local admin interface. |
| `UDM_SITE` | No | `default` | UniFi site name. Change only if you have multiple sites configured. |
| `UDM_TLS_VERIFY` | No | `false` | TLS certificate verification. The UDM Pro uses a self-signed certificate — leave `false` unless you have a custom cert. |
| `UDM_WAN_IP` | No | — | Fallback WAN IP if automatic resolution via `stat/device` fails. |
| `UDM_INTERNAL_SUBNET` | No | `192.168.0.0/24` | CIDR subnet used to classify destination IPs as internal hosts. |
| `UDM_BACKFILL_DAYS` | No | `30` | Number of days to ingest on first run. |
| `UDM_PAGE_SIZE` | No | `500` | Flow records per API page. Maximum 500. |

---

## Data Model

### Container

Each UTC day with blocked flows produces one **Case Incident** (Incident Response container):

```
{CONNECTOR_NAME} Blocked Flows — YYYY-MM-DD
```

Sightings are scoped to Incident Response containers per STIX 2.1 convention.

### Entities created per flow

| Entity | STIX Type | Source Field |
|---|---|---|
| Incident | SDO | One per flow — named `UDM-{policy_type}-{flow_id}` |
| IPv4-Addr | SCO | `source.ip` — source of blocked connection |
| Country | Location | `source.region` — resolved via pycountry |
| IPv4-Addr | SCO | `destination.ip` — fallback path only |
| Mac-Addr | SCO | `destination.mac` — internal host MAC |
| System | SDO | Internal host hostname (from active client cache) |
| Organization | SDO | NIC vendor (OUI prefix, normalized) |
| System | SDO | `UDM-WAN` — WAN interface, when dst matches WAN IP |
| IPv4-Addr | SCO | WAN IP — linked to UDM-WAN System |
| Software | SCO | `ips.affected_product` — IPS signature flows only |

### Relationships

| Source | Relationship | Target | Notes |
|---|---|---|---|
| Source IPv4 | `related-to` | Incident | Links triggering IP to the incident it generated |
| Source IPv4 | `related-to` | Country | `originates-from` not permitted for Observable→Location in OpenCTI schema |
| Incident | `originates-from` | Country | Valid — Incident is modeled as an Identity extension |
| Software | `related-to` | Incident | Affected product linked to the triggering incident |
| Mac-Addr | `related-to` | System | Internal MAC linked to its host System |
| Organization | `related-to` | System | OUI vendor linked to the host System |
| WAN IPv4 | `related-to` | UDM-WAN | WAN IP linked to WAN interface System |
| Source IPv4 | `related-to` | Dst IPv4 | Fallback path — `related-to` not `communicates-with` (traffic was blocked) |

### Sightings

Sightings are created from **source IPv4 → destination System** (UDM-WAN or internal host). On subsequent runs, existing sightings are updated rather than duplicated: `attribute_count` is incremented and `last_seen` is advanced to the most recent flow timestamp.

---

## Philosophy

### Blocked traffic is not communication

The fallback relationship between source and destination IP uses `related-to`, not `communicates-with`. The UDM blocked the connection before a session was established. `communicates-with` asserts bidirectional communication and is semantically wrong for blocked flows.

### One flow, one Incident

Each blocked flow maps to one Incident SDO. This preserves full per-event fidelity — each Incident carries the complete structured flow description as its description field. The alternative (clustering flows by policy or region) reduces cardinality but loses individual flow provenance.

### Lazy containment

No OpenCTI objects are created during startup. Client discovery and WAN resolution build in-process caches only. All entities — Systems, MACs, OUI organizations, Countries — are materialized in OpenCTI and added to the day container at the moment they are first referenced by a flow. This ensures zero orphaned objects outside a container.

### Graph-driven deduplication

The connector holds no local state between runs. All deduplication is performed by querying OpenCTI before each create attempt. This means the connector is safe to restart, re-deploy, or run against an existing graph without producing duplicates.

### Country resolution via pycountry

Source region codes from the UDM API (ISO 3166-1 alpha-2) are resolved to full country names via `pycountry` before graph entry. This prevents abbreviated codes (`US`, `DE`) from entering the graph as canonical country names. An in-process cache prevents redundant API calls when multiple flows share the same source region.

### No Indicators

The connector does not create Indicator objects. Indicators in OpenCTI are generated automatically by the platform's inference engine from Observables. Manual Indicator creation is intentionally omitted.

### Marking definitions are required

The connector aborts at startup if `TLP_AMBER_STRICT_ID` is not set. Leaving marking definitions unconfigured would silently create unprotected objects in the graph — a governance risk the connector explicitly prevents.

---

## Deduplication Reference

| Object | Dedup Key | On Match |
|---|---|---|
| Case Incident | `name` (exact) | Return existing ID |
| Incident SDO | `name` (exact) | Return existing ID |
| IPv4-Addr | `value` (exact) | Return existing ID |
| Mac-Addr | `value` (exact) | Return existing ID |
| System | `name` (exact) | Return existing ID |
| Organization | `name` (normalized, exact) | Return existing ID |
| Country | `name` (pycountry-resolved, exact) | Return existing ID (in-process cache) |
| Software | `name` (exact) | Return existing ID |
| SRO | `fromId + toId + relationship_type` | Return existing ID |
| Sighting | `fromId + toId` | Update `attribute_count` + `last_seen` |

---

## Run Cadence

The connector runs every 6 hours (`PT6H`) by default. Each incremental run uses an **8-hour lookback window**, providing 2 hours of overlap between consecutive runs to absorb late-arriving flow records.

| Run type | Cutoff |
|---|---|
| First run (backfill) | `now − UDM_BACKFILL_DAYS` |
| Incremental | `now − 8 hours` |

First-run detection searches OpenCTI for any Case Incident matching the connector's container naming pattern. If none is found, backfill mode activates.

---

## Known Limitations

**Full page scan per run** — The UDM Pro API does not support server-side timestamp filtering without breaking the `action` filter. Every run fetches all pages and filters client-side. Performance degrades as total flow volume grows.

**Heuristic first-run detection** — Backfill triggers on the absence of matching Case Incidents. A partial prior run or manually created matching container will prevent backfill from activating.

**Micro-incident volume** — One Incident SDO per flow. High-volume periods (active scanning events) produce many Incident objects per day container.

**Offline host identity** — Hosts not visible in `stat/sta` at run time are created from flow destination fields, which may differ from the hostname used when the host is online. This can produce duplicate System entities for the same physical device over time.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `pycti` | `6.9.13` | OpenCTI Python client — pinned to instance version |
| `requests` | latest | HTTP client for UDM API |
| `pyyaml` | latest | `config.yml` parsing |
| `urllib3` | latest | TLS warning suppression |
| `pycountry` | latest | ISO 3166-1 alpha-2 → full country name resolution |

---

## Security Notes

- **Rotate your UDM API key** regularly. It grants local administrative API access to the device.
- **Never commit** `docker-compose.override.yml`, `config.yml`, or `.env` files containing live credentials. The provided `.gitignore` covers these.
- The connector creates all objects with the marking definition specified in `TLP_AMBER_STRICT_ID`. Verify this UUID maps to the correct marking definition in your OpenCTI instance before the first run.

---

## License

MIT
