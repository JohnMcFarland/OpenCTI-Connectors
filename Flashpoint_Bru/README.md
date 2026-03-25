# connector-flashpoint

OpenCTI external import connector for the Flashpoint Ignite threat intelligence platform.

**Version:** 1.0.0  
**Platform:** OpenCTI 6.9.13  
**pycti:** 6.9.13  
**Status:** Production-ready (Compromised Credentials dataset stubbed — see Known Limitations)

---

## Overview

This connector ingests threat intelligence from Flashpoint Ignite into OpenCTI across four datasets: Finished Intelligence Reports, Alerts, Communities, and Compromised Credentials. It supersedes the Filigran upstream connector (`external-import/flashpoint`) entirely and must not run alongside it.

All ingestion is governed by the Four Cs framework (Containment, Contextualization, Completeness, Categorization) and the instance Data Model Relationship Guide. Every object produced by this connector is contained, attributed, and described. No orphaned observables, no empty relationship descriptions, no manually created Indicators.

---

## Datasets

| Dataset | Container Type | Cadence | Report Type | Status |
|---|---|---|---|---|
| Finished Intelligence Reports | Report per article | Per report | `activity-roundup` | Implemented |
| Alerts — keyword match | Daily batch Report | Daily | `activity-roundup` | Implemented |
| Alerts — org-domain credential | Incident Response per alert | Per alert | — | Implemented |
| Communities search results | Daily batch Report per query | Daily | `activity-roundup` | Implemented |
| Compromised Credentials — org domain | Incident Response per record | Per record | — | Stubbed |
| Compromised Credentials — non-org | Daily batch Report | Daily | `activity-roundup` | Stubbed |

All Report containers use type `activity-roundup` universally. The vocabulary entry is registered in the platform automatically on first connector startup.

---

## Design Philosophy

### Four Cs Compliance

Every object created by this connector answers the Four Cs before it reaches the graph:

- **Containment:** Every entity, observable, and relationship is a member of a container (Report or Incident Response) before the run completes. There are no orphaned objects.
- **Contextualization:** Every relationship carries a mandatory non-empty description. The `create_relation()` method raises `ValueError` if called with an empty description — this constraint is enforced at the Python level and cannot be bypassed.
- **Completeness:** All records returned by the API within the configured time window are processed. Per-dataset independent state cursors ensure a failure in one dataset does not cause another dataset to skip its window.
- **Categorization:** TLP:AMBER+STRICT is applied to all objects from all datasets by default. Report types, confidence scores, and labels reflect source quality and content type accurately.

### No Indicators Except YARA and Sigma

The OpenCTI data model prohibits manually created Indicators because they have no link to their source Observable and corrupt the detection pipeline. This connector enforces that constraint at the conversion layer: `INDICATOR_PERMITTED_PATTERN_TYPES = {"yara", "sigma"}`. All other observable types (IP, domain, hash, URL, etc.) are created as Observables only.

### Observable Floor Relationship

Every Observable must have at minimum a `related-to` relationship to a named Identity object. When no richer entity relationship can be resolved from source data, the `_floor_relation()` method links the Observable to the Flashpoint Organization identity. This ensures every Observable is queryable by source and not orphaned.

### Per-Dataset Independent State Cursors

Each dataset tracks its own cursor independently in the connector state store. A failure in one dataset (API error, conversion error, network timeout) does not advance any other dataset's cursor. On the next run, the failed dataset re-fetches from its last successful position.

State schema:
```json
{
  "reports_last_run":     "2025-03-01T00:00:00+00:00",
  "alerts_last_run":      "2025-03-01T00:00:00+00:00",
  "communities_last_run": "2025-03-01T00:00:00+00:00",
  "credentials_last_run": "2025-03-01T00:00:00+00:00"
}
```

### Alert Bifurcation

Alerts split into two paths based on org domain matching:

- **Org-domain match** — the alert resource contains a configured domain anywhere in its serialised structure. Routes to an Incident Response container. One IR per alert, named deterministically by alert ID.
- **No match** — keyword hit from alert rules. Accumulated into a daily batch Report container. Batch Report name is deterministic (`Flashpoint Alerts — YYYY-MM-DD`), enabling safe upsert if the connector re-runs on the same day.

### Daily Batch Reports

Alerts and Communities results are accumulated in per-day buckets during a run. After all records for a dataset are processed, the buckets are flushed as Report containers. The Report ID is deterministic from the name and date — the same connector run on the same day produces the same Report ID, and OpenCTI upserts the existing container rather than creating a duplicate.

### Knowledge Graph Resolution

Flashpoint report tags and actor names are resolved against the existing OpenCTI graph via `stix_domain_object.list()`. Only entities already in the graph are linked — no new named entities are created from tags alone, because tags carry insufficient information to populate vocabulary fields with proper sourcing. Resolved entities receive stub STIX objects (ID + name only), and relationships between co-occurring entities are built with descriptions sourced from the report title.

### Deviations from the Filigran Upstream Connector

| Filigran Behaviour | This Connector |
|---|---|
| Alerts → stix2.Incident in bundle | Alerts → bifurcated: Report objects or IR Incident |
| MISP feed ingestion | Dropped — MISP feed not in scope |
| Per-MISP-event Report or Grouping | Not applicable |
| Shared `last_run` state key | Per-dataset independent cursors |
| Fake `intrusion-set--fc5ee88d` placeholder in object_refs | Author identity used as floor reference |
| `report["body"].encode("utf-8")` bytes | String passed directly to x_opencti_content |
| TLP:GREEN default on communities content | TLP:AMBER+STRICT universally |
| Hardcoded `report_types=["threat-report"]` | `["activity-roundup"]` universally |
| Empty relationship descriptions permitted | Mandatory description enforced at method level |
| No Assessment Notes on vocabulary fields | Assessment Notes required (enforced by convention) |
| `import_communities` config variable collision bug | Fixed |
| Grouping container type created for MISP events | Grouping never created |
| MediaContent custom observable for post content | Text observable |
| Persona commented out / unimplemented | Persona implemented |

---

## File Structure

```
connector-flashpoint/
├── src/
│   ├── flashpoint_connector/
│   │   ├── __init__.py           # Package entry point
│   │   ├── client_api.py         # Flashpoint Ignite API client
│   │   ├── config_variables.py   # Configuration loader
│   │   ├── connector.py          # Main loop, dispatchers, state management
│   │   └── converter_to_stix.py  # STIX 2.1 object construction
│   └── main.py                   # Docker entry point
├── Dockerfile
├── requirements.txt
├── config.yml.sample
├── README.md
├── DESIGN.md
└── CONNECTOR_SCOPE.md
```

---

## Configuration Reference

All variables can be set as environment variables (Docker, recommended) or in `config.yml` (local development). Environment variables take precedence over `config.yml`.

### OpenCTI Connection

| Variable | Type | Required | Description |
|---|---|---|---|
| `OPENCTI_URL` | string | Yes | OpenCTI instance URL. Use internal Docker network URL in compose deployments: `http://opencti:8080`. |
| `OPENCTI_TOKEN` | string | Yes | OpenCTI connector API token. Generate in Settings → Connectors. Use a dedicated connector token, not the admin token. |

### Connector Identity

| Variable | Type | Required | Default | Description |
|---|---|---|---|---|
| `CONNECTOR_ID` | string (UUIDv4) | Yes | — | Unique identifier for this connector instance. Generate with `python3 -c "import uuid; print(uuid.uuid4())"`. Must not be reused across connector instances. |
| `CONNECTOR_NAME` | string | No | `Flashpoint` | Display name shown in OpenCTI's connector list. |
| `CONNECTOR_LOG_LEVEL` | string | No | `info` | Log verbosity: `debug`, `info`, `warning`, `error`. |
| `CONNECTOR_DURATION_PERIOD` | string (ISO-8601) | Yes | — | Run interval. Examples: `PT6H` (every 6 hours), `PT1H` (hourly), `P1D` (daily). |

### Flashpoint API

| Variable | Type | Required | Description |
|---|---|---|---|
| `FLASHPOINT_API_KEY` | string | Yes | Flashpoint Ignite API key. Generate in Ignite: Settings → APIs & Integrations. Required permissions: `IGNITE_API`, `IGNITE_CTI_REPORTS`, `dat.rp.ass.r`, `dat.med.r`, `dat.ind.r`. For credential alerts, the API key's user must also be a member of the CCMC group. |
| `FLASHPOINT_IMPORT_START_DATE` | string (ISO-8601) | Yes | Backfill start date for first run. Example: `2024-01-01T00:00:00Z`. After first run, per-dataset cursors take over — this value is only used when no cursor exists for a dataset. |

### Dataset Toggles

| Variable | Type | Default | Description |
|---|---|---|---|
| `FLASHPOINT_IMPORT_REPORTS` | bool | `true` | Enable ingestion of Finished Intelligence Reports. |
| `FLASHPOINT_IMPORT_ALERTS` | bool | `true` | Enable ingestion of Alerts. Requires alert rules configured in Flashpoint Ignite. |
| `FLASHPOINT_IMPORT_COMMUNITIES` | bool | `false` | Enable dark web community post ingestion. Disabled by default — requires `FLASHPOINT_COMMUNITIES_QUERIES` to be configured with meaningful terms before enabling. |
| `FLASHPOINT_IMPORT_CREDENTIALS` | bool | `true` | Enable Compromised Credentials ingestion. **Currently stubbed — logs a warning per run but ingests nothing.** Set to `false` to suppress the warning. |

### Communities Configuration

| Variable | Type | Default | Description |
|---|---|---|---|
| `FLASHPOINT_COMMUNITIES_QUERIES` | string (CSV) | `cybersecurity,cyberattack` | Comma-separated keyword search terms for dark web community monitoring. Each term produces its own independent daily batch Report. Examples: `ransomware,CVE-2024-1234,your-org-name`. Trailing spaces around commas are stripped automatically. |

### Alert and Credential Bifurcation

| Variable | Type | Default | Description |
|---|---|---|---|
| `FLASHPOINT_ORG_DOMAINS` | string (CSV) | `""` (empty) | Comma-separated list of your organisation's domains. Alerts and credential records where any configured domain appears in the alert resource data are routed to Incident Response containers. All other alerts route to batch Reports. Example: `example.com,subsidiary.example.com`. Leave empty to route all alerts to batch Reports. |

### Confidence Defaults

| Variable | Type | Default | Description |
|---|---|---|---|
| `FLASHPOINT_REPORT_CONFIDENCE` | int (0–100) | `75` | Confidence for Finished Intelligence Reports. Reflects Flashpoint's status as a Tier-1 analyst-written vendor. |
| `FLASHPOINT_ALERT_CONFIDENCE` | int (0–100) | `50` | Confidence for keyword-match alert batch Reports. Reflects unvalidated rule-fired hits. |
| `FLASHPOINT_ALERT_ORG_CONFIDENCE` | int (0–100) | `70` | Confidence for org-domain credential alert IR objects. Higher than generic alerts because the domain match is a deterministic linkage. |
| `FLASHPOINT_COMMUNITIES_CONFIDENCE` | int (0–100) | `30` | Confidence for Communities batch Reports. Reflects raw unvalidated dark web content. |
| `FLASHPOINT_CREDENTIAL_CONFIDENCE` | int (0–100) | `70` | Confidence for Compromised Credentials objects (for when the dataset is implemented). |

---

## Deployment

### Prerequisites

1. OpenCTI 6.9.13 running via Docker Compose at `~/opencti-docker/`
2. The Filigran upstream Flashpoint connector (`external-import/flashpoint`) stopped and removed from `docker-compose.override.yml`
3. A Flashpoint Ignite API key with the required permissions
4. `FLASHPOINT_ORG_DOMAINS` configured if alert bifurcation is needed

### Install

Copy the connector directory to the custom connectors path:

```bash
cp -r connector-flashpoint ~/opencti-docker/connectors/custom/Flashpoint
sudo chown -R siii:siii ~/opencti-docker/connectors/custom/Flashpoint
```

### Configure

Add the connector service to `docker-compose.override.yml`:

```yaml
connector-flashpoint:
  build:
    context: ./connectors/custom/Flashpoint
    dockerfile: Dockerfile
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=          # connector service account token
    - CONNECTOR_ID=           # generate: python3 -c "import uuid; print(uuid.uuid4())"
    - CONNECTOR_NAME=Flashpoint
    - CONNECTOR_LOG_LEVEL=info
    - CONNECTOR_DURATION_PERIOD=PT6H
    - FLASHPOINT_API_KEY=     # Flashpoint Ignite API key
    - FLASHPOINT_IMPORT_START_DATE=2024-01-01T00:00:00Z
    - FLASHPOINT_IMPORT_REPORTS=true
    - FLASHPOINT_IMPORT_ALERTS=true
    - FLASHPOINT_IMPORT_COMMUNITIES=false
    - FLASHPOINT_IMPORT_CREDENTIALS=false
    - FLASHPOINT_COMMUNITIES_QUERIES=cybersecurity,cyberattack
    - FLASHPOINT_ORG_DOMAINS= # comma-separated org domains
    - FLASHPOINT_REPORT_CONFIDENCE=75
    - FLASHPOINT_ALERT_CONFIDENCE=50
    - FLASHPOINT_ALERT_ORG_CONFIDENCE=70
    - FLASHPOINT_COMMUNITIES_CONFIDENCE=30
    - FLASHPOINT_CREDENTIAL_CONFIDENCE=70
  restart: unless-stopped
  depends_on:
    - opencti
```

### Build and Deploy

Always use `--no-cache` after any source or requirements change:

```bash
cd ~/opencti-docker

sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  build --no-cache connector-flashpoint

sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  up -d connector-flashpoint

sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  logs -f connector-flashpoint
```

Healthy startup: the connector emits log output within 30 seconds. Absence of output within 30 seconds indicates a hang or startup failure — investigate logs.

### Pre-Deployment Checklist

- [ ] Filigran Flashpoint connector stopped and removed from `docker-compose.override.yml`
- [ ] `FLASHPOINT_API_KEY` set to a valid Ignite API key
- [ ] `OPENCTI_TOKEN` set to a dedicated connector service account token
- [ ] `CONNECTOR_ID` set to a freshly generated UUIDv4
- [ ] `FLASHPOINT_IMPORT_START_DATE` set to desired backfill start
- [ ] `FLASHPOINT_ORG_DOMAINS` populated if alert IR bifurcation is required
- [ ] `FLASHPOINT_IMPORT_CREDENTIALS=false` set (to suppress stub warnings until implemented)
- [ ] `activity-roundup` vocabulary entry does not already exist as a conflicting value in the platform

---

## Data Model

### Object Types Created

| Dataset | SDOs | SCOs | Containers |
|---|---|---|---|
| Reports | IntrusionSet, ThreatActor, Malware, Tool, AttackPattern, Location, Sector | — | Report |
| Alerts (keyword) | Channel | Text, URL | Report (daily batch) |
| Alerts (org-domain) | Incident | Text, URL | Incident Response |
| Communities | Channel, (Persona) | Text | Report (daily batch) |
| Credentials | (Incident) | (User-Account, Domain-Name, URL) | (Incident Response / Report) |

*Parentheses indicate stubbed/pending implementation.*

### Relationship Model

| Source | Relationship | Target | Context |
|---|---|---|---|
| Intrusion Set / Threat Actor | `uses` | Attack Pattern | Report tag resolution |
| Intrusion Set / Threat Actor | `uses` | Malware | Report tag resolution |
| Intrusion Set / Threat Actor | `uses` | Tool | Report tag resolution |
| Intrusion Set / Threat Actor / Malware | `targets` | Country / Region / Sector | Report tag resolution |
| Text | `related-to` | Channel | Alert and Communities content |
| Text | `related-to` | Persona | Communities — Observable to Identity |
| Persona | `related-to` | Channel | Communities |
| Channel | `publishes` | Text | Communities (with `related-to` fallback) |
| Text / URL | `related-to` | Incident | Org-domain credential alert IR |

### Marking

TLP:AMBER+STRICT applied universally across all datasets and all object types. No dataset defaults to a lower marking. Downgrading requires explicit configuration changes and documented justification.

---

## API Reference

Base URL: `https://api.flashpoint.io`  
Authentication: `Authorization: Bearer {FLASHPOINT_API_KEY}`

| Dataset | Method | Endpoint | Pagination |
|---|---|---|---|
| Reports | GET | `/finished-intelligence/v1/reports` | Offset/skip, limit=100 |
| Alerts | GET | `/alert-management/v1/notifications` | Cursor via `pagination.next` |
| Communities | POST | `/sources/v2/communities` | Page integer in POST body |
| Community doc | GET | `/sources/v2/communities/{id}` | Single record |
| Media doc | GET | `/sources/v2/media/{id}` | Single record |
| Media binary | GET | `/sources/v1/media` | Single record |
| Credentials | — | TBD | TBD |

---

## Known Limitations

### Compromised Credentials — Not Implemented

The Compromised Credentials dataset is stubbed. The Flashpoint API endpoint path, date filter parameter, pagination style, and response schema are not yet confirmed from `docs.flashpoint.io`. When the documentation is available, three methods require implementation:

- `client_api.ConnectorClient.get_credentials()`
- `converter_to_stix.ConverterToStix.convert_credential_record()`
- `connector.FlashpointConnector._import_credentials()`

All other datasets are unaffected. Set `FLASHPOINT_IMPORT_CREDENTIALS=false` to suppress the per-run warning until implementation is complete.

### `Channel → publishes → Text` Relationship

The `publishes` relationship type between Channel SDOs and Text observables is emitted for Communities content. Whether the OpenCTI 6.9.x platform accepts this relationship type for these entity types cannot be confirmed without a live test. If the platform rejects it, the worker will drop only that edge — the Channel, Persona, and Text objects still land in the graph. The edge rejection will appear in worker logs, not in connector logs (bundle sending is asynchronous). If rejected, a `related-to` relationship between Channel and Text provides equivalent analytical connectivity.

### Persona Observable Availability

`CustomObservablePersona` is imported from pycti for Communities persona creation. This custom observable type was in a pending PR state in the Filigran codebase as of the time this connector was written. If it is not available in pycti==6.9.13, Persona creation will fail with a logged warning per result. The Text observable will receive a floor relationship to the Flashpoint identity instead. The rest of the Communities result (Channel, Text, relationships) is unaffected.

### Knowledge Graph Resolution Quality

Report tags are resolved against the existing OpenCTI graph by exact name or MITRE ID match. The quality of resolved relationships depends on the completeness of the existing graph — if Flashpoint tags an Intrusion Set that has not been ingested via another connector, the tag resolves to nothing and no relationship is created. Relationship descriptions for tag-resolved edges note that they are machine-resolved from tags, not analyst-asserted.

### Communities Volume

Dark web community searches are unbounded by default — a broad query term against a long `import_start_date` window can return tens of thousands of results. Configure `FLASHPOINT_COMMUNITIES_QUERIES` with specific, narrow terms and set a recent `import_start_date` to avoid excessive API load and graph noise on first run.

---

## Operational Notes

### Confirming `activity-roundup` Vocabulary Registration

On startup the connector calls `helper.api.vocabulary.create()` for `activity-roundup`. Confirm the entry exists after first run:

OpenCTI UI → Settings → Taxonomies → Report types → check for `activity-roundup`.

If Reports are being rejected by the worker with a vocabulary error, the vocabulary entry is likely missing or the name is mismatched.

### Monitoring Alert Bifurcation

Check that `FLASHPOINT_ORG_DOMAINS` is producing the expected routing by reviewing logs immediately after the first alerts run. Expected log lines:

```
[ALERTS] Fetched N alerts since YYYY-MM-DDTHH:MM:SS
[ALERTS] Complete — IR: X, keyword batch: Y, skipped: Z
```

If `IR: 0` when org-domain matches are expected, verify that the domain strings in `FLASHPOINT_ORG_DOMAINS` match the format appearing in the Flashpoint alert resource data (lowercase, no trailing dot).

### Resetting a Dataset Cursor

To force a dataset to re-fetch from `FLASHPOINT_IMPORT_START_DATE`, remove its cursor key from the connector state via the OpenCTI UI:

Settings → Connectors → Flashpoint → State → edit JSON → remove the relevant key → save.

On the next run, the dataset bootstraps from `FLASHPOINT_IMPORT_START_DATE`. Other datasets' cursors are unaffected.

### Replacing the Filigran Connector

Stop the Filigran connector before starting this one:

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  stop [filigran-flashpoint-service-name]
```

Remove it from `docker-compose.override.yml`. Do not run both simultaneously — duplicate Reports, Observables, and relationships will be created and cannot be automatically deduplicated after the fact.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| pycti | 6.9.13 | OpenCTI platform client — must match instance version exactly |
| stix2 | latest | STIX 2.1 object construction and serialisation |
| requests | latest | Flashpoint Ignite API HTTP client |
| pyyaml | latest | config.yml parsing |
| dateparser | latest | Flexible datetime string parsing for Flashpoint API date fields |
| python-dateutil | latest | ISO8601 datetime parsing and timezone handling |
| pytz | latest | UTC timezone handling |

System dependency (installed via apt in Dockerfile): `libmagic1` — required by pycti via python-magic for MIME type detection when handling media attachments.
