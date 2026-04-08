# CrowdStrike Intel Reports Connector

An OpenCTI `EXTERNAL_IMPORT` connector that polls the CrowdStrike Falcon Intelligence API and ingests finished intelligence reports as OpenCTI Report containers with the original CrowdStrike PDFs attached.

---

## Overview

This connector polls the Falcon Intel Reports API (`/intel/combined/reports/v1`) on a configurable interval, downloads the pre-rendered PDF for each new report via `GetIntelReportPDF` (`/intel/entities/report-files/v1`), and creates a provenance-complete OpenCTI Report container. All ingestion is non-destructive. Report containers land in the platform ready for analyst review and manual ingestion.

**What the connector produces:**

- One OpenCTI Report container per CrowdStrike intelligence report
- Report metadata: verbatim name, description, published date, report type, external reference URL
- PDF attachment embedded in the container (base64-encoded, accessible via the platform UI)
- TLP:AMBER+STRICT marking applied to all containers
- CrowdStrike Organization identity set as author

**What the connector does not produce:**

- Entity stubs (Intrusion Sets, Malware, Attack Patterns, etc.)
- Relationships between entities
- Observables or Indicators

All entity creation and relationship modeling is left to the analyst ingestion workflow.

---

## Prerequisites

Before starting the connector, two objects must exist in the OpenCTI platform:

1. **CrowdStrike Organization identity** — Create an Organization named exactly `CrowdStrike` under Entities. The connector will refuse to initialize if this identity is absent.
2. **TLP:AMBER+STRICT marking definition** — Must exist in the platform. Present by default in standard OpenCTI deployments.

**Falcon API scope required:** `Reports (Falcon Intelligence): READ`

Assign this scope to your API client in the Falcon console under Support > API Clients and Keys.

---

## Architecture

```
Falcon Intel API
      |
      | GET /intel/combined/reports/v1  (paginated, FQL date filter)
      |
 FalconIntelClient.get_reports_since()
      |
      | GET /intel/entities/report-files/v1  (per report, synchronous)
      |
 FalconIntelClient.get_report_pdf()
      |
 CrowdStrikeIntelReportsConnector
      |
      |-- High-water mark  (graph-driven, no state files)
      |-- Deduplication    (name match against live graph)
      |-- Bundle build     (STIX2 Report + Identity + PDF)
      |
 OpenCTI send_stix2_bundle()
      |
 Report container in platform
```

**Token management** is handled entirely by FalconPy. The connector does not manage OAuth2 tokens manually.

**High-water mark** is derived from the most recently published CrowdStrike report already in the graph, sorted client-side. On first run, or when no prior ingestion exists, falls back to `now - CROWDSTRIKE_LOOKBACK_DAYS`. No local state files are used; the graph is the state store, and the connector survives container restart without re-ingesting already-processed reports.

**Deduplication** is performed by name: for each candidate report, the connector queries OpenCTI for an existing Report with the same verbatim name and performs a client-side exact match. If a match is found, the report is skipped.

---

## Configuration

All configuration is provided via environment variables. No `config.yml` is required for production deployment.

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | Yes | — | OpenCTI platform URL (e.g. `http://opencti:8080`) |
| `OPENCTI_TOKEN` | Yes | — | Service account token for this connector |
| `CONNECTOR_ID` | Yes | — | UUIDv4 uniquely identifying this connector instance |
| `CONNECTOR_CONFIDENCE_LEVEL` | No | `75` | Confidence applied to ingested objects (0-100). 75 = High, appropriate for a Tier-1 vendor. |
| `CONNECTOR_LOG_LEVEL` | No | `info` | Log verbosity: `debug`, `info`, `warning`, `error` |
| `CROWDSTRIKE_CLIENT_ID` | Yes | — | Falcon API client ID. Must carry `Reports (Falcon Intelligence): READ` scope. |
| `CROWDSTRIKE_CLIENT_SECRET` | Yes | — | Falcon API client secret. |
| `CROWDSTRIKE_BASE_URL` | No | `https://api.crowdstrike.com` | Falcon API base URL. Override for EU-1 (`https://api.eu-1.crowdstrike.com`) or US-2 (`https://api.us-2.crowdstrike.com`). |
| `CROWDSTRIKE_LOOKBACK_DAYS` | No | `7` | Days to look back on first run (no prior ingestion in graph). |
| `CROWDSTRIKE_INTERVAL_HOURS` | No | `24` | Polling interval in hours. |
| `CROWDSTRIKE_API_TIMEOUT` | No | `60` | HTTP timeout in seconds for all Falcon API calls, including PDF downloads. Increase for very large reports. |
| `CROWDSTRIKE_REPORT_TYPES` | No | `` (all) | Comma-separated list of CrowdStrike report type names to ingest. Case-insensitive. Empty value ingests all types. Example: `Adversary Intelligence Report,Vulnerability Report` |

---

## Deployment

### 1. Add the service block to `docker-compose.override.yml`

```yaml
connector-crowdstrike-intel-reports:
  image: crowdstrike-intel-reports:latest
  build:
    context: ./connectors/custom/CrowdStrikeIntelReports
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${CS_INTEL_REPORTS_OPENCTI_TOKEN}
    - CONNECTOR_ID=${CS_INTEL_REPORTS_CONNECTOR_ID}
    - CONNECTOR_TYPE=EXTERNAL_IMPORT
    - CONNECTOR_NAME=CrowdStrike Intel Reports
    - CONNECTOR_SCOPE=identity,report
    - CONNECTOR_CONFIDENCE_LEVEL=75
    - CONNECTOR_LOG_LEVEL=info
    - CROWDSTRIKE_CLIENT_ID=${CROWDSTRIKE_CLIENT_ID}
    - CROWDSTRIKE_CLIENT_SECRET=${CROWDSTRIKE_CLIENT_SECRET}
    - CROWDSTRIKE_BASE_URL=${CROWDSTRIKE_BASE_URL:-https://api.crowdstrike.com}
    - CROWDSTRIKE_API_TIMEOUT=${CROWDSTRIKE_API_TIMEOUT:-60}
    - CROWDSTRIKE_LOOKBACK_DAYS=${CROWDSTRIKE_LOOKBACK_DAYS:-7}
    - CROWDSTRIKE_INTERVAL_HOURS=${CROWDSTRIKE_INTERVAL_HOURS:-24}
    - CROWDSTRIKE_REPORT_TYPES=${CROWDSTRIKE_REPORT_TYPES:-}
  restart: always
```

### 2. Set credential values in the environment section of `docker-compose.override.yml`

```yaml
CS_INTEL_REPORTS_OPENCTI_TOKEN: "your-token-here"
CS_INTEL_REPORTS_CONNECTOR_ID: "your-uuid-here"
CROWDSTRIKE_CLIENT_ID: "your-falcon-client-id"
CROWDSTRIKE_CLIENT_SECRET: "your-falcon-client-secret"
```

Generate a connector ID with:

```bash
python3 -c "import uuid; print(uuid.uuid4())"
```

### 3. Build and start

```bash
cd ~/opencti-docker

sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  build --no-cache connector-crowdstrike-intel-reports

sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  up -d connector-crowdstrike-intel-reports

sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  logs -f connector-crowdstrike-intel-reports
```

### Healthy startup log

```
Connector registered with ID {"id": "<your-connector-id>"}
[CrowdStrikeIntelReports] Connector initialized. Author: 'CrowdStrike', Marking: 'TLP:AMBER+STRICT', ...
[CrowdStrikeIntelReports] Connector starting.
[CrowdStrikeIntelReports] Starting poll cycle.
[CrowdStrikeIntelReports] Using 7-day lookback: <timestamp>
[CrowdStrikeIntelReports] Ingested: '<report name>'
[CrowdStrikeIntelReports] Cycle complete — ingested: X, skipped: Y, errors: 0.
[CrowdStrikeIntelReports] Next cycle in 24h (86400s).
```

---

## Report Type Mapping

CrowdStrike report type names are mapped to OpenCTI `report_types` vocabulary. The default map covers common types. Unknown types fall back to `threat-report` and are logged at INFO level so the map can be extended.

| CrowdStrike Type | OpenCTI Type |
|---|---|
| Alert | `threat-report` |
| Adversary Intelligence Report | `threat-report` |
| Intelligence Summary | `threat-report` |
| Monthly Report | `threat-report` |
| Weekly Report | `threat-report` |
| Threat Intelligence Report | `threat-report` |
| Vulnerability Report | `vulnerability-advisory` |
| Malware Analysis | `malware-analysis` |
| Malware Report | `malware-analysis` |
| Technical Analysis | `malware-analysis` |
| Hunting Report | `threat-report` |

To add a new type, update `DEFAULT_REPORT_TYPE_MAP` in `connector.py`.

---

## Known Limitations

**No entity stubs.** The connector creates Report containers only. Intrusion Set, Malware, Attack Pattern, and Observable entities are not created from CrowdStrike's structured metadata. This is by design — entity creation and relationship modeling is handled by the analyst ingestion workflow using the attached PDF and the OpenCTI Workbench.

**No recovery path for partially-ingested reports.** If a report passes the dedup check but the bundle send fails, the next cycle will skip it by name match because `update=False`. The incomplete container must be manually deleted and the connector allowed to re-ingest on the following cycle.

**`object_refs` contains only the author identity.** STIX requires at least one `object_refs` entry. The author Organization is used to satisfy this minimum. The Report container's related-objects panel will be empty until analysts manually add entities during ingestion.

---

## File Structure

```
CrowdStrikeIntelReports/
├── Dockerfile
├── docker-compose.yml          # Clean reference — no credentials
└── src/
    ├── main.py
    ├── requirements.txt
    └── crowdstrike_intel_reports/
        ├── __init__.py
        ├── client.py           # FalconPy wrapper (query + PDF download)
        └── connector.py        # Main connector logic
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `pycti` | `==6.9.13` | OpenCTI connector framework |
| `crowdstrike-falconpy` | `>=1.4.0` | Falcon API client (token management, Intel service class) |
| `stix2` | latest | STIX 2.1 bundle construction |
| `pyyaml` | latest | Optional local config file support |
