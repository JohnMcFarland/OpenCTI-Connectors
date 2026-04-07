# GTI Report Connector for OpenCTI

An OpenCTI external-import connector that ingests finished intelligence
reports published by Google Threat Intelligence (GTI) into the OpenCTI
knowledge graph.

Each ingested report creates an OpenCTI Report container with:
- The **official Mandiant-formatted PDF**, downloaded directly from GTI.
- A **structured markdown attachment** containing all available GTI API
  metadata fields, including threat scape, targeted regions, targeted
  industries, motivations, and full report content.

---

## Overview

GTI publishes finished intelligence reports authored by Mandiant analysts
covering campaigns, threat actors, vulnerabilities, malware families, and
weekly roundups. This connector automates the ingestion of those reports
into OpenCTI on a configurable polling interval.

The connector is scoped exclusively to GTI-authored content
(`origin:"Google Threat Intelligence"`). Crowdsourced OSINT articles are
excluded because they violate the Four Cs data model: wrong author identity,
future-dated timestamps, wrong report type, and secondary-source content.

---

## Design Philosophy

**Graph-driven deduplication.** The connector uses the GTI portal URL as
the dedup key, checked against the live OpenCTI graph via External Reference
URL lookup. No local state files are used. This survives container restarts
and state resets without requiring local state synchronization.

**Correctness over speed.** The connector favors accuracy in field mapping
over bulk ingestion. Report types are mapped to the correct OpenCTI values.
The `creation_date` field is used as the published date because it reflects
the actual publication timestamp for GTI-authored reports. Crowdsourced
reports have artificially future-dated `creation_date` values, which is
another reason they are excluded.

**Non-fatal per-report errors.** A single failed report does not abort the
run. Errors are logged as warnings and the connector proceeds with the
remaining batch.

**Official PDF over rendered alternatives.** The GTI
`/api/v3/collections/{id}/download_report` endpoint returns a signed GCS
URL pointing to the official Mandiant-formatted PDF. This is used in
preference to any local rendering approach. No separate Mandiant Advantage
API credentials are required — only the GTI API key.

---

## Requirements

- OpenCTI 6.9.13 or compatible
- GTI/VirusTotal API key with access to GTI-authored reports
- Docker and Docker Compose
- The following marking definitions must exist in OpenCTI before the
  connector starts: any definitions listed in `GTI_MARKING_DEFINITION`
  (default: `TLP:AMBER+STRICT`)

---

## Configuration

All configuration is via environment variables. No secrets should be
committed to version control — use `docker-compose.override.yml` for
sensitive values.

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | Yes | — | OpenCTI platform base URL, e.g. `http://localhost:8080` |
| `OPENCTI_TOKEN` | Yes | — | OpenCTI connector service account token |
| `GTI_API_KEY` | Yes | — | GTI/VirusTotal API key |
| `GTI_INTERVAL` | No | `60` | Polling interval in minutes |
| `GTI_IMPORT_LIMIT` | No | `40` | Maximum reports to fetch per run (GTI API cap: 40 per page) |
| `GTI_REPORT_FILTER` | No | `collection_type:report origin:"Google Threat Intelligence"` | GTI API filter string. The quoted origin value is required — unquoted multi-word values return zero results |
| `GTI_CONFIDENCE` | No | `85` | OpenCTI confidence score applied to all ingested reports |
| `GTI_MARKING_DEFINITION` | No | `TLP:AMBER+STRICT` | Comma-separated list of marking definition names to apply, e.g. `TLP:AMBER+STRICT,Sensitive` |

### Connector Identity Variables

Standard OpenCTI connector identity variables are also required. These
are set in `docker-compose.yml` and do not contain sensitive values:

| Variable | Description |
|---|---|
| `CONNECTOR_ID` | Unique UUID for this connector instance |
| `CONNECTOR_TYPE` | Must be `EXTERNAL_IMPORT` |
| `CONNECTOR_NAME` | Display name in OpenCTI UI |
| `CONNECTOR_SCOPE` | `identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report` |
| `CONNECTOR_LOG_LEVEL` | `info` recommended for production |

---

## Deployment

### 1. Clone or copy the connector directory

```
connectors/custom/gti/
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
└── src/
    ├── gti.py
    ├── config.yml
    └── requirements.txt
```

### 2. Add credentials to your override file

In `docker-compose.override.yml` (never committed to version control):

```yaml
services:
  connector-gti-reports:
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your-connector-token
      - GTI_API_KEY=your-gti-api-key
      - GTI_MARKING_DEFINITION=TLP:AMBER+STRICT
```

### 3. Build and start

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  build --no-cache connector-gti-reports

sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  up -d connector-gti-reports
```

### 4. Verify startup

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.override.yml \
  logs -f connector-gti-reports
```

Healthy startup produces log output within 30 seconds. Absence of any log
output within 30 seconds indicates a hang — treat as a failure and
investigate.

Expected startup sequence:
1. Health check against the OpenCTI platform
2. Connector registered with ID
3. Identity resolved or created
4. Marking definitions resolved
5. Cold start / last run timestamp
6. Work ID initiated
7. Page fetch log lines
8. Per-report creation and attachment logs
9. Done message with count and next run time

---

## Report Type Mapping

| GTI Report Type | OpenCTI report_types |
|---|---|
| Weekly Vulnerability Exploitation Report | Activity Roundup |
| Actor Profile | Activity Roundup |
| Trends and Forecasting | Activity Roundup |
| All other types | threat-report |

---

## PDF Download

The connector uses the GTI `download_report` endpoint:

```
GET /api/v3/collections/{collection_id}/download_report
```

This returns a signed Google Cloud Storage URL. The connector fetches
that URL to retrieve the PDF bytes, which are validated against the `%PDF`
magic bytes before attachment.

The following alternative endpoints were investigated and are not used:
- `/api/v3/reports/{id}/pdf` — returns 404 at this subscription tier
- `/ui/collections/{id}/download_report` — reCAPTCHA protected

---

## Resetting Connector State

To force a full re-evaluation of the API window on the next run:

```bash
curl -s -X POST http://localhost:8080/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{"query":"mutation { resetStateConnector(id: \"YOUR_CONNECTOR_ID\") { id } }"}'
```

Note: a state reset causes the connector to re-evaluate all reports in
the current API window against the graph. Reports already in the graph
are skipped via dedup. Only genuinely new reports are ingested.

---

## Known Limitations

- **API window**: The `relevance-` ordering does not guarantee chronological
  completeness for older reports. Reports outside the relevance window may
  not appear regardless of import limit. The connector is designed for
  ongoing operational ingestion, not full historical backfill.

- **PDF availability**: Not all GTI collection types have PDFs via
  `download_report`. Missing PDFs are handled non-fatally — the connector
  attaches markdown only in those cases.

- **Report type mapping**: New GTI report types introduced after deployment
  will default to `threat-report`. The `_map_report_type` method should be
  reviewed periodically.

- **Relationship ingestion**: The connector ingests Report containers only.
  Entity and relationship creation from report content requires manual
  analyst review per the CTI Ingestion Manual.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| pycti | 6.9.13 | OpenCTI Python client — pinned to match platform version |
| requests | >=2.31.0 | HTTP client for GTI API calls |
| pyyaml | >=6.0.1 | Config file parsing |
| markdown | >=3.5.0 | Markdown processing for the structured attachment |

System dependency: `libmagic1` — required by pycti via python-magic.
Installed via apt in the Dockerfile before the pip install step.
