# VirusTotal Enrichment Connector — OpenCTI

A data-model-compliant internal enrichment connector for OpenCTI that enriches all observables within a **Case-Rfi (Request for Information)** container against the VirusTotal v3 API. This is a custom fork of the upstream OpenCTI VirusTotal connector, rebuilt to enforce strict graph model conformance, container-level enrichment, and principled intelligence production.

---

## Overview

| Property | Value |
|---|---|
| **Connector Type** | `INTERNAL_ENRICHMENT` |
| **Trigger Scope** | `Case-Rfi` |
| **Supported Observable Types** | `StixFile`, `Artifact`, `IPv4-Addr`, `Domain-Name`, `Hostname`, `Url` |
| **OpenCTI Version** | 6.9.x |
| **Trigger** | Manual (analyst-initiated on RFI container) or automatic |
| **Output Marking** | TLP:GREEN on all derived objects |

---

## How It Works

The connector is triggered on **Case-Rfi containers**, not on individual observables. When enrichment is initiated on an RFI:

1. The connector reads the last-run timestamp for that container from a persistent state file
2. All SCOs in the container added since that timestamp are queried
3. Each observable is enriched against the VT API with per-observable TLP checking and rate-limiting between calls
4. All derived objects (entities, relationships, notes, indicators) are scoped back into the RFI container
5. The state file is updated with the current timestamp

On **first run** against an RFI, all existing observables in the container are processed regardless of when they were added.

---

## Key Design Decisions

### Container-Level Trigger

The connector scope is `Case-Rfi`. Enrichment fires on the container, not on individual observables. This allows an analyst to enrich an entire investigation context in a single action rather than enriching each observable individually.

SDOs (Malware, ThreatActor, etc.) in the container are skipped — only SCOs matching the supported types are processed.

### State Tracking Per Container

A JSON state file maps each RFI container ID to the timestamp of its last enrichment run. On subsequent runs, only observables added to the container after that timestamp are enriched. This prevents redundant re-enrichment of already-processed observables.

The state file requires a volume mount to persist across container restarts. See the deployment section.

### TLP Policy

TLP is checked **per observable** within the container run. Observables marked `TLP:RED` are skipped individually — they do not abort processing of the remaining observables. All other standard TLP levels (`TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`) are processed.

All VT-derived objects are created with `TLP:GREEN` marking regardless of the parent observable's marking. VT enrichment output is public-source intelligence — the marking should reflect the source.

### No Threshold-Based Indicators

The upstream connector creates `stix2.Indicator` objects when VT's detection count exceeds a threshold. **This has been removed.** The only Indicators this connector creates are **YARA rules** from VT's crowdsourced YARA analysis, which are genuine STIX Indicators with machine-readable patterns and validated authorship.

### Tag-to-Entity Conversion

VT's `tags` array is classified and converted to typed STIX entities rather than string labels:

| Tag Pattern | Action |
|---|---|
| `CVE-YYYY-NNNNN` | `stix2.Vulnerability` with NVD external reference |
| `TNNNN` / `TNNNN.NNN` | `stix2.AttackPattern` with MITRE ATT&CK external reference |
| Known behavioral / platform / generic | Dropped — content preserved in assessment note |
| All other strings | `stix2.Malware` (is_family=True) |

Generic tags include VT's behavioral analysis vocabulary (`long-sleeps`, `detect-debug-environment`), platform descriptors (`windows`, `linux`), file format tags (`peexe`, `rar`), and generic malware class nouns (`trojan`, `ransomware`).

### Assessment Notes

Every enrichment produces a structured `note_types=["assessment"]` Note linked to the enriched observable. Notes include a full observable summary header (hashes, name, size, MIME type, original author, ingestion date) so each note is self-contained.

When VT has no record of an observable, a **"No Record Found"** assessment note is created instead of failing the job. The absence of a VT record is treated as an analytical finding, not an error.

### Score Handling

`x_opencti_score` is **not written** to observables. VT's detection ratio is surfaced in the assessment note as context only. This preserves analyst-assigned scores.

---

## Derived Objects by Type

### StixFile / Artifact
- Malware entities (named family tags)
- Vulnerability entities (CVE tags)
- AttackPattern entities (ATT&CK technique tags)
- YARA Indicators (crowdsourced YARA matches)
- Assessment Note
- Full Engine Report Note (optional)

### IPv4-Addr
- AutonomousSystem observable (`belongs-to` relationship)
- Location / Country entity (`located-at` relationship) — full name resolved from alpha-2 via `pycountry`, alpha-2 stored as alias
- Assessment Note

### Domain-Name / Hostname
- IPv4-Addr observables from passive DNS A records (`resolves-to` relationships)
- Assessment Note

### Url
- Assessment Note

---

## State Management

The connector maintains a JSON state file at `VIRUSTOTAL_STATE_PATH` that tracks the last-run timestamp per RFI container:

```json
{
  "8b29dbfc-100a-4d42-9a24-c1de0560399a": "2026-03-24T10:20:59.526336",
  "other-rfi-id": "2026-03-23T14:30:00.000000"
}
```

**First run behaviour:** If no entry exists for an RFI, all observables in the container are processed regardless of age.

**Subsequent runs:** Only observables with `created_at` after the stored timestamp are processed.

**State write timing:** The timestamp is written after full iteration completes. If the connector is killed mid-run, the next run reprocesses from the previous timestamp — no observables are skipped.

**Volume mount required:** The state file must be persisted to a host directory via a Docker volume mount. Without this, state is lost on every container restart and all observables are re-enriched on every run.

To reset state for a specific container (force re-enrichment of all observables), delete its entry from the JSON file or delete the file entirely.

---

## Configuration

### Required

| Variable | Description |
|---|---|
| `OPENCTI_URL` | OpenCTI instance URL |
| `OPENCTI_TOKEN` | OpenCTI API token for the connector service account |
| `CONNECTOR_ID` | Unique UUID for this connector instance |
| `VIRUSTOTAL_TOKEN` | VirusTotal API key |

### Enrichment Behaviour

| Variable | Default | Description |
|---|---|---|
| `VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE` | `false` | If true, overwrite a higher existing score with VT's lower value. |
| `VIRUSTOTAL_REQUEST_DELAY_SECONDS` | `15` | Delay in seconds between VT API calls. 15 = safe for free tier (4 req/min). Set to 1 for premium API keys. |
| `VIRUSTOTAL_STATE_PATH` | `/opt/connector/state/virustotal_state.json` | Path to the state file. Must match the volume mount. |
| `VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT` | `true` | Create a supplemental per-engine scan table note for file observables. |
| `VIRUSTOTAL_FILE_IMPORT_YARA` | `true` | Import crowdsourced YARA rules as STIX Indicators. |
| `VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS` | `false` | Upload unknown Artifact entities to VT for analysis. |
| `VIRUSTOTAL_IP_ADD_RELATIONSHIPS` | `true` | Create ASN and Country relationships for IP observables. |
| `VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS` | `true` | Create passive-DNS IPv4 observables for domain observables. |
| `VIRUSTOTAL_URL_UPLOAD_UNSEEN` | `false` | Submit unknown URLs to VT for analysis. |

### Removed Upstream Variables

The following upstream configuration variables are **not supported** and will be ignored if present:

- `VIRUSTOTAL_*_INDICATOR_CREATE_POSITIVES`
- `VIRUSTOTAL_*_INDICATOR_VALID_MINUTES`
- `VIRUSTOTAL_*_INDICATOR_DETECT`
- `VIRUSTOTAL_MAX_TLP` — TLP filtering is now per-observable with a hardcoded permitted set (all except TLP:RED)

---

## Deployment

### Prerequisites

Create the state directory on the host before starting the connector:

```bash
mkdir -p ./state
```

### Docker Compose (standalone)

```yaml
services:
  connector-virustotal:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your_token_here
      - CONNECTOR_ID=your_uuid_here
      - CONNECTOR_SCOPE=Case-Rfi
      - CONNECTOR_AUTO=false
      - VIRUSTOTAL_TOKEN=your_vt_api_key_here
      - VIRUSTOTAL_REQUEST_DELAY_SECONDS=1
      - VIRUSTOTAL_STATE_PATH=/opt/connector/state/virustotal_state.json
    volumes:
      - ./state:/opt/connector/state
    restart: always
```

### Docker Compose Override (recommended for production)

Add to your `docker-compose.override.yml`:

```yaml
services:
  connector-virustotal-custom:
    build:
      context: /path/to/connectors/custom/virustotal
      dockerfile: Dockerfile
    image: custom/connector-virustotal:${OPENCTI_VERSION}
    depends_on:
      opencti:
        condition: service_healthy
    environment:
      OPENCTI_URL: http://opencti:8080
      OPENCTI_TOKEN: ${VIRUSTOTAL_OPENCTI_TOKEN}
      CONNECTOR_ID: your_uuid_here
      CONNECTOR_NAME: VirusTotal
      CONNECTOR_TYPE: INTERNAL_ENRICHMENT
      CONNECTOR_SCOPE: Case-Rfi
      CONNECTOR_AUTO: "false"
      CONNECTOR_ONLY_CONTEXTUAL: "false"
      CONNECTOR_LOG_LEVEL: info
      VIRUSTOTAL_TOKEN: ${VIRUSTOTAL_API_KEY}
      VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE: "false"
      VIRUSTOTAL_REQUEST_DELAY_SECONDS: "1"
      VIRUSTOTAL_STATE_PATH: /opt/connector/state/virustotal_state.json
      VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT: "true"
      VIRUSTOTAL_FILE_IMPORT_YARA: "true"
      VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS: "false"
      VIRUSTOTAL_IP_ADD_RELATIONSHIPS: "true"
      VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS: "true"
      VIRUSTOTAL_URL_UPLOAD_UNSEEN: "false"
    volumes:
      - /path/to/state:/opt/connector/state
    restart: unless-stopped
```

Add to your `.env`:

```
VIRUSTOTAL_API_KEY=your_vt_api_key
VIRUSTOTAL_OPENCTI_TOKEN=your_opencti_token
```

---

## Usage

Enrichment is triggered from the **RFI container** in OpenCTI:

1. Navigate to **Cases → Requests for Information**
2. Open the RFI you want to enrich
3. Open the enrichment panel on the RFI container itself
4. Select **VirusTotal** and trigger enrichment

The connector will process all observables in the container that were added since the last run. On first run, all existing observables are processed.

### Resetting State

To force re-enrichment of all observables in an RFI (e.g. after adding new observables or for a full refresh):

```bash
# Reset a specific container
python3 -c "
import json
with open('/path/to/state/virustotal_state.json', 'r') as f:
    state = json.load(f)
state.pop('your-rfi-container-id', None)
with open('/path/to/state/virustotal_state.json', 'w') as f:
    json.dump(state, f, indent=2)
"

# Reset all state (re-enrich everything on next run)
rm /path/to/state/virustotal_state.json
```

---

## Dependencies

- `pycti==6.9.13` — OpenCTI Python client (must match platform version)
- `plyara` — YARA rule parsing for crowdsourced YARA import
- `pycountry` — ISO 3166-1 alpha-2 to full country name resolution

---

## Differences from Upstream

| Behavior | Upstream | This Connector |
|---|---|---|
| Trigger scope | Individual observables platform-wide | Case-Rfi containers |
| Enrichment model | Per-observable job | Container iteration with state tracking |
| New observable detection | Every observable triggers a job | Only observables added since last run |
| Indicator creation | Threshold-based for all types | YARA rules only |
| VT tags | Written as string labels | Converted to Malware / Vulnerability / AttackPattern entities |
| Not-found handling | Raises error | Creates assessment note |
| Score writing | Writes `x_opencti_score` to observable | Score in note only |
| Author identity | Transient bundle object | Graph-registered Organization entity |
| TLP marking | Not applied to created objects | TLP:GREEN on all emitted objects |
| Country names | Alpha-2 code stored as name | Full name resolved, alpha-2 stored as alias |
| Container scoping | None | All derived objects scoped to originating RFI |
| Note structure | Raw markdown table | Structured assessment note with observable summary header |
| Rate limiting | None | Configurable delay between API calls |

---

## License

This connector is based on the [OpenCTI connectors](https://github.com/OpenCTI-Platform/connectors) repository, which is licensed under the Apache 2.0 License.
