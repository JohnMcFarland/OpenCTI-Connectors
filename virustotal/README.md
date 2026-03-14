# VirusTotal Enrichment Connector — OpenCTI

A data-model-compliant internal enrichment connector for OpenCTI that enriches observables against the VirusTotal v3 API. This is a custom fork of the upstream OpenCTI VirusTotal connector, rebuilt to enforce strict graph model conformance, analyst-workbench scoping, and principled intelligence production.

---

## Overview

| Property | Value |
|---|---|
| **Connector Type** | `INTERNAL_ENRICHMENT` |
| **Supported Scope** | `StixFile`, `Artifact`, `IPv4-Addr`, `Domain-Name`, `Url` |
| **OpenCTI Version** | 6.9.x |
| **Trigger** | Manual (analyst-initiated) or automatic — RFI gate enforced at runtime |
| **Output Marking** | TLP:GREEN on all derived objects |

---

## Key Design Decisions

### RFI-Only Enrichment Gate

Enrichment only executes for observables that belong to a **Case-Rfi (Request for Information)** container. Observables in Reports, Case-Incidents, or with no container are silently skipped. When multiple RFIs contain the observable, derived objects are scoped to the **most recently updated** RFI — a reliable proxy for the active analyst workbench.

This gate enforces the principle that enrichment is a deliberate analytical act, not an automated data accumulation pipeline.

### No Threshold-Based Indicators

The upstream connector creates `stix2.Indicator` objects when VT's malicious detection count exceeds a configurable threshold. **This behavior has been removed.** Indicators are OpenCTI inference-engine output — creating them from a detection count bypasses the data model and produces unmanaged detection artifacts.

The only Indicators this connector creates are **YARA rules** from VT's crowdsourced YARA analysis, which are genuine STIX Indicators with machine-readable patterns, validated authorship, and temporal bounds.

### Tag-to-Entity Conversion

VT's `tags` array is classified and converted to typed STIX entities rather than being written as string labels:

| Tag Pattern | Action |
|---|---|
| `CVE-YYYY-NNNNN` | `stix2.Vulnerability` with NVD external reference |
| `TNNNN` / `TNNNN.NNN` | `stix2.AttackPattern` with MITRE ATT&CK external reference |
| Known behavioral / platform / generic | Dropped — content preserved in assessment note |
| All other strings | `stix2.Malware` (is_family=True) |

Generic tags include VT's behavioral analysis vocabulary (`long-sleeps`, `detect-debug-environment`, `pedll`), platform descriptors (`windows`, `linux`, `64bits`), file format tags (`peexe`, `pdf`, `rar`), and generic malware class nouns (`trojan`, `ransomware`, `worm`).

### Assessment Notes

Every enrichment job produces a structured `note_types=["assessment"]` Note linked to the enriched observable. Notes include:

- **Observable Summary** — all available entity fields (hashes, name, size, MIME type, author, ingestion date)
- **Detection Statistics** — engine counts and computed score
- **VT Tags** — full raw tag list including dropped tags
- **Source permalink** — VT GUI link

When VT has no record of an observable (`NotFoundError`), a **"No Record Found"** assessment note is created instead of failing the job. This surfaces the absence of VT data as an explicit, traceable analytical finding.

### Score Handling

`x_opencti_score` is **not written** to observables or derived entities. VT's detection ratio is surfaced in the assessment note as analytical context, not as an authoritative fact. This preserves analyst-assigned scores and prevents automated scoring from masquerading as validated intelligence.

### Provenance on Every Object

Every object the connector creates carries:
- `created_by_ref` → VirusTotal Identity (graph-registered at startup)
- `object_marking_refs` → TLP:GREEN (resolved from instance at startup)
- `external_references` → VT GUI permalink
- `description` → semantic context including VT permalink

The VirusTotal Identity is registered as a graph-persisted Organization entity at startup, not generated as a transient bundle object.

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
- Location / Country entity (`located-at` relationship) — full country name resolved from alpha-2 via `pycountry`, alpha-2 stored as alias
- Assessment Note

### Domain-Name / Hostname
- IPv4-Addr observables from passive DNS A records (`resolves-to` relationships)
- Assessment Note

### Url
- Assessment Note

---

## Container Scoping

All derived objects are added to the originating RFI container after bundle submission. A retry loop with exponential backoff handles the worker processing delay between bundle submission and database commit:

- Maximum 5 attempts per object
- Initial delay 2 seconds, doubling on each retry
- Retry triggered only on `internal_id undefined` errors
- Scoping failures are non-fatal and logged as warnings

---

## Configuration

Copy `src/config.yml.sample` to `src/config.yml` for local development, or configure via environment variables.

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
| `VIRUSTOTAL_MAX_TLP` | `TLP:AMBER` | Maximum TLP of observables sent to VT. Observables above this level are skipped. |
| `VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE` | `false` | If true, overwrite a higher existing score with VT's lower value. |
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

Threshold-based Indicator creation has been removed. See design decisions above.

---

## Deployment

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
      - VIRUSTOTAL_TOKEN=your_vt_api_key_here
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
      CONNECTOR_SCOPE: StixFile,Artifact,IPv4-Addr,Domain-Name,Url
      CONNECTOR_AUTO: "true"
      CONNECTOR_ONLY_CONTEXTUAL: "false"
      CONNECTOR_LOG_LEVEL: info
      VIRUSTOTAL_TOKEN: ${VIRUSTOTAL_API_KEY}
      VIRUSTOTAL_MAX_TLP: TLP:AMBER
      VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE: "false"
      VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT: "true"
      VIRUSTOTAL_FILE_IMPORT_YARA: "true"
      VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS: "false"
      VIRUSTOTAL_IP_ADD_RELATIONSHIPS: "true"
      VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS: "true"
      VIRUSTOTAL_URL_UPLOAD_UNSEEN: "false"
    restart: unless-stopped
```

Add to your `.env`:

```
VIRUSTOTAL_API_KEY=your_vt_api_key
VIRUSTOTAL_OPENCTI_TOKEN=your_opencti_token
```

---

## Usage

Enrichment is triggered from the observable entity page in OpenCTI:

1. Navigate to an observable inside a **Case-Rfi (Request for Information)** container
2. Open the enrichment panel
3. Select **VirusTotal** and trigger enrichment

If the observable is not in any RFI container, the connector will skip enrichment silently. No API call is made and no objects are created.

Enriched results (entities, relationships, notes) are automatically scoped to the RFI container and appear in the **Entities**, **Relationships**, and **Notes** tabs.

---

## Dependencies

- `pycti` — OpenCTI Python client
- `plyara` — YARA rule parsing for crowdsourced YARA import
- `pycountry` — ISO 3166-1 alpha-2 to full country name resolution

---

## Differences from Upstream

| Behavior | Upstream | This Connector |
|---|---|---|
| Enrichment scope | All observables platform-wide | Case-Rfi containers only |
| Indicator creation | Threshold-based for all types | YARA rules only |
| VT tags | Written as string labels | Converted to Malware / Vulnerability / AttackPattern entities |
| Not-found handling | Raises error | Creates assessment note |
| Score writing | Writes `x_opencti_score` to observable | Score in note only — observable not modified |
| Author identity | Transient bundle object | Graph-registered Organization entity |
| TLP marking | Not applied to created objects | TLP:GREEN on all emitted objects |
| Country names | Alpha-2 code stored as name | Full name resolved, alpha-2 stored as alias |
| Container scoping | None | All derived objects scoped to originating RFI |
| Note structure | Raw markdown table | Structured assessment note with observable summary header |

---

## License

This connector is based on the [OpenCTI connectors](https://github.com/OpenCTI-Platform/connectors) repository, which is licensed under the Apache 2.0 License.
