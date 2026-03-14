# Report Model QA Connector

An OpenCTI internal enrichment connector that performs automated, non-destructive quality assurance analysis on Report containers. When triggered, it evaluates a report against the CTI data model, produces a structured QA disposition with a PASS/FAIL verdict, quantitative quality scores, and writes a detailed findings note directly to the report in OpenCTI.

---

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [How It Works](#how-it-works)
- [QA Rule Modules](#qa-rule-modules)
- [Scoring Model](#scoring-model)
- [Document Extraction and Reconciliation](#document-extraction-and-reconciliation)
- [Entity Knowledge Base](#entity-knowledge-base)
- [Installation](#installation)
- [Configuration Reference](#configuration-reference)
- [Output Format](#output-format)
- [Known Limitations](#known-limitations)

---

## Design Philosophy

### Non-Destructive by Contract

The connector never creates, modifies, or deletes any object in the OpenCTI graph. Its only write operation is appending a QA Note to the report under evaluation. All findings are advisory — the connector surfaces problems and their severity, but remediation is always left to the analyst.

### The Four Cs as the Evaluation Framework

QA rules are organized around the Four Cs of CTI data modeling:

| C | What it measures |
|---|-----------------|
| **Containment** | Are all entities and observables inside a container? Are referenced objects resolvable? |
| **Contextualization** | Are entities connected to other entities via meaningful relationships? Are observables linked to a named Identity? |
| **Completeness** | Do relationships carry descriptions, authorship, and dates? Does the report's scope match what the source document asserts? |
| **Categorization** | Does the report carry required metadata — markings, author, publication date, report type? Does relationship provenance align with container markings? |

### Severity as a Spectrum, Not a Binary

The connector avoids treating all findings as equal. Each finding carries a severity level that directly affects the verdict and quality scores:

| Severity | Meaning | Verdict effect |
|----------|---------|----------------|
| `BLOCKER` | Fundamental structural violation — container is unusable as a graph representation | FAIL |
| `ERROR` | Required field violation, provenance breach, or high-confidence completeness gap | FAIL |
| `WARN` | Quality degradation that does not invalidate the report but limits its analytical value | PASS (advisory) |
| `INFO` | Observations, suggestions, and low-confidence extraction candidates for analyst review | PASS (advisory) |

A report FAILs only when it contains at least one BLOCKER or ERROR finding. WARNs and INFOs produce a PASS with an advisory assessment listing the deficiencies.

### Epistemic Conservatism

The connector never invents relationships, infers attribution, or assumes analyst intent. When signal is ambiguous — for example, when a name appears in a document but could be a false positive — the finding is advisory (INFO or WARN) rather than FAIL-triggering. Only unambiguous structural identifiers (CVE IDs, UNC cluster designations, ATT&CK technique codes) trigger ERROR-level reconciliation gaps.

---

## How It Works

1. **Trigger** — OpenCTI dispatches the connector when a Report is created or manually enriched.
2. **Scope resolution** — The connector reads all object IDs referenced by the report and resolves each to its full entity or relationship object via the OpenCTI API.
3. **Rule evaluation** — Each rule module evaluates the resolved scope and returns zero or more findings.
4. **Document extraction** — If the report has an attached PDF, Markdown, or text file, the connector extracts its text and runs deterministic pattern matching, KB lookup, and smart-parse actor extraction against the prose.
5. **Reconciliation** — Extracted document candidates are compared against the report scope to identify named entities present in the source but absent from the graph.
6. **Disposition** — All findings are aggregated, a verdict is computed, and quality scores are calculated.
7. **Note write** — A structured QA note is written to the report. The note title includes the verdict so it is visible in the notes list without opening the note.

---

## QA Rule Modules

### QA.CONTAINMENT.001 — Containment

Verifies that all object IDs referenced by the report are resolvable via the OpenCTI API. Unresolvable IDs indicate orphaned references, deleted objects, or permission gaps. Severity is proportional to the count of unresolvable objects.

---

### QA.CONTEXT.002 — Contextualization

Checks that every entity and observable in the report scope is connected to at least one other entity via a relationship. Two failure modes are detected:

- **Uncontextualized entities** — entities with no relationships at all within the report scope.
- **Orphaned observables** — SCO-type objects (IP addresses, domains, file hashes, URLs, etc.) that lack a `related-to` relationship to a named Identity (Threat Actor, Intrusion Set, or Organization). Per the data model, observables derive analytical meaning only through their association with a named actor or organization.

---

### QA.COMPLETENESS.001 — Report Required Fields

Checks that the report container itself carries the minimum required metadata: name, description, author (`createdBy`), and at least one marking definition. Missing fields are ERROR severity.

---

### QA.COMPLETENESS.002 — Relationship Required Fields

Evaluates every relationship in the report scope across three dimensions:

**Description quality** — Relationships must carry a description of at least 8 words that provides analytical context. Self-referential descriptions (e.g. a description that simply restates the relationship type or endpoint names) fail this check. The proportion of relationships failing the description check is compared against a configurable threshold (`QA_REL_DESC_FAIL_THRESHOLD`). If the proportion exceeds the threshold, the finding escalates from WARN to ERROR.

**Required metadata** — Relationships must carry authorship (`createdBy`) and a timestamp.

**Temporal coherence** — Relationship date windows are checked for internal consistency: `last_seen` must not precede `first_seen`, `last_seen` must not be in the future, and relationship `first_seen` must not predate both endpoints' earliest known activity.

---

### QA.CATEGORIZATION.002 — Relationship Provenance

Checks that relationships created in the context of this report carry the same author and marking definitions as the report container. Relationships that predate the report's publication date by more than the configured grace period are treated as pre-existing shared objects and exempted from provenance checks. This prevents false positives when analysts link a report to long-standing entities with different markings.

---

### QA.RELATIONSHIPS.001 — Relationship Policy

Validates all relationships against a hard-coded allowlist of permitted source → relationship type → target combinations derived from STIX 2.1 and the OpenCTI data model. Relationships that do not appear in the allowlist are flagged. The policy covers over 120 valid relationship combinations across all major SDO and SCO types.

---

### QA.LABELS.001 — Label Policy

Validates that labels applied to entities within the report scope conform to the Collection Requirement format (`CR-NNNN`, `REQ-NNNN`, or `COLREQ-NNNN`). Labels are reserved for collection requirement tracking; free-text or ad-hoc labels are flagged as WARN.

---

### QA.SIGHTINGS.001 — Sightings Policy

Enforces that sightings are only created for Observable entities, only appear inside Incident Response containers (not Report containers), and carry the required `first_seen`/`last_seen` timestamps. Sightings in Report containers are a common ingestion error that contaminates the graph's temporal model.

---

### QA.THREATACTOR.001 — Threat Actor Policy

Flags Threat Actor entities whose names suggest they are software tools, vulnerability identifiers, or other non-actor concepts. The connector is configured to expect Threat Actor entities to represent real-world organizations or groups (e.g. a nation-state bureau or criminal syndicate), not malware families or CVE identifiers.

---

### QA.DOC.010 — Document Extraction

Extracts text from the report's attached file and surfaces candidates for analyst review. This is an **advisory-only** rule — it does not create or modify any objects. Three extraction signals are used:

- **Deterministic** — structured identifiers extracted via regex: CVE IDs, UNC cluster designations, ATT&CK technique codes, IPv4 addresses, domain-like tokens.
- **KB match** — names of entities already present in the live OpenCTI graph, matched against the document text.
- **Smart-parse** — contextual actor extraction using cue phrase patterns (e.g. "tracked as", "attributed to") to identify named threat actors described in prose.

---

### QA.RECONCILIATION.001 — Document-to-Graph Reconciliation

Compares document extraction candidates against the report scope. Candidates present in the document but absent from the scope are reported as gaps. Severity is assigned per gap based on extraction signal:

| Signal | Severity | Rationale |
|--------|----------|-----------|
| Deterministic (CVE, UNC, T-code) for a named threat intel type | `ERROR` | Unambiguous structured identifier — no reasonable false positive |
| Smart-parse confidence ≥ 0.80 for a named threat intel type | `ERROR` | High-confidence contextual extraction |
| Named threat intel type mentioned ≥ 5 times | `ERROR` | Frequency indicates centrality to the report |
| KB match or smart-parse < 0.80, 2–4 mentions | `WARN` | Plausible gap but not certain |
| Observable type (IP, domain, hash) | `INFO` | May be intentionally excluded; no ERROR |
| Single mention, low confidence | `INFO` | Noise level |

---

## Scoring Model

Two scores are calculated and displayed in the disposition block:

### Compliance Score (0–100)

Deduction-based. Starts at 100 and loses points per finding:

| Severity | Deduction per finding |
|----------|-----------------------|
| BLOCKER  | 30 |
| ERROR    | 20 |
| WARN     | 7 |
| INFO     | 0 |

Floored at 0.

### Rule Pass Rate (0–100)

Proportion of rule modules that produced no BLOCKER, ERROR, or WARN findings, expressed as a percentage of total rules run.

### Score Labels

| Score | Label |
|-------|-------|
| ≥ 90  | Excellent |
| ≥ 75  | Good |
| ≥ 60  | Fair |
| ≥ 40  | Poor |
| < 40  | Critical |

Both scores are displayed in the disposition block alongside the severity breakdown, giving analysts an immediate quantitative signal for how much remediation work remains.

---

## Document Extraction and Reconciliation

### Supported File Types

The connector attempts document extraction in the following order:

1. `pdftotext` (system binary, highest fidelity for machine-generated PDFs)
2. `PyPDF2` fallback
3. OCR via `pytesseract` for scanned documents (up to `QA_DOC_OCR_MAX_PAGES` pages)
4. Report description field (always attempted as a final fallback)

Supported MIME types: `application/pdf`, `text/markdown`, `text/plain`.

### Smart-Parse Actor Extraction

Smart-parse scans document prose for cue phrases that introduce named actors:

- **Tracked-as cues** — "tracked as X", "designated X", "known as X"
- **Attribution cues** — "attributed to X", "associated with X", "linked to X"
- **Operator cues** — "operated by X", "conducted by X"

Extracted candidates are classified using the Entity Knowledge Base (see below) and assigned a confidence score. Candidates below `QA_DOC_SMART_PARSE_MIN_CONFIDENCE` are discarded. The maximum number of smart-parse candidates per report is bounded by `QA_DOC_SMART_PARSE_MAX_CANDIDATES`.

### KB Reclassification

When smart-parse extracts a candidate with a type that conflicts with the KB (e.g., smart-parse classifies "GRIMBOLT" as an Intrusion-Set based on cue phrase context, but the KB records GRIMBOLT as a Malware family), the KB classification takes precedence. This prevents false reconciliation errors when the document uses tracking-language patterns for non-actor entities.

---

## Entity Knowledge Base

The connector maintains an in-memory Knowledge Base (KB) built from the live OpenCTI graph. The KB indexes all named entities — their type, aliases, and MITRE ATT&CK identifiers — and is used for:

- **KB scan** — matching entity names and aliases against document text
- **KB reclassification** — correcting smart-parse type assignments when the graph's authoritative type differs from what the extraction context implies

The KB is rebuilt from the graph at startup and then refreshed every `QA_KB_TTL_HOURS` hours. Reducing the TTL increases freshness at the cost of additional API calls on busy instances. The KB entry count and build timestamp are recorded in the configuration snapshot of every QA note for auditability.

---

## Installation

### Prerequisites

- OpenCTI 6.x instance
- Docker and Docker Compose
- A dedicated OpenCTI connector user with the **Connector** role
- `pdftotext` available in the container image (included in the provided Dockerfile via `poppler-utils`)

### Standalone Deployment

```bash
git clone <repo>
cd report_model_qa
cp .env.example .env
# Edit .env — set OPENCTI_URL, OPENCTI_TOKEN, CONNECTOR_ID at minimum
docker compose up -d
```

### Integrated Deployment (existing opencti-docker stack)

Add the following block to your `docker-compose.override.yml`, substituting your token and connector ID:

```yaml
connector-report-model-qa:
  container_name: connector-report-model-qa
  build:
    context: ./connectors/custom/report_model_qa
    dockerfile: Dockerfile
  image: opencti/connector-report-model-qa:local
  restart: unless-stopped
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${QA_OPENCTI_TOKEN}
    - CONNECTOR_ID=${QA_CONNECTOR_ID}
    - CONNECTOR_NAME=Report Model QA (Non-Destructive)
    - CONNECTOR_TYPE=INTERNAL_ENRICHMENT
    - CONNECTOR_SCOPE=Report
    - CONNECTOR_LOG_LEVEL=info
    - QA_WRITE_NOTE=true
    - QA_FAIL_ON_BLOCKERS=true
    - QA_REL_DESC_FAIL_THRESHOLD=0.50
```

### Generating a Connector ID

```bash
python3 -c "import uuid; print(uuid.uuid4())"
```

---

## Configuration Reference

All configuration is via environment variables. Variables with defaults are optional.

### Core

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENCTI_URL` | Yes | — | URL of the OpenCTI instance. Use `http://opencti:8080` on the same Docker network. |
| `OPENCTI_TOKEN` | Yes | — | API token for the connector user. Create a dedicated user with the Connector role. |
| `CONNECTOR_ID` | Yes | — | Unique UUID for this connector instance. Generate with `python3 -c "import uuid; print(uuid.uuid4())"`. |
| `CONNECTOR_NAME` | No | `Report Model QA (Non-Destructive)` | Display name in OpenCTI. |
| `CONNECTOR_TYPE` | No | `INTERNAL_ENRICHMENT` | Do not change. |
| `CONNECTOR_SCOPE` | No | `Report` | Do not change. |
| `CONNECTOR_LOG_LEVEL` | No | `info` | Log verbosity. Options: `debug`, `info`, `warn`, `error`. |
| `CONNECTOR_INTERVAL` | No | `120` | Polling interval in seconds. |

### QA Output

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `QA_WRITE_NOTE` | No | `true` | Write QA findings as a Note on the report. Set to `false` for dry-run mode. |
| `QA_ATTACH_JSON` | No | `false` | Attach raw findings JSON to the note. Useful for pipeline integration. |
| `QA_NOTE_MAX_ROWS` | No | `50` | Maximum findings rows to include in the note. Findings beyond this limit are summarized. |
| `QA_FAIL_ON_BLOCKERS` | No | `true` | If `false`, BLOCKER findings are treated as ERROR for verdict purposes. |

### Entity Knowledge Base

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `QA_KB_TTL_HOURS` | No | `24` | Hours before the in-memory KB is rebuilt from the graph. Lower = more current; higher = less API overhead. |

### Document Extraction

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `QA_DOC_OCR_MAX_PAGES` | No | `6` | Maximum pages to process via OCR (pytesseract) when pdftotext and PyPDF2 both fail. |
| `QA_DOC_SMART_PARSE` | No | `true` | Enable contextual smart-parse actor extraction from document prose. |
| `QA_DOC_SMART_PARSE_MIN_CONFIDENCE` | No | `0.70` | Minimum confidence score (0.0–1.0) for smart-parse candidates to be surfaced. |
| `QA_DOC_SMART_PARSE_MAX_CANDIDATES` | No | `80` | Maximum number of smart-parse candidates evaluated per report. |

### Provenance

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `QA_PROVENANCE_GRACE_HOURS` | No | `24` | Relationships created within this many hours of the report's publication date are treated as report-scoped and subject to provenance checks. Relationships outside this window are treated as pre-existing shared objects and skipped. |

### Completeness Thresholds

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `QA_REL_DESC_FAIL_THRESHOLD` | No | `0.50` | Proportion of relationships with insufficient descriptions that escalates QA.COMPLETENESS.002 from WARN to ERROR. `0.0` = zero tolerance (any missing description triggers FAIL). `1.0` = descriptions never trigger FAIL. |

---

## Output Format

### Note Title

The note title includes the verdict so it is visible in the notes list without opening the note:

```
QA [✓ PASS]: Report Title Here
QA [✗ FAIL]: Report Title Here
```

### Disposition Block

The top of each note contains a disposition block:

```
╔══════════════════════════════════════╗
║                                      ║
║   ✓  VERDICT: PASS                   ║
║                                      ║
╚══════════════════════════════════════╝

────────────────────────────────────────
REPORT MODEL QA DISPOSITION
────────────────────────────────────────

Report Title: ...
Report ID:    report--...
Generated:    2026-03-14T11:31:38Z

Quality Scores
  • Compliance score:   46 / 100  (Poor)   — starts at 100, deducts 30/BLOCKER, 20/ERROR, 7/WARN
  • Rule pass rate:      X / 100  (Fair)   — N of 11 rule modules clean

Scope Overview
  • Entities evaluated:      19
  • Relationships evaluated:  32
  • Findings: 6  (BLOCKER: 0  ERROR: 2  WARN: 2  INFO: 2)

Assessment
This report does not satisfy minimum data-model requirements...
```

### Findings

Each finding section identifies the rule, severity, the standard being evaluated, and a table of specific violations with source, relationship type, target, and reason columns. Machine-readable evidence JSON is appended to each section for pipeline consumption.

### Configuration Snapshot

The bottom of each note includes a JSON snapshot of the connector configuration at the time of evaluation. This ensures findings can be interpreted correctly even if configuration changes between runs.

---

## Known Limitations

**Java class names as domain false positives** — The domain extractor uses a dot-notation pattern that matches Java class names (e.g. `base64.getdecoder`, `catalina.startup`). These appear as `DomainName` candidates in Document Extraction and as INFO-level reconciliation gaps. They will not trigger FAIL. A stop-list is a planned improvement.

**KB false positives on generic words** — If a generic word (e.g. "endpoint", "discussed") exists as an entity name in the graph, the KB scan will match it in document text and surface it as a suggestion. These are INFO-level only and require analyst validation.

**Re-run deduplication** — Running the connector multiple times on the same report produces multiple QA notes. The connector does not currently detect or replace prior QA notes for the same report. Manual deletion of stale notes is required.

**Smart-parse duplicate candidates** — Smart-parse may produce duplicate candidates for the same entity when the cue phrase appears in multiple sentences. These are deduplicated before reconciliation but may appear as duplicate rows in the Document Extraction table.

**Token scope for identity resolution** — The `createdBy` field on relationships uses a UUID that may not resolve via the standard `identities` query depending on the connector token's permission scope. If provenance checks show unexpected mismatches, verify the connector user has access to the relevant identity objects.


