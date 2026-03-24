# OpenCTI Custom Connectors

A suite of production-grade connectors for a self-hosted [OpenCTI](https://github.com/OpenCTI-Platform/opencti) instance. This repository centralizes all custom external import and enrichment connectors built against the OpenCTI 6.9.13 platform API.

---

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [Data Model](#data-model)
  - [Entities](#entities)
  - [Observables](#observables)
  - [Relationships](#relationships)
  - [Containers](#containers)
- [Connector Catalog](#connector-catalog)
- [Architecture Conventions](#architecture-conventions)
- [Deployment](#deployment)
- [Contributing](#contributing)

---

## Design Philosophy

These connectors are built around a single organizing principle: **the knowledge graph is a long-lived analytical asset whose value compounds over time.** Every architectural decision follows from that premise.

### The Four Cs

All ingestion and enrichment logic is governed by the **Four Cs** framework, which defines the quality bar for every object written to the graph:

| Principle | Definition |
|---|---|
| **Containment** | Every entity and observable must exist inside a container (Report, Incident Response). No orphan objects. |
| **Contextualization** | Entities are only meaningful through their relationships. Every ingested object must carry at least one relationship that defines its analytical role. |
| **Completeness** | Connectors represent the full assertional scope of their source. Partial ingestion and cherry-picking are explicitly prohibited. |
| **Categorization** | Every object is classified — marked with a TLP definition, attributed to an author identity, and typed correctly. |

### Core Constraints

**Non-destructive by default.** Connectors never delete, overwrite, or purge existing graph data. Deduplication is handled via External Reference URL lookup — if a record already exists, it is updated or skipped; never replaced.

**Data model authority.** The OpenCTI STIX 2.1 data model is the single source of truth. No connector silently bypasses schema constraints. Modeling conflicts are surfaced as warnings, not suppressed.

**Separation of concerns.** External reporting lives in `Report` containers. Internal observations and sensor alerts live in `Incident Response` containers. These are not interchangeable.

**No Indicators.** Indicators are generated automatically by the OpenCTI platform from Observables when detection rules are configured. Connectors in this repository do not create Indicator objects.

**Identity-anchored observables.** Every Observable ingested by a connector carries at least one `related-to` relationship pointing to a named Identity (Threat Actor, Intrusion Set, or Organization). Unanchored observables are noise.

**Externalized configuration.** All secrets, tokens, and tunable parameters are passed via Docker Compose environment overrides. No configuration is hardcoded.

---

## Data Model

The data model used across all connectors is a strict subset of STIX 2.1 as implemented in OpenCTI 6.x. The authoritative relationship matrix is maintained in [`Data_Model_Relationship_Guide.csv`](./Data_Model_Relationship_Guide.csv).

### Entities

| Entity | Usage |
|---|---|
| **Threat Actor Group** | Real-world adversary organizations (e.g., Reconnaissance General Bureau, Cozy Bear). Not a proxy for an Intrusion Set. |
| **Intrusion Set** | Analyst-constructed cluster of activity attributed to a threat actor. APT29 ≠ SVR. |
| **Malware** | Purpose-built offensive software (e.g., Emotet, KEYPLUG). Distinct from Tool. |
| **Tool** | Legitimate software repurposed by attackers (e.g., AnyDesk, Mimikatz). |
| **Infrastructure** | Named, organized adversary infrastructure (e.g., C2 clusters, staging environments). Not raw IPs or domains. |
| **Campaign** | A time-bounded cluster of adversary activity with a defined objective. |
| **Attack Pattern** | MITRE ATT&CK technique or sub-technique. |
| **Vulnerability** | CVE or vendor-assigned vulnerability. |
| **Channel** | Specific platform or location for adversary communication or distribution (e.g., a named Telegram channel). |
| **Narrative** | Overarching theme or messaging used by a threat actor (e.g., Ghostwriter NATO narratives). |
| **Course of Action** | Defensive recommendation, preferably MITRE-defined. |
| **Individual** | Named real-world person. Dual-modeled with Threat Actor Group when the individual is an adversary. |
| **Organization** | Real-world organization — victim, vendor, or infrastructure provider. |
| **Sector** | Industry vertical (e.g., Energy, Finance). |
| **Location** | Geographic region, country, or city. |
| **Incident** | Used exclusively within Incident Response containers to represent the adversary activity cluster under investigation. Not a synonym for "event." |
| **Note (Assessment)** | Any analytical judgment made from a source. Assessment Notes are the mechanism for documenting analyst-assigned vocabulary fields. |

### Observables

Observables are atomic technical markers extracted from source data. They are the raw material of technical correlation — not intelligence assertions on their own. All observables must be anchored to at least one named Identity via `related-to`.

| Observable | Notes |
|---|---|
| IPv4 / IPv6 Address | Must link to ASN where resolvable. Link to Infrastructure via `resolves-to` or `communicates-with`. |
| Domain Name | Fully qualified only. Link to IPv4 via `resolves-to`. Anchor to Identity via `related-to`. |
| URL | Full path required. Link to Infrastructure or Malware. |
| File / Hash | SHA-256 preferred. Consolidate multiple hashes into a single File entity. |
| Email Address | Operational emails only (not generic/public). |
| Email Message | Only when full message structure is analytically relevant. |
| Network Traffic | Represents total traffic between two entities, not individual log lines. |
| Process | Unique process behaviors associated with specific malware or tools. |
| Windows Registry Key | Persistence or deployment paths only. |
| User Account | Persona-based TTPs, compromised accounts, platform IDs. |
| Mutex | Full mutex string. Link to Malware. |
| X509 Certificate | Attacker-generated or infrastructure-associated certs only. |
| Autonomous System | ASN format (e.g., AS13335). Link to Organization. |
| Software | When part of a forensic timeline or attacker toolchain. |
| MAC Address | Operationally unique instances only (e.g., malware beacon, router). |
| Persona | Monikers or handles used by threat actors or individuals. |

### Relationships

All relationships must be semantically grounded in source assertions or strong analytical implication. The full relationship matrix is in [`Data_Model_Relationship_Guide.csv`](./Data_Model_Relationship_Guide.csv). Core patterns are summarized below.

| Relationship | Source → Target | Meaning |
|---|---|---|
| `uses` | Threat Actor / Intrusion Set → Malware / Tool / Infrastructure | Attribution of capability |
| `attributed-to` | Intrusion Set → Threat Actor Group | Analytical attribution claim |
| `targets` | Intrusion Set / Malware → Organization / Sector / Vulnerability | Targeting assertion |
| `originates-from` | Threat Actor → Location | Geographic nexus claim |
| `communicates-with` | Threat Actor → Channel | Adversary communication vector |
| `has` | Channel → Narrative | Narrative carried by a channel |
| `related-to` | Any → Any | Contextual association (catch-all; required for Observable anchoring) |
| `exploits` | Malware → Vulnerability | Technical exploitation assertion |
| `delivers` | Infrastructure → Malware | Delivery mechanism |
| `resolves-to` | Domain Name → IPv4 | DNS resolution |
| `belongs-to` | IPv4 → Autonomous System | Network ownership |
| `part-of` | System → Infrastructure / Individual → Organization | Membership or composition |
| `sighted-at` | Observable / Indicator → System / Organization | Internal observation (IR containers only) |
| `references` | Report → External Reference | Source provenance chain |

**Observable-to-Identity anchoring rule:** The Observable is always the relationship source. The Identity (Threat Actor, Intrusion Set, or Organization) is always the target. Relationship type is always `related-to`.

### Containers

| Container | Scope | Contains Sightings? |
|---|---|---|
| **Report** | External source reporting — what the world says | No |
| **Incident Response** | Internal investigations and sensor alerts — what we observe | Yes |

Sightings are strictly scoped to Incident Response containers and must target a System, Individual, or Organization. They are never created inside Report containers.

---

## Connector Catalog


Each connector directory contains its own `README.md` documenting source-specific behavior, field mappings, known limitations, and deduplication strategy.

---

## Architecture Conventions

### Deduplication

All connectors deduplicate via **External Reference URL lookup**. If an object with the matching external reference URL already exists in the graph, the connector updates metadata fields where applicable and skips creation. No local state files. No Redis-only deduplication patterns.

### Identity Inheritance

Every object created by a connector inherits:
- `createdBy` — the connector's registered author identity
- `objectMarking` — TLP marking definitions (explicitly initialized; never left as empty list)
- `confidence` — source-derived, connector-configurable
- `created` / `modified` — source publication timestamps where available

### Deterministic IDs

Connectors generate deterministic STIX IDs via `pycti`'s `generate_id` utilities. Where Unicode normalization may cause divergence between connector-generated IDs and server-side IDs (curly quotes, non-breaking spaces in titles), connectors implement dual-strategy ID resolution: `standard_id` lookup first, name-based fallback second.

### Error Handling

Connectors do not fail silently. All graph write errors are logged at `ERROR` level with the full object payload. Partial bundle failures do not abort the run — the connector continues and reports a summary at completion.

### Configuration

All configuration is externalized via Docker Compose environment overrides. No secrets, tokens, or tunable parameters exist in source code. Each connector's `docker-compose.yml` documents all available environment variables and their defaults.

---

## Deployment

All connectors are deployed as Docker Compose services alongside the OpenCTI stack at `/home/siii/opencti-docker`.

**Add a connector to the stack:**

```bash
# From the opencti-docker root
sudo docker compose -f docker-compose.yml -f connectors/connector-<name>/docker-compose.yml up -d
```

**Rebuild after source changes:**

```bash
sudo docker compose -f docker-compose.yml -f connectors/connector-<name>/docker-compose.yml build --no-cache connector-<name>
sudo docker compose -f docker-compose.yml -f connectors/connector-<name>/docker-compose.yml up -d connector-<name>
```

**View connector logs:**

```bash
sudo docker logs -f connector-<name> --tail=100
```

> **Note:** The Dockerfile copies `src/` at build time. Editing source files on the host has no effect without a container rebuild.

---

## Contributing

This repository is maintained as a closed, production-grade system. Contributions must satisfy the following requirements before merge:

1. **Data model compliance.** All entities, relationships, and containers must conform to the OpenCTI 6.x STIX 2.1 model and the relationship matrix in `Data_Model_Relationship_Guide.csv`. Conflicts must be resolved before submission.

2. **Non-destructive behavior.** Connectors must not delete, reset, or overwrite existing graph objects under any operating condition.

3. **Four Cs compliance.** Every ingested object must satisfy Containment, Contextualization, Completeness, and Categorization requirements as defined in the CTI Ingestion Manual.

4. **No Indicators.** Connectors must not create Indicator objects.

5. **Full configuration externalization.** No hardcoded secrets or environment-specific values in source.

6. **Connector-level README.** Every connector must ship with a `README.md` documenting source behavior, field mappings, deduplication logic, and known limitations.

---

> This repository is maintained in support of a long-lived, self-hosted OpenCTI threat intelligence instance. All connectors are purpose-built for this environment. The data model, ingestion conventions, and operational constraints documented here take precedence over upstream OpenCTI defaults where they differ. 
