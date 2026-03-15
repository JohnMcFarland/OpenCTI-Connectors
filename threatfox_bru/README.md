# ThreatFox OpenCTI Connector — Design Document

## Overview

This connector ingests IOC data from the [ThreatFox](https://threatfox.abuse.ch/) API (abuse.ch) and converts it to STIX 2.1 objects within OpenCTI. It runs as a persistent Docker container, polling ThreatFox every 6 hours and pushing content into OpenCTI via the pycti SDK.

Each run produces a dated Report container (`Threat Fox Feed YYYY-MM-DD`) that wraps all observables, malware family references, and reporter identities ingested in that cycle. All ingestion is non-destructive and idempotent.

---

## Functionality

### Polling and State Management

The connector uses OpenCTI's built-in state API (`helper.get_state()` / `helper.set_state()`) to persist a `last_run` timestamp between runs. On startup, if no prior state exists, the connector fetches the configured initial lookback window (default: 7 days). On subsequent runs, it computes the day delta since the last run plus one day boundary guard, capped at 7 — the ThreatFox API maximum. This prevents gaps at day boundaries while respecting the hard API limit.

### IOC Conversion

Each ThreatFox IOC entry is converted to a set of STIX 2.1 objects:

**SCOs produced per IOC type:**

| ThreatFox `ioc_type` | STIX SCO | Notes |
|---|---|---|
| `domain` | `domain-name` | |
| `ip:port` | `ipv4-addr` | IP extracted from value; port in separate network-traffic SCO |
| `ip:port` | `network-traffic` | Port-only SCO, no `dst_ref`; linked via `ipv4-addr --related-to-->` |
| `url` | `url` | |
| `sha256_hash` | `file` | `hashes.SHA-256` |
| `sha1_hash` | `file` | `hashes.SHA-1` |
| `md5_hash` | `file` | `hashes.MD5` |

**SDOs produced per run (deduplicated):**

| Source | STIX SDO | Notes |
|---|---|---|
| `malware_printable` field | `malware` | `is_family: true`; `malware_types` derived from `threat_type` |
| MITRE software tags | `malware` or `tool` | Enriched with ATT&CK S-number external reference |
| ASN tags (e.g. `AS207994`) | `autonomous-system` | SCO, not SDO |
| `reporter` field | `identity` | `identity_class: organization`; skipped for anonymous reporters |

**SROs produced per IOC:**

| Source | Relationship | Target |
|---|---|---|
| Observable | `related-to` | Malware (`malware_printable`) |
| Observable | `related-to` | MITRE Malware/Tool (from tags) |
| Observable | `related-to` | Reporter identity |
| `ipv4-addr` | `belongs-to` | Autonomous system (from ASN tags) |
| `ipv4-addr` | `related-to` | Network-traffic |

### Tag Processing

ThreatFox IOC entries carry tags that are processed into one of three outcomes:

- **ASN tags** (matching `^AS\d+$`): converted to `autonomous-system` SCOs with `belongs-to` relationships from IPv4 observables
- **MITRE ATT&CK software tags**: looked up against a pre-built cache of ATT&CK software entries; matching tags produce `malware` or `tool` SDOs with ATT&CK external references
- **Everything else**: skipped — tactic descriptors (`C2`, `EXECUTION`, `PERSISTENCE`), technique descriptors (`RAT`, `TROJAN`), ISP names, scanner metadata, and redundant malware names are all discarded

### Report Container Creation

The connector uses a two-step approach:

1. All content objects (observables, malware SDOs, identities, autonomous systems, relationships) are pushed via `send_stix2_bundle()` through the standard RabbitMQ queue
2. The Report container is created separately via a direct `helper.api.report.create()` call, then each content object is added to it via `add_stix_object_or_stix_relationship()`

This separation exists because `send_stix2_bundle` is unreliable for large Report containers — bundles are chunked for transmission, and a report with 3,000+ `object_refs` is either stripped or fails OpenCTI's validation during reassembly. The synchronous API call is slower but reliable.

The Report uses a deterministic UUID keyed on `threatfox-feed:YYYY-MM-DD`. Same-day re-runs update the existing report rather than creating a duplicate.

### Confidence Normalization

ThreatFox confidence scores (0–100) are multiplied by 0.8 before ingestion. ThreatFox is a community feed with variable submission quality. The haircut prevents community IOCs from anchoring at maximum confidence in the graph and preserves room for higher-confidence sources to take precedence via OpenCTI's confidence hierarchy.

### Deduplication

All STIX IDs are deterministic UUIDv5:

| Object type | UUID key | Namespace |
|---|---|---|
| `domain-name`, `ipv4-addr`, `url`, `file` | `<stix_type>:<value>` | STIX OASIS namespace |
| `autonomous-system` | `autonomous-system:<number>` | STIX OASIS namespace |
| `network-traffic` | `network-traffic:<ip>:<port>` | STIX OASIS namespace |
| `malware`, `tool` | `lowercase(name)` | Connector namespace |
| `identity` | `lowercase(reporter)` | Connector namespace |
| `report` | `threatfox-feed:<YYYY-MM-DD>` | Connector namespace |
| `relationship` | `<source_id>:<type>:<target_id>` | Connector namespace |

Observables use the STIX OASIS namespace so identical observables from other feeds merge automatically into the same graph node. Malware and identity SDOs use a connector-specific namespace so they remain stable across connector restarts without colliding with identically-named objects from other sources.

Within each run, relationships are deduplicated by (source, type, target) triple in memory before bundle construction, preventing duplicate SROs in the bundle even when the same malware family appears across hundreds of IOC entries.

---

## Data Model Philosophy

### Observables Over Indicators

ThreatFox IOCs are modeled as STIX Cyber Observables, not Indicators. OpenCTI's native inference engine generates Indicators from Observables automatically based on configured rules. Manually creating Indicators from feed data bypasses this pipeline, pollutes the indicator index with unreviewed machine-generated pattern objects, and conflates raw IOC ingestion with detection rule management. The connector produces no Indicator SDOs.

### Strict Containment

Every object produced by a run is referenced in a dated Report container. This enforces the platform principle that no entity or observable should exist outside a container. It ensures full traceability to the source event, supports access control scoping by report, and enables lifecycle management by ingestion date.

### Reporter Identity as Organization

ThreatFox reporters are modeled as `identity_class: organization`. Most reporters are handles, community accounts, automated scanners, or research organizations — not natural persons. Using `individual` for these entities would pollute the individual identity space with thousands of pseudonymous community handles. Anonymous reporters (`anonymous`, `unknown`, `0`, empty string) are excluded entirely — they carry no analytical value as graph nodes.

### No Infrastructure Entities

ThreatFox does not provide named, bounded infrastructure clusters. The original connector collapsed all C2 IPs for a given malware family into a single `Infrastructure` entity (e.g., "AsyncRAT C2"). This is analytically incorrect — it treats a malware family name as a topological identifier for a network cluster, destroys temporal and geographic granularity across hundreds of distinct C2 nodes, and creates a permanently polluted singleton that grows in scope with every run. IPs and domains are modeled as `ipv4-addr` and `domain-name` observables with `related-to` relationships to their malware family instead.

### No Attack Pattern Objects from Tags

ThreatFox tactic and technique tags (`C2`, `EXECUTION`, `RAT`, `TROJAN`) are generic descriptors submitted by community reporters, not verifiable ATT&CK technique assertions tied to specific adversary procedures. Creating `attack-pattern` SDOs from these tags would introduce false analytical precision into the graph. The connector skips all tactic and technique descriptor tags. Only tags that match ATT&CK *software* entries — which are structured, externally verifiable references — are converted into Malware/Tool SDOs.

### Malware Deduplication Over Fragmentation

When a MITRE ATT&CK software tag matches the `malware_printable` name of an existing Malware SDO (case-insensitive, with and without spaces), the connector reuses the existing SDO and enriches it with the ATT&CK external reference. It does not create a second entity. This prevents the graph from accumulating duplicate malware family nodes under cosmetically different names from different data sources within the same feed.

---

## Changes from the Original Connector

The original connector was a functional first implementation that did not align with the platform's data model. The following changes were made during the production refactor.

### Removed

| Component | Reason |
|---|---|
| `indicator` SDO creation | Indicators are generated automatically by OpenCTI. Manual creation bypasses the inference pipeline and violates platform policy. |
| `infrastructure` SDO creation | ThreatFox does not provide named infrastructure clusters. Per-family C2 aggregation is analytically incorrect and contaminates the graph. |
| `attack-pattern` SDO creation from tactic tags | Tactic tags (`EXECUTION`, `C2`, `PERSISTENCE`, etc.) are generic community descriptors, not verifiable ATT&CK assertions. |
| `TACTIC` and `TECHNIQUE` tag categories | Eliminated from `TagProcessor` — no longer produce any STIX objects. |
| `indicator --indicates--> malware` relationships | Not present in the data model relationship guide. Observable `related-to` malware is the correct pattern. |
| `malware --uses--> infrastructure` relationships | Removed with infrastructure entities. |
| `network-traffic` with `dst_ref` | OpenCTI rejected nested single-ref objects in this version. Replaced with port-only SCO linked via SRO. |
| `TACTIC_TAG_MAP` and `TECHNIQUE_TAG_MAP` config constants | Dead code once tactic/technique processing was removed. |
| `indicator_id`, `infrastructure_id`, `attack_pattern_id` UUID generators | Removed with their corresponding object types. |
| `identity_class: "individual"` for reporter identities | Incorrect — reporters are organizations or handles, not natural persons. |
| Duplicate SRO generation | The original `_add_relationship` appended unconditionally. The refactored version deduplicates by (source, type, target) triple. |
| Hardcoded tokens and private IPs in `test_push.py` | File removed entirely before GitHub publication. |
| `HANDOFF_INSTRUCTIONS.md`, `BUILD_SPEC.md`, `LOCAL_TESTING_GUIDE.md` | Deployment-specific and stale; removed before GitHub publication. |

### Added

| Component | Purpose |
|---|---|
| Report container creation via `api.report.create()` | Bundle-based report creation was unreliable for large `object_refs` lists. Switched to direct synchronous API call. |
| `object_refs` population via `add_stix_object_or_stix_relationship()` | Explicit per-object membership in the Report container. |
| State management via `helper.get_state()` / `helper.set_state()` | Persists `last_run` timestamp to compute delta-based lookback windows. |
| Delta-based fetch window | Subsequent runs fetch only days since last run (+1 boundary guard), capped at 7. Prevents redundant full pulls every run. |
| `network-traffic` SCO (port-only) | Preserves port context from `ip:port` IOCs without the rejected `dst_ref` pattern. |
| `report_id()` UUID generator | Deterministic report ID keyed on date for idempotent same-day re-runs. |
| Internal ID resolution for `createdBy` and `objectMarking` | `pycti 6.9.13` `report.create()` requires internal platform UUIDs for these fields, not STIX IDs. Resolved via API lookup on each run. |
| `ANONYMOUS_REPORTERS` exclusion set | Prevents creation of analytically worthless identity entities for anonymous or unknown reporters. |
| `THREATFOX_MAX_DAYS = 7` | Corrects the original `30` — the ThreatFox API hard-caps `get_iocs` at 7 days. |
| `pycti==6.9.13` version pin | Original `pycti>=6.4.0` pulled a newer version that queried a `jwks` field not present in the instance's schema, causing `GRAPHQL_VALIDATION_FAILED`. |
| `libmagic1` system dependency in Dockerfile | Required by `pycti` via `python-magic`; absent from `python:3.11-slim`. |
| `build_mitre_cache.py` | Standalone script to regenerate `data/mitre_attack_software.json` from the MITRE ATT&CK STIX dataset. Replaces the original static file that shipped with the zip. |

### Modified

| Component | Change |
|---|---|
| `identity_class` for reporter identities | Changed from `"individual"` to `"organization"` |
| `identity_class` for `[C]ThreatFox` connector identity | Changed from `"system"` to `"organization"` for consistency with other connector identities in the stack |
| `TagProcessor` | Reduced from five categories (ASN, TACTIC, TECHNIQUE, MITRE_SOFTWARE, SKIP) to three (ASN, MITRE_SOFTWARE, SKIP) |
| `StixConverter` | Removed indicator, infrastructure, attack-pattern registries and all associated creation methods |
| `config.py` | Removed tactic/technique tag maps; added `ANONYMOUS_REPORTERS`, `CTHREATFOX_IDENTITY_ID`, `CTHREATFOX_IDENTITY_NAME`; corrected `THREATFOX_MAX_DAYS`; removed hardcoded token default |
| `docker-compose.yml` | Made fully generic — all values via env vars, no hardcoded credentials |

---

## Known Gaps

| Gap | Notes |
|---|---|
| `network-traffic` lacks `dst_ref` | STIX 2.1 specifies that network-traffic objects should reference IPs via `src_ref`/`dst_ref`. Current implementation uses a `related-to` SRO instead due to an OpenCTI validation constraint. |
| Report population is serial | ~3,300 individual API calls per run to populate `object_refs`. Functional but slow (~2–3 minutes). A bulk add method would significantly reduce this. |
| IPv6 not supported | `ipv6-addr` IOCs from ThreatFox are silently skipped. |
| No historical backfill | The API is capped at 7 days. Full historical ingestion requires a separate process against the ThreatFox bulk export. |
| MITRE cache is static | Built at image build time. Must rebuild the image to pick up new ATT&CK releases. |
| Test suite is absent | The original tests targeted the pre-refactor model and were not carried forward. |
| Reporter identity quality | Long tail of low-value community handles will accumulate as identity entities over time. No minimum submission threshold is currently enforced. |
