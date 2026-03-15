# ThreatFox Connector — Scope, Design Philosophy, and Data Model

## Purpose

This document describes the functional scope, design decisions, data model alignment, and known gaps of the ThreatFox OpenCTI connector. It is intended for CTI practitioners and platform administrators who need to understand what the connector produces, why it is structured the way it is, and where its limitations lie.

---

## Functional Scope

The connector ingests recent IOC data from the ThreatFox API (abuse.ch) and converts it into a structured STIX 2.1 representation within OpenCTI. It operates as an automated, non-destructive, idempotent external import pipeline.

### In scope

- Conversion of all ThreatFox IOC types: `domain`, `ip:port`, `url`, `sha256_hash`, `sha1_hash`, `md5_hash`
- Creation of malware family entities from `malware_printable` and MITRE ATT&CK software tags
- Creation of reporter identity entities from the ThreatFox `reporter` field
- Creation of autonomous system entities from ASN tags
- Creation of port-only network-traffic SCOs for `ip:port` IOCs
- Report container creation per calendar day, authored by `[C]ThreatFox`
- Stateful incremental polling with delta-based lookback
- Cross-feed observable deduplication via STIX-standard deterministic UUIDs

### Out of scope (by design)

- **Indicator creation**: OpenCTI generates Indicators automatically from Observables via its inference engine. Manual Indicator creation bypasses this pipeline and violates the platform's detection workflow. The connector produces no Indicator SDOs.
- **Infrastructure entities**: ThreatFox does not provide named, bounded infrastructure clusters. Collapsing all C2 IPs for a malware family into a single Infrastructure entity would be analytically meaningless and would contaminate the graph with phantom relationships. IPs and domains are modeled as Observables with relationships to malware families instead.
- **Attack Pattern objects**: ThreatFox tactic and technique tags (e.g., `EXECUTION`, `C2`, `RAT`) are generic descriptors, not verifiable ATT&CK technique assertions tied to specific adversary procedures. Creating Attack Pattern objects from these tags would introduce false precision into the graph. Tags that match MITRE ATT&CK *software* entries (which are verifiable, structured references) are converted to Malware/Tool SDOs.
- **Sightings**: Sightings represent internal observations against known assets and belong in Incident Response containers. ThreatFox data is external threat intelligence and belongs in Report containers.
- **Historical data beyond 7 days**: The ThreatFox API hard-caps `get_iocs` at 7 days. Backfilling history requires a separate process against the ThreatFox bulk export endpoint, which is outside this connector's scope.

---

## Design Philosophy

### Observables over Indicators

The connector models ThreatFox IOCs as STIX Cyber Observables (SCOs) rather than Indicators. This is consistent with the OpenCTI data model, which reserves Indicators for platform-generated pattern objects with detection semantics. Treating raw IOC feed entries as Indicators conflates threat data ingestion with detection rule management.

### Strict containment

All objects produced by each run are referenced in a dated Report container (`Threat Fox Feed YYYY-MM-DD`). This ensures every observable and relationship in the graph is traceable to its source event, supports access control scoping, and enables lifecycle management by report date.

### Deterministic identity

All STIX IDs are generated via UUIDv5 with stable namespace keys. This provides:
- **Cross-feed deduplication**: An `ipv4-addr` from ThreatFox that also appears in another feed merges into a single graph node
- **Idempotency**: Re-running the connector on the same data produces no duplicates
- **Auditability**: Every object's ID is reproducible from its source data

### Conservative confidence

ThreatFox confidence scores (0–100) are multiplied by 0.8 before ingestion. ThreatFox is a community feed with variable submission quality. The 0.8x haircut prevents community-reported IOCs from anchoring at maximum confidence in the graph, preserving room for higher-confidence sources to take precedence.

### Reporter identity as organization

ThreatFox reporters are modeled as `identity_class: organization` rather than `individual`. Most reporters are handles, automated scanners, or research organizations — not natural persons. Anonymous and unknown reporters are excluded from identity creation entirely, as they provide no analytical value.

### Malware deduplication over fragmentation

When a MITRE ATT&CK software tag matches the `malware_printable` name of an existing Malware SDO (case-insensitive), the connector reuses the existing SDO and enriches it with the MITRE external reference rather than creating a second entity. This prevents the graph from accumulating duplicate malware families under slightly different names.

---

## Data Model Alignment

The connector was designed against the platform's custom relationship guide. The following relationships produced by the connector are explicitly supported:

| Relationship | Source → Target | Guide Entry |
|---|---|---|
| `related-to` | Observable → Malware | `Observable, related to, Malware` |
| `related-to` | Observable → Identity | `Observable, Related To, Intrusion Set` (analogous) |
| `belongs-to` | IPv4 → Autonomous System | `IPv4, Belongs-to, Autonomous System` |
| `related-to` | IPv4 → Network-Traffic | `Observable, Related To, ...` |
| `related-to` | Observable → MITRE Tool/Malware | `Observable, related to, Malware` |

### Identity authorship

The `[C]ThreatFox` system identity (`identity_class: organization`) is the `created_by_ref` on all Report containers. Individual reporter identities are the `created_by_ref` on their respective Observables, reflecting that the observable was submitted to ThreatFox by that reporter.

---

## Known Gaps and Future Work

### Network-traffic SCOs lack `dst_ref`

STIX 2.1 specifies that `network-traffic` objects should reference IP addresses via `src_ref` or `dst_ref`. The connector currently creates port-only `network-traffic` SCOs without `dst_ref` and links them to the `ipv4-addr` via a `related-to` SRO instead. This is a pragmatic workaround for an OpenCTI validation constraint. The correct implementation would embed `dst_ref` pointing to the `ipv4-addr` SCO directly in the `network-traffic` object, eliminating the need for the SRO.

### No IPv6 support

ThreatFox does include IPv6 IOCs. The connector currently skips any `ioc_type` it does not recognise, which includes IPv6 entries. Adding `ipv6-addr` handling mirrors the `ipv4-addr` implementation.

### Test suite is stale

The unit tests in `tests/` were written against an earlier version of the connector that produced Indicators and Infrastructure objects. They will fail against the current codebase and need to be rewritten to reflect the current data model.

### No historical backfill

The ThreatFox API returns at most 7 days of data. The connector has no mechanism to ingest the full ThreatFox dataset. Historical backfill requires a separate process using the ThreatFox CSV or MISP export endpoints.

### MITRE cache is static

The `data/mitre_attack_software.json` cache is built at image build time and does not update automatically. New MITRE ATT&CK software entries added after the image was built will not be resolved from tags. The `build_mitre_cache.py` script must be re-run and the image rebuilt to pick up new ATT&CK releases.

### Reporter identity quality

ThreatFox reporters are community-sourced handles of variable quality. Many reporters are anonymous or use single-use handles. The connector creates identity entities for all non-anonymous reporters, which means the graph will accumulate a long tail of low-value identity entities over time. A future improvement could apply a minimum submission threshold before creating a reporter identity.

### No TLP escalation

All objects are marked `TLP:CLEAR`, consistent with ThreatFox's public feed policy. The connector has no mechanism to apply higher TLP markings to specific IOC subsets.
