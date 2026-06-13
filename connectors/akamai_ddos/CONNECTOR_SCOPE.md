# Akamai DDoS Connector — Scope

Status: **scoped, scaffolding**. Authoritative design reference for `connectors/akamai_ddos/`.
All STIX output conforms to `data_model/` (the source of truth): the relationship allow-list
(`Data_Model_Relationship_Guide5.csv`) and the CTI Ingestion Manual.

## 1. Purpose & type

Pull Akamai DDoS telemetry into OpenCTI as **first-hand internal observation**.

- Connector type: **EXTERNAL_IMPORT** (scheduled poll), using the `pycti` `OpenCTIConnectorHelper`.
- Two ingestion paths in one connector, each independently toggleable:
  - **Prolexic Analytics API** — network-layer (L3/L4) DDoS attack reports.
  - **SIEM Integration API** — application-layer (L7) DoS / rate-control / Slow-POST events.
- Auth: **Akamai EdgeGrid** (`edgegrid-python`) — client_token, client_secret, access_token, host.

## 2. Why Incident Response (not Report)

The CTI Ingestion Manual splits containers by epistemology: *Report = "what the world says"*
(third-party assertion); *Incident Response = "what we saw"* (first-hand detection). Akamai is our
edge sensor detecting attacks against our own assets — first-hand. Therefore:

- Container = **Incident Response**, **one per attack episode** (decision A).
- **Sightings are legal only inside Incident Response** (Manual §3.4m) — required, since source IPs
  hitting our systems are Sightings.
- Default marking **TLP:AMBER+STRICT** (internal detection telemetry).
- **No manually-created Indicators** (Manual §1.2). We emit Observables; OpenCTI auto-promotes.

## 3. Source API reference

### Prolexic Analytics (L3/L4) — base path `/prolexic-analytics/v2`
| Op | Method | Path |
|---|---|---|
| List attack reports | GET | `/attack-reports/contract/{contract}/start/{start}/end/{end}` |
| Get attack report | GET | `/attack-report/contract/{contract}/attack-id/{attackId}` |
| List events | GET | `/events/contract/{contract}` |
| List critical events | GET | `/critical-events/contract/{contract}` |
| Time-series / metrics | GET/POST | `/time-series-data`, `/metrics` |

Confirmed `attack-reports` item shape (OpenAPI + `tests/fixtures/attack-reports-get.json`):
`attackId` int, `destinationPort` str|null, `eventStartTime`/`eventEndTime`/`startTime`/`endTime`
epoch-seconds-UTC, `eventTypes` [str] (vectors), `peaks` [{`location`, `peakId`, `bandwidth` bps,
`pps`}], `destinations` [{`netmask`, `ip`}], `ticketId`, `eventId`.

> 🔴 **Confirmed finding — Prolexic carries NO attacker source IPs.** `ip`/`destinations[].ip` are the
> **target** (victim). Source top-talkers exist only in `/events` (`eventInfo.topSourceIPs`, ~3 entries,
> human-formatted strings) under a **different, non-correlatable** `attackId` namespace, and are
> typically spoofed (L3/L4). ⇒ **Decision B (top-1000 source IPs) effectively applies to SIEM only.**
> Prolexic Incidents = vectors + ports + target + peaks, with source IPs only if `/events` enrichment
> is explicitly enabled (open item #1).

### SIEM Integration (L7) — `GET /siem/v1/configs/{configId}`
NDJSON stream; incremental via the `offset` token — the **last line is an offset-context object, not an
event** (store its `offset` per configId); first run uses `from`/`to`. Confirmed shape (OpenAPI +
`tests/fixtures/siem-event-200.json`): `attackData.{clientIP, configId, policyId, appliedAction, rules,
ruleActions, ruleMessages, ruleTags, ruleData, ruleSelectors, ruleVersions, slowPostAction(W|A),
slowPostRate}`, `httpMessage.{host, method, path, port(80|443), protocol, query, start(epoch), requestId,
status, bytes}`, `geo.{asn, country, city, regionCode, continent}`.

> The `rule*` facets are **URL-encoded, `;`-separated, base64 per element**. Decode = `unquote` → split
> `;` → base64. Verified: `ruleTags` → `OWASP_CRS/WEB_ATTACK/FILE_INJECTION`…, `ruleActions` →
> `alert;alert;deny`. `clientIP` is a **real** per-request source IP (decision E keeps them all).

## 4. Normalized intermediate model (`AttackEvent`)

Both pollers emit the same `AttackEvent` so the STIX builder is source-agnostic:

```
AttackEvent
  source_system   "prolexic" | "siem"
  attack_id       str                      # stable per-attack id from the source
  start_time      datetime  (source time)  # → Incident.first_seen + Sighting.first_seen
  end_time        datetime  (source time)  # → Incident.last_seen  + Sighting.last_seen
  vectors         [str]                     # raw vector / ruleTag strings
  is_ddos         bool                      # gate (decision D)
  protocols       [str]
  dest_ports      [int]                     # → one Network-Traffic per port (single-port rule)
  target_hostnames[str]                     # → System per hostname (decision C)
  target_ips      [str]                     # destination/victim IPs or prefixes
  peak_bps        int | None                # → Incident description / Note (NOT Network-Traffic)
  peak_pps        int | None
  source_ips      [SourceIp]                # top 1000 (decision B); spoofed kept (decision E)
  url_paths       [str]                     # L7 only → URL observable
  mitigation      str | None               # scrubbing / action taken → Incident desc / Note
  ticket_id       str | None
  raw             dict                      # original payload for provenance

SourceIp { ip, version(4|6), asn, asn_name, country_iso, volume }
```

## 5. STIX output per AttackEvent

Container: **Incident Response** (`x_opencti_case` / `case-incident`), createdBy = Akamai Organization,
marking TLP:AMBER+STRICT, name + description summarizing the attack. Members:

| Object | Source of values | Notes |
|---|---|---|
| **Incident** | attack_id, times, vectors, peak bps/pps, mitigation, ticket | `incident_type=ddos`; first/last_seen = source times |
| **Attack Pattern** | `mitre_map(vectors)` | only if `is_ddos`; DDoS technique family |
| **Network-Traffic** ×N | one per `dest_ports` entry | **single port only** — no protocol/refs/bps/pps |
| **System** ×N | `target_hostnames` | one per hostname |
| **Organization** (target) | `AKAMAI_TARGET_ORG_NAME` | the asset owner |
| **Organization** (author) | "Akamai" | createdBy |
| **IPv4/IPv6-Addr** ×≤1000 | `source_ips` | provenance-only description |
| **Autonomous System** | `source_ips[].asn` | dedup |
| **Country** | `source_ips[].country_iso` | **lookup-only, never create** |
| **Domain-Name / URL** | L7 host + `url_paths` | L7 only |
| **Note** | source geo/ASN distribution beyond top-1000; assessment of inferred claims | Manual §3.4l |
| **Sighting** ×≤1000 | each source IP on the target System | first/last_seen mandatory |

### Relationships — every edge validated against the allow-list
| Edge | Row |
|---|---|
| Incident → uses → Attack Pattern | 76 |
| Network-Traffic → related-to → Incident | 78 |
| IPv4 → related-to → Network-Traffic *(only when source ties IP↔port; avoid cross-product)* | 77 |
| IPv4 → belongs-to → Autonomous System | 30 |
| IPv4 → located-at → Country | 74 |
| Autonomous System → related-to → Organization | 2 |
| System → belongs-to → Organization | 53 |
| URL → related-to → Domain-Name | 80 |
| URL → related-to → IPv4-Addr | 79 |
| (optional) Incident → originates-from → Country | 72 |
| **Sighting**: Observable Sighted at/on System | 42 |

**No `Incident → targets → System/Organization` edge exists** in the allow-list — victim linkage is
carried by container membership + Sightings (matches the Manual's Sighting-target model). Every
relationship gets a description + confidence + start/stop dates.

## 6. Scheduling, state, lifecycle
- `helper.schedule_iso` / `CONNECTOR_DURATION_PERIOD` (no hand-rolled `while/sleep`).
- `helper.set_state` / `get_state`: `{ "prolexic": {"last_end": iso, "seen_attack_ids": [...]},
  "siem": { "<configId>": "<offset>" } }`.
- `helper.api.work.initiate_work` / `to_processed` per run.
- Dedup: deterministic STIX ids (`Incident.generate_id`, etc.) + state.
- Decision F: first run backfills `AKAMAI_INITIAL_LOOKBACK_DAYS` (default 7), then incremental.
- Bundle chunking: with up to 1000 IPs (+ASN/Country/Sighting) per attack, `send_stix2_bundle`
  in chunks.

## 7. Configuration keys
```
OPENCTI_URL, OPENCTI_TOKEN
CONNECTOR_ID, CONNECTOR_NAME=Akamai DDoS, CONNECTOR_SCOPE=incident,
CONNECTOR_DURATION_PERIOD=PT1H, CONNECTOR_LOG_LEVEL=info

AKAMAI_EDGERC_PATH                 # or the 4 discrete EdgeGrid values below
AKAMAI_HOST, AKAMAI_CLIENT_TOKEN, AKAMAI_CLIENT_SECRET, AKAMAI_ACCESS_TOKEN

AKAMAI_PROLEXIC_ENABLED=true, AKAMAI_PROLEXIC_CONTRACT=
AKAMAI_SIEM_ENABLED=true, AKAMAI_SIEM_CONFIG_IDS=         # comma-separated
AKAMAI_SIEM_DDOS_RULE_TAGS=                                # tags that count as DDoS

AKAMAI_INITIAL_LOOKBACK_DAYS=7
AKAMAI_SOURCE_IP_TOP_N=1000
AKAMAI_TARGET_ORG_NAME=                                    # asset owner Organization
AKAMAI_TLP=TLP:AMBER+STRICT
AKAMAI_CONFIDENCE=80
```

## 8. Open items (field names now CONFIRMED against OpenAPI + fixtures)

Field schemas are settled; the remaining items are modeling decisions surfaced by the findings:

1. **Prolexic source IPs** — RESOLVED: accept **source-less Prolexic Incidents** (vectors + ports +
   target + peaks). No `/events` scraping. Source observables come only from the SIEM L7 path.
2. **Prolexic target asset** — RESOLVED: **System per target prefix** (`ip`+`netmask`, e.g.
   `192.0.2.148/32`), each `belongs-to` the configured target Organization — mirrors SIEM's
   System-per-hostname.
3. **SIEM DDoS classifier** — default: `slowPostAction` present OR a decoded `ruleTag` containing
   DOS/DDOS/RATE/FLOOD/SLOW_POST (override via `AKAMAI_SIEM_DDOS_RULE_TAGS`). Tune to your rule set.

Implemented & validated against fixtures: both normalizers (`prolexic._normalize`,
`siem._aggregate` + `decode_facet`). Remaining to build: `stix_builder.build` (gated on #1/#2).
