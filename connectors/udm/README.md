# UDM connector

OpenCTI `EXTERNAL_IMPORT` connector for a **UniFi Dream Machine Pro**. It imports the
gateway's **blocked traffic flows** and the **Security** entries of its system log (IPS
threats) as first-hand internal telemetry: daily Incident Response containers holding
Sightings of external addresses on the System they involved. **No Incident objects**
are created: one per event was ~900 a day (~330k a year) on a live UDM, too noisy.

This rebuild (v1.0.0) replaces connector-udm v0.4.2, which lived in the old top-level
`UDM/` folder (last copy at commit `4a54951`). v0.4.2 ran a search before every write,
added objects to containers one call at a time, re-read the whole flow history every
run, and re-imported (and re-counted) an 8-hour overlap, all of which loaded
Elasticsearch heavily and produced duplicate entities.

## What changed vs v0.4.2

| v0.4.2 | v1.0.0 |
|---|---|
| ~20 OpenCTI searches + ~20 API writes per flow | Zero per-object searches. Deterministic STIX ids, sent as bundles (`send_stix2_bundle`) |
| Full page scan of every blocked flow, every run | Saved cursor; paging stops at the first page older than the window |
| 8 h re-import each run, Sighting `count` re-added | 30 min overlap, already-imported records skipped. A record re-read with newer activity updates the same objects |
| "First run" guessed from container names | Real connector state (`get_state`/`set_state`), saved after every bundle |
| Systems keyed on whatever hostname was visible, so offline or renamed hosts got duplicates | System name pinned per MAC in state; offline clients come from `rest/user` |
| Page fetch errors swallowed (data silently cut short) | Every API error fails the stream; cursor kept, resumed next run |
| `UDM_TLS_VERIFY=false` parsed as a truthy string; `interval: 86400` vs ISO duration | pydantic-parsed booleans; ISO 8601 `CONNECTOR_DURATION_PERIOD` |
| Internal / WAN IPs as IPv4 observables (candidate Indicators for your own hosts) | Only globally routable, non-WAN addresses become observables. Internal hosts are Systems |
| Countries and Software created on demand; OUI vendor Organizations; MAC observables | Countries and CVEs looked up, never created. Vendor and MAC go in the System description |
| One Incident SDO per flow | No Incidents; the event's details live on its Sighting |

## Graph shape

Per UTC day and stream, one **Incident Response** (`case-incident`):
`UDM Blocked Flows`, `UDM Security Events`, `UDM Admin Access` and `UDM Inventory`,
each suffixed `— YYYY-MM-DD`.

Per UDM event **that has an external address** (events without one, such as
internal-to-internal or internal-to-gateway blocks and honeypot hits, are not imported):

| Object | Notes |
|---|---|
| Sighting | External IP sighted on the System, with UniFi's count and times. Its description is the full event: policy, type, severity, signature, IPS rule set (flagging the reputation lists `ciarmy`, `dshield` and `compromised`), service (SSH, HTTPS, ...), zone/network of each side, CVE, bytes, the port-forward it hit if any, and the UniFi record id. Id keyed on the UniFi record, so a re-read updates it; one per event |
| IPv4/IPv6-Addr | The external side only. No description, no labels |
| Network-Traffic | The destination port, single `dst_port` only (house rule) |
| System | Internal host (name pinned per MAC), a UniFi device under its UniFi name, or the gateway `UDM-WAN` (traffic to the WAN address; the UDM's own MAC) |

| Edge | Verb | Basis |
|---|---|---|
| IPv4 → Country | `located-at` | listed in `Data_Model_Acceptable_Relationships.csv` |
| IPv6 → Country | `related-to` | not listed (escape hatch, with description) |
| IP → Port (Network-Traffic) | `related-to` | escape hatch; the protocol (TCP/UDP) is text in this edge's description, never an object. A Sighting can't target a port (STIX `where_sighted_refs` must be an identity or location) |
| Port → System | `related-to` | escape hatch |
| IP → existing Vulnerability (signature CVE) | `related-to` | escape hatch; looked up by name, never created. The CVE is signature metadata (what the rule detects), not proof the target was vulnerable |
| IP → System | `related-to` | observable → Identity floor |
| Port → port-forward target System | `related-to` | escape hatch; "exposed to the internet by port forward 'X'", added when traffic hits a forwarded port |
| System → Organization (`UDM_ORGANIZATION_NAME`) | `related-to` | escape hatch |
| Software (firmware) → device System | `related-to` | escape hatch; inventory only |

Relationships are structural and undated: one per pair, however many events repeat it.

No Indicators, no Labels. Marking `TLP:AMBER+STRICT` by default, resolved once at
start-up; the connector refuses to start if the marking is missing.

## Streams

**Blocked flows**: `POST /proxy/network/v2/api/site/{site}/traffic-flows` with
`action=[blocked]`. Includes firewall, IPS-signature and other blocks.

**Security events**: `POST /proxy/network/v2/api/site/{site}/system-log/all` with
`categories: ["SECURITY"]` (time-bounded and filtered server-side). The legacy
`stat/ips/event` endpoint returns 404 on current Network versions. Entries include
`THREAT_BLOCKED*` (IPS) and `HONEYPOT_HIT_DETECTED*`. `*_IP` parameters carry an
address; `*_CLIENT` / `CLIENT` parameters carry the client's MAC and display name.

By default **blocked threats are skipped** (`UDM_SECURITY_SKIP_BLOCKED=true`): each one
is already a `SIGNATURE` traffic-flow carrying more detail (signature, CVE, ports) than
the log entry. What remains is anything the gateway detected without blocking that has
an external address, e.g. threats when the IPS runs in detect-only mode. On a UDM in
prevention mode this stream imports little or nothing (honeypot hits have no external
address and are dropped).

**Admin access**: the same system log with `categories: ["AUDIT"]`, `ADMIN_ACCESS`
entries only (admin account, source IP, platform). A login from an **external** address
becomes a Sighting of that IP on `UDM-WAN`, in `UDM Admin Access — day`; logins from
inside the network are dropped. Note that a legitimate remote login (you, from a phone)
also becomes an observable of that IP. Live UDM: 148 logins in 30 days, 1 external.

**Port forwards** (`rest/portforward`, read each run): enabled rules are matched against
each event's destination (the WAN port, or the internal target after translation). A
hit adds the forward to the Sighting text and links the port to the target System.

**Inventory** (`stat/device`): each UniFi device's firmware as a Software observable
(`UniFi <model> firmware`, version, vendor Ubiquiti) related to the device's System, in
`UDM Inventory — day`. Sent on the first run and then only when a version changes
(tracked in state), so it costs nothing on a normal run.

Each stream has its own cursor. A failing stream (or inventory) is logged, marks the
work in error, and does not stop the others.

## Configuration

Env vars (or `config.yml`, see `config.yml.sample`; env wins).

| Variable | Default | |
|---|---|---|
| `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID` | required | |
| `CONNECTOR_DURATION_PERIOD` | `PT1H` | ISO 8601 |
| `UDM_HOST`, `UDM_API_KEY` | required | API key from UniFi OS → Settings → Control Plane → Integrations |
| `UDM_SITE` | `default` | |
| `UDM_VERIFY_SSL` / `UDM_CA_BUNDLE` | `false` / empty | the UDM ships a self-signed cert |
| `UDM_FLOWS_ENABLED`, `UDM_SECURITY_ENABLED` | `true` | |
| `UDM_SECURITY_SKIP_BLOCKED` | `true` | see above |
| `UDM_ADMIN_ENABLED` | `true` | external admin logins |
| `UDM_INVENTORY_ENABLED` | `true` | device firmware, on change |
| `UDM_PORT_FORWARDS_ENABLED` | `true` | port-forward matching |
| `UDM_INITIAL_LOOKBACK_DAYS` | `30` | first run only |
| `UDM_OVERLAP_MINUTES` | `30` | re-read window for late or extended records |
| `UDM_PAGE_SIZE` / `UDM_MAX_PAGES` | `500` / `200` | paging (all streams) and its safety cap |
| `UDM_WAN_IPS` | empty | fallback if the gateway in `stat/device` reports none |
| `UDM_INTERNAL_SUBNETS` | empty | extra internal ranges; all non-global space is internal already |
| `UDM_ORGANIZATION_NAME` | required | owner of the Systems |
| `UDM_AUTHOR_NAME` / `UDM_GATEWAY_NAME` | `UDM Alert` / `UDM-WAN` | kept from v0.4.2 |
| `UDM_EVENTS_PER_BUNDLE` | `200` | events per bundle (and per cursor save) |
| `UDM_TLP` / `UDM_CONFIDENCE` | `TLP:AMBER+STRICT` / `85` | |

**WAN fail-closed:** if no WAN address is known (the gateway's `wan1`/`wan2` in
`stat/device`, plus `UDM_WAN_IPS`), the run is skipped. Only gateway devices are read:
switches and APs report their own LAN address as `uplink.ip`. Otherwise inbound flows would import your own public IP as an external
observable. Every WAN address ever seen is remembered, so an ISP address change does
not turn the old one into an observable.

## Run

```bash
docker compose up -d --build connector-udm
```

Tests (no UDM or OpenCTI needed):

```bash
python -m pytest -q
```

They include a 48-run simulation against a fake UDM with a moving clock (new,
late and extended records, failures mid-run), and checks through pycti's own bundle
splitter.

## Verified against a live UDM Pro (2026-11-18, read-only)

Probed with a read-only API key and dry-run (OpenCTI faked, nothing sent):

- traffic-flows pages are **0-based** (v0.4.2 started at page 1 and skipped the
  newest 500 flows) and **newest-first by `time`**. Records have no `flow_start_time`.
- The UDM keeps only **~2 days** of flows (1,761 blocked, ~900/day), so a run at least
  daily is needed; the hourly default is fine.
- `stat/ips/event` → 404; `system-log/all` + `categories` filter works (2,035 SECURITY
  entries in 30 days: 2,034 `THREAT_BLOCKED*`, 1 honeypot hit).
- `stat/device` reported 5 "WAN" addresses, 4 of them switch uplinks (fixed: gateway only).
- Dry run (with the earlier per-event Incident model): 1,762 Incidents, 219 external
  IPv4 observables (none private, none WAN), 683 Sightings, 14 Systems, ~7.7k objects
  for two days; the second run sent nothing. Only 683 of the 1,762 events had an
  external address, and those are the ones the Sightings-only model now imports.
- Fields that look useful but are **empty or opaque on this UDM**, so not used:
  `destination.domains` (14 of 1,766 flows, mostly IPs), `client_fingerprint` (numeric
  IDs only), `ips.relevant_cve` / `description` / `signature_class` (empty on all 1,276
  signature flows: the CVE edge never fires here), `application` (numeric IDs). No VPN
  server is configured, so there are no VPN logins to read.

## Still to verify against OpenCTI

1. **Day containers accumulate.** Each bundle re-sends the day's container with only
   its own members; OpenCTI should merge them, so the container lists every Sighting.
2. **Sighting count on re-send.** A record re-read with later activity re-sends its
   Sighting (same id) with UniFi's cumulative count. Confirm OpenCTI replaces
   `count` on upsert rather than adding to it.
3. **Country lookups.** Countries are matched by ISO alias, then by English name. If
   your OpenCTI has no location dataset loaded, the edges are simply skipped.

## Known limits

- Events with no external address are not imported: on the live UDM that was ~60% of
  blocked flows (internal-to-internal and internal-to-gateway) plus honeypot hits.
- Sightings still scale with events: ~340 a day on the live UDM (~125k a year).
- `UDM_MAX_PAGES` caps a read (default 100k flows). When it is hit, the newest flows
  are imported and the work is marked in error, naming the time range that was not
  read. Raise the cap or shorten the lookback.
- Records dated more than an hour ahead of the connector's clock are skipped with a
  warning, so a bad timestamp cannot push the cursor into the future.
- A client with no UniFi alias or hostname the first time it appears is pinned as
  `Client <mac>`, and keeps that name.
