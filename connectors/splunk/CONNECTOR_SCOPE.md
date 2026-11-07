# Splunk connector: scope and decisions

Scoped 2026-10-27.

## Scope

- **Direction:** Splunk → OpenCTI only (internal data source). Pushing OpenCTI intel
  into Splunk is out of scope.
- **Deployment:** self-hosted Splunk, REST management API (8089).
- **Sources:** fully operator-defined. Any SPL query or saved search, each with its
  own field map, in `searches.yml`. Nothing about a particular index, app, or ES is
  hard-coded.

## Modelling (internal observation)

Same pattern as `akamai_ddos` and `twinwave`:

- Container = **Incident Response** (`case-incident`), one per case (row group).
- **Incident** SDO inside it; `incident_type` and `severity` from the search entry.
- **Sightings** of each observable on the asset **System(s)** named in the rows that
  carry it, else on the `Splunk` sensor System, with that pairing's own count and times. Sightings only exist inside Incident Response.
- **System → Organization** for asset ownership.
- **Attack Patterns** are looked up by MITRE ID, never created.
- No Indicators, no Labels, single-port Network-Traffic, TLP:AMBER+STRICT fail-closed.

## Relationship verbs

Checked against the repo-root `Data_Model_Acceptable_Relationships.csv` (380 rows).

| Edge | CSV | Emitted as |
|---|---|---|
| incident → attack-pattern | `incident,uses,attack-pattern` | `uses` |
| observable → system | not listed | `related-to` + description (manual §3.4k escape hatch; also satisfies the observable→Identity floor) |
| network-traffic → incident | not listed | `related-to` + description |
| system → organization | not listed (the older Guide5 had `belongs-to`) | `related-to` + description |
| observable sighted on system | not listed (the CSV's only sighting row is `indicator,sighted-at-on,organization`) | STIX Sighting, per the manual's rule that a sighting target is a System, Individual or Organization (§3.4m), as in `akamai_ddos` |

The current CSV has no rows for `system` as a source or for `network-traffic` at all.
If `system,belongs-to,organization` is added back, switch that edge to `belongs-to`
by adding it to `ALLOWED_EDGES` in `src/stix_builder.py`.

## Not yet verified against a live platform

- pycti 6.9.13 `attack_pattern.read` filter key `x_mitre_id` and
  `marking_definition.read` key `definition` (same keys `akamai_ddos` uses, also
  unverified live there).
- `case-incident` `severity` accepted on import.
- Rolling mode re-sends activity relationships and Sightings with a growing
  `stop_time` / `last_seen`. This relies on OpenCTI's relationship deduplication
  (`relations_deduplication`, same endpoints within +/-30 days by default) merging them
  into the existing ones. Case and Incident ids are pinned in state, so those never
  duplicate. Note ids hash the SPL, so editing a search adds a second Note on purpose.
- Splunk REST behaviour is covered by mocked tests only: `index_earliest` /
  `index_latest`, `max_count`, the `f` field projection on the v2 results endpoint, and
  `resultCount` for non-transforming searches, and the job fields used to detect
  partial results (`isFinalized`, `isZombie`, the `messages` list and its wording).

## Review log

Twelve review passes (ten independent). Fixed: sighting id argument type,
`max_results` silently dropping rows (now splits windows), unbounded `_time` in index
mode, title-derived case-id collisions and row-order dependence, rolling-mode case /
Note duplication, object cap ignoring Systems and technique links, missing
`max_count`, downloading truncated jobs, `stop_time == start_time`, fail-open marking,
retried job-creating POSTs, punycode TLDs, unbounded settings, disabled searches losing
their cursor, rows lost to `maxresultrows`. Pass 4 (second independent review): case
identity re-keyed when earlier rows joined a rolling group (now pinned via `created`),
placeholder asset values becoming Systems, cursor moving backwards, untimed rolling
cases re-sent every run, Sightings falling back to the sensor when the cap dropped
every asset, empty YAML sections crashing config, quoted `enabled: "false"` read as
true, Sightings missing a description. `build()` split into step methods; rolling state
moved to `cases.RollingCases`. Pass 5 (third independent review): Sightings were a
cross-product of a group's assets and observables, recording sightings that never
happened (now per row, with per-pairing counts and times); oversized cursor searches
stalled forever (now import the complete part and resume); partial Splunk jobs were
accepted as complete; placeholders counted as invalid; rolling cases never gained
late-loading technique links; multivalue group columns could merge cases; many assets
could crowd every observable out of the object cap. Pass 6 (fourth independent review):
rolling pins lost after one empty run or a partial send, `lookback` without `group_by`
minting cases, job timeouts growing the window forever, transient lookup errors losing
technique links, blank YAML keys becoming the string `None`, row order changing
fingerprints, case-variant asset names. Added an end-to-end test through the real
builder and pycti's splitter. Pass 7 (fifth independent review): columns named like a
template built-in were never fetched (broke `stats`-based searches); a slow backlog
still stalled because each run restarted at the full window (now remembers the size
that worked in `span`). Pass 8 (sixth independent review): HTTP 204 on a status poll,
a job error discarding finished parts, `span` inflating during outages, bad time values
failing a search. Pass 9 (seventh independent review): a `span` shrunk by an outage froze
and the search fell behind forever (now doubles after any run with no failed jobs; rolling
span has a floor of window/32). Pass 10 (eighth independent review; cursor mode clean over
12 seeds x 200 simulated runs): the 5,000 cap evicted groups still being returned, splitting
them into new cases (now caps only groups no longer returned); a rolling `span` re-failed
every other run (now probes larger sizes every 16 clean runs). Pass 11 (ninth independent
review; no rows lost over 6 seeds x 300 cursor and 6 x 400 rolling runs): rolling severity
dropping when a critical row aged out, a long send outage dropping pins of live groups.
Pass 12 (tenth independent review): no functional defects; 4 seeds x 250 cursor and 4 x 300
rolling runs lost no rows and split no cases. Doc fixes and test gaps closed. Kept as is: one bundle per case (house pattern, and what
lets a failed send lose only that case); the timeout/success alternation when a full
normal window outruns `SPLUNK_JOB_TIMEOUT` (no rows lost, fixed by raising the timeout).
Split `searches.py` into `searches.py`,
`observables.py`, `cases.py`; OpenCTI lookups moved to `opencti_lookup.py`.
