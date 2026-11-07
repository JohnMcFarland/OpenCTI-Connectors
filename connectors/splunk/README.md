# Splunk connector

An internal data source connector: runs SPL searches you define against a
self-hosted Splunk deployment and imports what Splunk saw into OpenCTI as
**Incident Response** cases with **Sightings**.

Type: `EXTERNAL_IMPORT` (scheduled poll). Direction: Splunk → OpenCTI only.

## What it produces

For each **case** (a group of result rows, see `group_by`):

| Object | Notes |
|---|---|
| Incident Response (`case-incident`) | Container; holds everything below. Severity from `severity_field`: the highest across the group's rows. |
| Incident | Name/description from templates; `first_seen`/`last_seen` = min/max row time. |
| Observables | From the `observables` field map. Validated per type; bad values are rejected and counted. |
| System(s) | One per value in `system_fields` (the asset). Related to the owning Organization. |
| Sightings | Each observable on the asset System(s) named in the rows that carry it, or on the `Splunk` System when those rows name no asset. A group's assets are never crossed with its observables. `count`, `first_seen` and `last_seen` are that pairing's own. |
| Attack Pattern links | `Incident uses Attack Pattern` for MITRE IDs found in `attack_pattern_fields`. Existing Attack Patterns only; unknown IDs are listed in the container description. If the OpenCTI lookup itself errors, the search fails and retries. |
| Note | Provenance: search name, app, time mode, group, SPL. Stays the same as a case grows; editing the search adds a second Note recording the new SPL. |
| Container description | The case description plus import details: row count, window, rejected values, unknown MITRE IDs, anything truncated by the object cap. |

Data model rules applied (repo `Data_Model_Acceptable_Relationships.csv` + CTI
Ingestion Manual): no Indicators, no Labels, Sightings only inside Incident Response,
Network-Traffic = one port only, every observable `related-to` an Identity, verbs
not on the allow-list fall back to `related-to` with a description, TLP:AMBER+STRICT
by default (startup fails if the marking can't be resolved).

## Defining searches

All sources live in `searches.yml` (mounted into the container). Start from
[searches.yml.sample](searches.yml.sample), which documents every key. Minimal entry:

```yaml
searches:
  - name: Proxy blocks
    spl: index=proxy action=blocked | table _time src_ip dest url user
    group_by: src_ip
    system_fields: src_ip
    observables:
      url: url
      user: user-account
```

Only the columns the entry references are fetched from Splunk, so a search that
forgets `table` does not ship `_raw`. In templates the built-ins (`{count}`,
`{first_seen}`, ...) win over a column of the same name, unless that column is in
`group_by`, which wins so that a title built from it tells groups apart. Ending the SPL with `table` is still faster.

The case title (plus its first event time) is the case id in OpenCTI. If the `title`
template does not include `{group}` or every `group_by` column, ` ({group})` is
appended so two groups can never merge. `{count}` and `{last_seen}` are refused in
titles because they change as the case grows; use them in `description`. OpenCTI
ignores letter case when it compares names, so two groups whose keys differ only in
case (`Alice` vs `alice`) land in the same case.

Omitting `group_by` makes every row its own Incident Response case. That suits
notables and alerts; for raw event searches, group (or `stats`) first, or a busy
window becomes thousands of cases.

### Windows and state

- **Cursor (default).** Each run searches `[last cursor, now - SPLUNK_INGEST_LAG_SECONDS)`.
  Windows never overlap, so a group whose rows span two runs becomes two cases. The
  cursor only moves forward.
  `time_mode: index` (default) windows on `_indextime`, so events indexed late are not
  skipped. `_time` is still bounded to the window +/- `SPLUNK_INDEX_TIME_SKEW_SECONDS`
  (default 1 day) so Splunk does not scan every bucket; events whose `_time` is further
  off than that are missed. Splitting a window narrows `_indextime` only: every part still
  scans at least twice the skew of `_time`, so if split jobs on a busy index keep timing
  out, lower the skew. `time_mode: event` windows on `_time`.
- **Rolling (`lookback: -7d`).** Each run re-searches the same relative window. Use for
  data that changes after it is indexed, such as ES notables that are dispositioned
  later. Each group keeps the title, start time and highest severity it has been sent
  with, so it updates the same case even after its oldest rows leave the window (row
  counts in the description cover the current window only). Unchanged cases
  are not re-sent. A group is remembered until a full window has passed since it last
  appeared. Groups still in the results are always kept; of those no longer returned, at
  most 5,000 per search are. Past 5,000 live groups a warning is logged, because state
  keeps growing (roughly 150-350 KB per 1,000). Requires `group_by`, which is how a case is
  recognised from run to run.
- A failing search keeps its cursor and is retried next run. Other searches still run.
- Ids are deterministic, so re-sent cases update rather than duplicate.
- Renaming a search starts a new cursor (from `SPLUNK_INITIAL_LOOKBACK`).
- `max_results` caps rows per Splunk job. A window that hits it, or that outruns
  `SPLUNK_JOB_TIMEOUT`, is split in half and re-run until every part fits, so no rows are
  dropped. A search gets 32 jobs and 3 timeouts per run. A cursor search that runs out
  imports the complete, oldest part and resumes there next run (a group crossing that
  boundary becomes two cases). The connector remembers the window size that worked, so
  even a run that finished nothing makes the next one smaller and a backlog drains
  instead of stalling; the size doubles after each run with no failed jobs, so it recovers
  within a few runs of an outage ending. A cursor search whose whole normal window cannot
  finish inside `SPLUNK_JOB_TIMEOUT` alternates a timeout with a success, which loses
  nothing but wastes a timeout every other run: raise the timeout. A rolling window never
  shrinks, so it tries a larger size only every 16 clean runs (about 4 hours at the
  default schedule). A try that is too large fails that one run, shown as an error in
  OpenCTI; nothing is lost and the next run picks the same cases up. Any other job
  error also keeps the parts already finished. Searches run one after another, so a slow
  backlog delays the searches after it: a run is limited by the 32 jobs, not by a clock.
  A rolling search that does not fit in the budget fails, as does any run whose first
  part does not fit (one second over the cap, or SPL that ignores time bounds such as
  `inputlookup`, never will); both keep their cursor and show as errors in OpenCTI.
- A job Splunk stopped early or that reports incomplete results (for example a search
  peer was down) counts as failed, so its window is retried rather than skipped.
- `lookback` and `SPLUNK_INITIAL_LOOKBACK` take `-<n><s|m|h|d|w>` (e.g. `-24h`, `-7d`);
  snapping like `@d` is not supported.

## Splunk prerequisites

- Management port (default **8089**) reachable from the connector container.
- A service account with a role that can search the indexes used, and an
  **authentication token** for it (Settings → Tokens). Basic auth also works.
- Privately-signed cert: mount your CA PEM and set `SPLUNK_CA_BUNDLE`. Avoid
  `SPLUNK_VERIFY_SSL=false` outside testing.
- Splunk older than 9.0.1: set `SPLUNK_RESULTS_API=v1`.

## Configuration

Env vars take precedence over `config.yml` (see [config.yml.sample](config.yml.sample)).

| Variable | Default | |
|---|---|---|
| `SPLUNK_BASE_URL` | required | e.g. `https://splunk.corp:8089` |
| `SPLUNK_TOKEN` | | Bearer token (preferred) |
| `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` | | Basic auth fallback |
| `SPLUNK_VERIFY_SSL` | `true` | |
| `SPLUNK_CA_BUNDLE` | | CA PEM path; overrides `VERIFY_SSL` |
| `SPLUNK_OWNER` | `nobody` | `servicesNS` owner for jobs |
| `SPLUNK_RESULTS_API` | `v2` | `v1` for Splunk < 9.0.1 |
| `SPLUNK_REQUEST_TIMEOUT` | `60` | Seconds per HTTP request to Splunk |
| `SPLUNK_JOB_TIMEOUT` | `900` | Seconds one search may run |
| `SPLUNK_PAGE_SIZE` | `10000` | Result rows per request |
| `SPLUNK_SEARCHES_FILE` | `searches.yml` | |
| `SPLUNK_INITIAL_LOOKBACK` | `-24h` | First-run window |
| `SPLUNK_INGEST_LAG_SECONDS` | `300` | Newest data left for the next run |
| `SPLUNK_INDEX_TIME_SKEW_SECONDS` | `86400` | `_time` slack around the window in index mode |
| `SPLUNK_MAX_OBJECTS_PER_CASE` | `2000` | Beyond this, the least-seen observables and Sightings, then leftover Systems, are dropped; technique links count too (all reported in the case) |
| `SPLUNK_ORGANIZATION_NAME` | required | Organization owning the monitored assets |
| `SPLUNK_AUTHOR_NAME` | `Splunk` | `created_by` Organization |
| `SPLUNK_SENSOR_SYSTEM_NAME` | `Splunk` | Fallback Sighting target |
| `SPLUNK_TLP` | `TLP:AMBER+STRICT` | |
| `SPLUNK_CONFIDENCE` | `75` | |

## Run

```bash
cp searches.yml.sample searches.yml
docker compose up -d --build
```

## Tests

```bash
python -m pytest tests
```

Run from this folder. The builder and connector tests need `pycti` installed.
