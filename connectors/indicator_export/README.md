# Indicator Export

Creates and maintains Indicators in OpenCTI, then exports them with a label for
every entity linked to the underlying observable. Replaces ObservableGate.

It is the only connector in this repository that creates Indicators from
Observables.

## What each cycle does

1. **Promote.** An Observable with a `related-to` Attack Pattern gets a scored
   Indicator, with `based-on` and `indicates` relationships. No Attack Pattern
   means no Indicator, however strong its other links are.
2. **Reconcile.** Existing Indicators get their score, types, markings and
   `indicates` edges synced, so scores follow the graph up and down. If the
   Observable stops qualifying, the Indicator enters decay for
   `INDICATOR_DECAY_DAYS` and is then revoked. If it qualifies again during decay,
   it is restored.
3. **Export.** Indicators are labeled and sent to `EXPORT_LOCATION`.
4. **Group.** Indicators created or exported today are added to that day's
   Grouping.

Labels exist only on the exported copy. They are never written to OpenCTI, where
labels are reserved for collection requirements.

## Scoring

The score follows the Diamond Model. Every Indicator already has infrastructure
(the Observable) and capability (the Attack Pattern), so the score depends on the
other two vertices. Only a direct relationship to the Observable counts.

| Score | Linked to | `indicator_types` |
|---|---|---|
| 50 | Neither | `anomalous-activity` |
| 75 | An adversary or a victim | `malicious-activity` |
| 100 | An adversary and a victim | `malicious-activity` |

- **Adversary:** Malware, Intrusion Set, Threat Actor Group or Threat Actor
  Individual.
- **Victim:** Organization.

The value is written to both `x_opencti_score` and `confidence`, and both are
exported. Tools do not change the score.

## Daily Groupings

Each Eastern-time day has one Grouping named `Indicator Export YYYY-MM-DD`. The
day changes at midnight in `America/New_York`, so it follows daylight saving time.
The Grouping holds Indicators only and is marked `TLP:AMBER+STRICT`.

An Indicator joins on the day it is created and on any day it is exported:

- With `debug`, every snapshot exports every Indicator, so each day's Grouping
  holds the full set, revoked Indicators included.
- With an IP address, only changed Indicators are exported, so each day's Grouping
  holds that day's new and changed Indicators.

A failed add is retried next cycle into its original day. Dry run creates no
Grouping.

## Choosing the export location

Set `EXPORT_LOCATION` in `docker-compose.override.yml`. See
`docker-compose.override.yml.sample` for the block to add.

| Value | Behavior |
|---|---|
| `debug` | Writes a full CSV snapshot to `./data` each cycle. |
| An IPv4 or IPv6 address | POSTs STIX 2.1 bundles to that address. |
| Anything else | Stops the connector at startup. Hostnames are rejected. |

### debug

Files are named `indicators_<UTC time>.csv`, and the newest
`EXPORT_CSV_RETENTION` are kept. Each one has a row per Indicator, including
revoked ones. Cells that a spreadsheet would run as a formula get a leading `'`,
except `pattern`, which must stay exact and always starts with `[`.

`status` is `would_create`, `active`, `decaying` or `revoked`. `labels_dropped`
counts what the filters removed by reason (`marking`, `excluded_type`, `limit`,
`unnamed`), without naming the entities.

A CSV cannot enforce markings, so handle `./data` as the most restricted data it
holds, which can include `TLP:RED`.

### IP address

The target is `EXPORT_SCHEME://EXPORT_LOCATION:EXPORT_PORT/EXPORT_PATH`, sent as
`application/stix+json;version=2.1`, in batches of `EXPORT_BATCH_SIZE`.

- Only changed Indicators are sent, including a change to labels alone.
- `modified` is the send time, so consumers accept a label-only update.
- An Indicator counts as sent only after a 2xx response. Otherwise it is sent
  again next cycle.
- Redirects are refused, so data cannot leave the configured address.
- TLS certificates must list the IP. Set `EXPORT_VERIFY_TLS` to a CA bundle path
  under `/data` if yours is private.

## Label rules

Labels look like `intrusion-set:APT29`. Relationships are read in both
directions, one hop from the observable. Observables, Indicators and containers
never become labels.

| Rule | Default | Setting |
|---|---|---|
| Excluded entity types | System, Organization, Individual, Incident | `EXPORT_EXCLUDED_ENTITY_TYPES` |
| Blocked markings | Sensitive | `EXPORT_BLOCKED_MARKINGS` |
| Label limit per Indicator | 50 | `EXPORT_MAX_LABELS` |

- The type exclusions exist because every observable must link to an Identity,
  so "all entities" would otherwise publish internal hostnames and victims.
- Every marking can leave except blocked ones, `TLP:RED` included. Terms match
  anywhere in the definition, ignoring case, so `Sensitive` also blocks
  `Highly Sensitive`. A blank setting falls back to `Sensitive`.
- A label is dropped if the entity or the relationship has a blocked marking. A
  marking with no definition counts as blocked.
- An Indicator with a blocked marking still exists in OpenCTI and joins the
  Grouping when created, but is not exported.
- The connector logs a warning if no marking on the platform matches a term,
  which usually means a typo.
- Over the limit, adversaries are kept first, then Malware, then Attack Patterns,
  Tools and Vulnerabilities, then Infrastructure, then the rest.
- Labels starting `CR-`, `REQ-` or `COLREQ-` on the Indicator or Observable pass
  through and do not count toward the limit.

## Deployment

1. Add the override block with real values and leave `INDICATOR_DRY_RUN=true`.
2. Run one cycle, then review the CSV and the counts in the connector's work
   message: `promoted`, `collisions`, `errors` and `Blocked by marking`.
3. Set `INDICATOR_DRY_RUN=false` to create Indicators.
4. Check the lifecycle: remove an Attack Pattern link and confirm the Indicator
   becomes `decaying`, then remove an entity link and confirm its label goes.
5. Point `EXPORT_LOCATION` at the destination.

Dry run writes nothing to OpenCTI, sends nothing, and leaves connector state
unchanged apart from `last_run`. The CSV is still written, so a dry run can be reviewed.

## Settings

| Variable | Default | Description |
|---|---|---|
| `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID` | none | Required. |
| `CONNECTOR_DURATION_PERIOD` | `PT1H` | Time between cycles. |
| `INDICATOR_DRY_RUN` | `true` | Must be set to `false` to write or stream. |
| `INDICATOR_AUTHOR_NAME` | `Indicator Export` | Identity that marks Indicators as owned. **Do not change after going live**, or existing Indicators stop being maintained. |
| `INDICATOR_DECAY_DAYS` | `30` | Days from lapse to revocation. |
| `INDICATOR_MAX_ERRORS` | `50` | Errors before a cycle stops its lifecycle pass. |
| `INDICATOR_EXCLUDED_OBSERVABLE_TYPES` | empty | Added to Network-Traffic and Persona, which are always excluded. |
| `INDICATOR_EXCLUDED_LABELS` | empty | Observables with these labels are not promoted. |
| `EXPORT_LOCATION` | none | Required. `debug` or an IP address. |
| `EXPORT_BLOCKED_MARKINGS` | `Sensitive` | Comma-separated terms. Matching markings never leave. |
| `EXPORT_MAX_LABELS` | `50` | Labels per Indicator. |
| `EXPORT_EXCLUDED_ENTITY_TYPES` | `System,Organization,Individual,Incident` | Entity types that never become labels. |
| `EXPORT_DATA_DIR` | `/data` | Debug CSV files and an optional CA bundle. |
| `EXPORT_CSV_RETENTION` | `5` | CSV snapshots to keep. |
| `EXPORT_SCHEME` | `https` | `http` or `https`. |
| `EXPORT_PORT` | scheme default | Destination port. |
| `EXPORT_PATH` | `/` | Destination path. |
| `EXPORT_AUTH_TOKEN` | empty | Sent as a Bearer token if set. |
| `EXPORT_VERIFY_TLS` | `true` | `true`, `false`, or a CA bundle path. |
| `EXPORT_BATCH_SIZE` | `500` | Indicators per bundle. |
| `EXPORT_TIMEOUT_SECONDS` | `30` | Request timeout. |

## Behavior worth knowing

- **Connector state.** Decay deadlines, what the stream destination confirmed,
  and pending Grouping adds live in the connector's platform state
  (`get_state`/`set_state`), like every other connector here. Nothing is kept on
  local disk except debug CSVs. State is saved once per cycle, so a crash
  mid-cycle restarts decay windows and re-sends objects under the same STIX ids.
  The `sent` map holds one short fingerprint per exported Indicator.
- **Nothing is deleted.** When an Attack Pattern stops qualifying, this
  connector's `indicates` edge to it is revoked, and it is restored if the
  Attack Pattern qualifies again. Edges authored by anyone else are never
  touched.
- **Organization does not always mean victim.** Any direct link to an Organization
  counts, including an owner, vendor or provider.
- **Scores can show what labels hide.** Organization labels are excluded by default,
  so a 100 will not show which victim produced it.
- **Score and platform decay.** If OpenCTI lowers a score through its own decay
  rules, the next cycle sets it back.
- **Pattern collisions.** An Indicator with the same pattern from another source
  is the same object in OpenCTI. It is left alone, not exported, and counted in
  `collisions`.
- **Revocation is final.** A revoked Indicator that qualifies again is counted in
  `revoked_but_qualifying` and stays revoked.
- **Empty query guard.** If no observables qualify but Indicators exist, the cycle
  skips reconciliation and reports an error, so a broken query cannot put every
  Indicator into decay.
- **Markings only go up.** A raised Observable marking reaches the Indicator, but
  a lowered one is left for an analyst.
- **Marked Sensitive after sending.** Exports stop, but nothing tells the
  destination to withdraw its existing copy.

## Tests

```bash
python -m pytest
```

The tests use fakes for OpenCTI and a real local HTTP server for the stream. The
GraphQL queries have not run against a live platform, so the first dry run is
their first real test.
