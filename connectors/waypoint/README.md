# Waypoint

One OpenCTI connector for every article source. Each publisher is an entry in
`sources.yml`; the engine (`engine/`) is shared. Waypoint replaces the 78
per-publisher connectors generated from the shared feed template and writes
exactly what they wrote. The spec, migration plan and open decisions are in
[`docs/WAYPOINT_SCOPE.md`](../../docs/WAYPOINT_SCOPE.md).

| | |
| --- | --- |
| Type | `EXTERNAL_IMPORT`, registered as `Waypoint` |
| Service account | `[C] Waypoint` (one account for all sources; Connectors group, `user_service_account: true`, no default groups) |
| Output | One container-only Report per article: publisher Organization as author, TLP:CLEAR on the Report and its file, one External Reference, one PDF of the live article |
| Dedup | Graph only: skip any article whose URL is already cited by a Report (any connector's) |
| Sources | 78 profiles; 8 enabled (the live Phase 1 connectors) |
| Deployment proof | `WAYPOINT-V1` in `main.py` and in the startup log line |

## Layout

```
main.py          entry point: config, connector registration, run loop
engine/
  settings.py    engine constants and AGG_* budgets (environment)
  profile.py     sources.yml loading and per-entry validation
  scheduler.py   due sources, global budgets, round-robin render queue
  worker.py      one source's poll and per-item ingestion
  discovery.py   feed / sitemap / listing / json discovery
  scope.py       scope filters, skip_if checks
  dedup.py       External Reference URL dedup
  render.py      pdf-renderer calls (shared microservices/make_pdf.py)
  report.py      Report id, file name, classification, report.create
  dates.py, text.py, status.py, timing.py
sources.yml      one profile per publisher (generated; see below)
tests/           ported per-source tests, equivalence, invariants, scheduler
```

The shared `microservices/` package (pdf-renderer client and Crucible
classifier) is mounted read-only at `/microservices`; it is never copied.

## Adding a source

1. Add an entry to `sources.yml`, keyed by a slug (lower case, digits,
   underscores). Required: `name`, `author_name`, `feed_urls`,
   `allowed_hosts`. Everything else has a default; the full field list and
   defaults are in docs/WAYPOINT_SCOPE.md, "Source profile schema", plus:
   - `request_delay` (seconds, default 3): pause between this source's
     article fetches, and the base of its render backoff (capped at 30 s).
     Set it to the site's robots.txt crawl delay.
   - `author_description` (default empty): description of the publisher
     Organization when it is first created.
   - `stale_after_days` (default `AGG_STALE_AFTER_DAYS`): see the status
     section.
2. Start it disabled (`enabled: false`) and vet it first: paywall or
   registration wall, scope, overlap with existing connectors.
3. Set `enabled: true` and restart the container. No rebuild.

Site-specific behaviour is always a profile option, never a code fork:

- `render_headers`: extra request headers for the renderer's page load
  (BleepingComputer sends its own browser User-Agent; Cloudflare challenges
  the renderer's default one).
- `skip_if`: skip an article before rendering. `members_only_paywall` is the
  Dark Web Informer check (Ghost members-only posts); any other value is a
  regex matched against element class attributes on the article page.

A new kind of site quirk means a new profile option in the engine, with
tests, not a per-source branch.

## Disabling a source

Set `enabled: false` and restart. Its status entry says `disabled`. An entry
that fails validation is not started either: the startup log and the status
file name the source and the failing field (for example
`exclude_url_re: invalid regex (...)`), and every other source starts
normally.

## Budgets

All limits are global, so adding sources never multiplies load. Defaults are
starting points (docs/WAYPOINT_SCOPE.md, "Budgets", is still an open
decision):

| Variable | Meaning | Default |
| --- | --- | --- |
| `AGG_SOURCE_WORKERS` | Sources discovered at the same time | 4 |
| `AGG_RENDER_CONCURRENCY` | Renders in flight to pdf-renderer, all sources | 2 |
| `AGG_REPORTS_PER_CYCLE` | Reports written per cycle window, all sources | 120 |
| `AGG_MAX_REPORTS_PER_SOURCE_POLL` | New Reports one source may write per poll | 10 |
| `AGG_CLASSIFY_CONCURRENCY` | Collector `/classify` calls in flight | 2 |
| `AGG_CYCLE_SECONDS` | Length of the budget window | 1800 |
| `AGG_RENDERER_PAUSE_SECONDS` | Rendering pause after a renderer outage | 300 |
| `AGG_STALE_AFTER_DAYS` | Default stale-source threshold | 7 |
| `AGG_DRY_RUN` | Discover, filter, dedup and log only; write nothing | false |

How they apply:

- Due sources run oldest-first. New items are rendered round-robin across
  sources (at most one item per source at a time, with that source's
  `request_delay` between its items), so one source's backlog cannot starve
  the others.
- When a budget is spent, nothing is dropped: the remaining items stay
  unwritten and the source is polled again at the next window, where graph
  dedup finds exactly what is left. A source's first run drains its 30-day
  backlog over several windows.
- A pdf-renderer outage seen by any item pauses all rendering for
  `AGG_RENDERER_PAUSE_SECONDS`. Items are not counted against for it.
- Site failures (429/5xx, bot challenge, page fetch errors) are retried on
  later polls, up to 5 attempts per item, tracked in memory per source.
- A poll that fails unexpectedly is logged with a traceback and that source
  backs off (poll_interval doubling per consecutive failure, capped at 6
  hours). Other sources carry on.

Engine-wide constants that were identical in all 78 generated connectors
stay engine settings with environment overrides: `AGG_MAX_PDF_BYTES`
(25 MB), `AGG_MAX_TRANSIENT_ATTEMPTS` (5), `AGG_MAX_PAGE_PROBES` (50),
`AGG_MAX_DESCRIPTION_CHARS` (2000), `AGG_BROWSER_UA`, `AGG_RENDER_RETRIES`
(3), `AGG_RENDER_TIMEOUT` (120 s).

## Dry run

`AGG_DRY_RUN=true` (the shadow-run phase): every enabled source is
discovered, scope-filtered and checked against the graph, and each article
it would create is logged once as `DRY-RUN would create Report for <url>`.
Nothing is written: no Organization, vocabulary, work, External Reference or
Report, and nothing is rendered or classified. Only reads reach OpenCTI
(dedup lookups, the marking definition). The connector registration and its
heartbeat are the platform's, as for any connector.

## Status file and logs

`/data/status.json` (volume `waypoint-data`), rewritten after each scheduler
tick:

```json
{"updated": "...", "sources": {"bleepingcomputer": {
  "state": "running", "last_poll": "...", "last_outcome": "ok",
  "last_report": "...", "consecutive_failures": 0, "next_due": "..."}}}
```

`state` is `running`, `disabled`, `invalid` (with `reason`) or
`failed-start` (author or marking could not be resolved). `last_outcome` is
`ok`, `idle`, `feed-failed`, `dedup-failed` or `error`. `last_report`
survives restarts and drives the stale warning: a source with no new Report
for longer than its threshold logs a WARNING once a day.

Log lines:

- One per source poll: `<Source> poll (<outcome>): discovered N, in scope N,
  already ingested N, created N (N without PDF), transient N, skipped
  permanently N[, N waiting for the next cycle]; <duration>`.
- One per tick: `Cycle: N sources polled, N Reports written (used/limit this
  window), render queue depth N`.
- OpenCTI works are named `<Source> poll`, so Data > Ingestion > Works still
  splits by publisher.

## sources.yml is generated (for now)

`scripts/extract_profiles.py` reads the 78 generated connectors' `main.py`
(statically, with `ast`) and `config.yml` and writes `sources.yml`; with
`--fixtures` it also writes the per-source test data in
`tests/fixtures/`. `tests/test_equivalence.py` imports the same connectors
at runtime and checks every profile against them. Until the generated
directories are retired (migration phase 6), regenerate rather than
hand-edit:

```
python scripts/extract_profiles.py --fixtures connectors/waypoint/tests/fixtures
python scripts/extract_profiles.py --check
```

After phase 6, `sources.yml` is the source of truth and is edited by hand.

## Tests

```
cd connectors/waypoint
python -m pytest -q tests
```

- `test_ported_sources.py`: the generated connectors' per-source suite, run
  for all 78 profiles with each source's own fixtures.
- `test_dark_web_informer.py`: the members-only cases, against `skip_if`.
- `test_equivalence.py`: every profile vs its generated connector, at
  runtime.
- `test_invariants.py`: one test per data-model invariant, for each live
  source, through the scheduler.
- `test_scheduler.py`: budgets, round-robin, outage pause, backoff, status,
  stale warning.
- `test_dry_run.py`: dry run writes nothing (mocked client).
- `test_profiles.py`, `test_main_entry.py`, `test_static.py`: registry,
  validation, startup, repository rules.
