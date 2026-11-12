# Waypoint Connector Scope

2026-11-12 - John

Replace the 78 generated per-publisher connectors (8 live, 70 in the repo) with one OpenCTI connector, Waypoint, driven by a `sources.yml` registry. The code is about 96% identical across connectors, so the engine is written once and each publisher becomes a data entry.

## Why

The 78 connectors are one program copied 78 times. Measured on repo commit `f6b94d4`:

| Measure | Value |
| --- | --- |
| Connectors from the shared template | 78 (8 live on OpenCTI .138, 70 not deployed) |
| `main.py` size | 1,574 to 1,638 lines each; 147,130 lines in total |
| Lines that differ between two connectors (The Register vs Securelist) | 58 of about 1,580 (3.7%): docstrings and constants |
| Methods per connector | The same 18 in all 78 |
| Constants that vary by source | 18 (the source profile below) |
| Sources with code no other source has | 2: Dark Web Informer (members-only paywall skip), BleepingComputer (render User-Agent, `BLEEPING-RENDER-UA-V1`) |
| Where the template lives | Outside the repo (Claude Code scaffolding); connectors are kept in sync by regenerating them |

What this costs today:

- A fix lands in one copy. The BleepingComputer User-Agent fix on 2026-11-12 had to be patched into its own `main.py`.
- Each source is its own container, service account, override stanza, `CONNECTOR_ID` and image build.
- Load is not coordinated. Every connector takes up to 30 days of backlog on its first run, all at once, while OpenCTI Elasticsearch is already saturated (backlog item C1).
- A defect in generated config goes unnoticed: `long_war_journal/config.yml` is invalid YAML (an unescaped apostrophe) and would crash at startup; its tests pass because they never load it.

## Goals and non-goals

Goals:

1. One connector, one image, one service account, one override stanza for every article source.
2. Each publisher is a `sources.yml` entry. Adding, disabling or tuning a source is an edit and a restart, never a rebuild.
3. Identical graph output to today's connectors: same Report shape, author, marking, dedup and PDF (see Data model invariants).
4. Central control of load: a global cap on concurrent renders and on Reports written per cycle, across all sources.
5. One source failing never stops the others.
6. The template becomes the repo's code. No generator outside the repo, no regenerated copies.

Non-goals:

- No change to the Report data model, PDF policy or dedup rule.
- No new sources beyond the 78 already scaffolded; vetting the 70 (paywalls, scope) is a separate decision per source.
- No change to pdf-renderer or the Crucible Collector. The connector only calls them.
- Not a replacement for API connectors (ThreatFox, Silent Push, Indicator Export, Google Threat Intelligence, CrowdStrike Intel Reports) or for the older hand-built article connectors (MERICS, ProPublica and others). Those can be folded in later, case by case.

## Architecture

```
                      +--------------------------------------------+
  sources.yml  ---->  | Scheduler: picks due sources; global        |
  (78 profiles,       |            per-cycle budgets               |
   read-only)         |     |                                      |
                      |     v                                      |
  status.json  <----  | Source workers: discover, scope-filter,    |
  (per-source health) |                 URL dedup in OpenCTI       |
                      |     |                                      |
                      |     v                                      |
  pdf-renderer <--->  | Render queue: round-robin across sources;  |
                      |               capped renders at once       |
                      |     |                                      |
                      |     v                                      |
  Collector    <--->  | Report writer: one report.create per       |
  (/classify,         |                article, PDF inline,        |
   only when wired)   |                TLP:CLEAR                   |
                      +-----|--------------------------------------+
                            v
                      OpenCTI (.138): one Report per new article;
                      works named per source
```

Sources are data; the four stages inside the container are shared. The scheduler and the render queue are where global limits apply, so load no longer grows with the number of sources.

## Source profile schema

One entry per publisher in `sources.yml`, keyed by a stable slug (today's connector directory name). Every field below exists today as a constant or `config.yml` key in each generated `main.py`; the build extracts them mechanically.

| Field | Today's constant / key | Type | Default |
| --- | --- | --- | --- |
| `name` | `SOURCE_NAME` | string | required |
| `author_name` | `author_name` | string (Organization name) | required |
| `enabled` | (none: container on or off) | bool | `true` |
| `discovery` | `DISCOVERY` | `feed` / `sitemap` / `listing` / `json` | `feed` |
| `discovery_config` | `DISCOVERY_CONFIG` | map (child_re, url_re, selectors, API params) | `{}` |
| `feed_urls` | `feed_url` | list of URLs | required for `feed` |
| `allowed_hosts` | `ALLOWED_HOSTS` | list of hosts | required |
| `poll_interval` | `poll_interval` | seconds | 3600 (today: 45 at 3600, 28 at 1800, 5 at 900) |
| `max_age_days` | `MAX_AGE_DAYS` | days, 0 = off | 30 |
| `category_keep` / `category_allow` / `category_deny` | `CATEGORY_*` | lists | empty |
| `exclude_url_re` / `exclude_title_re` | `EXCLUDE_URL_RE`, `EXCLUDE_TITLE_RE` | regex | none |
| `content_selectors` | `CONTENT_SELECTOR(S)` | list of CSS selectors, first match wins | `generic` |
| `hide_selectors` | `HIDE_SELECTORS` | list of CSS selectors | `[]` |
| `date_text_selector` | `DATE_TEXT_SELECTOR` | CSS selector | none |
| `byline_author` | `BYLINE_AUTHOR` | bool | `true` |
| `file_prefix` | `FILE_PREFIX` | string | slug |
| `slug_from_id` | `SLUG_FROM_ID` | bool | `false` |
| `resolve_redirect_hosts` | `RESOLVE_REDIRECT_HOSTS` | list of hosts | `[]` |
| `no_content_is_transient` | `NO_CONTENT_IS_TRANSIENT` | bool | `false` |
| `render_headers` | BleepingComputer's `headers=` | map (e.g. `User-Agent`) | `{}` |
| `skip_if` | Dark Web Informer's `PAYWALL_RE` check | named check (`members_only_paywall`) or element-class regex | none |
| `confidence`, `tlp`, `report_type` | `config.yml` keys | int, marking, vocabulary | 50, `TLP:CLEAR`, `open-source-reporting` |

Rules for the schema:

- Site-specific behaviour is an option in the profile, never a code fork. The two existing forks become `render_headers` and `skip_if`.
- The loader validates every entry at startup (types, required fields, regex compiles, hosts present) and refuses to start a source whose entry is invalid, naming the field. The other sources still start.
- Engine-wide constants that are the same in all 78 today (`MAX_PDF_BYTES` 25 MB, `MAX_TRANSIENT_ATTEMPTS` 5, `MAX_PAGE_PROBES` 50, `MAX_DESCRIPTION_CHARS` 2,000, `BROWSER_UA`) stay engine settings with environment overrides, not per-source fields.

## Scheduling and load control

One scheduler decides what runs; all limits are global, so adding sources never multiplies load. Defaults are starting points, set by environment variable.

| Control | Meaning | Default |
| --- | --- | --- |
| `AGG_SOURCE_WORKERS` | Sources polled at the same time (discovery, dedup checks) | 4 |
| `AGG_RENDER_CONCURRENCY` | Renders in flight to pdf-renderer at once, across all sources | 2 |
| `AGG_REPORTS_PER_CYCLE` | Reports written per 30-minute cycle, across all sources | 120 |
| `AGG_MAX_REPORTS_PER_SOURCE_POLL` | New Reports one source may write in one poll | 10 |
| `AGG_CLASSIFY_CONCURRENCY` | Collector `/classify` calls in flight (only when `CRUCIBLE_COLLECTOR_URL` is set) | 2 |

How it runs:

1. Each source has a `next_due` time from its `poll_interval`. The scheduler picks due sources, oldest `next_due` first.
2. A poll discovers items, applies scope filters, then checks dedup against the graph (External Reference URL), exactly as today.
3. New items queue for rendering. The render queue is served round-robin across sources, so one source's 30-day backlog cannot starve the others.
4. When a budget is spent, remaining items wait for the next cycle; nothing is dropped. A source's first run therefore drains its backlog over several cycles instead of at once.
5. Transient failures (renderer busy or down, site 429/5xx, bot challenge) follow today's rules: retried on later polls, up to 5 attempts per item, tracked in memory per source.
6. A pdf-renderer outage pauses all rendering (one shared signal), instead of each source discovering it separately.

Optional, later: back-pressure from OpenCTI. Before each cycle, read the import queue depth (the same GraphQL source `cru-octi-status` already samples) and skip writing when it is above a threshold. This would let the connector slow down on its own while Elasticsearch is saturated.

## Data model invariants

The aggregator must write exactly what the per-source connectors write today. These are acceptance criteria, each covered by a test.

- One container-only Report per article. No Labels, entities, Observables or Relationships. Labels stay reserved for collection requirements; classifier output never becomes a Label.
- Report STIX id = `uuid5(NAMESPACE_URL, article URL)`, so the same article always maps to the same Report.
- `createdBy` = the publisher's Organization (`author_name`), resolved once per source. The author identity is never added to the Report's contents.
- `published` = the article's own date. Items without a parseable date are skipped, never stamped with ingestion time.
- TLP:CLEAR on the Report and on the attached file itself (`filesMarkings`). Confidence 50.
- `report_types` from the Collector `/classify` when `CRUCIBLE_COLLECTOR_URL` is set; otherwise the source's default (`open-source-reporting`).
- One External Reference: the canonical article URL, `utm_*` removed. Dedup = skip any item whose URL is already cited by a Report, checked in the graph; no local dedup state.
- One PDF of the live article from pdf-renderer: site selectors, chrome stripped, links defanged and dead, feed title injected, byline with author, publisher and date. Over 25 MB = no attachment. No second PDF.
- Description = plain text, no live links, at most 2,000 characters.
- One `report.create` per article with the PDF inline and `update=False`.

Because the Report id and the dedup key are derived from the URL alone, moving a source from its old connector to the aggregator cannot create duplicates.

## Identity, isolation and observability

OpenCTI identity:

- One connector registration (`EXTERNAL_IMPORT`, named `Waypoint`) and one service account in the Connectors group, created with `user_service_account: true` and no default groups.
- Each OpenCTI work is named per source (`<Source> poll`), so Data > Ingestion > Works still splits by publisher.
- Source attribution in the graph is unchanged: `createdBy` is the publisher. Only the platform's creator field becomes the one aggregator account instead of one account per publisher.

Failure isolation:

- Every source poll runs inside its own exception boundary. An unexpected error ends that poll, is logged with a traceback, and the source backs off (doubling, capped at 6 hours); the other sources carry on.
- A source whose `sources.yml` entry fails validation is not started; the rest are.
- The process runs with `restart: always` and a memory limit. A broken image still stops every source until rollback, which is the main cost of consolidation (see Risks).

Observability:

- One summary log line per source poll: discovered, in scope, already ingested, created, created without PDF, transient, skipped permanently, duration.
- One summary line per cycle: sources polled, Reports written against `AGG_REPORTS_PER_CYCLE`, render queue depth.
- A status file on the connector's volume (`/data/status.json`): per source, last poll time and outcome, last Report time, consecutive failures, next due. The HMI can read it later; nothing in Crucible depends on it now.
- A source with no new Report for longer than a per-source threshold (default 7 days) logs a WARNING once a day. This catches dead feeds, like Brookings' 302 to its homepage since 2026-10-05.

## Migration plan

The 8 live connectors keep running until the aggregator has matched them. Each phase has a gate; nothing moves on without John's approval.

1. **Build (Claude Code, repo only).** Engine package, `sources.yml` extracted from all 78 generated `main.py` files by a script, ported tests. Gate: all tests pass, and an equivalence test shows each profile reproduces its connector's 18 constants exactly.
2. **Shadow run (OpenCTI .138).** Aggregator deployed with only the 8 live sources and `AGG_DRY_RUN=true`: it discovers, filters and checks dedup, logs what it would create, and writes nothing. Gate: over 24 hours, every URL it would create was also created by the old connectors, and nothing the old connectors created was missed.
3. **Cut over the 8.** `docker compose stop` the 8 old services (stanzas and images kept), then turn dry run off. Gate: 48 hours with per-source Report counts in line with the previous 48 hours, no unexpected Reports without PDF, no ERROR lines.
4. **Add Phase 2 (17 threat-research sources).** Enable their entries; the global caps meter their 30-day backlogs. Gate: Elasticsearch rejection and queue metrics no worse than before (backlog C1), renderer healthy.
5. **Add Phase 3-6 in waves**, each source vetted first: paywall or registration test like BleepingComputer's, scope check, overlap check against existing connectors.
6. **Retire.** Remove the 8 old stanzas; disable (never delete) their 8 service accounts; remove the 78 generated directories from the repo (git history keeps them).

Rollback at any phase: stop the aggregator and `docker compose start` the old services. URL-derived Report ids and graph dedup mean switching in either direction creates no duplicates.

## Deliverables and acceptance criteria

The build is phase 1 of the migration plan, done in Claude Code against `JohnMcFarland/OpenCTI-Connectors`. Proposed layout:

```
connectors/waypoint/
  main.py              entry point: config, connector registration, run loop
  engine/              profile.py (load + validate), scheduler.py, discovery.py
                       (feed, sitemap, listing, json), scope.py, dedup.py,
                       render.py, report.py, status.py
  sources.yml          one entry per publisher (78, generated)
  config.yml, Dockerfile, docker-compose.yml, requirements.txt
  README.md, CONNECTOR_SCOPE.md
  tests/               engine unit tests, per-source fixture tests, equivalence test
scripts/extract_profiles.py   generated main.py files -> sources.yml
```

This is a deliberate exception to the flat single-file `main.py` house style: one engine serving 78 sources needs modules. It reuses the shared `microservices/` package (mounted at `/microservices`) for `render_live_pdf` (with `headers=`) and `classify_report`, not copies.

Acceptance criteria:

- [ ] `extract_profiles.py` reads all 78 generated connectors and writes `sources.yml`; the equivalence test shows every profile matches its connector's constants and `config.yml` defaults.
- [ ] Long War Journal's name is quoted correctly in the generated YAML (today's `config.yml` is invalid).
- [ ] Every existing per-source test case (feed samples, title and category filters, date parsing) passes against the engine with that source's profile.
- [ ] One test per Data model invariant, including the Report id, dedup, file marking and the plain-text description.
- [ ] Scheduler tests: global render and Report budgets hold; round-robin prevents one backlog starving the others; a renderer outage pauses all rendering; a failing source backs off without stopping the rest.
- [ ] `AGG_DRY_RUN=true` writes nothing to OpenCTI, proven by a test with a mocked client.
- [ ] `sources.yml` is mounted read-only from the override; changing it needs only a restart. An invalid entry disables that source only.
- [ ] No credentials, instance URLs or `CONNECTOR_ID`s in the repo; `OPENCTI_URL` (not `OPENCTI_BASE_URL`).
- [ ] All source files ASCII-only; fix marker `WAYPOINT-V1` in `main.py` for deployment proof.
- [ ] README covers adding a source, disabling one, the budgets and the status file.

## Open decisions and risks

Decisions for John before or during the build:

- **Name.** Decided 2026-11-12: connector `Waypoint`, service account `[C] Waypoint`. The locked `[C] <Publisher>` rule assumes one publisher per account; record Waypoint as the named exception in `crucible_decisions.md`.
- **Budgets.** Defaults above (2 renders, 120 Reports per cycle) are guesses; confirm or set from Elasticsearch measurements (C1).
- **Back-pressure from the OpenCTI queue.** Build now or later?
- **Stronger By Science** (strength-training site): drop from `sources.yml`, or keep for the health domain?
- **Possible paywalls**: Jerusalem Post, BankInfoSecurity, Dark Reading. Test each before enabling, or drop.
- **Overlaps**: WHO Disease Outbreak News vs the existing `world_health_organization` connector; Google GTIG blog vs the `gti` API connector; CrowdStrike blog vs CrowdStrike Intel Reports. URL dedup only catches exact URL matches.
- **Older hand-built article connectors** (MERICS, ProPublica, Carnegie and others): fold into `sources.yml` later, or leave as they are?
- **Template generator**: retire it once the aggregator exists, so there is one source of truth.

Risks:

| Risk | Effect | Mitigation |
| --- | --- | --- |
| One bad image or crash loop | All sources stop until rollback | Per-source exception boundaries; shadow run before cutover; old services kept for rollback until phase 6 |
| Extraction misses a site quirk | A source behaves differently than its generated connector | Equivalence test on all 18 constants; the two known forks become explicit options; per-source fixture tests |
| Global budgets too low | Backlogs drain slowly; new posts wait | Budgets are environment settings; per-cycle log shows when the budget is spent |
| Budgets too high | Same Elasticsearch saturation as 78 separate connectors | Start low; add back-pressure; enable sources in waves |
| Less visibility in OpenCTI's Connectors page | One heartbeat instead of one per source | Per-source works, per-source poll log lines, `status.json` |
