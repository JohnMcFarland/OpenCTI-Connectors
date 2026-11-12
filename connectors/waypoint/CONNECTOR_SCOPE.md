# Waypoint: connector scope

Full scope, rationale and migration plan: [docs/WAYPOINT_SCOPE.md](../../docs/WAYPOINT_SCOPE.md).
This file records what the phase 1 build delivers and the decisions taken
during it.

## What it ingests

Articles from the publishers in `sources.yml` (78 profiles, extracted from
the generated per-source connectors). Phase 1 enables only the 8 sources
already live as their own connectors:

BleepingComputer, The Hacker News, Security Affairs, TechCrunch, The
Register, The Record, CyberScoop, Dark Web Informer.

All 70 others are present with `enabled: false`. Enabling them is migration
phases 4 and 5, each source vetted first.

## Data model

Unchanged from the generated connectors (each rule has a test in
`tests/test_invariants.py`):

- One container-only Report per article. No Labels, entities, Observables or
  Relationships; classifier output never becomes a Label.
- Report STIX id `uuid5(NAMESPACE_URL, article URL)`.
- `createdBy` the publisher's Organization, resolved once per source.
- `published` the article's own date; undated items are skipped, never
  stamped with ingestion time.
- TLP:CLEAR on the Report and on the attached file (`filesMarkings`);
  confidence 50.
- `report_types` from the Crucible Collector when `CRUCIBLE_COLLECTOR_URL`
  is set, else the profile's `report_type` (`open-source-reporting`).
- One External Reference: the canonical article URL, `utm_*` removed.
- One PDF from pdf-renderer; over 25 MB means no attachment.
- Plain-text description, no live links, at most 2,000 characters.
- One `report.create` per article, PDF inline, `update=False`.

## Decisions taken in the build (2026-11-12)

- **Schema additions** (approved by John before the build): `request_delay`
  (per-source politeness delay, from robots.txt crawl delays: 2 to 420 s
  across the 78) and `author_description` (the publisher Organization's
  description). Neither was in the original schema; both were per-source in
  the generated connectors.
- **`stale_after_days`**: optional per-source field for the stale-source
  threshold the scope describes; default `AGG_STALE_AFTER_DAYS` (7).
- **Engine settings, not profile fields**: `render_retries` (3),
  `pdf_render_timeout` (120 s) and `max_reports` (0) were identical in all 78
  and become `AGG_RENDER_RETRIES`, `AGG_RENDER_TIMEOUT` and the per-poll cap.
- **Works** are named `<Source> poll` (the generated connectors used
  `<Source> feed poll`).
- **Single writer**: renders, page probes and classification run in worker
  threads; every OpenCTI write happens on the main thread.
- **Per-source politeness under concurrency**: at most one item per source
  in flight, with its `request_delay` between items, as each generated
  connector did sequentially.
- **Budget spill**: items that do not fit the cycle budget or the per-poll
  cap are not queued in memory; the source is polled again at the next
  window and graph dedup finds them. No local state is added.
- **Renderer outage**: pauses all rendering for `AGG_RENDERER_PAUSE_SECONDS`
  (300 s); during the pause sources still poll and dedup but open no works.
- **Backoff** applies to unexpected errors (as the scope says). An
  unreachable feed or a failed dedup lookup keeps the normal interval, as
  in the generated connectors, and counts in `consecutive_failures`.
- **Dry run** skips author/vocabulary creation and all rendering; it logs
  each URL it would create once per process.
- **A source whose author or marking cannot be resolved** at startup does
  not start (status `failed-start`); the generated connectors exited.
- **sources.yml is not baked into the image**; it must be mounted
  (read-only), so a stale copy can never run.
- **Back-pressure** from the OpenCTI queue: not built (deferred, as
  instructed).

## Not in scope

API connectors (ThreatFox, Silent Push, Indicator Export, Google Threat
Intelligence, CrowdStrike Intel Reports) and the older hand-built article
connectors (MERICS, ProPublica and others). No change to pdf-renderer, the
microservices package or the Report data model.
