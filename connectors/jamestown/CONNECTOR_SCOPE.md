# CONNECTOR_SCOPE — The Jamestown Foundation

Decision log for `connectors/jamestown/`. Authoritative for this connector;
supersedes conversation memory after compaction.

## What it is

EXTERNAL_IMPORT connector. Ingests the **entire Jamestown Foundation corpus**
(https://jamestown.org) as container-only OpenCTI **Reports**, one per article,
each with the live source page attached as a Playwright-rendered PDF. Adapts the
house style of [DFIR Report] (WordPress REST API enumeration) and
[ScienceDaily]/[arXiv] (full-corpus, persisted positional cursor, container-only).

## Locked decisions (confirmed with user, 2026-06-26)

- **Entire corpus.** All publication series across the `posts` stream (~51.5k items
  back to ~2004) **plus** the content-bearing custom post types `brief` (921),
  `report` (83), `interview` (31), `book` (31). User was shown the per-series
  breakdown and the multi-day Playwright-crawl cost and chose full breadth — the
  same deliberate choice made for ScienceDaily and arXiv. **Do not narrow to a CTI
  subset in a future session.** Levers to scope without code edits:
  `JAMESTOWN_POST_TYPES` (which types) and `JAMESTOWN_PUBLICATIONS` (which series,
  comma slugs, `posts` only — server-side `?publications=<id>` filter).
- **Playwright render.** Articles are HTML with no native per-article PDF; each
  Report gets a full-fidelity rendered PDF (house style). Render failure → skip +
  advance cursor (logged, never revisited); never a Report without its PDF.
- **Confidence 50 (Medium).** Expert secondary analysis on primary sources — above
  press aggregators (would-be lower), at the open-source-reporting baseline shared
  with ScienceDaily/arXiv. (DFIR is 80 for first-party incident forensics.)
- **Container-only.** Report containers only — no Observables / SDOs / SROs / labels.
  Named-entity / IOC extraction is an explicit out-of-scope downstream phase. Keeps
  the connector purely additive and non-contaminating at full scale. No Labels
  (reserved for collection requirements).
- **TLP:CLEAR**, author = single `The Jamestown Foundation` Organization (series
  identity carried on the External Reference, not as an Organization fan-out),
  `report_type = open-source-reporting`.

## Collection mechanics

- **Enumeration:** WordPress REST API, per post type:
  `GET /wp-json/wp/v2/<rest_base>?per_page=100&page=N&order=asc&orderby=date`.
  One pass yields id, link, slug, date_gmt, rendered title/excerpt, and the
  `class_list` (encodes series/topic/region). Series/topic/region are recorded in
  the article's External Reference description (`publications-*`, `topic-*`,
  `region-*` body classes; series names resolved from the `publications` taxonomy).
- **Cursor (positional, NOT date-valued):** `state[<post_type>] = {page, index}` in
  OpenCTI connector state, walked ascending one article at a time. A **positional**
  cursor is mandatory: ~2,300 legacy articles share an identical `1970-01-01`
  placeholder date (CMS-migration loss), which a date cursor cannot disambiguate.
  Backfill resumes within the current page; steady state rests at each type's
  partial tail page and re-checks it each poll for appended articles, rolling to a
  new page when one fills. One code path for backfill + steady state.
- **Dedup:** graph-driven via External Reference URL (`external_reference.read` on
  `url`) before any render. The cursor is the efficiency layer; the graph check is
  the correctness backstop — idempotent even if state is lost.
- **Date:** `published = date_gmt + "+00:00"`. The ~2,300 epoch-dated legacy posts
  are ingested faithfully (no fabricated date).

## Known tradeoffs / caveats

- **Forward-only cursor.** If an old article is *deleted* upstream, ascending page
  positions shift and an item could be skipped on the affected page. Jamestown is an
  archive; deletions of decades-old articles are rare. Graph-dedup prevents
  duplicates on the (common) re-read case; the (rare) skip case is the accepted
  tradeoff, identical to ScienceDaily. Wiping connector state forces a full
  re-enumeration that the graph check makes idempotent.
- **Deep pagination.** The `posts` type is ~516 pages at 100/page; deep WP offsets
  are O(offset) server-side. `JAMESTOWN_REQUEST_DELAY` paces page fetches to stay
  polite. Acceptable for a once-through backfill that then rests at the tail.
- **Series filter is `posts`-only.** The `publications` taxonomy is registered on
  the main post stream; the custom types (`brief`/`report`/…) are not series-filtered.

## Enforcement-gate caveat

As recorded for [arXiv]: the gate tooling CLAUDE.md names (`scripts/preflight.py`,
the `datamodel/` package, the pytest scaffolding) is absent from this checkout, and
`data_model/` holds `Data_Model_Relationship_Guide5.csv`. Relationship validation is
**vacuous here** — the connector emits zero relationships (container-only). Hygiene
(pin/base/secrets/state) checked manually. Flagged, not silently resolved.

[DFIR Report]: ../dfir_report/
[ScienceDaily]: ../sciencedaily/
[arXiv]: ../arxiv/CONNECTOR_SCOPE.md
