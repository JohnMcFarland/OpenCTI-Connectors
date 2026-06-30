# CONNECTOR_SCOPE - The Jamestown Foundation

Decision log for `connectors/jamestown/`. Authoritative for this connector;
supersedes conversation memory after compaction.

## What it is (current model)

EXTERNAL_IMPORT connector. Ingests new analytical articles from
https://jamestown.org as container-only OpenCTI Reports, one per RSS feed item, each
with the live source page attached as a Playwright-rendered PDF. Collection is a
single forward poll of the main RSS feed. It is forward-only: there is no historical
backfill on this origin.

Fixed field mapping (unchanged from the original design):

- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR. Confidence: 50 (Medium band). report_type: open-source-reporting.
- Author: the single "The Jamestown Foundation" Organization identity.
- Name: verbatim feed title. published: RSS pubDate (RFC 822) parsed to ISO 8601.
- Exactly one External Reference per Report (the article URL).
- Container-only: no Observables, Domain Objects, Relationships, or Labels. Zero
  relationships emitted; the relationship CSV is not implicated.

## Revision 2026-06-30: API/sitemap model superseded by forward-only RSS

This revision is a STRUCTURAL change. It records why the prior model was abandoned
and what replaced it.

### (a) Supersession of the 2026-06-26 entire-corpus lock

The 2026-06-26 decision (below) locked "ingest the entire corpus" via the WordPress
REST API plus a positional page/index cursor, with the XML sitemap as the fallback
enumeration surface. That model is not achievable on this origin and is superseded.
Reason: the origin blocks both structured enumeration surfaces (see
BLOCKED-AT-ORIGIN). The RSS feed is the only reachable structured surface, and RSS is
a recent-items window rather than an archive, so collection is forward-only from
turn-on. Full historical backfill is not achievable here.

### (b) Four chosen decisions

1. Posts stream only. The main feed is the WordPress posts stream. No custom post
   types (brief / report / interview / book), no per-series feeds.
2. Single main feed, take everything. Every item in the main feed window becomes a
   Report. No series scoping, no category filtering.
3. Hourly poll. JAMESTOWN_POLL_INTERVAL default 3600. The window is sampled often
   enough to keep the burst-day margin (see (d)) wide.
4. Category terms observed, not bound. Each item's category terms are parsed and the
   distinct set is logged once per cycle ("Distinct feed categories observed (not
   bound to Reports): [...]"). They are not written to Reports, Labels, or the
   External Reference. The intent is to surface the full term set in logs before any
   later binding decision.

### (c) Finding-2 fix: dedup keyed on deterministic Report id

The prior connector keyed dedup on the External Reference, created before the Report,
which permanently suppressed an article if the process crashed between the two writes
(the orphan reference made the URL look "done" with no Report). Additionally, the
reports GraphQL nested filter on externalReferences.url is unsupported on this
platform build, so dedup cannot query Reports by reference URL at all.

Fix: derive a deterministic Report STIX id from the article URL
("report--" + uuid5(NAMESPACE_URL, link)). Dedup checks report.read(id) before
rendering (so duplicates never trigger a wasted render). A new item creates the
External Reference (upsert-safe), then the Report with that stix_id (update=True),
then attaches the PDF. Because the existence check keys on the Report id and not on
the External Reference, every sub-write is idempotent: a crash anywhere leaves the
item still "not done" per report.read, and the next poll re-enters and completes it
while the item is still in the feed window. No compensating deletes, no
orphan-marker suppression.

### (d) Open failure mode: burst-day feed-window risk

The feed window has a fixed, shallow depth (a small number of most-recent items). If
a single interval produces more new articles than fit in the window before the next
poll, the overflow rolls off and is dropped silently. The hourly poll keeps the
margin wide but does not eliminate the risk. This is the connector's one accepted
open failure mode, documented rather than mitigated this pass.

## BLOCKED-AT-ORIGIN

The Jamestown origin (nginx behind Cloudflare) blocks the structured enumeration
surfaces that the original design depended on:

- /wp-json/ (WordPress REST API): HTTP 403.
- /sitemap*.xml (XML sitemaps): HTTP 403.

The 403 was confirmed three ways: to curl (plain HTTP client), to headless Chromium,
and to a cleared same-origin in-page fetch. The RSS feed at {base_url}/feed/ is
reachable (HTTP 200, valid RSS 2.0) with a plain HTTP client, and article pages
render at HTTP 200. This is the origin constraint that forces the forward-only RSS
model above. If the origin later unblocks /wp-json/, revisiting the entire-corpus
model would require re-opening the 2026-06-26 decision deliberately.

## Superseded: 2026-06-26 entire-corpus decision (kept for history)

Recorded here for the decision-log trail; superseded by the 2026-06-30 revision
above. Do not re-implement without re-opening it deliberately.

- Entire corpus: all publication series across the posts stream (~51.5k items back to
  ~2004) plus the custom post types brief / report / interview / book. Confirmed with
  user 2026-06-26 after showing the per-series breakdown and crawl cost.
- Enumeration: WordPress REST API per post type
  (GET /wp-json/wp/v2/<rest_base>?per_page=100&page=N&order=asc&orderby=date), with a
  positional {page, index} cursor (positional because ~2,300 legacy posts share an
  identical 1970-01-01 placeholder date that a date cursor cannot disambiguate), and
  the XML sitemap as the fallback surface.
- Series/topic/region were read from each post's class_list and recorded on the
  External Reference.

All of that machinery has been removed (not patched): the page-walk, the
cursor/state usage, the publications-taxonomy and series-slug code, and the
JAMESTOWN_POST_TYPES and JAMESTOWN_PUBLICATIONS variables. The parked orderby/cursor
finding is moot because the code is gone.

## Enforcement-gate caveat

As recorded for arXiv: the gate tooling CLAUDE.md names (scripts/preflight.py, the
datamodel/ package, the pytest scaffolding) is absent from this checkout, and
data_model/ holds Data_Model_Relationship_Guide5.csv. Relationship validation is
vacuous here: the connector emits zero relationships (container-only). Hygiene
(pin/base/secrets) checked manually. Flagged, not silently resolved.

[DFIR Report]: ../dfir_report/
[ScienceDaily]: ../sciencedaily/
[arXiv]: ../arxiv/CONNECTOR_SCOPE.md
