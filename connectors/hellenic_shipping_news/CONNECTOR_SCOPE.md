# CONNECTOR_SCOPE - Hellenic Shipping News

Decision log for `connectors/hellenic_shipping_news/`. Authoritative for this
connector; supersedes conversation memory after compaction.

## What it is (current model)

EXTERNAL_IMPORT connector. Ingests category-scoped articles from
https://www.hellenicshippingnews.com as container-only OpenCTI Reports, one per
WordPress post, each with the live source page attached as a Playwright-rendered
PDF. Enumeration is a category-filtered WordPress REST backfill walked by a
persisted positional `{page, index}` cursor; the same path drives steady state.

Fixed field mapping:

- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR. Confidence: 50 (Medium band). report_type: open-source-reporting.
- Author: the single "Hellenic Shipping News" Organization identity.
- Name: verbatim post title (`title.rendered`, HTML-stripped). Description: post
  excerpt (`excerpt.rendered`, HTML-stripped). published: `date_gmt`
  (fallback `modified_gmt`) parsed as UTC.
- Exactly one External Reference per Report (the article URL).
- Container-only: no Observables, Domain Objects, Relationships, or Labels. Zero
  relationships emitted; the relationship CSV is not implicated.

## Decisions (2026-07-19, confirmed with user this session)

1. **Origin surfaces open.** Unlike Jamestown, this origin returns HTTP 200 to a
   browser-UA client on `/wp-json/wp/v2/posts`, `/feed/`, and `/sitemap.xml`.
   Full backfill is mechanically achievable. WebFetch (non-browser UA) gets 403;
   curl/Playwright with a browser UA get 200.

2. **Scope = category allowlist, not full corpus.** The full corpus is ~94,487
   posts, dominated by routine market-data tickers. Applied server-side via the REST
   `categories` parameter (`HSN_CATEGORIES`). Final allowlist = three tiers, 14
   category ids, ~82,247 posts full corpus / ~16,973 for a one-year backfill:
   - Security/legal/risk: 109 Piracy & Security, 118 Shipping Law, 115 Marine
     Insurance P&I.
   - Geopolitics/energy/economy: 107 World Economy, 103 Oil & Companies, 101
     Commodity, 125 IMF/OECD, 108 General Energy.
   - Shipping operations (ADDED after full-menu review): 27 International Shipping
     News (32.7k), 112 Port News (11.7k), 124 Emission Possible (4.6k), 113 Freight
     News (3.7k), 105 Shipbuilding News (2.9k), 122 Dry Bulk Market (2.9k).

   (History: the initial pick was the first two tiers, 9 ids, ~30,330 posts. After
   the full 50-category menu review the user added shipping-operations (-> 15 ids),
   then dropped 120 Report/Analysis after a content audit (-> 14 ids); see the
   content-audit revision below.)

   Explicitly NOT ingested: the Hellenic/Greek-market tier (26 Hellenic Shipping
   News, 135 Hellenic Shipping Companies), the Greek "front page" catch-all (144
   Πρώτη σελιδα, 61k — mirrors everything), the Bunkerports section-mirrors (166/191/
   165), the News1–6 Greek stubs, Interviews/Videos/Social Media, and all
   daily/weekly/monthly ticker + periodic-report categories (Daily Currencies
   Ratings, Daily Bunker Report, Chinese iron ore prices, Weekly *-Estimates/Reports,
   Stock News, etc.). Widening/narrowing scope is a config edit (`HSN_CATEGORIES`),
   not a code change.

3. **Ascending-id positional cursor, not date.** Thousands of legacy posts carry a
   broken placeholder publication date (year `-0001`, e.g. post id 242893) that a
   date cursor cannot disambiguate. Enumeration therefore orders by
   `orderby=id&order=asc` and walks a positional `{page, index}` cursor from page 1.
   Post ids are monotonic and stable; new posts get the highest ids and append to
   the last page. A full page (per_page items) advances to the next page; a partial
   page is the current tail, so the cursor rests on it and the next poll re-reads it
   to pick up freshly-appended posts. One uniform code path covers backfill and
   steady state (mirrors ScienceDaily).

4. **robots.txt honored.** The site's robots.txt disallows ClaudeBot and sets
   `ai-train=no`, but signals `search=yes` and `use=reference` with
   `Crawl-Delay: 30`. User chose **Proceed, honor 30s delay**: run reference-use
   ingestion under a plain browser UA (not ClaudeBot, no model training) and default
   `HSN_REQUEST_DELAY=30`. At that delay the ~30k backfill spans multiple weeks; it
   is fully resumable from the state cursor.

5. **Placeholder-date fallback.** An in-scope post whose only dates are the `-0001`
   placeholder (fromisoformat rejects the negative year) is dated to ingestion time
   with a warning rather than dropped. These are real in-scope articles with a CMS
   date defect and no other date signal. (This differs from Jamestown, which
   *skips* undated feed items — there the item stays in the feed window and can be
   retried; here the post would otherwise be permanently excluded.)

## Revision 2026-07-19 (same session): configurable backfill depth + scope signature

User asked for a date-configurable backfill (e.g. two years) and for the pullable
options to be revisited and configurable. Additive change; one enumeration path
unchanged.

- **`HSN_BACKFILL_START_DATE`** (empty = full filtered corpus). When set, passed to
  the origin as the WordPress `after` query param, so the server returns only posts
  published on/after the date. Layered on the existing `orderby=id&order=asc` walk:
  one ordering mode, no second code path. Validated live: no floor = 30,330 in-scope
  posts; `after=2024-07-19` = 10,511 (a two-year window); the oldest post under the
  floor is a real 2024 date, and the `-0001` placeholder posts drop out server-side.
- **Absolute date, not a rolling window (deliberate).** A relative `now - N days`
  floor recomputed each restart would drift forward, changing the filtered set and
  silently mis-positioning the positional id cursor (excluded low-id posts shift
  every later position). An absolute floor keeps the filtered set — and thus the
  cursor — stable across restarts. A set-but-unparseable value fails closed (raises)
  so a typo can never silently widen the backfill to the whole corpus.
- **Scope signature.** The cursor state now carries a `scope_sig` =
  `categories|backfill_after`. If it changes between polls (operator edits the
  allowlist or the floor), the cursor resets to page 1 instead of mis-indexing into
  a different filtered set. Graph dedup (`report.read(id)`) makes the re-scan safe:
  already-ingested posts are skipped, nothing is duplicated, nothing is missed.

Full category menu (50 non-empty categories) was pulled from
`/wp-json/wp/v2/categories` this session and reviewed with the user; the allowlist
remains fully operator-configurable via `HSN_CATEGORIES` (see decision 2).

## Revision 2026-07-19 (same session): content audit of 120 and 122

Two categories were audited by pulling ALL their posts in the one-year window
(after=2025-07-19) and classifying titles, before deciding whether to keep them.

- **120 Report/Analysis — DROPPED.** 96/96 (100%) of one-year posts are recurring
  "Weekly Tanker/Dry Time Charter Estimates" tables — market data, not analysis.
  The label is misleading; zero substantive content lost by dropping it. Removed
  from the allowlist (15 -> 14 ids); one-year distinct total 17,069 -> 16,973.
- **122 Dry Bulk Market — KEPT.** 602 one-year posts: 334 (56%) Baltic Dry Index
  daily ticker quotes, but 268 (44%) substantive (Capesize/Panamax market
  commentary, coal/iron-ore/grain/soybean trade flows, typhoon supply-chain
  disruption, ship recycling, Greek-owner ordering). An earlier "mostly tickers"
  characterization was an overstatement; the 44% substantive minority is real
  maritime-economic intelligence, so 122 stays. Do NOT drop 122 without re-auditing.
  If the BDI ticker volume later becomes a problem, the right fix is a title-level
  skip filter (an additive feature, e.g. exclude titles matching the "Baltic Dry
  Index ... points" pattern), NOT dropping the whole category.

## Revision 2026-07-19 (same session): HSN_TITLE_EXCLUDE (client-side title filter)

Added the title-level skip filter anticipated above. Motivation and design:

- **Why not server-side.** Verified the BDI tickers in category 122 carry no
  distinguishing taxonomy: they sit in the SAME category (122) as substantive
  dry-bulk posts and have empty `tags` (a sample substantive post had tag 134,
  tickers had none). So neither `categories_exclude` nor `tags_exclude` can separate
  them. The only reliable discriminator is the title pattern.
- **Design.** `HSN_TITLE_EXCLUDE` = a single case-insensitive regex (empty = off).
  Applied in the per-post loop after enumeration, before dedup/render; a match is
  counted (`excluded`) and skipped, and the cursor still advances past it. Default
  empty -> zero behavior change unless configured. Invalid regex fails closed
  (RuntimeError at startup).
- **NOT part of scope_sig (deliberate).** Unlike `HSN_CATEGORIES`/
  `HSN_BACKFILL_START_DATE`, the title filter is client-side: it does not change the
  set or ordering of posts the API returns, so the positional {page,index} cursor
  stays valid when it changes. Editing it therefore does NOT reset the cursor; it
  takes effect going forward. Posts already scanned past are not retroactively
  revisited unless connector state is reset (documented forward-only semantics).
- **Now ON by default (user-confirmed 2026-07-19).** After a 77-day title-cluster
  audit of the 14-cat stream, the user chose to drop the recurring machine-generated
  data/listing series and keep the editorial ones. Shipped default pattern:
  `Baltic Dry Index|HOT PORT NEWS from GAC|World Container Index|Intra-Asia
  Container Index|Container Report|^ENGINE:|Bidding Announcement|Fujairah.*Inventor`
  — removes ~2.7/day (~1k/yr, ~4-5% of inflow). DROPPED series: BDI tickers, GAC
  port bulletins, Drewry/Intra-Asia container indices + weekly Container Reports,
  ENGINE bunker-availability outlooks, vessel-auction (Bidding Announcement)
  listings, Fujairah inventory reports. KEPT editorial series: ING "The Commodities
  Feed", "The Week in Alt Fuels", GTT newbuild-order PRs. `^ENGINE:` is anchored and
  a blanket `Drewry` match was deliberately avoided to minimize catching a
  substantive piece. The category counts reported elsewhere describe what is
  *enumerated*; the title filter reduces what is *ingested* and does not change
  X-WP-Total.

## Dedup: deterministic Report id (Jamestown Finding-2 pattern)

Dedup keys on a deterministic Report STIX id (`report--` + uuid5(NAMESPACE_URL,
link)) checked via `report.read(id)` before rendering. A new post creates the
External Reference (upsert-safe), then the Report with that stix_id (update=True),
then attaches the PDF. Because the existence check keys on the Report id and not on
the External Reference, every sub-write is idempotent and a crash anywhere leaves
the post still "not done"; the next poll re-enters and completes it. No compensating
deletes, no orphan-marker suppression. This is the evolved house pattern from
Jamestown (strictly safer than external-reference-URL dedup, which an orphan
reference can permanently suppress).

## State cursor vs "no state files"

CLAUDE.md mandates graph-driven dedup and "no state files". The `{page, index}`
cursor is held in **OpenCTI connector state** (`helper.get_state/set_state`, stored
in the platform), not a local file, and is an efficiency layer only: graph-driven
`report.read(id)` remains the correctness backstop and is idempotent even if the
cursor state is lost. This is the same resolution recorded for ScienceDaily.

## Enforcement-gate caveat

As recorded for arXiv and Jamestown: the gate tooling CLAUDE.md names
(`scripts/preflight.py`, the `datamodel/` package, the pytest scaffolding) is absent
from this checkout, and `data_model/` holds `Data_Model_Relationship_Guide5.csv`.
Relationship validation is vacuous here: the connector emits zero relationships
(container-only). Hygiene (pin/base/secrets) checked manually. Flagged, not silently
resolved.

## Cross-connector open item

`OPENCTI_URL` vs `OPENCTI_BASE_URL` naming remains an unresolved cross-connector
decision (CLAUDE.md). This connector follows the prevailing pattern in the existing
render connectors (Jamestown, ScienceDaily) and uses `OPENCTI_URL`; it does not
settle the naming decision.

[ScienceDaily]: ../sciencedaily/
[Jamestown]: ../jamestown/CONNECTOR_SCOPE.md
