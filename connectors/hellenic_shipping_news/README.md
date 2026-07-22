# Hellenic Shipping News OpenCTI Connector

External-import connector that ingests articles from
[Hellenic Shipping News](https://www.hellenicshippingnews.com) into OpenCTI as
Report containers, one per post, each with the source page attached as a
full-fidelity PDF.

## Functionality

Enumerates the site's WordPress REST API on a fixed interval and creates one
OpenCTI **Report** per in-scope post. Each Report carries the verbatim title, the
post excerpt as its description, the source publication date, the "Hellenic
Shipping News" organization as author, a TLP:CLEAR marking, the
`open-source-reporting` report-type, a Medium-band confidence, and an External
Reference to the canonical article URL. The live article page is rendered to PDF
with headless Chromium (Playwright) and attached to the Report.

REST enumeration uses a plain HTTP client (browser User-Agent); Playwright is used
only to render article pages, never to enumerate.

## Collection model (category-filtered REST backfill + steady state)

Hellenic Shipping News is a WordPress site (single post type `post`, ~94k posts).
Unlike the Jamestown origin, this origin leaves the structured surfaces open to a
browser-UA client (`/wp-json/`, `/feed/`, `/sitemap.xml` all return 200), so the
REST API is used as the enumeration surface: it supports server-side category
filtering and stable ordering.

- **Category-scoped, not full corpus.** The bulk of the ~94k posts are routine
  daily/weekly market-data tickers (currency ratings, bunker prices, index quotes)
  with no intelligence value. Collection is scoped to a fixed category allowlist
  (`HSN_CATEGORIES`), applied server-side via the REST `categories` parameter. The
  default allowlist is three tiers, 14 categories (~82,247 posts full corpus /
  ~17k for a one-year backfill):
  - *Security / legal / risk*: Piracy and Security News (109), Shipping Law News
    (118), Marine Insurance P&I Club News (115).
  - *Geopolitics / energy / economy*: World Economy News (107), Oil & Companies
    News (103), Commodity News (101), IMF/OECD News (125), General Energy News
    (108).
  - *Shipping operations*: International Shipping News (27), Port News (112),
    Shipping: Emission Possible (124), Freight News (113), Shipbuilding News (105),
    Dry Bulk Market (122).

  Report/Analysis (120) was evaluated and excluded: its posts are 100% recurring
  weekly time-charter-estimate tables (market data), not analysis.

  The Greek-market/namesake tier, the Greek "front page" catch-all, and every pure
  market-data ticker/periodic-report category are excluded. Change the scope by
  editing `HSN_CATEGORIES` (no code change).
- **Title-level exclusion (`HSN_TITLE_EXCLUDE`).** Some recurring machine-generated
  "sub reports" share a category with substantive posts and carry no distinguishing
  tag or sub-category, so they cannot be separated server-side. `HSN_TITLE_EXCLUDE`
  is a single case-insensitive regex matched against each post's title; matches are
  skipped before render (empty = off). **The default is enabled** and drops the
  recurring data/listing series (~2.7/day, ~1k/yr, ~4–5% of inflow):
  - Baltic Dry Index daily tickers (~56% of Dry Bulk Market / 122),
  - "HOT PORT NEWS from GAC" port bulletins,
  - Drewry / Intra-Asia container indices and weekly "Container Report" issues,
  - "ENGINE:" bunker fuel-availability outlooks,
  - "Bidding Announcement" vessel-auction listings,
  - Fujairah fuel-oil inventory reports.

  Editorial recurring series are intentionally **kept**: ING's "The Commodities
  Feed", "The Week in Alt Fuels", and GTT newbuild-order PRs. Substantive dry-bulk
  content (Capesize/Panamax commentary, coal/iron-ore/grain trade flows) is
  unaffected. Because the filter does not change the set or ordering of posts the API
  returns, it is applied to the same enumerated stream and does **not** reset the
  positional cursor — editing it takes effect going forward (posts already scanned
  past are not retroactively revisited unless you reset connector state). An invalid
  regex fails closed (the connector refuses to start). Each run logs the count it
  dropped (`N title-excluded`).
- **Bounded or full backfill.** Enumeration walks the filtered posts in ascending
  post-id order behind a persisted positional `{page, index}` cursor. Ascending id
  (not date) is used because thousands of legacy posts carry a broken placeholder
  date (year `-0001`) that a date cursor cannot disambiguate, whereas post ids are
  monotonic and stable. New posts receive the highest ids and land on the last
  page, so the same cursor drives both backfill and steady state: once it reaches
  the tail it rests there and each subsequent poll picks up freshly-appended posts.
- **Backfill depth (`HSN_BACKFILL_START_DATE`).** How far back the backfill reaches
  is bounded by this date, passed to the origin as the WordPress `after` filter.
  Empty = the full filtered corpus (~82.2k posts). Set an **absolute** date for a
  bounded window — e.g. `2023-07-19` for a two-year backfill at deployment (~30k
  posts). It must be absolute, not a rolling window: the positional id cursor is
  only stable if the filtered set is stable across restarts, so a drifting floor
  would silently mis-position it. The floor also excludes the `-0001` placeholder
  posts. Changing the floor (or the category allowlist) resets the cursor to page 1,
  since both define the filtered set the cursor indexes into; graph dedup makes the
  re-scan safe (already-ingested posts are skipped).
- **Crawl-delay honored.** The site's `robots.txt` requests `Crawl-Delay: 30` and
  its content-signal permits reference use. `HSN_REQUEST_DELAY` defaults to **30
  seconds**. At that delay the full ~82.2k-post backfill is roughly a month-long
  continuous crawl (a two-year `HSN_BACKFILL_START_DATE` floor cuts it to ~30k); it
  is fully resumable from the state cursor across restarts.

### Deduplication and crash-safety

Deduplication keys on a **deterministic Report STIX id** derived from the article
URL (`uuid5` over the URL). Before rendering, the connector checks
`report.read(id)` and skips if the Report already exists (so re-read posts never
trigger a wasted render). For a new post it creates the External Reference
(upsert-safe), then the Report (with the deterministic `stix_id`), then attaches
the PDF. Because the existence check keys on the Report id and not on the External
Reference, every sub-write is idempotent: a crash at any point leaves the post still
"not done", and the next poll re-enters and completes it. The graph lookup is the
correctness backstop (idempotent even if the cursor state is lost); the `{page,
index}` cursor is the efficiency layer that avoids re-reading the whole corpus every
poll.

## Design philosophy

**Container-only.** The connector creates Report containers and nothing else: no
Domain Objects, no Observables, no Relationships, no Labels. Named-entity / IOC
extraction is a separate, out-of-scope downstream phase. Keeping the connector
container-only makes it purely additive to the knowledge graph and prevents it from
acting as a contamination vector. Zero relationships are emitted, so the relationship
allowlist is not implicated.

Category ids drive **server-side filtering only**; they are not bound to Reports,
Labels, or the External Reference.

## Configuration

All configuration is supplied via environment variables (in
`docker-compose.override.yml`). Environment variables take precedence over
`config.yml`.

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | string | (none) | Platform URL (pycti `opencti.url`). |
| `OPENCTI_TOKEN` | string | (none) | Connector service-account token. |
| `CONNECTOR_ID` | uuid | (none) | Unique connector ID (`uuidgen`). |
| `CONNECTOR_TYPE` | string | `EXTERNAL_IMPORT` | Connector type. |
| `CONNECTOR_NAME` | string | `Hellenic Shipping News` | Connector name. |
| `CONNECTOR_SCOPE` | string | `hellenic_shipping_news` | Connector scope. |
| `CONNECTOR_LOG_LEVEL` | string | `info` | Log verbosity. |
| `HSN_BASE_URL` | string | `https://www.hellenicshippingnews.com` | Source site root. |
| `HSN_CATEGORIES` | csv | `27,101,103,105,107,108,109,112,113,115,118,122,124,125` | WordPress category ids to ingest (server-side OR filter). |
| `HSN_BACKFILL_START_DATE` | ISO date | (empty) | Backfill floor. Empty = full filtered corpus. Absolute date (e.g. `2023-07-19`) bounds how far back the backfill reaches. Invalid value fails closed. |
| `HSN_TITLE_EXCLUDE` | regex | (see below) | Case-insensitive regex; posts whose title matches are skipped before render. Ships enabled, dropping recurring ticker/listing series (BDI, GAC port news, container indices, ENGINE bunker outlooks, auction listings, Fujairah inventories). Set empty to disable. Invalid regex fails closed. |
| `HSN_PER_PAGE` | int | `100` | REST page size (capped at 100). |
| `HSN_POLL_INTERVAL` | int (s) | `86400` | Seconds between enumeration runs (24h). |
| `HSN_REQUEST_DELAY` | int (s) | `30` | Delay between successive renders. Honors robots `Crawl-Delay: 30`. |
| `HSN_MAX_REPORTS` | int | `0` | Per-run cap on new Reports. `0` = unlimited. Set small for a bounded test. |
| `PLAYWRIGHT_NAV_TIMEOUT` | int (ms) | `60000` | Page navigation timeout. |
| `HSN_RENDER_RETRIES` | int | `3` | Render attempts before skipping a post. |
| `HSN_CONFIDENCE` | int | `50` | OpenCTI confidence 0-100 (Medium band). |
| `HSN_REPORT_TYPE` | string | `open-source-reporting` | report_type vocabulary value. |
| `HSN_TLP` | string | `TLP:CLEAR` | Marking applied to every Report. |
| `HSN_AUTHOR_NAME` | string | `Hellenic Shipping News` | Author Organization name. |

## Deployment

1. Place under `~/opencti-docker/connectors/custom/hellenic_shipping_news/`.
2. Add the service to `docker-compose.override.yml` with real values
   (`OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`).
3. Build with `--no-cache` and bring up; tail logs and watch for the resolved
   author and marking UUIDs, the category allowlist line, and the in-scope post
   count.
4. Validate with a bounded test (`HSN_MAX_REPORTS=3`) before running unbounded
   (`=0`). The state cursor makes the long backfill fully resumable.

## Known limitations

- **Scoped by category, by design.** Only `HSN_CATEGORIES` posts are ingested;
  everything else (including all market-data tickers) is skipped. Widen the scope by
  editing the variable.
- **Legacy placeholder dates.** A minority of in-scope posts carry the WordPress
  `-0001` placeholder date with no other date signal; these are dated to ingestion
  time with a warning rather than dropped.
- **Live-page rendering** archives current page state, which can drift from the
  publication snapshot (consent banners, late edits).
- **Cloudflare.** A transient challenge backs off and retries; a persistently blocked
  post is skipped (logged) and the cursor advances past it so it does not block the
  backfill.
- **Long backfill.** At the 30s crawl-delay, the full ~82.2k-post backfill runs for
  roughly a month (a two-year floor cuts it to ~30k / a couple of weeks). It is
  resumable from the state cursor and runs unattended.

## Policy note

The site's `robots.txt` disallows `ClaudeBot` and sets `ai-train=no`, but signals
`search=yes` and `use=reference` and requests `Crawl-Delay: 30`. This connector is
not ClaudeBot and does not train any model: it performs reference-use ingestion into
a private OpenCTI graph under a plain browser User-Agent, and honors the 30-second
crawl delay by default. Hellenic Shipping News content is publicly published;
internal ingestion under TLP:CLEAR with attribution to the source is consistent with
the site's stated reference-use signal. Any future redistribution must respect the
publisher's terms.
