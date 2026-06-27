# The Jamestown Foundation OpenCTI Connector

External-import connector that ingests the entire
[Jamestown Foundation](https://jamestown.org) corpus into OpenCTI as Report
containers, one per article, each with the source page attached as a full-fidelity
PDF.

## Functionality

Enumerates every published item across the configured WordPress post types
(`posts`, `brief`, `report`, `interview`, `book`) through the site's WordPress REST
API (`/wp-json/wp/v2/<type>`, ascending by date, paginated to the
`X-WP-TotalPages` boundary) and creates one OpenCTI **Report** per article. Each
Report carries the verbatim title, source publication date (`date_gmt`), the
"The Jamestown Foundation" organization as author, TLP:CLEAR marking, the
`open-source-reporting` report-type, a Medium-band confidence, and an External
Reference to the canonical article URL. The live article is rendered to PDF with
headless Chromium (Playwright) and attached to the Report.

The corpus spans every Jamestown publication series — **Eurasia Daily Monitor,
China Brief, Terrorism Monitor, Militant Leadership Monitor, North Caucasus Weekly,
Terrorism Focus, Prism, Spotlight on Terror, Jamestown Perspectives**, and the rest.
The series, topics, and regions for each article (read from the post's WordPress
`class_list`) are recorded in the Report's External Reference description, preserving
series provenance without fanning out author identities or applying Labels.

Because the REST API supplies title, publication date, and excerpt directly,
Playwright is used **only** to render the page to PDF — there is no on-page metadata
scraping.

## Design philosophy

**Container-only.** The connector creates Report containers and nothing else: no
Domain Objects, no Observables, no Relationships. Jamestown analysis is narrative
geopolitical and counterterrorism reporting; named-entity / IOC extraction is a
separate, out-of-scope downstream phase. Keeping the connector container-only makes
it purely additive to the knowledge graph and prevents it from acting as a
contamination vector, even across the full ~51k-item corpus.

## Collection model

- **Enumeration via the WordPress REST API**, per post type, ascending by date.
- **Positional cursor**, persisted in OpenCTI connector state as
  `{<post_type>: {page, index}}`, advancing one article at a time. A positional
  (page/index) cursor is used rather than a date cursor because ~2,300 legacy
  articles share an identical `1970-01-01` placeholder date (lost in a CMS
  migration) that a date cursor cannot disambiguate. An interrupted multi-day
  backfill resumes within the current page; steady state rests at each type's tail
  page and re-checks it each poll for newly-appended articles. One code path covers
  backfill and steady state.
- **Graph-driven deduplication** via External Reference URL lookup, performed before
  any render. The cursor is the efficiency layer; the graph check is the correctness
  backstop — idempotent even if connector state is lost.
- **Failed render means the article is skipped** (logged, cursor advanced), never a
  Report without its PDF.

## Key decisions

- **Report, not Incident Response.** Jamestown is third-party assertion (external
  intelligence), never first-hand observation. No Sightings.
- **Author is the "The Jamestown Foundation" organization**, never the connector
  service account. A single author for every series; series identity is carried on
  the External Reference, not as an Organization fan-out.
- **TLP:CLEAR** — the content is free and publicly published.
- **Confidence 50 (Medium)** — expert secondary analysis built on primary sources.
- **No Labels** — reserved for explicit collection requirements.

## Configuration

All configuration is supplied via environment variables (in
`docker-compose.override.yml`). Environment variables take precedence over
`config.yml`.

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | string | — | Platform URL (pycti `opencti.url`). |
| `OPENCTI_TOKEN` | string | — | Connector service-account token. |
| `CONNECTOR_ID` | uuid | — | Unique connector ID (`uuidgen`). |
| `CONNECTOR_TYPE` | string | `EXTERNAL_IMPORT` | Connector type. |
| `CONNECTOR_NAME` | string | `The Jamestown Foundation` | Connector name. |
| `CONNECTOR_SCOPE` | string | `jamestown` | Connector scope. |
| `CONNECTOR_LOG_LEVEL` | string | `info` | Log verbosity. |
| `JAMESTOWN_BASE_URL` | string | `https://jamestown.org` | Source site root. |
| `JAMESTOWN_POST_TYPES` | csv | `posts,brief,report,interview,book` | WP post types (rest_base) to enumerate. |
| `JAMESTOWN_PUBLICATIONS` | csv | _(empty)_ | Restrict the `posts` stream to these series slugs (e.g. `tm,mlm,cb`). Empty = all series. Server-side filter; `posts` type only. |
| `JAMESTOWN_POLL_INTERVAL` | int (s) | `86400` | Seconds between full enumeration runs (24h). |
| `JAMESTOWN_REQUEST_DELAY` | int (s) | `2` | Delay between successive renders / API pages. |
| `JAMESTOWN_MAX_REPORTS` | int | `0` | Per-run cap on new Reports across all types. `0` = unlimited. Set small for a bounded test. |
| `PLAYWRIGHT_NAV_TIMEOUT` | int (ms) | `60000` | Page navigation timeout. |
| `JAMESTOWN_RENDER_RETRIES` | int | `3` | Render attempts before skipping an article. |
| `JAMESTOWN_CONFIDENCE` | int | `50` | OpenCTI confidence 0-100 (Medium band). |
| `JAMESTOWN_REPORT_TYPE` | string | `open-source-reporting` | report_type vocabulary value. |
| `JAMESTOWN_TLP` | string | `TLP:CLEAR` | Marking applied to every Report. |
| `JAMESTOWN_AUTHOR_NAME` | string | `The Jamestown Foundation` | Author Organization name. |

### Series slugs (for `JAMESTOWN_PUBLICATIONS`)

`edm` (Eurasia Daily Monitor), `cb` (China Brief), `tm` (Terrorism Monitor),
`mlm` (Militant Leadership Monitor), `ncw` (North Caucasus Weekly),
`tf` (Terrorism Focus), `prism`, `st` (Spotlight on Terror),
`jamestown-perspectives`, `is`/`in-a-fortnight`/`fir`, `hot-issues`, … (the full
list is enumerable at `/wp-json/wp/v2/publications`).

## Deployment

1. Place under `~/opencti-docker/connectors/custom/jamestown/`.
2. Add the service to `docker-compose.override.yml` with real values
   (`OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`).
3. Build with `--no-cache` and bring up; tail logs and watch for the resolved
   author and marking UUIDs, the loaded series-term count, and the per-type
   `resuming at page=…` lines.
4. Validate with a bounded test (`JAMESTOWN_MAX_REPORTS=3`) before the full backfill
   (`=0`). To scope, set `JAMESTOWN_PUBLICATIONS` (e.g. `tm,mlm,cb`) and/or trim
   `JAMESTOWN_POST_TYPES`.

## Known limitations

- **Full backfill is large.** ~51k items at one Playwright render each is a
  multi-day, multi-hundred-GB crawl. This breadth is intentional (see
  `CONNECTOR_SCOPE.md`); narrow with `JAMESTOWN_PUBLICATIONS` / `JAMESTOWN_POST_TYPES`
  if a subset is wanted.
- **Forward-only cursor.** An upstream *deletion* of an old article shifts ascending
  page positions and could skip an item on the affected page; deletions of
  decades-old archive articles are rare. Wiping connector state forces a full,
  graph-idempotent re-enumeration.
- **Legacy dates.** ~2,300 pre-migration posts carry a `1970-01-01` placeholder
  publication date; these are ingested faithfully rather than given a fabricated date.
- **Series filter is `posts`-only.** The custom post types are not series-filtered.
- **Live-page rendering** archives current page state, which can drift from the
  publication snapshot (consent banners, late edits).
- **Cloudflare.** Large first-run backfills may trigger rate limiting or bot
  challenges; the connector backs off, skips a persistently blocked article, and
  picks it up on a later poll.

## License note

Jamestown Foundation content is publicly published. Internal ingestion under
TLP:CLEAR with attribution to the source organization is consistent with fair use of
public OSINT; any future redistribution must respect the publisher's terms.
