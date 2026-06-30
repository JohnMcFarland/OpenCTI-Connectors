# The Jamestown Foundation OpenCTI Connector

External-import connector that ingests new analytical articles from
[The Jamestown Foundation](https://jamestown.org) into OpenCTI as Report
containers, one per RSS feed item, each with the source page attached as a
full-fidelity PDF.

## Functionality

Polls the site's main RSS feed (`{base_url}/feed/`) on a fixed interval and creates
one OpenCTI **Report** per feed item. Each Report carries the verbatim title, the
source publication date (RSS `pubDate`), the "The Jamestown Foundation" organization
as author, a TLP:CLEAR marking, the `open-source-reporting` report-type, a
Medium-band confidence, and an External Reference to the canonical article URL. The
live article page is rendered to PDF with headless Chromium (Playwright) and attached
to the Report.

The feed fetch uses a plain HTTP client (browser User-Agent); Playwright is used
only to render article pages, never to fetch the feed.

## Collection model (forward-only RSS)

The Jamestown origin (nginx behind Cloudflare) blocks the WordPress REST API
(`/wp-json/`) and the XML sitemaps (`/sitemap*.xml`): both return HTTP 403 to a plain
HTTP client, to headless Chromium, and to a cleared same-origin in-page fetch. The
RSS feed is the only reachable structured surface, and article pages render at 200.

Consequences, stated plainly:

- **Posts stream only.** The main feed is the WordPress posts stream. There is no
  custom-post-type ingestion (brief / report / interview / book) and no per-series
  feed polling.
- **No historical backfill.** RSS exposes only a recent-items window, not the
  archive. Collection is **forward-only from the moment the connector is turned on**.
  Articles published before turn-on are not retrievable on this origin.
- **Burst-day window risk.** The feed window has a fixed depth (a small number of
  most-recent items). If a single interval produces more new articles than fit in the
  window before the next poll, the overflow items roll off the window and are dropped
  silently. The hourly default keeps this margin wide, but a heavy publishing burst
  between two polls can still drop items. This is the connector's one accepted
  failure mode.

### Deduplication and crash-safety

Deduplication keys on a **deterministic Report STIX id** derived from the article URL
(`uuid5` over the URL). Before rendering, the connector checks `report.read(id)` and
skips if the Report already exists (so duplicate feed items never trigger a wasted
render). For a new item it creates the External Reference (upsert-safe), then the
Report (with the deterministic `stix_id`), then attaches the PDF. Because the
existence check keys on the Report id and not on the External Reference, every
sub-write is idempotent: a crash at any point leaves the item still "not done", and
the next poll re-enters and completes it while the item is still in the feed window.
No compensating deletes and no orphan-marker suppression.

## Design philosophy

**Container-only.** The connector creates Report containers and nothing else: no
Domain Objects, no Observables, no Relationships, no Labels. Named-entity / IOC
extraction is a separate, out-of-scope downstream phase. Keeping the connector
container-only makes it purely additive to the knowledge graph and prevents it from
acting as a contamination vector.

Category terms on each feed item are parsed and the distinct set is logged once per
poll cycle for visibility, but they are **not** bound to Reports, Labels, or the
External Reference.

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
| `CONNECTOR_NAME` | string | `The Jamestown Foundation` | Connector name. |
| `CONNECTOR_SCOPE` | string | `jamestown` | Connector scope. |
| `CONNECTOR_LOG_LEVEL` | string | `info` | Log verbosity. |
| `JAMESTOWN_BASE_URL` | string | `https://jamestown.org` | Source site root. |
| `JAMESTOWN_FEED_URL` | string | (empty) | RSS feed URL. Empty resolves to `{base_url}/feed/`. |
| `JAMESTOWN_POLL_INTERVAL` | int (s) | `3600` | Seconds between forward feed polls (1h). |
| `JAMESTOWN_REQUEST_DELAY` | int (s) | `2` | Delay between successive renders. |
| `JAMESTOWN_MAX_REPORTS` | int | `0` | Per-run cap on new Reports. `0` = unlimited. Set small for a bounded test. |
| `PLAYWRIGHT_NAV_TIMEOUT` | int (ms) | `60000` | Page navigation timeout. |
| `JAMESTOWN_RENDER_RETRIES` | int | `3` | Render attempts before skipping an article. |
| `JAMESTOWN_CONFIDENCE` | int | `50` | OpenCTI confidence 0-100 (Medium band). |
| `JAMESTOWN_REPORT_TYPE` | string | `open-source-reporting` | report_type vocabulary value. |
| `JAMESTOWN_TLP` | string | `TLP:CLEAR` | Marking applied to every Report. |
| `JAMESTOWN_AUTHOR_NAME` | string | `The Jamestown Foundation` | Author Organization name. |

## Deployment

1. Place under `~/opencti-docker/connectors/custom/jamestown/`.
2. Add the service to `docker-compose.override.yml` with real values
   (`OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`).
3. Build with `--no-cache` and bring up; tail logs and watch for the resolved author
   and marking UUIDs, the feed item count, and the distinct-categories line.
4. Validate with a bounded test (`JAMESTOWN_MAX_REPORTS=3`) before running unbounded
   (`=0`) on the hourly interval.

## Known limitations

- **Forward-only, no backfill.** Pre-turn-on articles are not retrievable (origin
  blocks the API and sitemaps). See Collection model.
- **Burst-day window risk.** A publishing burst that exceeds the feed window between
  two polls drops the overflow items silently. The hourly poll keeps the margin wide
  but does not eliminate the risk.
- **Posts stream only.** No custom post types and no per-series scoping.
- **Items without a parseable pubDate are skipped** (logged), never dated to
  ingestion time.
- **Live-page rendering** archives current page state, which can drift from the
  publication snapshot (consent banners, late edits).
- **Cloudflare.** A transient challenge backs off and retries; a persistently blocked
  article is skipped and retried on the next poll while it remains in the window.

## License note

Jamestown Foundation content is publicly published. Internal ingestion under
TLP:CLEAR with attribution to the source organization is consistent with fair use of
public OSINT; any future redistribution must respect the publisher's terms.
