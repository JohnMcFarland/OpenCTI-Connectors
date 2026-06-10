# Bellingcat OpenCTI Connector

External-import connector that ingests Bellingcat investigative output into
OpenCTI as Report containers, each with the source article attached as a
full-fidelity PDF.

## Functionality

Polls the Bellingcat WordPress REST API (`/wp-json/wp/v2/posts`), filtered to a
configurable set of categories, and creates one OpenCTI **Report** per post.
Each Report carries the verbatim title, source publication date, the Bellingcat
organization as author, TLP:CLEAR marking, the `open-source-reporting`
report-type, a Medium-band confidence, and an External Reference to the
canonical article URL. The live article is rendered to PDF with headless
Chromium (Playwright) and attached to the Report.

## Design philosophy

**Container-only.** The connector creates Report containers and nothing else:
no Domain Objects, no Observables, no Relationships. Bellingcat content is
narrative investigative OSINT, not an indicator feed. Automated entity
extraction is a separate, out-of-scope phase. Keeping this connector
container-only makes it purely additive to the knowledge graph and prevents it
from acting as a contamination vector. Entity-graph construction from these
reports is performed downstream by analysts.

## Key decisions

- **Report, not Incident Response.** Bellingcat is third-party assertion
  (external intelligence), never first-hand observation. No Sightings.
- **Author is the Bellingcat organization**, never the individual byline and
  never the connector service account.
- **Graph-driven deduplication** via External Reference URL lookup. No local
  state file and no last-processed cursor. Every run enumerates the full
  in-scope set and skips posts already present in the graph, which makes an
  interrupted backfill inherently resumable.
- **Playwright rendering** of the live URL captures JavaScript-embedded
  evidence (maps, satellite imagery, embeds) that an HTML-only renderer would
  lose. For this connector the standard weasyprint render-timeout wrap does not
  apply; Playwright's navigation timeout replaces it.
- **Failed render means the post is skipped**, never a Report without its PDF.
  The skipped post is retried on the next pass via deduplication.

## Configuration

All configuration is supplied via environment variables (in
`docker-compose.override.yml`). Environment variables take precedence over
`config.yml`.

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | string | — | Platform URL (pycti `opencti.url`). Canonical per resolution A. |
| `OPENCTI_TOKEN` | string | — | Connector service-account token. |
| `CONNECTOR_ID` | uuid | — | Unique connector ID (`uuidgen`). |
| `CONNECTOR_TYPE` | string | `EXTERNAL_IMPORT` | Connector type. |
| `CONNECTOR_NAME` | string | `Bellingcat` | Connector name. |
| `CONNECTOR_SCOPE` | string | `bellingcat` | Connector scope. |
| `CONNECTOR_LOG_LEVEL` | string | `info` | Log verbosity. |
| `BELLINGCAT_BASE_URL` | string | `https://www.bellingcat.com` | Source site root. |
| `BELLINGCAT_CATEGORIES` | csv | `news,open-source-in-short,resources` | Category **slugs** to ingest. Provisional; confirmed against the live categories endpoint at init. Unresolved slugs are logged and skipped. |
| `BELLINGCAT_POLL_INTERVAL` | int (s) | `21600` | Seconds between full enumeration runs. |
| `BELLINGCAT_REQUEST_DELAY` | int (s) | `3` | Delay between successive renders. |
| `BELLINGCAT_MAX_POSTS` | int | `0` | Per-run cap on new Reports. `0` = unlimited. Set to a small value for a bounded test run. |
| `PLAYWRIGHT_NAV_TIMEOUT` | int (ms) | `60000` | Page navigation timeout. |
| `BELLINGCAT_RENDER_RETRIES` | int | `3` | Render attempts before skipping a post. |
| `BELLINGCAT_CONFIDENCE` | int | `60` | OpenCTI confidence 0-100 (Medium band). |
| `BELLINGCAT_REPORT_TYPE` | string | `open-source-reporting` | report_type vocabulary value. |
| `BELLINGCAT_TLP` | string | `TLP:CLEAR` | Marking applied to every Report. |

## Deployment

1. Place under `~/opencti-docker/connectors/custom/Bellingcat/`.
2. Add the service to `docker-compose.override.yml` with real values
   (`OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`).
3. Build with `--no-cache` and bring up; tail logs and watch for the resolved
   author, marking, and category IDs at startup.
4. Validate deduplication with a bounded test (`BELLINGCAT_MAX_POSTS=3`) before
   running the full backfill.

## Known limitations

- **No in-graph topic faceting.** No Labels are applied, so the category scope
  is a collection-time filter only and is not queryable on the Reports.
- **Live-page rendering** archives current page state, which can drift from the
  API content snapshot (consent banners, late edits).
- **Steady-state re-scan.** With no cursor, each poll re-enumerates the full
  in-scope post set; dedup makes already-ingested posts cheap to skip.
- **Cloudflare.** Large first-run backfills may trigger rate limiting or bot
  challenges; the connector backs off and the run is resumable.
- **Category slugs are provisional** until confirmed against the live
  categories endpoint.

## License note

Bellingcat content is published under a Creative Commons license (verify the
exact variant against the publisher's terms). Internal ingestion under
TLP:CLEAR with attribution is consistent with CC terms; any future
redistribution must respect NonCommercial/NoDerivatives conditions if present.
