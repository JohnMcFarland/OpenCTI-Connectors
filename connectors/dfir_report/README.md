# The DFIR Report OpenCTI Connector

External-import connector that ingests the full historic backlog of incident
reports from [The DFIR Report](https://thedfirreport.com/reports/) into OpenCTI as
Report containers, each with the source page attached as a full-fidelity PDF.

## Functionality

Enumerates every published post through the site's WordPress REST API
(`/wp-json/wp/v2/posts`, paginated to the `X-WP-TotalPages` boundary) and creates
one OpenCTI **Report** per article. Each Report carries the verbatim title, source
publication date (`date_gmt`), the "The DFIR Report" organization as author,
TLP:CLEAR marking, the `open-source-reporting` report-type, a High-band confidence,
and an External Reference to the canonical article URL. The live article is rendered
to PDF with headless Chromium (Playwright) and attached to the Report.

Because the REST API supplies the title, publication date, and excerpt directly,
Playwright is used **only** to render the page to PDF — there is no on-page metadata
scraping. There is no category filter: The DFIR Report's categories are
malware/tool/technique-named rather than a report/non-report split, and the post set
is the entire report corpus, so every post is ingested.

## Design philosophy

**Container-only.** The connector creates Report containers and nothing else: no
Domain Objects, no Observables, no Relationships. DFIR reports are rich in IOCs and
MITRE ATT&CK mappings, but those are defanged inline HTML; automated extraction is a
separate, out-of-scope phase. Keeping this connector container-only makes it purely
additive to the knowledge graph and prevents it from acting as a contamination
vector. Entity-graph construction from these reports is performed downstream by
analysts.

## Key decisions

- **Report, not Incident Response.** The DFIR Report is third-party assertion
  (external intelligence), never first-hand observation by us. No Sightings.
- **Author is the "The DFIR Report" organization**, never the connector service
  account.
- **TLP:CLEAR** — the reports are free and publicly published.
- **Enumeration via the WordPress REST API**, not HTML-archive scraping. The API is
  live here (it was disabled on Bellingcat), so it gives a stable post id, canonical
  link, slug, `date_gmt`, and rendered title/excerpt in one pass.
- **Graph-driven deduplication** via External Reference URL lookup. No local state
  file and no last-processed cursor. Every run enumerates the full post set and skips
  articles already present in the graph, which makes an interrupted backfill
  inherently resumable.
- **Playwright rendering** of the live URL captures the report's 60+ lazy-loaded
  evidence screenshots that an HTML-only renderer would lose.
- **Failed render means the article is skipped**, never a Report without its PDF. The
  skipped article is retried on the next pass via deduplication.

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
| `CONNECTOR_NAME` | string | `The DFIR Report` | Connector name. |
| `CONNECTOR_SCOPE` | string | `dfir-report` | Connector scope. |
| `CONNECTOR_LOG_LEVEL` | string | `info` | Log verbosity. |
| `DFIR_REPORT_BASE_URL` | string | `https://thedfirreport.com` | Source site root. |
| `DFIR_REPORT_POLL_INTERVAL` | int (s) | `86400` | Seconds between full enumeration runs (24h; DFIR publishes ~1-2/month). |
| `DFIR_REPORT_REQUEST_DELAY` | int (s) | `3` | Delay between successive renders / API pages. |
| `DFIR_REPORT_MAX_REPORTS` | int | `0` | Per-run cap on new Reports. `0` = unlimited. Set to a small value for a bounded test run. |
| `PLAYWRIGHT_NAV_TIMEOUT` | int (ms) | `60000` | Page navigation timeout. |
| `DFIR_REPORT_RENDER_RETRIES` | int | `3` | Render attempts before skipping an article. |
| `DFIR_REPORT_CONFIDENCE` | int | `80` | OpenCTI confidence 0-100 (High band). |
| `DFIR_REPORT_TYPE` | string | `open-source-reporting` | report_type vocabulary value. |
| `DFIR_REPORT_TLP` | string | `TLP:CLEAR` | Marking applied to every Report. |

## Deployment

1. Place under `~/opencti-docker/connectors/custom/dfir_report/`.
2. Add the service to `docker-compose.override.yml` with real values
   (`OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`).
3. Build with `--no-cache` and bring up; tail logs and watch for the resolved
   author and marking UUIDs and the backlog count at startup.
4. Validate deduplication with a bounded test (`DFIR_REPORT_MAX_REPORTS=3`) before
   running the full backfill (`=0`).

## Known limitations

- **No in-graph topic faceting.** No Labels are applied; the report corpus is not
  faceted by the site's categories/tags on the resulting Reports.
- **Live-page rendering** archives current page state, which can drift from the
  publication snapshot (consent banners, late edits).
- **Steady-state re-scan.** With no cursor, each poll re-enumerates the full post
  set; dedup makes already-ingested articles cheap to skip.
- **Cloudflare.** Large first-run backfills may trigger rate limiting or bot
  challenges; the connector backs off, skips a persistently blocked article, and
  picks it up on the next daily poll.

## License note

The DFIR Report content is publicly published. Internal ingestion under TLP:CLEAR
with attribution to the source organization is consistent with fair use of public
OSINT; any future redistribution must respect the publisher's terms.
