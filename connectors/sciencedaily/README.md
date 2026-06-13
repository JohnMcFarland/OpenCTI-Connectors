# ScienceDaily OpenCTI Connector

External-import connector that ingests the **entire ScienceDaily release corpus**
(all topics, 1997 → present) from [ScienceDaily](https://www.sciencedaily.com/) into
OpenCTI as Report containers, each with the source page attached as a full-fidelity PDF.

## Functionality

Enumerates the site's XML sitemap and creates one OpenCTI **Report** per article.
ScienceDaily exposes no content API and only a rolling ~50-item RSS window per topic,
so the sitemap is the only complete enumeration surface:

1. `GET /sitemap-index.xml` → the per-year, gzipped release sitemaps
   (`sitemap-releases-YYYY.xml.gz`, 1997…present).
2. `GET` each yearly sitemap, gunzip, and read every `<loc>` as a canonical article URL.

Collection walks the years **chronologically (oldest → newest)** behind a persisted
cursor `{year, url_index}` in OpenCTI connector state. The cursor advances one article at
a time, so an interrupted backfill resumes within a few articles rather than restarting.
The same cursor drives steady state: once it reaches the newest year, each poll
re-enumerates that year and the cursor picks up freshly-appended articles, rolling onto a
new yearly sitemap when one appears. There is **one uniform code path** for backfill and
steady state.

Each Report carries the page title, the publication date, the "ScienceDaily" organization
as author, TLP:CLEAR marking, the `open-source-reporting` report-type, a Medium-band
confidence, and an External Reference to the canonical article URL. The live article is
rendered to PDF with headless Chromium (Playwright) and attached to the Report.

Per-article metadata is **derived, not fetched separately**:
- **Publication date** comes from the URL itself
  (`/releases/YYYY/MM/<YYMMDDHHMMSS>.htm`) — no extra request.
- **Title and description** are read from the rendered DOM during the same Playwright pass
  that produces the PDF (`document.title` minus the ` -- ScienceDaily` suffix; the page's
  meta description / `og:description`).

## ⚠️ Scale

ScienceDaily publishes across **all** science domains, not just computing. The full corpus
is **~250,000–350,000 articles** (measured: 2005 ≈ 6.7k, 2015 ≈ 23.9k, 2025 ≈ 6.8k). A full
backfill therefore means **~300k PDF renders (~1–2 weeks of polite crawling)** and
**~150–600 GB of PDFs** in OpenCTI's object store, the majority of which is general-science
news with no CTI relevance. Because the connector is container-only it cannot contaminate
the graph at any scale — the cost is purely volume, storage, and time.

To scope the corpus down, set `SCIENCEDAILY_BACKFILL_START_YEAR` (e.g. `2020`) or run a
bounded test with `SCIENCEDAILY_MAX_REPORTS`.

## Design philosophy

**Container-only.** The connector creates Report containers and nothing else: no Domain
Objects, no Observables, no Relationships. ScienceDaily content is research news with no
extractable CTI entities (no IOCs, no threat actors), so a container-only design is both the
correct shape per the data model and a guarantee that the connector is purely additive and
can never act as a graph-contamination vector.

## Key decisions

- **Report, not Incident Response.** ScienceDaily is third-party assertion (external
  intelligence), never first-hand observation by us. No Sightings.
- **Author is the "ScienceDaily" organization**, never the connector service account.
- **TLP:CLEAR** — the articles are free and publicly published.
- **Enumeration via the XML sitemap**, not RSS or HTML scraping. RSS only exposes a rolling
  ~50-item window per topic; the sitemap is the only complete historic surface.
- **Chronological cursor + graph-driven deduplication.** The persisted `{year, url_index}`
  cursor is the efficiency layer (avoids re-reading the corpus every poll); the External
  Reference URL lookup is the correctness backstop (idempotent even if state is lost).
- **Playwright rendering** of the live URL captures the full article body, figures, source
  institution, and journal citation that the sitemap and feed summaries lack.
- **Failed render means the article is skipped** (logged), never a Report without its PDF.

## Configuration

All configuration is supplied via environment variables (in
`docker-compose.override.yml`). Environment variables take precedence over `config.yml`.

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | string | — | Platform URL (pycti `opencti.url`). |
| `OPENCTI_TOKEN` | string | — | Connector service-account token. |
| `CONNECTOR_ID` | uuid | — | Unique connector ID (`uuidgen`). |
| `CONNECTOR_TYPE` | string | `EXTERNAL_IMPORT` | Connector type. |
| `CONNECTOR_NAME` | string | `ScienceDaily` | Connector name. |
| `CONNECTOR_SCOPE` | string | `sciencedaily` | Connector scope. |
| `CONNECTOR_LOG_LEVEL` | string | `info` | Log verbosity. |
| `SCIENCEDAILY_BASE_URL` | string | `https://www.sciencedaily.com` | Source site root. |
| `SCIENCEDAILY_POLL_INTERVAL` | int (s) | `86400` | Seconds between enumeration runs (24h). |
| `SCIENCEDAILY_REQUEST_DELAY` | int (s) | `2` | Delay between successive renders / fetches. |
| `SCIENCEDAILY_MAX_REPORTS` | int | `0` | Per-run cap on new Reports. `0` = unlimited. Set small for a bounded test run. |
| `SCIENCEDAILY_BACKFILL_START_YEAR` | int | `0` | Earliest year to backfill. `0` = earliest year in the sitemap (full corpus). |
| `PLAYWRIGHT_NAV_TIMEOUT` | int (ms) | `60000` | Page navigation timeout. |
| `SCIENCEDAILY_RENDER_RETRIES` | int | `3` | Render attempts before skipping an article. |
| `SCIENCEDAILY_CONFIDENCE` | int | `50` | OpenCTI confidence 0-100 (Medium band). |
| `SCIENCEDAILY_REPORT_TYPE` | string | `open-source-reporting` | report_type vocabulary value. |
| `SCIENCEDAILY_TLP` | string | `TLP:CLEAR` | Marking applied to every Report. |

## Deployment

1. Place under `~/opencti-docker/connectors/custom/sciencedaily/`.
2. Add the service to `docker-compose.override.yml` with real values
   (`OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`).
3. Build with `--no-cache` and bring up; tail logs and watch for the resolved author and
   marking UUIDs, the release-year count, and the `year=/url_index=` cursor progress.
4. Validate with a bounded test (`SCIENCEDAILY_MAX_REPORTS=3`) before running the full
   backfill (`=0`). To scope down, set `SCIENCEDAILY_BACKFILL_START_YEAR`.

## Known limitations

- **No in-graph topic faceting.** The sitemap carries no category, so no Labels are applied;
  the corpus is not faceted by ScienceDaily's topics on the resulting Reports.
- **Live-page rendering** archives current page state, which can drift from the publication
  snapshot (consent banners, late edits, related-story modules).
- **Forward-only cursor.** A render that fails all retries is permanently skipped (logged),
  and the cursor does not revisit completed positions, so an article added to a *prior* year's
  sitemap after the cursor has passed that year is not picked up. The graph-dedup backstop only
  re-checks years the cursor re-scans (the current year).
- **Steady-state re-scan cost.** Each poll re-enumerates the current year and issues one
  dedup read per URL from the cursor onward; bounded to the current year, not the full corpus.

## License note

ScienceDaily content is publicly published. Internal ingestion under TLP:CLEAR with
attribution to the source publisher is consistent with fair use of public OSINT; any future
redistribution must respect the publisher's and the original institutions' terms.
