# SPLC OpenCTI Connector

External-import connector that ingests articles from the
[Southern Poverty Law Center](https://www.splcenter.org) — civil rights
research, hate-group monitoring, and extremism tracking — into OpenCTI as
Report containers with full-fidelity PDF attachments.

## Collection model

SPLC uses Yoast SEO XML sitemaps. The connector walks each sub-sitemap
sequentially and renders every in-scope article URL to PDF.

- **~106,000 URLs** across multiple sub-sitemaps.
- **Positional cursor** `{sitemap_idx, url_idx}` persisted in OpenCTI
  connector state; resumes across restarts.
- **10-second crawl-delay** honored per `robots.txt`.
- Graph dedup via deterministic Report STIX ID skips already-ingested articles.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `SPLC_BASE_URL` | `https://www.splcenter.org` | Site root |
| `SPLC_POLL_INTERVAL` | `86400` | Seconds between runs (24 h) |
| `SPLC_REQUEST_DELAY` | `10` | Seconds between requests (robots.txt crawl-delay) |
| `SPLC_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `SPLC_RENDER_RETRIES` | `3` | Render attempts per article |
| `SPLC_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `SPLC_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `SPLC_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `SPLC_AUTHOR_NAME` | `Southern Poverty Law Center` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set SPLC_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
