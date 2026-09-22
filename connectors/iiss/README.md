# IISS OpenCTI Connector

External-import connector that ingests articles from the
[International Institute for Strategic Studies](https://www.iiss.org) —
defense, geopolitics, and strategic affairs analysis — into OpenCTI as Report
containers with full-fidelity PDF attachments.

## Collection model

IISS runs on Episerver/Optimizely CMS with an XML sitemap. The connector
parses the sitemap to discover article URLs, then uses Playwright to render
each article to PDF (the site requires a browser for content loading).

- **~70 in-scope articles** out of ~200 total sitemap URLs.
- **No cursor/state**: small corpus means full re-walk each poll cycle with
  graph-driven deduplication via deterministic Report STIX ID.
- Sitemap recursion capped at depth 3.
- Page-fetch retry with exponential backoff.
- Cloudflare challenge detection with automatic retry.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `IISS_BASE_URL` | `https://www.iiss.org` | Site root |
| `IISS_POLL_INTERVAL` | `86400` | Seconds between runs (24 h) |
| `IISS_REQUEST_DELAY` | `3` | Seconds between requests |
| `IISS_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `IISS_PLAYWRIGHT_NAV_TIMEOUT` | `60000` | Navigation timeout (ms) |
| `IISS_RENDER_RETRIES` | `3` | Render attempts per article |
| `IISS_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `IISS_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `IISS_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `IISS_AUTHOR_NAME` | `IISS` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set IISS_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
