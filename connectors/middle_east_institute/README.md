# Middle East Institute OpenCTI Connector

External-import connector that ingests articles from the
[Middle East Institute](https://www.mei.edu) — policy research and analysis on
the Middle East and North Africa — into OpenCTI as Report containers with
full-fidelity PDF attachments.

## Collection model

MEI is behind Cloudflare with no public API, RSS feed, or XML sitemap. The
connector uses Playwright to walk listing pages at `/publications` and
`/experts/articles`, then renders each article to PDF.

- **Graph-dedup re-walk** with early-stop; no cursor persisted.
- Events, exhibitions, podcasts, audio, and video content are skipped.
- Browser recycled every ~50 renders to control memory.
- Cloudflare challenge detection with automatic retry.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `MEI_BASE_URL` | `https://www.mei.edu` | Site root |
| `MEI_LISTING_URLS` | `/publications,/experts/articles` | Comma-separated listing paths |
| `MEI_POLL_INTERVAL` | `21600` | Seconds between runs (6 h) |
| `MEI_REQUEST_DELAY` | `3` | Seconds between page loads |
| `MEI_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `MEI_PLAYWRIGHT_NAV_TIMEOUT` | `60000` | Navigation timeout (ms) |
| `MEI_RENDER_RETRIES` | `3` | Render attempts per article |
| `MEI_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `MEI_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `MEI_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `MEI_AUTHOR_NAME` | `Middle East Institute` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set MEI_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
