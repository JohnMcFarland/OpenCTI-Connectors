# Migration Policy Institute OpenCTI Connector

External-import connector that ingests articles from the
[Migration Policy Institute](https://www.migrationpolicy.org) — independent
research on international migration policy — into OpenCTI as Report containers
with full-fidelity PDF attachments.

## Collection model

MPI runs on Drupal behind an aggressive WAF that blocks all non-browser HTTP
requests. The connector uses Playwright exclusively to walk listing pages at
`/research` and `/news` (0-based `?page=N` pagination), then renders each
article to PDF.

- **Graph-dedup re-walk** with early-stop; no cursor persisted.
- Browser recycled every ~50 renders to control memory.
- Auto-scroll capped at 50,000 px to prevent infinite-scroll hangs.
- Cloudflare challenge detection with automatic retry.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `MPI_BASE_URL` | `https://www.migrationpolicy.org` | Site root |
| `MPI_LISTING_URLS` | `/research,/news` | Comma-separated listing paths |
| `MPI_POLL_INTERVAL` | `21600` | Seconds between runs (6 h) |
| `MPI_REQUEST_DELAY` | `3` | Seconds between page loads |
| `MPI_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `MPI_PLAYWRIGHT_NAV_TIMEOUT` | `60000` | Navigation timeout (ms) |
| `MPI_RENDER_RETRIES` | `3` | Render attempts per article |
| `MPI_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `MPI_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `MPI_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `MPI_AUTHOR_NAME` | `Migration Policy Institute` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set MPI_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
