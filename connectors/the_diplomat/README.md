# The Diplomat OpenCTI Connector

External-import connector that ingests articles from
[The Diplomat](https://thediplomat.com) — Asia-Pacific geopolitics, security,
and diplomacy analysis — into OpenCTI as Report containers with full-fidelity
PDF attachments.

## Collection model

The Diplomat publishes a paginated RSS feed at `/feed/?paged=N`. The connector
walks pages until the feed is empty and uses graph-driven deduplication to skip
articles already present.

- **No cursor/state**: full re-walk with graph dedup each poll cycle.
- **Playwright hybrid**: RSS provides article metadata; Playwright renders the
  live article page to PDF (the site is behind Cloudflare).
- Browser recycled every ~50 renders to control memory.
- Dual PDF: one rendered from RSS content (WeasyPrint), one from the live page
  (Playwright navigation + WeasyPrint).
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `THE_DIPLOMAT_BASE_URL` | `https://thediplomat.com` | Site root |
| `THE_DIPLOMAT_POLL_INTERVAL` | `86400` | Seconds between runs (24 h) |
| `THE_DIPLOMAT_REQUEST_DELAY` | `3` | Seconds between Playwright navigations |
| `THE_DIPLOMAT_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `THE_DIPLOMAT_PLAYWRIGHT_NAV_TIMEOUT` | `60000` | Navigation timeout (ms) |
| `THE_DIPLOMAT_RENDER_RETRIES` | `3` | Render attempts per article |
| `THE_DIPLOMAT_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `THE_DIPLOMAT_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `THE_DIPLOMAT_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `THE_DIPLOMAT_AUTHOR_NAME` | `The Diplomat` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set THE_DIPLOMAT_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
