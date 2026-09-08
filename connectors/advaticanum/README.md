# AdVaticanum OpenCTI Connector

External-import connector that ingests articles from
[AdVaticanum](https://advaticanum.com) — a Catholic news and analysis site
covering the Vatican and the wider Church — into OpenCTI as Report containers
with full-fidelity PDF attachments.

## Collection model

AdVaticanum is a Next.js site behind Cloudflare. There is no public API, RSS
feed, or XML sitemap. The connector uses Playwright to enumerate articles from
the `/category/latest/` listing pages and render each article to PDF.

- **~450 articles** across ~75 listing pages (6 per page, newest-first).
- **Deduplication** is graph-driven via deterministic Report STIX ID. No
  cursor/state is persisted; each poll re-walks the listing and stops early
  when an entire page of articles is already present.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `ADVATICANUM_BASE_URL` | `https://advaticanum.com` | Site root |
| `ADVATICANUM_POLL_INTERVAL` | `21600` | Seconds between runs (6 h) |
| `ADVATICANUM_REQUEST_DELAY` | `3` | Seconds between renders |
| `ADVATICANUM_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `ADVATICANUM_PLAYWRIGHT_NAV_TIMEOUT` | `60000` | Navigation timeout (ms) |
| `ADVATICANUM_RENDER_RETRIES` | `3` | Render attempts per article |
| `ADVATICANUM_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `ADVATICANUM_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `ADVATICANUM_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `ADVATICANUM_AUTHOR_NAME` | `AdVaticanum` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set ADVATICANUM_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
