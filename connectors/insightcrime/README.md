# InSight Crime OpenCTI Connector

External-import connector that ingests articles from
[InSight Crime](https://insightcrime.org) — investigative journalism covering
organized crime in Latin America and the Caribbean — into OpenCTI as Report
containers with full-fidelity PDF attachments.

## Collection model

InSight Crime runs on WordPress with the Newspack theme. The connector
enumerates all posts via the WP REST API (`/wp-json/wp/v2/posts`) in
ascending post-ID order with a sliding-window cursor.

- **Ascending-ID cursor** persisted in OpenCTI connector state; resumes
  across restarts.
- Podcasts and audio content are filtered out by category.
- Dual PDF: one rendered from the API content, one from the live HTML.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `INSIGHTCRIME_BASE_URL` | `https://insightcrime.org` | Site root |
| `INSIGHTCRIME_PER_PAGE` | `100` | Posts per API page (max 100) |
| `INSIGHTCRIME_POLL_INTERVAL` | `86400` | Seconds between runs (24 h) |
| `INSIGHTCRIME_REQUEST_DELAY` | `2` | Seconds between requests |
| `INSIGHTCRIME_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `INSIGHTCRIME_RENDER_RETRIES` | `3` | Render attempts per article |
| `INSIGHTCRIME_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `INSIGHTCRIME_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `INSIGHTCRIME_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `INSIGHTCRIME_AUTHOR_NAME` | `InSight Crime` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set INSIGHTCRIME_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
