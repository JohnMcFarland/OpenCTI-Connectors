# World Health Organization OpenCTI Connector

External-import connector that ingests news articles from
[WHO News Room](https://www.who.int/news) -- the World Health Organization's
public news feed covering global health events, disease outbreaks, policy
statements, and organizational updates -- into OpenCTI as Report containers
with full-fidelity PDF attachments.

## Collection model

The WHO website runs on Sitefinity CMS and exposes an OData REST API at
`/api/news/newsitems`. The API returns metadata only (title, publication
date, URL slug); article body content is fetched from the rendered HTML page.

- **~6,493 articles** spanning 1996 to present.
- **Ascending datetime cursor**: enumeration walks items ordered by
  `PublicationDateAndTime asc`. The cursor stores the last processed
  publication date; subsequent runs filter with `$filter=PublicationDateAndTime gt {cursor}`.
- **Content fetch**: plain HTTP GET on each article URL (no Playwright needed).
  BeautifulSoup extracts the article body; WeasyPrint renders to PDF.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `WORLD_HEALTH_ORGANIZATION_BASE_URL` | `https://www.who.int` | Site root |
| `WORLD_HEALTH_ORGANIZATION_POLL_INTERVAL` | `86400` | Seconds between runs (24 h) |
| `WORLD_HEALTH_ORGANIZATION_REQUEST_DELAY` | `2` | Seconds between requests |
| `WORLD_HEALTH_ORGANIZATION_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `WORLD_HEALTH_ORGANIZATION_RENDER_RETRIES` | `3` | Render attempts per article |
| `WORLD_HEALTH_ORGANIZATION_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `WORLD_HEALTH_ORGANIZATION_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `WORLD_HEALTH_ORGANIZATION_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `WORLD_HEALTH_ORGANIZATION_AUTHOR_NAME` | `World Health Organization` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set WORLD_HEALTH_ORGANIZATION_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
