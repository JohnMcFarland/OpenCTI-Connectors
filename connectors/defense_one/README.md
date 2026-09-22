# Defense One OpenCTI Connector

External-import connector that ingests articles from
[Defense One](https://www.defenseone.com) — U.S. defense, national security,
and military policy news — into OpenCTI as Report containers with full-fidelity
PDF attachments.

## Collection model

Defense One publishes an RSS feed at `/rss/all/` containing the most recent
articles (~21 items). The connector re-walks the feed each poll cycle and uses
graph-driven deduplication (deterministic Report STIX ID) to skip articles
already present.

- **No cursor/state**: newest-first feed with pure graph-dedup re-walk.
- Dual PDF: one rendered from RSS content, one from the live article HTML.
- Content selector: `.content-body`; ads, related-stories, nav, and comments
  are stripped before render.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `DEFENSE_ONE_BASE_URL` | `https://www.defenseone.com` | Site root |
| `DEFENSE_ONE_RSS_URL` | `https://www.defenseone.com/rss/all/` | RSS feed URL |
| `DEFENSE_ONE_POLL_INTERVAL` | `86400` | Seconds between runs (24 h) |
| `DEFENSE_ONE_REQUEST_DELAY` | `1` | Seconds between requests (robots.txt crawl-delay) |
| `DEFENSE_ONE_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `DEFENSE_ONE_RENDER_RETRIES` | `3` | Render attempts per article |
| `DEFENSE_ONE_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `DEFENSE_ONE_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `DEFENSE_ONE_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `DEFENSE_ONE_AUTHOR_NAME` | `Defense One` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set DEFENSE_ONE_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
