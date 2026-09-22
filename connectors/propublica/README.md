# ProPublica OpenCTI Connector

External-import connector that ingests articles from
[ProPublica](https://www.propublica.org) — nonprofit investigative journalism
in the public interest — into OpenCTI as Report containers with full-fidelity
PDF attachments.

## Collection model

ProPublica publishes an RSS feed at `/feed/`. The connector re-walks the feed
each poll cycle and uses graph-driven deduplication with early-stop: after
20 consecutive already-known articles (configurable), it assumes nothing new
remains and ends the run.

- **No cursor/state**: graph-dedup re-walk with configurable early-stop
  threshold.
- Podcasts and audio content are filtered out by RSS category tags.
- Dual PDF: one rendered from RSS content, one from the live article HTML.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `PROPUBLICA_BASE_URL` | `https://www.propublica.org` | Site root |
| `PROPUBLICA_FEED_PATH` | `/feed/` | RSS feed path |
| `PROPUBLICA_POLL_INTERVAL` | `86400` | Seconds between runs (24 h) |
| `PROPUBLICA_REQUEST_DELAY` | `2` | Seconds between requests |
| `PROPUBLICA_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `PROPUBLICA_EARLY_STOP` | `20` | Consecutive known articles before stopping |
| `PROPUBLICA_RENDER_RETRIES` | `3` | Render attempts per article |
| `PROPUBLICA_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `PROPUBLICA_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `PROPUBLICA_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `PROPUBLICA_AUTHOR_NAME` | `ProPublica` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set PROPUBLICA_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
