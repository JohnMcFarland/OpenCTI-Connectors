# Hungarian Conservative OpenCTI Connector

External-import connector that ingests articles from
[hungarianconservative.com](https://www.hungarianconservative.com) as container-only
OpenCTI Reports with attached PDFs.

## Quick start

```bash
cd connectors/hungarian_conservative
cp docker-compose.yml docker-compose.override.yml
# Edit docker-compose.override.yml: fill in OPENCTI_URL, OPENCTI_TOKEN, CONNECTOR_ID
docker compose up -d
```

Set `HUNGARIAN_CONSERVATIVE_MAX_REPORTS=3` for a bounded test before the full backfill.

## How it works

1. Enumerates all posts via the WordPress REST API in ascending post-ID order
2. Checks each post against the OpenCTI graph (deterministic STIX ID from the URL)
3. Renders new articles to PDF from the REST API content using WeasyPrint
4. Creates a Report container with the PDF attached

The connector persists a positional cursor in OpenCTI connector state and resumes
from where it left off across restarts.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `HUNGARIAN_CONSERVATIVE_BASE_URL` | `https://www.hungarianconservative.com` | Site root |
| `HUNGARIAN_CONSERVATIVE_PER_PAGE` | `100` | Posts per API page (max 100) |
| `HUNGARIAN_CONSERVATIVE_POLL_INTERVAL` | `86400` | Seconds between runs (24h) |
| `HUNGARIAN_CONSERVATIVE_REQUEST_DELAY` | `2` | Seconds between renders |
| `HUNGARIAN_CONSERVATIVE_MAX_REPORTS` | `0` | Per-run cap (0 = unlimited) |
| `HUNGARIAN_CONSERVATIVE_RENDER_RETRIES` | `3` | Render attempts before skip |
| `HUNGARIAN_CONSERVATIVE_CONFIDENCE` | `50` | Report confidence (0-100) |
| `HUNGARIAN_CONSERVATIVE_REPORT_TYPE` | `open-source-reporting` | Report type |
| `HUNGARIAN_CONSERVATIVE_TLP` | `TLP:CLEAR` | TLP marking |
| `HUNGARIAN_CONSERVATIVE_AUTHOR_NAME` | `Hungarian Conservative` | Author identity |
