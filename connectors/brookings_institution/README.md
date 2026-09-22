# Brookings Institution Foreign Policy -- OpenCTI Connector

EXTERNAL_IMPORT connector that ingests foreign-policy articles from
[brookings.edu](https://www.brookings.edu) as container-only OpenCTI
Reports with WeasyPrint PDFs attached.

## How it works

Brookings runs on WordPress VIP. The connector enumerates articles via
the WP REST API (`/wp-json/wp/v2/article`) in ascending post-ID order
and filters client-side for the foreign-policy topic (ID 69), since
server-side topic filtering is broken. Matched articles are re-fetched
individually for full ACF content, rendered to PDF via WeasyPrint, and
ingested as Reports.

- **Total articles**: ~54,488 site-wide; ~6,636 foreign policy
- **Content source**: `acf.page_layout` blocks (`layout_wysiwyg`)
- **Cursor**: Positional {page, index} with sliding window for WP 100-page cap
- **Dedup**: Deterministic STIX ID (uuid5 on article URL) + graph read check

## Configuration

| Environment variable | config.yml key | Default | Description |
|---|---|---|---|
| `BROOKINGS_INSTITUTION_BASE_URL` | `brookings_institution.base_url` | `https://www.brookings.edu` | Site root URL |
| `BROOKINGS_INSTITUTION_PER_PAGE` | `brookings_institution.per_page` | `100` | Articles per API page (max 100) |
| `BROOKINGS_INSTITUTION_POLL_INTERVAL` | `brookings_institution.poll_interval` | `86400` | Seconds between runs (24h) |
| `BROOKINGS_INSTITUTION_REQUEST_DELAY` | `brookings_institution.request_delay` | `2` | Seconds between requests |
| `BROOKINGS_INSTITUTION_MAX_REPORTS` | `brookings_institution.max_reports` | `0` | Max reports per run (0 = unlimited) |
| `BROOKINGS_INSTITUTION_RENDER_RETRIES` | `brookings_institution.render_retries` | `3` | PDF render retry attempts |
| `BROOKINGS_INSTITUTION_CONFIDENCE` | `brookings_institution.confidence` | `50` | OpenCTI confidence (0-100) |
| `BROOKINGS_INSTITUTION_REPORT_TYPE` | `brookings_institution.report_type` | `open-source-reporting` | Report type vocabulary value |
| `BROOKINGS_INSTITUTION_TLP` | `brookings_institution.tlp` | `TLP:CLEAR` | TLP marking definition |
| `BROOKINGS_INSTITUTION_AUTHOR_NAME` | `brookings_institution.author_name` | `Brookings Institution` | Author Organization name |

## Quick start

```bash
cd connectors/brookings_institution
cp docker-compose.yml docker-compose.override.yml
# Edit docker-compose.override.yml: set OPENCTI_URL, OPENCTI_TOKEN, CONNECTOR_ID
docker compose up -d
```

Set `BROOKINGS_INSTITUTION_MAX_REPORTS=3` for a bounded test run.
