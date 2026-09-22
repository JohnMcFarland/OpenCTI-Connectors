# Chalkbeat OpenCTI Connector

External-import connector that ingests articles from [Chalkbeat](https://www.chalkbeat.org) as container-only OpenCTI Reports with WeasyPrint-rendered PDFs.

## Overview

Chalkbeat is a nonprofit education news organization covering schools and education policy across the United States. This connector enumerates the full Chalkbeat article corpus (~33,000+ articles from 2003 to present) and creates one OpenCTI Report per article with an attached PDF.

### Collection model

Chalkbeat runs on Arc Publishing (the Washington Post's platform). There is no WordPress REST API, and the RSS feed and sitemaps cover only the most recent items. The **Queryly Search API** is the sole viable enumeration surface for the full corpus.

- **Queryly Search API**: Queries all articles sorted oldest-first, paginated by offset (`endindex` parameter, `batchsize=100`)
- **Cursor**: The `endindex` offset is persisted in OpenCTI connector state. On restart the connector resumes from the saved offset
- **Content fetch**: Plain HTTP requests to each article URL (no browser/Playwright needed)
- **PDF rendering**: WeasyPrint from extracted article body HTML (Arc Publishing selectors)
- **Deduplication**: Deterministic STIX IDs via `uuid5(NAMESPACE_URL, article_url)` with graph-dedup check before rendering

### Key decisions

| Decision | Value |
|---|---|
| Container type | Report (external intelligence) |
| TLP | CLEAR (publicly published) |
| Author identity | Chalkbeat (Organization) |
| report_type | open-source-reporting |
| Confidence | 50 (Medium band) |
| Enumeration | Queryly Search API, oldest-first |
| PDF renderer | WeasyPrint |

## Dependencies

This connector depends on the **Queryly Search API** (`api.queryly.com`) for article enumeration. The Queryly key (`12a8b884283a4e73`) is Chalkbeat's public site-search key embedded in their frontend. If Chalkbeat changes their search provider or key, the `CHALKBEAT_QUERYLY_KEY` config must be updated.

## Configuration

| Environment variable | config.yml path | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | `opencti.url` | | OpenCTI platform URL |
| `OPENCTI_TOKEN` | `opencti.token` | | OpenCTI API token |
| `CONNECTOR_ID` | `connector.id` | | Unique connector UUID (generate once with `uuidgen`) |
| `CONNECTOR_TYPE` | `connector.type` | `EXTERNAL_IMPORT` | Must be EXTERNAL_IMPORT |
| `CONNECTOR_NAME` | `connector.name` | `Chalkbeat` | Display name in OpenCTI |
| `CONNECTOR_SCOPE` | `connector.scope` | `chalkbeat` | Connector scope identifier |
| `CONNECTOR_LOG_LEVEL` | `connector.log_level` | `info` | Log level |
| `CHALKBEAT_BASE_URL` | `chalkbeat.base_url` | `https://www.chalkbeat.org` | Chalkbeat site base URL |
| `CHALKBEAT_QUERYLY_KEY` | `chalkbeat.queryly_key` | `12a8b884283a4e73` | Queryly search API key |
| `CHALKBEAT_POLL_INTERVAL` | `chalkbeat.poll_interval` | `86400` | Seconds between enumeration runs |
| `CHALKBEAT_REQUEST_DELAY` | `chalkbeat.request_delay` | `2` | Seconds between article fetches |
| `CHALKBEAT_MAX_REPORTS` | `chalkbeat.max_reports` | `0` | Max reports per run (0 = unlimited) |
| `CHALKBEAT_RENDER_RETRIES` | `chalkbeat.render_retries` | `3` | PDF render retry attempts |
| `CHALKBEAT_CONFIDENCE` | `chalkbeat.confidence` | `50` | OpenCTI confidence score (0-100) |
| `CHALKBEAT_REPORT_TYPE` | `chalkbeat.report_type` | `open-source-reporting` | Report type vocabulary value |
| `CHALKBEAT_TLP` | `chalkbeat.tlp` | `TLP:CLEAR` | TLP marking definition |
| `CHALKBEAT_AUTHOR_NAME` | `chalkbeat.author_name` | `Chalkbeat` | Author Organization name |

## Quick start

1. Generate a connector UUID:
   ```bash
   uuidgen
   ```

2. Create `docker-compose.override.yml` with your credentials:
   ```yaml
   version: '3'
   services:
     chalkbeat:
       environment:
         - OPENCTI_URL=http://opencti:8080
         - OPENCTI_TOKEN=your-token-here
         - CONNECTOR_ID=your-generated-uuid
   ```

3. Start the connector:
   ```bash
   docker compose up -d
   ```

4. For a bounded test run, set `CHALKBEAT_MAX_REPORTS=3` in your override file.

## Architecture notes

- **No Playwright/browser needed**: Chalkbeat serves full article content to plain HTTP clients
- **Queryly API**: Public search API used by Chalkbeat's own site search; no authentication required
- **Arc Publishing selectors**: Article content extracted via `.article-body-wrapper` or `.body-paragraph` CSS selectors
- **Metadata**: Extracted from `og:title`, `og:description`, `article:published_time` meta tags and JSON-LD structured data
- **Crash recovery**: Offset cursor saved after each article; deterministic STIX IDs make all writes idempotent
