# Carnegie Endowment for International Peace — OpenCTI Connector

EXTERNAL_IMPORT connector that ingests research articles from the
[Carnegie Endowment for International Peace](https://carnegieendowment.org)
as container-only OpenCTI Reports with PDF attachments.

## Overview

| Property | Value |
|---|---|
| **Source** | carnegieendowment.org |
| **CMS** | Payload CMS + Next.js |
| **Enumeration** | Sitemap (`/sitemaps/research-0.xml`) |
| **Corpus** | ~4,049 English research articles (1991–present) |
| **Dedup strategy** | Graph-dedup re-walk (no cursor) |
| **PDF strategy** | Native PDF from `assets.carnegieendowment.org/files/` when available; WeasyPrint render otherwise |
| **Container-only** | Report + PDF + External Reference |

## Configuration

| Environment variable | config.yml path | Default | Description |
|---|---|---|---|
| `CARNEGIE_ENDOWMENT_BASE_URL` | `carnegie_endowment.base_url` | `https://carnegieendowment.org` | Site root URL |
| `CARNEGIE_ENDOWMENT_POLL_INTERVAL` | `carnegie_endowment.poll_interval` | `86400` | Seconds between enumeration runs |
| `CARNEGIE_ENDOWMENT_REQUEST_DELAY` | `carnegie_endowment.request_delay` | `2` | Seconds between HTTP requests |
| `CARNEGIE_ENDOWMENT_MAX_REPORTS` | `carnegie_endowment.max_reports` | `0` | Max reports per run (0 = unlimited) |
| `CARNEGIE_ENDOWMENT_RENDER_RETRIES` | `carnegie_endowment.render_retries` | `3` | Retry attempts for fetch/render |
| `CARNEGIE_ENDOWMENT_CONFIDENCE` | `carnegie_endowment.confidence` | `50` | OpenCTI confidence score (0–100) |
| `CARNEGIE_ENDOWMENT_REPORT_TYPE` | `carnegie_endowment.report_type` | `open-source-reporting` | Report type vocabulary value |
| `CARNEGIE_ENDOWMENT_TLP` | `carnegie_endowment.tlp` | `TLP:CLEAR` | TLP marking definition |
| `CARNEGIE_ENDOWMENT_AUTHOR_NAME` | `carnegie_endowment.author_name` | `Carnegie Endowment for International Peace` | Author identity name |

## Quick start

```bash
cd connectors/carnegie_endowment
cp docker-compose.yml docker-compose.override.yml
# Edit docker-compose.override.yml with your OpenCTI URL, token, and connector ID
docker compose up -d
```

Set `CARNEGIE_ENDOWMENT_MAX_REPORTS=3` for a bounded test run.

## Language filtering

The sitemap contains ~4,387 URLs including Russian, Chinese, Arabic, French,
and Hindi translations. The connector filters out URLs with `/ru/`, `/zh/`,
`/ar/`, `/fr/`, or `/hi/` path prefixes, ingesting only the ~4,049 English
articles.

## PDF handling

Paper-type articles on Carnegie link to downloadable PDFs hosted at
`assets.carnegieendowment.org/files/`. The connector checks for these native
PDFs first and downloads them directly. For article-type content without a
native PDF, WeasyPrint renders the article HTML into a PDF. Both paths enforce
a 50 MB size guard.
