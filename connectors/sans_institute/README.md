# SANS Institute Blog — OpenCTI External-Import Connector

Ingests blog posts from [https://www.sans.org/blog/](https://www.sans.org/blog/) as
container-only OpenCTI **Reports**, each with a rendered PDF and an External Reference
back to the source article.

## How it works

| Step | Detail |
|------|--------|
| **Enumerate** | Parses the flat sitemap at `/sitemaps/blogs.xml` (~976 blog URLs) |
| **Dedup** | Graph-dedup re-walk: checks `report.read(id)` for each URL before rendering |
| **Fetch** | `requests.get()` per article (no Playwright needed; Imperva CDN allows plain HTTP) |
| **Metadata** | JSON-LD `BlogPosting` schema (headline, description, datePublished, author); CSS selector fallback |
| **Render** | WeasyPrint PDF from cleaned article HTML |
| **Ingest** | Report + PDF + External Reference (container-only, no SDOs/SCOs/SROs) |

## Configuration

| Environment variable | config.yml key | Default | Description |
|---|---|---|---|
| `SANS_INSTITUTE_BASE_URL` | `sans_institute.base_url` | `https://www.sans.org` | Site root |
| `SANS_INSTITUTE_SITEMAP_URL` | `sans_institute.sitemap_url` | `https://www.sans.org/sitemaps/blogs.xml` | Blog sitemap URL |
| `SANS_INSTITUTE_POLL_INTERVAL` | `sans_institute.poll_interval` | `86400` | Seconds between enumeration runs |
| `SANS_INSTITUTE_REQUEST_DELAY` | `sans_institute.request_delay` | `2` | Seconds between HTTP requests |
| `SANS_INSTITUTE_MAX_REPORTS` | `sans_institute.max_reports` | `0` | Max reports per run (0 = unlimited) |
| `SANS_INSTITUTE_RENDER_RETRIES` | `sans_institute.render_retries` | `3` | PDF render retry attempts |
| `SANS_INSTITUTE_CONFIDENCE` | `sans_institute.confidence` | `50` | OpenCTI confidence score (0-100) |
| `SANS_INSTITUTE_REPORT_TYPE` | `sans_institute.report_type` | `open-source-reporting` | Report type vocabulary value |
| `SANS_INSTITUTE_TLP` | `sans_institute.tlp` | `TLP:CLEAR` | Traffic Light Protocol marking |
| `SANS_INSTITUTE_AUTHOR_NAME` | `sans_institute.author_name` | `SANS Institute` | Author identity name |

## Quick start

```bash
cd connectors/sans_institute
cp docker-compose.yml docker-compose.override.yml
# Edit docker-compose.override.yml: set OPENCTI_URL, OPENCTI_TOKEN, CONNECTOR_ID
docker compose up -d
```

Set `SANS_INSTITUTE_MAX_REPORTS=3` for a bounded test run.
