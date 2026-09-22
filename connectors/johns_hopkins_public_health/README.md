# Johns Hopkins Bloomberg School of Public Health OpenCTI Connector

External-import connector that ingests news articles from
[publichealth.jhu.edu](https://publichealth.jhu.edu) as container-only
OpenCTI Reports with source PDFs attached.

## How it works

1. **Enumeration** -- Parses `/sitemap.xml` and its 9 sub-sitemaps to collect
   all article URLs (paths matching `/{year}/...` or `/{center}/{year}/...`).
   ~7,130 articles out of ~18,785 total URLs.
2. **Deduplication** -- Deterministic STIX ID (`uuid5(NAMESPACE_URL, url)`)
   checked against the graph before processing (graph-dedup re-walk).
3. **Content fetch** -- Playwright navigates each article page (Cloudflare
   blocks plain HTTP clients). Metadata extracted from JSON-LD `NewsArticle`
   schema, falling back to CSS selectors.
4. **PDF render** -- WeasyPrint converts the extracted HTML content to PDF.
5. **Ingest** -- Creates a Report with the PDF attached and an External
   Reference linking back to the source article.

## Configuration

| Environment variable | config.yml key | Default | Description |
|---|---|---|---|
| `JOHNS_HOPKINS_PUBLIC_HEALTH_BASE_URL` | `base_url` | `https://publichealth.jhu.edu` | Site root URL |
| `JOHNS_HOPKINS_PUBLIC_HEALTH_POLL_INTERVAL` | `poll_interval` | `86400` | Seconds between enumeration runs |
| `JOHNS_HOPKINS_PUBLIC_HEALTH_REQUEST_DELAY` | `request_delay` | `3` | Seconds between page loads |
| `JOHNS_HOPKINS_PUBLIC_HEALTH_MAX_REPORTS` | `max_reports` | `0` | Max reports per run (0 = unlimited) |
| `JOHNS_HOPKINS_PUBLIC_HEALTH_PLAYWRIGHT_NAV_TIMEOUT` | `playwright_nav_timeout` | `60000` | Playwright navigation timeout (ms) |
| `JOHNS_HOPKINS_PUBLIC_HEALTH_RENDER_RETRIES` | `render_retries` | `3` | Retries for navigation and PDF render |
| `JOHNS_HOPKINS_PUBLIC_HEALTH_CONFIDENCE` | `confidence` | `50` | OpenCTI confidence score (0-100) |
| `JOHNS_HOPKINS_PUBLIC_HEALTH_REPORT_TYPE` | `report_type` | `open-source-reporting` | Report type vocabulary value |
| `JOHNS_HOPKINS_PUBLIC_HEALTH_TLP` | `tlp` | `TLP:CLEAR` | TLP marking definition |
| `JOHNS_HOPKINS_PUBLIC_HEALTH_AUTHOR_NAME` | `author_name` | `Johns Hopkins Bloomberg School of Public Health` | Author Organization name |

## Quick start

```bash
cd connectors/johns_hopkins_public_health
cp docker-compose.yml docker-compose.override.yml
# Edit docker-compose.override.yml: fill in OPENCTI_URL, OPENCTI_TOKEN,
# and CONNECTOR_ID (run uuidgen to generate one).
# Set JOHNS_HOPKINS_PUBLIC_HEALTH_MAX_REPORTS=3 for a bounded test run.
docker compose up --build -d
docker compose logs -f
```
