# OCCRP OpenCTI Connector

External-import connector that ingests articles from the
[Organized Crime and Corruption Reporting Project](https://www.occrp.org) --
investigative journalism covering organized crime, corruption, and related
threats worldwide -- into OpenCTI as Report containers with full-fidelity PDF
attachments.

## Collection model

OCCRP uses a custom Next.js site with XML sitemaps. The connector walks the
sitemap index at `/sitemap.xml` to discover article sub-sitemaps, then
enumerates every English article URL and renders it to PDF.

- **~21,795 articles** across 3 article sub-sitemaps (2004-present).
- **Positional cursor** `{sitemap_idx, url_idx}` persisted in OpenCTI
  connector state; resumes across restarts.
- **1-second crawl-delay** honored per `robots.txt`.
- Only English (`/en/`) URLs processed; Russian (`/ru/`) translations skipped.
- Graph dedup via deterministic Report STIX ID skips already-ingested articles.
- **Container-only**: creates Reports and nothing else.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `ORGANIZED_CRIME_CORRUPTION_REPORTING_BASE_URL` | `https://www.occrp.org` | Site root |
| `ORGANIZED_CRIME_CORRUPTION_REPORTING_POLL_INTERVAL` | `86400` | Seconds between runs (24 h) |
| `ORGANIZED_CRIME_CORRUPTION_REPORTING_REQUEST_DELAY` | `1` | Seconds between requests (robots.txt crawl-delay) |
| `ORGANIZED_CRIME_CORRUPTION_REPORTING_MAX_REPORTS` | `0` | Per-run cap; 0 = unlimited |
| `ORGANIZED_CRIME_CORRUPTION_REPORTING_RENDER_RETRIES` | `3` | Render attempts per article |
| `ORGANIZED_CRIME_CORRUPTION_REPORTING_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `ORGANIZED_CRIME_CORRUPTION_REPORTING_REPORT_TYPE` | `open-source-reporting` | Report type vocabulary |
| `ORGANIZED_CRIME_CORRUPTION_REPORTING_TLP` | `TLP:CLEAR` | Traffic-light marking |
| `ORGANIZED_CRIME_CORRUPTION_REPORTING_AUTHOR_NAME` | `Organized Crime and Corruption Reporting Project` | Organization identity name |

## Quick start

```bash
# 1. Copy the template compose file
cp docker-compose.yml docker-compose.override.yml

# 2. Fill in OPENCTI_URL, OPENCTI_TOKEN, and CONNECTOR_ID in the override

# 3. Bounded test (3 articles)
#    Set ORGANIZED_CRIME_CORRUPTION_REPORTING_MAX_REPORTS=3 in the override

# 4. Run
docker compose up --build
```
