# connector-newsapi

An external import connector for [OpenCTI](https://www.opencti.io) that ingests open-source news articles from the [NewsAPI.org](https://newsapi.org) `/v2/everything` endpoint as `Open Source Report` containers.

---

## Overview

This connector polls NewsAPI on a configurable schedule, evaluates each article against a domain allowlist, deduplicates against both a local state cache and the OpenCTI graph, and creates a Report container per article with a Markdown summary and rendered PDF attachment.

It is designed for CTI programs that ingest open-source news as part of a collection requirements framework — where articles are structured intelligence inputs, not raw feeds.

---

## Features

- **Profile-based collection** — Query behavior is driven by a `query_profiles.json` file, volume-mounted at runtime. Each profile defines a named query against the NewsAPI `/v2/everything` endpoint. Profiles can be updated without rebuilding the image.
- **Domain allowlist filtering** — Articles are filtered against a `domains_allowlist.txt` file before ingest. Domains not on the list are silently skipped and logged in aggregate at run end.
- **Graph-based deduplication** — Before creating any object, the connector checks whether an External Reference with the article URL already exists in the OpenCTI graph. This survives container restarts and state loss. A local TTL cache provides a fast-path skip for the current run window.
- **Cursor-based pagination** — Each profile maintains an independent cursor (last ingested `publishedAt` timestamp) in `state/state.json`. On subsequent runs, only articles newer than the cursor are fetched.
- **Daily request budget** — A configurable daily API request cap prevents quota exhaustion across runs. The budget resets at UTC midnight.
- **Report container per article** — Each article becomes a Report with: author identity (resolved or created as an Organization), external reference to the source URL, Markdown attachment, and optional PDF.
- **PDF attachment** — The connector fetches the article HTML and renders it to PDF via [WeasyPrint](https://weasyprint.org). PDF rendering failures are non-fatal and logged as warnings. Size limit is configurable.
- **Author identity caching** — Organization identity lookups are cached in-process for the duration of a run, reducing redundant API calls for repeat sources.
- **Rate limiting and retry** — Configurable minimum gap between requests and exponential backoff on HTTP 429 responses with `Retry-After` header support.
- **Non-destructive** — The connector never deletes or overwrites existing data. All operations are additive.

---

## Design Philosophy

### Containment

Every ingested article is immediately placed inside a Report container. No objects are written to the graph outside a container. This ensures traceability, scoping, and long-term source management consistent with the OpenCTI data model.

### Graph-authoritative deduplication

Local state files are a performance optimization, not the source of truth. The graph is always consulted before ingest. If the state file is lost or reset, the connector will not re-ingest articles already in the graph — it will detect the existing External Reference by URL and skip.

### Separation of code and configuration

Query profiles and domain allowlists are runtime configuration, not source code. They are volume-mounted files that can be changed without triggering an image rebuild. This enables collection posture to evolve independently of the connector lifecycle.

### Observable-free output

This connector does not create Indicators or Observables. It produces Report containers only. Enrichment of those reports — entity extraction, observable linking, relationship creation — is left to downstream connectors and analyst workflows. This keeps the ingestion pipeline clean and the data model uncontaminated.

### Confidence and marking as policy

Report confidence and TLP marking are externalized as environment variables. This allows the same connector binary to serve different collection contexts (e.g., public OSINT vs. restricted feeds) by varying deployment configuration alone.

---

## Configuration

All configuration is provided via environment variables. See `docker-compose.yml` for the full reference with inline documentation.

| Variable | Default | Description |
|---|---|---|
| `OPENCTI_URL` | — | OpenCTI instance URL |
| `OPENCTI_TOKEN` | — | Service account token |
| `CONNECTOR_ID` | — | Unique UUID for this connector instance |
| `CONNECTOR_REFRESH_INTERVAL` | `3600` | Seconds between runs |
| `NEWSAPI_API_KEY` | — | NewsAPI.org API key |
| `NEWSAPI_LANGUAGE` | — | ISO 639-1 language filter (e.g. `en`) |
| `NEWSAPI_SORT_BY` | `publishedAt` | `publishedAt`, `relevancy`, or `popularity` |
| `NEWSAPI_PAGE_SIZE` | `50` | Articles per page (max 100) |
| `NEWSAPI_LOOKBACK_HOURS` | `24` | Lookback window on first run or cursor miss |
| `NEWSAPI_MAX_PAGES_PER_RUN` | `1` | Pages fetched per profile per run |
| `NEWSAPI_DAILY_REQUEST_BUDGET` | `90` | Maximum API requests per calendar day |
| `NEWSAPI_MIN_SECONDS_BETWEEN_REQUESTS` | `2` | Minimum gap between API calls |
| `NEWSAPI_MAX_RETRIES` | `5` | Retry attempts on transient failures |
| `NEWSAPI_REPORT_TYPE` | `threat-report` | Must exist in OpenCTI report_types vocabulary |
| `NEWSAPI_MARKING` | `TLP:WHITE` | Must match an existing marking definition name |
| `NEWSAPI_CONFIDENCE` | `15` | Report confidence score (0–100) |
| `NEWSAPI_CR_LABELS` | — | Comma-separated collection requirement labels |
| `NEWSAPI_TECHNICAL_CREATOR` | `[C]NewsAPI` | Identity label in Markdown attachments |
| `NEWSAPI_ATTACH_PDF` | `true` | Render and attach article PDF |
| `NEWSAPI_PDF_MAX_MB` | `12` | Maximum PDF size before skipping upload |
| `NEWSAPI_PDF_TIMEOUT` | `30` | HTTP fetch timeout for PDF rendering (seconds) |
| `NEWSAPI_DOMAINS_ALLOWLIST_FILE` | — | Path to allowlist file inside container |
| `NEWSAPI_QUERY_PROFILES_FILE` | — | Path to query profiles JSON inside container |

### Query profiles

Query profiles are defined in `src/query_profiles.json`. Each profile is a named NewsAPI `q=` query. The file is volume-mounted at runtime.

```json
[
  {
    "name": "example_profile",
    "query": "(keyword1 OR keyword2) AND (keyword3 OR keyword4)"
  }
]
```

The `q=` field supports full boolean logic: `AND`, `OR`, `NOT`, phrase matching with quotes, and `+`/`-` prefix operators. Maximum 500 characters. See the [NewsAPI documentation](https://newsapi.org/docs/endpoints/everything) for full syntax.

### Domain allowlist

`src/domains_allowlist.txt` contains one domain per line. Lines starting with `#` are treated as comments. Subdomain matching is supported — listing `example.com` will also match `news.example.com`.

```
# Example allowlist
reuters.com
apnews.com
bbc.co.uk
```

If the file is empty or the environment variable is unset, all domains are permitted.

---

## State file

The connector maintains `state/state.json` with three keys:

- `cursors` — per-profile `publishedAt` timestamp of the last ingested article
- `seen` — local dedup cache mapping article URL hash to TTL expiry epoch
- `budget` — daily request counter and reset date

The `state/` directory should be excluded from version control (see `.gitignore`) and persisted via a Docker volume mount.

---

## Deployment

### Standalone

```bash
cp docker-compose.yml docker-compose.override.yml
# Edit docker-compose.override.yml with your values
docker compose up -d
```

### As part of an existing OpenCTI Docker Compose stack

Add the service block from `docker-compose.yml` to your existing `docker-compose.override.yml`. Adjust the `networks` block to reference your OpenCTI stack's network.

---

## Requirements

- OpenCTI 6.x (tested on 6.9.13)
- NewsAPI.org API key (Developer plan minimum for `/v2/everything`)
- Docker

---

## Dependencies

| Package | Purpose |
|---|---|
| `pycti` | OpenCTI Python client |
| `requests` | HTTP client for NewsAPI and PDF fetch |
| `python-dateutil` | ISO 8601 date parsing |
| `weasyprint` | HTML-to-PDF rendering for article attachments |

---

## Limitations

- NewsAPI free tier does not support `/v2/everything`. A Developer plan or higher is required.
- Article content is truncated to ~200 characters by the NewsAPI response. Full content is fetched via PDF render of the source URL.
- PDF quality depends on the source site. JS-heavy or paywalled sites will produce degraded or empty PDFs. Failures are non-fatal.
- NewsAPI rate limits vary by plan. The daily budget cap (`NEWSAPI_DAILY_REQUEST_BUDGET`) should be set conservatively relative to your plan's allowance.
