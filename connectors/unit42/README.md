# OpenCTI Unit 42 connector

External-import connector that harvests posts from the Palo Alto Networks
[Unit 42](https://unit42.paloaltonetworks.com) research blog — scoped by default to
the **Threat Research** category — into OpenCTI as **container-only Reports**, one
per post, each with the live source page attached as a full-fidelity
Playwright-rendered **PDF**.

It is a pure harvester: it creates Report containers and nothing else (no
observables, domain objects, relationships, indicators, or labels). Named-entity /
IOC extraction is a deliberately separate downstream concern. This keeps the
connector purely additive and clear of the data-model relationship allowlist.

## How it works

- **Enumeration** walks the category RSS feed page by page:
  - Page 1: `…/category/<category>/feed/` (bare — `?paged=1` is edge-blocked)
  - Pages 2..last: `…/category/<category>/feed/?paged=N`
  - 15 items/page, newest-first; a page past the last returns HTTP 404 (end of list).
- The WordPress REST API is edge-blocked (HTTP 403), so the feed is the surface.
- **No cursor / no state file.** The feed shifts as posts publish, so correctness is
  graph-driven: each post maps to a deterministic Report id (`uuid5` of the URL) and
  existing Reports are skipped before rendering. The same forward walk covers the
  historical backfill and steady state.
- **Rendering** uses Playwright/Chromium to capture each article as a PDF, attached
  to its Report.

## Field mapping

| Report field | Source |
|---|---|
| `name` | feed `<title>` (HTML-stripped) |
| `description` | feed `<description>` excerpt (HTML-stripped, WordPress boilerplate removed) |
| `published` | feed `<pubDate>` (RFC-822 → UTC) |
| `report_types` | `open-source-reporting` |
| `confidence` | `50` |
| `createdBy` | the "Unit 42" Organization identity |
| `objectMarking` | `TLP:CLEAR` |
| External Reference | the article URL |
| attached file | Playwright PDF of the article |

## Configuration

All config is externalized to `docker-compose.override.yml` (never committed). The
committed `docker-compose.yml` carries empty placeholders for the platform
connection and identity, and non-sensitive behaviour defaults.

| Env var | Default | Meaning |
|---|---|---|
| `OPENCTI_URL` | — | Platform URL (override) |
| `OPENCTI_TOKEN` | — | Connector service-account token (override) |
| `CONNECTOR_ID` | — | Connector UUID (`uuidgen`) |
| `UNIT42_BASE_URL` | `https://unit42.paloaltonetworks.com` | Blog base URL |
| `UNIT42_CATEGORY` | `threat-research` | WordPress category slug to ingest |
| `UNIT42_POLL_INTERVAL` | `86400` | Seconds between enumeration runs |
| `UNIT42_REQUEST_DELAY` | `3` | Seconds between renders / page fetches |
| `UNIT42_MAX_REPORTS` | `0` | Per-run cap on new Reports (0 = unlimited; set `3` for a bounded test) |
| `UNIT42_MAX_PAGES` | `500` | Safety bound on feed pages per run (real count ~61) |
| `PLAYWRIGHT_NAV_TIMEOUT` | `60000` | Page navigation timeout (ms) |
| `UNIT42_RENDER_RETRIES` | `3` | Render attempts before skipping a post |
| `UNIT42_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `UNIT42_REPORT_TYPE` | `open-source-reporting` | Report type (open vocabulary) |
| `UNIT42_TLP` | `TLP:CLEAR` | TLP marking (must already exist on the platform) |
| `UNIT42_AUTHOR_NAME` | `Unit 42` | Author Organization name |

## First run

Set `UNIT42_MAX_REPORTS=3` for a bounded smoke test, confirm three Reports appear
with attached PDFs, then set it back to `0` for the full ~915-post backfill. At the
default 3-second delay the full backfill runs in well under an hour and is fully
resumable (graph dedup skips what is already ingested).

## Build & run

```bash
docker compose -f docker-compose.yml -f docker-compose.override.yml up -d --build
```

Rebuild with `--no-cache` after any source or requirements change.

See [`CONNECTOR_SCOPE.md`](CONNECTOR_SCOPE.md) for the full decision log.
