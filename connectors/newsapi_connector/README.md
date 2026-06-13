# NewsAPI OpenCTI Connector

External-import connector that queries [NewsAPI.org](https://newsapi.org) across
configurable query profiles and creates one OpenCTI **Report** container per
article, with the source article attached as a **PDF rendered via
Playwright/Chromium**.

## What it does

- For each query profile, calls NewsAPI `/v2/everything` with a persistent
  per-profile time cursor and a daily request budget (NewsAPI free tier ≈ 100
  req/day).
- Filters articles by a domain allow-list, deduplicates against the graph
  (External Reference URL) plus a short TTL cache.
- Renders the **live publisher page** to PDF and extracts the article body text
  (via trafilatura, from the already-rendered DOM — no second fetch) into the
  Report description so it is searchable in the graph.
- **Paywall-aware:** known-paywalled domains (and pages detected as subscribe
  walls) skip the live render and use a **metadata-only fallback PDF** built from
  the NewsAPI title/description, rather than archiving a "subscribe to continue"
  screenshot. The same fallback covers Cloudflare/JS/timeout failures — so every
  Report always has a PDF.
- Co-mention `targets` relationships carry an **Assessment Note** marking them as
  unverified machine inferences.
- Enriches each Report with matched **Sector** and **Country** objects, and —
  when a known Intrusion Set / Threat Actor Group is co-mentioned with a
  resolved country — a low-confidence `targets` relationship (permitted by the
  data-model allow-list). No Indicators or Observables are created.

## Configuration

Configuration is read from environment variables (precedence) or `config.yml`.
See [docker-compose.yml](docker-compose.yml) for the full list. Key settings:

| Env var | Default | Notes |
|---|---|---|
| `NEWSAPI_API_KEY` | — | required |
| `NEWSAPI_MARKING` | `TLP:CLEAR` | must match a marking name in your instance |
| `NEWSAPI_REPORT_TYPE` | `open-source-reporting` | registered in the vocabulary at startup |
| `NEWSAPI_CONFIDENCE` | `15` | low; unverified OSINT |
| `NEWSAPI_DAILY_REQUEST_BUDGET` | `90` | per calendar day |
| `NEWSAPI_MAX_POSTS` | `0` | 0 = unlimited; set small for a bounded test |
| `PLAYWRIGHT_NAV_TIMEOUT` | `60000` | ms |
| `NEWSAPI_RENDER_RETRIES` | `3` | live-render attempts before fallback |

### Collection scope

- [`query_profiles.json`](query_profiles.json) — list of `{name, query}` objects
  (NewsAPI query syntax). Optional per-profile keys: `marking`, `cr_labels`,
  `geography` (list of country names; enables `targets` relationships for that
  profile).
- [`domains_allowlist.txt`](domains_allowlist.txt) — one domain per line; exact
  or subdomain match. Empty file = all domains allowed.
- **Paywalled domains** — a built-in default set (WSJ, FT, NYT, Economist, …)
  renders straight to the metadata fallback. Override with a file via
  `NEWSAPI_PAYWALL_DOMAINS_FILE` (one domain per line; replaces the defaults).

Both files are volume-mounted, so scope can be edited without rebuilding.

## Run

```bash
docker compose up -d --build
```

State (cursors, dedup cache, daily budget) persists under `./state`.
