# OpenCTI Trellix Blog connector

External-import connector that harvests posts from the
[Trellix blog](https://www.trellix.com/blogs/) — scoped by default to the
**Research** and **Platform** categories — into OpenCTI as **container-only
Reports**, one per post, each with the live source page attached as a
full-fidelity Playwright-rendered **PDF**.

It is a pure harvester: it creates Report containers and nothing else (no
observables, domain objects, relationships, indicators, or labels). Named-entity /
IOC extraction is a deliberately separate downstream concern. This keeps the
connector purely additive and clear of the data-model relationship allowlist.

## How it works

- **Enumeration** reads the single complete en-US sitemap declared in `robots.txt`:
  `https://www.trellix.com/en-us.sitemap.xml` (~1,570 URLs, 779 of them under
  `/blogs/`). Post URLs have the shape `/blogs/{category}/{slug}/`. There is **no
  RSS feed anywhere on the origin** — every WordPress-shaped feed path returns the
  site 404 page — and no listing page to paginate: the sitemap *is* the corpus.
- **Corpus size** (as of 2026-08-20): research 362, platform 91, perspectives 138
  (591 posts total; **453 in the default scope**), plus 182 contributor pages the
  filter excludes.
- **Everything goes through the browser.** The origin's edge WAF answers plain HTTP
  clients with HTTP 403, so article metadata is read from the DOM of the same
  Chromium page that is rendered to PDF — one page load per post, not two. The
  sitemap is tried over plain HTTP first and falls back to a same-origin `fetch()`
  inside a Chromium page parked on trellix.com.
- **No cursor / no state file.** Correctness is graph-driven: each post maps to a
  deterministic Report id (`uuid5` of the URL) and existing Reports are skipped
  before the page is loaded. The same walk covers the historical backfill and steady
  state. The sitemap's `<lastmod>` only orders the walk (freshest first) and is never
  written to the graph — it is a CMS modification date, not a publication date.

## Publication dates

Trellix absorbed the McAfee Enterprise and FireEye blogs at the January 2022
rebrand, and the migration overwrote `<meta name="releaseDate">` with the *migration*
date on the inherited posts. Over a 60-post sample, 9 posts (15%) carry a
`releaseDate` that disagrees with the byline — 8 of them stamped 2022-01-17/18 for
articles actually published between 2016 and 2021.

The connector therefore resolves `published` in this order:

1. The first `Month D, YYYY` in the article's own byline (`p.dateline`, read **only**
   from inside the `.stories-category` article container — the related-posts carousel
   has its own datelines) that is not tagged `Updated:`.
2. `<meta name="releaseDate">`, which covers posts with no byline and correctly wins
   for revision-only datelines.
3. Ingestion time, with a warning (not reached on the sampled corpus).

Over the sample this resolved a date for 60/60 posts and recovered every
migration-stamped date. Byline formats vary a lot across eras — `February 23, 2021`,
`Aug 24, 2021`, `NOV 08, 2018`, and `August 30, 2022This blog was written by …` with
the year running straight into the next sentence — and the parser covers all of them.

## Field mapping

| Report field | Source |
|---|---|
| `name` | `og:title` (falls back to the article `<h1>`) |
| `description` | `<meta name="description">` (falls back to `og:description`; ~17% of posts have neither and get an empty description) |
| `published` | byline date → `releaseDate` → ingestion time (see above) |
| `report_types` | `open-source-reporting` |
| `confidence` | `50` |
| `createdBy` | the "Trellix" Organization identity |
| `objectMarking` | `TLP:CLEAR` |
| External Reference | the canonical article URL |
| attached file | Playwright PDF of the article (`trellix-<category>-<slug>.pdf`) |

## Configuration

All config is externalized to `docker-compose.override.yml` (never committed). The
committed `docker-compose.yml` carries empty placeholders for the platform
connection and identity, and non-sensitive behaviour defaults.

| Env var | Default | Meaning |
|---|---|---|
| `OPENCTI_URL` | — | Platform URL (override) |
| `OPENCTI_TOKEN` | — | Connector service-account token (override) |
| `CONNECTOR_ID` | — | Connector UUID (`uuidgen`) |
| `TRELLIX_BASE_URL` | `https://www.trellix.com` | Site base URL |
| `TRELLIX_SITEMAP_URL` | *(derived from base URL)* | Sitemap to enumerate |
| `TRELLIX_CATEGORIES` | `research,platform` | Comma-separated category slugs; add `perspectives` for corporate content |
| `TRELLIX_POLL_INTERVAL` | `86400` | Seconds between enumeration runs |
| `TRELLIX_REQUEST_DELAY` | `3` | Seconds between article page loads |
| `TRELLIX_MAX_REPORTS` | `0` | Per-run cap on new Reports (0 = unlimited; set `3` for a bounded test) |
| `PLAYWRIGHT_NAV_TIMEOUT` | `60000` | Page navigation timeout (ms) |
| `TRELLIX_RENDER_RETRIES` | `3` | Load attempts before skipping a post |
| `TRELLIX_CONFIDENCE` | `50` | OpenCTI confidence (0-100) |
| `TRELLIX_REPORT_TYPE` | `open-source-reporting` | Report type (open vocabulary) |
| `TRELLIX_TLP` | `TLP:CLEAR` | TLP marking (must already exist on the platform) |
| `TRELLIX_AUTHOR_NAME` | `Trellix` | Author Organization name |

## First run

Set `TRELLIX_MAX_REPORTS=3` for a bounded smoke test, confirm three Reports appear
with attached PDFs and sensible publication dates, then set it back to `0` for the
full 453-post backfill. Because the walk is ordered freshest-first, a bounded run
picks up recent posts rather than an arbitrary slice.

At the default 3-second delay the full backfill takes roughly 1.5–2 hours and is
fully resumable — graph dedup skips whatever is already ingested, so an interrupted
run simply continues on the next poll.

## Build & run

```bash
docker compose -f docker-compose.yml -f docker-compose.override.yml up -d --build
```

Rebuild with `--no-cache` after any source or requirements change.

See [`CONNECTOR_SCOPE.md`](CONNECTOR_SCOPE.md) for the full decision log.
