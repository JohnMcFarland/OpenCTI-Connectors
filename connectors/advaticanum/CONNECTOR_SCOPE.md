# AdVaticanum Connector — Scope & Decision Log

## Source

[AdVaticanum](https://advaticanum.com) — Catholic news and analysis covering
the Vatican and the wider Church.

## Technical profile

| Property | Value |
|---|---|
| Platform | Next.js (App Router, Turbopack) |
| Bot protection | Cloudflare; ClaudeBot blocked in robots.txt |
| API | None (no REST, no GraphQL) |
| RSS | None (returns 403 / redirect) |
| Sitemap | None (404) |
| Listing URL | `/category/latest/page/{n}/` |
| Article URL | `/article/{slug}/` |
| Corpus size | ~450 articles (as of Sep 2026) |
| Articles per page | 6 |
| Date format | "Sep. 8, 2026" (visible span, no meta tag) |
| Structured data | None (no JSON-LD, no article:published_time) |
| Tags | Per-article (e.g. `/tag/china/`) |
| Categories (nav) | Latest, The Vatican, Outside the Walls, Catechesis, Culture, Laity |

## Decisions

### D-01: Playwright for enumeration and rendering

Non-browser HTTP clients receive 403 from Cloudflare. Playwright is required
for both listing-page enumeration and article PDF rendering.

### D-02: No cursor — graph-dedup re-walk with early-stop

Corpus is small (~450 articles). Each poll walks the "Latest" listing from
page 1 (newest) and checks each article URL against the graph via deterministic
Report STIX ID. When an entire listing page is already known, the walk stops.
Initial backfill walks all pages; steady-state polls stop after 1-2 pages.

### D-03: Container-only (Report + PDF)

No Domain Objects, no Observables, no Relationships, no Labels. The connector
is purely additive. Entity extraction is a separate phase.

### D-04: TLP:CLEAR

Public news source, freely accessible.

### D-05: Confidence 50

General Catholic news site; Medium band for a non-investigative news source.

### D-06: Author = Organization "AdVaticanum"

The publisher identity, not individual bylines. Individual author names are
recorded in the External Reference description.

### D-07: Date extraction from visible text

No `article:published_time` meta or JSON-LD. The date is extracted from the
visible span element near the h1 (format "Sep. 8, 2026") and parsed in Python.
Articles without a parseable date are skipped.
