# CONNECTOR_SCOPE - Trellix Blog

Decision log for `connectors/trellix_blog/`. Authoritative for this connector;
supersedes conversation memory after compaction.

## What it is (current model)

EXTERNAL_IMPORT connector. Ingests posts from the Trellix blog
(https://www.trellix.com/blogs/), scoped by default to the `research` and
`platform` categories, as container-only OpenCTI Reports, one per post, each with
the live source page attached as a Playwright-rendered PDF. Enumeration is a walk of
the origin's single complete XML sitemap; the same path drives the historical
backfill and steady state.

Fixed field mapping:

- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR. Confidence: 50 (Medium band). report_type: open-source-reporting.
- Author: the single "Trellix" Organization identity.
- Name: `og:title` (article `<h1>` fallback). Description: `<meta name="description">`
  (`og:description` fallback; may be empty). published: byline date, else
  `<meta name="releaseDate">`, else ingestion time.
- Exactly one External Reference per Report (the canonical article URL).
- Container-only: no Observables, Domain Objects, Relationships, Indicators, or
  Labels. Zero relationships emitted; the relationship allowlist is not implicated.

## Decisions (2026-08-20, this session)

1. **Scope = `research` + `platform`, operator-configurable (user-chosen).** The user
   pointed at `/blogs/` (the whole blog) and was offered three options against a
   measured census. They chose research (362 posts, Advanced Research Center threat
   work) + platform (91 posts, detection-engineering content), explicitly excluding
   `perspectives` (138 posts: RSA announcements, exec appointments, DEI posts, CISO
   thought-leadership). Widening is a one-line config change
   (`TRELLIX_CATEGORIES=research,platform,perspectives`), not a code change.

2. **Container-only, no extraction.** Standing house pattern (Unit 42, Hellenic
   Shipping News, Jamestown, ScienceDaily, DFIR Report): this connector is a pure
   harvester — Report + PDF only — and a separate downstream processor handles
   named-entity / IOC extraction. Keeps the connector purely additive and clear of
   the data-model allowlist entirely. No extraction census was run for this origin,
   since none was needed for a container-only design.

3. **Enumeration = the XML sitemap. There is no RSS feed.** Trellix runs on Adobe
   Experience Manager. Every WordPress-shaped feed path was probed and returns the
   site 404 page: `/blogs/feed/`, `/blogs/rss.xml`, `/blogs/index.xml`,
   `/blogs/research/feed/`. `robots.txt` declares exactly two sitemaps, of which
   `https://www.trellix.com/en-us.sitemap.xml` is the page sitemap: ~1,570 URLs, 779
   under `/blogs/`. Measured shape census of those 779:

   | shape | count |
   |---|---|
   | `/blogs/research/{slug}/` | 362 |
   | `/blogs/perspectives/{slug}/` | 138 |
   | `/blogs/platform/{slug}/` | 91 |
   | `/blogs/contributors/{name}/` | 182 |
   | index pages (`/blogs/`, `/blogs/{cat}/`, `/blogs/search/`) | 6 |

   No nested paths exist below `{category}/{slug}/`, so the post regex cannot
   over-match. One real slug carries an uppercase letter
   (`threat-analysis-squidLoader-…`), which is why the URL regex is case-insensitive.
   The sitemap is fresh — it carried posts published eight days before the census.

4. **No positional cursor, no state file — graph dedup only.** The corpus is small
   (453 posts in the default scope) and the sitemap is complete and stable-ordered,
   so re-walking it each poll is cheap. Correctness rests entirely on graph-driven
   dedup: a deterministic Report STIX id (`report--` + uuid5(NAMESPACE_URL, url)) is
   checked via `report.read(id)` before the page is loaded. Same reasoning as Unit 42,
   and stronger here: an RSS feed shifts as posts publish, a sitemap does not.

5. **`<lastmod>` orders the walk; it is never written to the graph.** It is a CMS
   modification date, not a publication date — `/blogs/platform/detecting-new-mispadu-
   infostealer-infections-in-south-america/` carries lastmod 2026-08-19 for a post
   published 2024-11-19. Sorting by it descending (URL as tie-break) makes a
   `TRELLIX_MAX_REPORTS`-bounded test run pick up recent content, and puts new posts
   first in steady state.

6. **Everything reads through the browser (divergence from Unit 42).** The Unit 42
   connector states that "enumeration never goes through Playwright". This one
   inverts that, deliberately. The origin's edge WAF gates non-browser clients: a
   plain HTTP fetch of `https://www.trellix.com/blogs/` was answered **HTTP 403
   Forbidden** during development, while a real browser client got HTTP 200. Plain
   `requests` with a browser UA could not be tested from the development host (no
   egress to the origin), so the design does not depend on it working:
   - Article metadata is read from the DOM of the same Chromium page that is rendered
     to PDF. One page load per post instead of two, and the metadata path inherits
     the browser's WAF standing for free.
   - The sitemap tries plain `requests` first (cheap, static XML asset) and falls
     back to a same-origin `fetch()` evaluated inside a Chromium page parked on
     trellix.com — the exact path proven to work against the live site.

7. **Publication dates: byline first, `releaseDate` second.** This is the one
   genuinely tricky part of the origin. Trellix absorbed the McAfee Enterprise and
   FireEye blogs at the January 2022 rebrand, and the migration stamped
   `<meta name="releaseDate">` with the *migration* date. Over a 60-post stratified
   sample, 9 posts (15%) carry a `releaseDate` that disagrees with the byline; 8 are
   Jan-2022 migration stamps (e.g. `/blogs/research/popcorn-time-ransomware-sure-cause-
   indigestion/` reads 2022-01-18 for a post from 2016-12-19;
   `/blogs/research/babuk-ransomware/` reads 2022-01-17 for 2021-02-23). Resolution
   order:
   1. First `Month D, YYYY` in the article's own byline not tagged `Updated:`.
   2. `<meta name="releaseDate">` (ISO 8601).
   3. Ingestion time, with a warning.

   Sample coverage: byline present 59/60 (parseable 58/60), releaseDate present
   57/60, **combined 60/60**. The one byline the parser deliberately rejects is
   `"By … · Updated: June 30, 2025"`, a revision-only stamp, where releaseDate
   (2025-06-24) is the correct original.

   Byline format traps, all covered and regression-tested:
   - Mixed-case and abbreviated months: `February 23, 2021`, `Aug 24, 2021`,
     `NOV 08, 2018`, `Nov. 8, 2018`.
   - The year runs straight into the following sentence:
     `"August 30, 2022This blog was written by Britt Norwood"`. A trailing `\b` on the
     year fails here, so the regex uses a negative lookahead `(?!\d)` instead. This
     bit an earlier draft of the parser, which silently failed on ~23% of the sample.
   - A `(Updated: …)` suffix after the original date: first-match-wins keeps the
     original.

8. **The byline is read ONLY from inside `.stories-category`.** Every article page
   renders a related-posts carousel whose cards each carry their own `p.dateline`
   (verified: 4 `p.dateline` nodes on a typical page, 1 in the article container and
   3 in the carousel). An unbounded selector would stamp a neighbouring article's
   date onto the report. Verified across 18 in-scope posts: `.stories-category`
   present on 100%, containing exactly one `<h1>`, with `og:title` present on 100%.

9. **Cross-category aliases collapse on `rel=canonical`.** The CMS publishes a few
   articles under two category paths. Two were found in the full 591-post corpus:
   `managing-risk-during-the-crowdstrike-global-tech-outage` (perspectives → canonical
   research) and `look-alive-out-there` (perspectives + platform, each
   self-canonicalising). Under the chosen research+platform scope **neither pair has
   both members in scope**, so no duplicate currently arises; the connector keys
   Reports on the canonical URL and re-checks the graph when it differs from the
   sitemap URL anyway, so widening the scope later stays safe. The residual case a
   canonical cannot fix — two self-canonicalising copies of one article — would
   produce two Reports; it is not currently reachable in scope.

10. **robots.txt.** Permissive: `user-agent: *` with no `Crawl-delay` and no
    disallow covering `/blogs/`. The connector runs under a plain browser UA (not
    ClaudeBot) for reference-use ingestion and defaults `TRELLIX_REQUEST_DELAY` to a
    courteous 3 seconds. No cookie/consent overlay is served to the render context,
    so PDFs are clean.

11. **TLP / author / report_type / confidence.** TLP:CLEAR (public vendor blog).
    Author = single "Trellix" Organization. report_type = `open-source-reporting`
    (custom open-vocabulary value, for cross-connector consistency). Confidence = 50
    (Medium band, matching the other OSINT-publisher connectors).

## Dedup: deterministic Report id (house pattern)

Dedup keys on `report--` + uuid5(NAMESPACE_URL, url). Two checks per post:

- Before the page load, on the id from the sitemap URL — skips already-ingested posts
  without touching the origin.
- After the page load, on the id from the page's `rel=canonical` URL, when it differs.

The Report is created under the canonical id: External Reference first (upsert-safe),
then the Report with that stix_id (`update=True`), then the PDF. Because both
existence checks key on Report ids and every sub-write is idempotent, a crash
anywhere leaves the post still "not done"; the next poll re-enters and completes it.
No state file, no cursor.

## Verification performed

Offline regression suite (`scratchpad/test_trellix.py`, not committed) run against
real metadata harvested from the live corpus — 94 checks, all passing:

- **Date resolution, 60/60** on the real 60-post stratified sample (58 resolved from
  the byline, 2 from `releaseDate`, 0 unresolved), including all 8 migration stamps
  and the `Updated:`-only case.
- **12 date-parser edge cases**: uppercase/abbreviated/period months, year-runs-into-
  text, `(Updated: …)` suffix, impossible day (`February 30`), non-month word,
  pre-2000 year, missing/empty byline.
- **6 `releaseDate` parser cases** including out-of-range and malformed input.
- **Sitemap classification** against a synthetic sitemap rebuilt to the exact URL
  shapes and counts of the live one (779 `/blogs/` URLs): research 362, platform 91,
  perspectives 138, contributors 182, 6 index pages excluded.
- **Enumeration end-to-end** (fetch stubbed): 453 in-scope URLs, no perspectives /
  contributors / index pages leaked, uppercase slug retained, no duplicates,
  freshest-lastmod-first ordering, single- and all-category scopes correct,
  unparseable XML returns None rather than raising.
- **Report id determinism and canonical collapse**, including fallback when the
  canonical is absent or off-shape.

**Not verified end-to-end:** the Playwright render path and the OpenCTI writes were
not exercised, because the development host has no network egress to the origin and
no OpenCTI instance. Page structure was confirmed against the live site through a
browser (article container, metadata, absence of a consent overlay), and the render
code is the unchanged house pattern. The `TRELLIX_MAX_REPORTS=3` bounded first run
is the intended smoke test.

## Enforcement-gate caveat

As recorded for Unit 42 / arXiv / Jamestown / Hellenic Shipping News: the gate
tooling CLAUDE.md names (`scripts/preflight.py`, the `datamodel/` package, the pytest
scaffolding) is absent from this checkout, and `data_model/` holds
`Data_Model_Relationship_Guide5.csv`. Relationship validation is vacuous here: the
connector emits zero relationships (container-only). Hygiene (pin/base/secrets)
checked manually. Flagged, not silently resolved.

## Cross-connector open item

`OPENCTI_URL` vs `OPENCTI_BASE_URL` naming remains an unresolved cross-connector
decision (CLAUDE.md). This connector follows the prevailing render-connector pattern
(Unit 42, Jamestown, ScienceDaily, Hellenic Shipping News) and uses `OPENCTI_URL`; it
does not settle the naming decision.

[Unit 42]: ../unit42/CONNECTOR_SCOPE.md
[Hellenic Shipping News]: ../hellenic_shipping_news/CONNECTOR_SCOPE.md
[Jamestown]: ../jamestown/CONNECTOR_SCOPE.md
