# CONNECTOR_SCOPE - Hungarian Conservative

Decision log for `connectors/hungarian_conservative/`. Authoritative for this
connector; supersedes conversation memory after compaction.

## What it is (current model)

EXTERNAL_IMPORT connector. Ingests the full article corpus from
https://www.hungarianconservative.com as container-only OpenCTI Reports, one per
WordPress post, each with TWO PDFs attached:
  1. REST API PDF — rendered from WP REST `content.rendered` via WeasyPrint.
  2. Live HTML PDF — fetched from the article URL, body extracted from the
     Elementor post-content widget with BeautifulSoup, cruft stripped, rendered
     via WeasyPrint. Serves as the auditor/processor reference copy.

Enumeration is a full WordPress REST backfill walked by a
persisted positional `{page, index}` cursor with a sliding-window mechanism for
corpora exceeding WordPress's 100-page pagination limit; the same path drives
steady state.

Fixed field mapping:

- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR. Confidence: 50 (Medium band). report_type: open-source-reporting.
- Author: the single "Hungarian Conservative" Organization identity.
- Name: verbatim post title (`title.rendered`, HTML-stripped). Description: post
  excerpt (`excerpt.rendered`, HTML-stripped), prefixed with the byline from the
  WP author lookup. published: `date_gmt` (fallback `modified_gmt`) parsed as UTC.
- Exactly one External Reference per Report (the article URL).
- Container-only: no Observables, Domain Objects, Relationships, or Labels. Zero
  relationships emitted; the relationship CSV is not implicated.

## Decisions (2026-09-20)

1. **Full corpus, no category filter.** The site has ~10,000+ posts across 19
   categories (Current, Politics, Culture & Society, Opinion, Interview, Philosophy,
   Diaspora, Tech, Review, Green, HU24EU, News, Slop Check, etc.). All categories
   contain substantive editorial content; there are no ticker-data or
   machine-generated categories to exclude.

2. **WP REST API for enumeration AND content.** The REST API is fully open (no WAF,
   no API key) and returns full article HTML in `content.rendered`. This means the
   connector gets both enumeration metadata and the complete article body in a single
   API call. The REST content drives the primary (REST API) PDF.

3. **Dual-PDF collection (2026-09-22).** Each Report carries two PDFs:
   - `hungarian-conservative-{slug}.pdf` — REST API content rendered via WeasyPrint.
     Clean structured content as WordPress stores it.
   - `hungarian-conservative-{slug}-live.pdf` — live article page fetched via
     requests, article body extracted from the Elementor post-content widget
     (`.elementor-widget-theme-post-content .elementor-widget-container`) with
     BeautifulSoup, ad/donation/self-embed cruft stripped, rendered via WeasyPrint.
     This captures the page as published and serves as the processor/auditor
     reference. A live PDF failure is non-fatal: the Report is still created with
     the REST API PDF only.

4. **WeasyPrint for PDF, no Playwright.** Both PDFs use WeasyPrint. The site has no
   WAF gating plain HTTP requests, so no browser automation is needed. This
   eliminates the Playwright dependency and its ~400 MB Chromium image.

5. **Ascending-ID cursor with sliding window.** Post IDs are monotonic and stable.
   The cursor walks ascending-ID order. WordPress caps REST pagination at 100 pages
   (10,000 posts with per_page=100); when the cursor reaches the limit, it shifts
   the query window forward using the `after` date filter and resets to page 1.
   This handles any corpus size with a single code path.

6. **Author byline in description.** The 224 WP authors are cached at startup.
   Each post's byline is included in the Report description but `createdBy` uses
   the single Organization identity (consistent with all other connectors in this
   repo).

7. **Politeness: 2-second delay.** No `Crawl-Delay` in robots.txt. The default
   2-second delay between renders is conservative for a site with no stated rate
   limit. Enumeration uses the REST API which is lightweight (no page rendering).

## Site characteristics

- CMS: WordPress (standard WP REST API at `/wp-json/wp/v2/posts`)
- Corpus: ~10,000+ posts, March 2021 to present
- Language: English
- Categories: 19 (all substantive editorial content)
- Authors: 224 registered WP users
- Oldest post: 2021-03-30 (ID 1453, "Lectori Salutem")
- Post ID range: 1453 to ~85,000+ (non-contiguous; WordPress IDs include drafts,
  revisions, media, and other post types)
- No WAF / Cloudflare challenge on REST or article pages
- No API key required
