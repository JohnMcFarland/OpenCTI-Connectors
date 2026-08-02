# CONNECTOR_SCOPE - Unit 42

Decision log for `connectors/unit42/`. Authoritative for this connector;
supersedes conversation memory after compaction.

## What it is (current model)

EXTERNAL_IMPORT connector. Ingests posts from the Palo Alto Networks Unit 42
research blog (https://unit42.paloaltonetworks.com), scoped by default to the
`threat-research` category, as container-only OpenCTI Reports, one per WordPress
post, each with the live source page attached as a Playwright-rendered PDF.
Enumeration is a paginated category RSS-feed walk; the same path drives the
historical backfill and steady state.

Fixed field mapping:

- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR. Confidence: 50 (Medium band). report_type: open-source-reporting.
- Author: the single "Unit 42" Organization identity.
- Name: verbatim post title (feed `<title>`, HTML-stripped). Description: post
  excerpt (feed `<description>`, HTML-stripped, WordPress "The post ... appeared
  first on Unit 42." boilerplate removed). published: `<pubDate>` (RFC-822) as UTC.
- Exactly one External Reference per Report (the article URL).
- Container-only: no Observables, Domain Objects, Relationships, Indicators, or
  Labels. Zero relationships emitted; the relationship allowlist is not implicated.

## Decisions (2026-08-02, confirmed with user this session)

1. **Container-only, no extraction (final).** The user first requested entity/IOC
   extraction, then reversed the decision before any extractor was written:
   "We're not going to mint anything. Just pull the reports themselves as PDFs.
   This connector just needs to collect the reports. The processor can process
   them." So this connector is a pure harvester — Report + PDF only — and a
   separate downstream processor handles named-entity / IOC extraction. This keeps
   the connector purely additive and clear of the data-model allowlist entirely,
   matching the house pattern (Hellenic Shipping News, Jamestown, ScienceDaily,
   DFIR Report). The extraction investigation is preserved below in case the
   downstream processor reuses it.

2. **Enumeration = paginated category RSS feed.** The origin's edge WAF gates the
   structured surfaces unevenly: the WordPress REST API (`/wp-json/wp/v2/posts`) is
   hard-blocked (HTTP 403 "Forbidden" even to a browser UA), but the per-category
   RSS feed and the article pages return 200 to a browser UA. The feed is the
   enumeration surface because it is category-native and paginated:
   - Page 1: `{base}/category/{category}/feed/` (bare). `?paged=1` is edge-blocked
     and returns an empty body — it must NOT be used for page 1.
   - Pages 2..last: `{base}/category/{category}/feed/?paged=N`.
   - 15 items/page, newest-first. A page past the last returns HTTP 404 (the
     end-of-list signal). Threat Research is ~61 pages / ~915 posts at deployment.

3. **No positional cursor — graph dedup only.** Unlike Hellenic Shipping News /
   ScienceDaily (which hold a `{page, index}` cursor), this connector holds no
   cursor. An RSS feed is ordered newest-first and shifts whenever a post is
   published, so a persisted positional cursor would silently mis-position. The
   corpus is also ~1% the size of those origins, so re-walking the whole feed each
   poll is cheap. Correctness rests entirely on graph-driven dedup: a deterministic
   Report STIX id (`report--` + uuid5(NAMESPACE_URL, link)) is checked via
   `report.read(id)` before rendering, and existing Reports are skipped. New posts
   always get the highest ids and land at the front of page 1, so the uniform
   forward walk (page 1 → HTTP 404) covers both backfill and steady state. A
   `UNIT42_MAX_PAGES` safety bound guards against a 404-detection failure.

4. **Scope = the `threat-research` category, operator-configurable.** The user
   pointed at `/category/threat-research/`. It is the flagship umbrella technical
   category (~915 posts) and, per the census, largely nests the sibling technical
   categories (Malware, Ransomware, etc.). Widening/narrowing is a one-line config
   change (`UNIT42_CATEGORY`), not a code change.

5. **robots.txt.** Permissive: only `/wp-admin/` disallowed, no Crawl-Delay. The
   connector runs under a plain browser UA (not ClaudeBot) for reference-use
   ingestion and defaults `UNIT42_REQUEST_DELAY` to a courteous 3 seconds.

6. **TLP / author / report_type / confidence.** TLP:CLEAR (public vendor blog).
   Author = single "Unit 42" Organization. report_type = `open-source-reporting`
   (custom open-vocabulary value, user-chosen for cross-connector consistency).
   Confidence = 50 (Medium band, matching the other OSINT-publisher connectors;
   user-chosen over a higher primary-source band for parity).

## Extraction investigation (NOT built — retained for the downstream processor)

Before the container-only reversal, a structural census of 18 posts spanning
2014-2026 was run to size IOC-extraction reliability. Findings, in case the
processor reuses them:

- **~40%** of posts have an inline, parseable IOC section (heading matches the
  case-insensitive substring `indicator` — usually "Indicators of Compromise", once
  "Indicators from this report"). **~28%** legitimately have zero IOCs (vuln
  disclosures, announcements); "no IOCs" is normal, not an error.
- **Markup drifts by era**: bulleted `<ul><li>` lists (2025-26), HTML `<table>`
  (2021-23), inline `<p>` prose (2015-16). No single parser covers all three.
- **Refanging is deterministic**: `[.]`→`.`, `hxxp`/`hxxps`→`http`/`https`,
  `[:]`→`:`. No email defang observed.
- **Precision landmine**: page chrome. A whole-page scan pulls neighbor-article
  CVEs and YARA-sample hashes into the wrong report. Extraction MUST be bounded to
  the article-body slice (`class="section blog-contents"` → `be-related-articles`)
  and, within it, to the IOC heading's DOM subtree.
- **ATT&CK technique-ID tables: ~6%** (not reliable). **GitHub-hosted IOCs: rare**;
  whitelist `pan-unit42/iocs` and `PaloAltoNetworks/Unit42-timely-threat-intel` if
  ever followed.
- **Adversary-entity minting (Malware / Intrusion-Set / Threat-Actor-Group) from
  prose/title/tags was judged low-precision** (no structured name field; tags
  include non-entities like "obfuscation") and would require guessing entity
  boundaries and semantic edges — barred by the enforcement gate. Deferred by
  design; then the whole extraction tier was dropped per decision 1.

## Dedup: deterministic Report id (house pattern)

Dedup keys on `report--` + uuid5(NAMESPACE_URL, link), checked via `report.read(id)`
before rendering. A new post creates the External Reference (upsert-safe), then the
Report with that stix_id (update=True), then attaches the PDF. Because the existence
check keys on the Report id and not the External Reference, every sub-write is
idempotent and a crash anywhere leaves the post still "not done"; the next poll
re-enters and completes it. No state file, no cursor.

## Enforcement-gate caveat

As recorded for arXiv / Jamestown / Hellenic Shipping News: the gate tooling
CLAUDE.md names (`scripts/preflight.py`, the `datamodel/` package, the pytest
scaffolding) is absent from this checkout, and `data_model/` holds
`Data_Model_Relationship_Guide5.csv`. Relationship validation is vacuous here: the
connector emits zero relationships (container-only). Hygiene (pin/base/secrets)
checked manually. Flagged, not silently resolved.

## Cross-connector open item

`OPENCTI_URL` vs `OPENCTI_BASE_URL` naming remains an unresolved cross-connector
decision (CLAUDE.md). This connector follows the prevailing render-connector pattern
(Jamestown, ScienceDaily, Hellenic Shipping News) and uses `OPENCTI_URL`; it does
not settle the naming decision.

[Hellenic Shipping News]: ../hellenic_shipping_news/CONNECTOR_SCOPE.md
[Jamestown]: ../jamestown/CONNECTOR_SCOPE.md
