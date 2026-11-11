# TechCrunch connector

External-import connector that creates one container-only OpenCTI **Report**
per TechCrunch article, with a rendered PDF and a raw HTML snapshot attached.
Replaces TechCrunch coverage from the deprecated Feedly connector.

| | |
|---|---|
| Source | `https://techcrunch.com/feed/` |
| Collection | Feed only, new posts only. No backfill. |
| Default poll | every 15 minutes |
| Dedup | Graph-driven by External Reference URL (cited by a Report). No state file. |
| PDF | Shared `pdf-renderer` service; content `.seamless-scroll-container` |
| Author | `TechCrunch` Organization |
| Marking / confidence | TLP:CLEAR / 50 |
| report_type | From the Crucible Collector (`CRUCIBLE_COLLECTOR_URL`); `open-source-reporting` when unset or on error |
| Graph objects | Report + External Reference + attached files only. No Labels, entities, Observables or Relationships. |

Whole site, not just the security category (user decision: the intelligence
requirements are broad). The feed holds the latest 20 posts, which can be as
little as ~16 hours, so the default poll is 15 minutes. The headline lives in
an .article-hero outside the body, so the container is the
.seamless-scroll-container that wraps both; selectors hide any following
article that the site's seamless scroll appends.

## Data model

- A Report is an external assertion ("what the world says"). No Incident
  Response containers or Sightings are created.
- `published` is the article's own date from the feed. Items without a
  parseable date are skipped, never stamped with ingestion time.
- Feed categories are not collection requirements, so they are never applied as
  Labels.

## Report type (Crucible Collector)

When `CRUCIBLE_COLLECTOR_URL` is set, each new article is POSTed through the
shared `microservices/classify_report.py` helper to
`$CRUCIBLE_COLLECTOR_URL/classify` with its title, feed summary, URL and the
full article text (the feed's full text where the feed has it, otherwise the
text of the rendered page's article element). The returned type becomes
`report_types`. The article text is sent only to the Collector; it is not
stored on the Report.

- The Collector's `collection_requirements` are ignored: Labels are reserved
  for collection requirements.
- On Collector error or timeout (`CRUCIBLE_CLASSIFY_TIMEOUT`, default 30s) the
  Report gets `open-source-reporting` and a WARNING is logged with the source,
  the report title and the error.
- With the variable unset, or the shared helper not mounted, no call is made
  (standalone mode).

## Elasticsearch footprint

- Dedup takes at most two exact-match batched queries per poll (External
  References by URL, then the Reports citing them), id/url fields only, no
  full-text search queries.
- Idle polls write nothing (no work record unless there is something new).
- One `report.create` per new article with the PDF and HTML attached inline and
  `update=False`, so there are no follow-up file uploads or upsert rewrites.
- Report descriptions are plain text, capped at 2,000 characters. Full text
  stays in the attached files. PDFs over 25 MB are skipped; HTML snapshots over
  10 MB are not attached.

## Deduplication

An article counts as ingested when an External Reference with its URL exists
and some Report cites it. Articles the deprecated Feedly connector already
ingested under the same URL are therefore not duplicated, and a reference left
behind by a failed Report create does not block a retry.

## Failures

- Permanent (no date, oversized PDF): skipped for the life
  of the process.
- Transient (render or API error): retried on later polls while the item is in
  the feed, up to 5 polls.
- If the dedup lookup fails, the whole poll is skipped (nothing written).
- If no item in a poll was already ingested, the connector warns that posts may
  have scrolled off the feed between polls.

## Running

Self-contained build; the shared `microservices/` package is volume-mounted at
`/microservices` (see `docker-compose.yml`):

```bash
docker compose -f techcrunch/docker-compose.yml build
```

Supply `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID` and
`CRUCIBLE_COLLECTOR_URL` through your uncommitted `docker-compose.override.yml`.
Set `TECHCRUNCH_MAX_REPORTS=3` for a bounded first run and check the PDFs.

## Tests

```bash
python -m pytest -q test_main.py
```
