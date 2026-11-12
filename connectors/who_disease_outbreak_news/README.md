# WHO Disease Outbreak News connector

External-import connector that creates one container-only OpenCTI **Report**
per WHO Disease Outbreak News article, with the live article attached as one rendered PDF.
Added from the Crucible proposed-sources list.

| | |
|---|---|
| Source | `https://www.who.int/api/news/diseaseoutbreaknews?$orderby=PublicationDateAndTime%20desc&$top=20&$select=Id%2CDonId%2CTitle%2CUrlName%2CPublicationDateAndTime%2CSummary` |
| Collection | Json discovery, new posts only. No backfill. |
| Default poll | every 60 minutes |
| Dedup | Graph-driven by External Reference URL (cited by a Report). No state file. |
| PDF | One per Report, live article via the house `pdf-renderer` client (`microservices/make_pdf.py`, `PDF_RENDERER_URL`); content `article.sf-detail-body-wrapper` |
| Author | `World Health Organization` Organization |
| Marking / confidence | TLP:CLEAR / 50 |
| report_type | From the Crucible Collector (`CRUCIBLE_COLLECTOR_URL`); `open-source-reporting` when unset or on error |
| Graph objects | Report + External Reference + attached PDF only. No Labels, entities, Observables or Relationships. |

WHO publishes NO RSS/Atom feed for Disease Outbreak News (legacy
/feeds/entity/csr/don/en/rss.xml is 404; the WHO news RSS used by
world_health_organization carries no DONs). Discovery = public OData API
https://www.who.int/api/news/diseaseoutbreaknews with
$orderby=PublicationDateAndTime desc&$top=20&$select=... (default order is NOT
newest-first). ~3 DONs/month (50 items span 489 days); every item is
substantive (no noise to filter). Article URL =
https://www.who.int/emergencies/disease-outbreak-news/item/<UrlName>; UrlName
is usually the DonId ('2026-DON625') but some items use a title slug (e.g.
'middle-east-respiratory-syndrome-coronavirus---kingdom-of-saudi-arabia' =
DonId 2026-DON618) - dedup on DonId or Id, build the URL from UrlName. The API
also returns the full DON text as HTML sections (Summary, Overview,
Epidemiology, Assessment, Advice, Response, FurtherInformation), so a
description can be taken from Summary without fetching the page. Page layout
(Sitefinity 'don-revamp'): header (h2 'Disease Outbreak News', h1.don-title,
.date) sits in a sibling .sf-item-header-wrapper; the body (h3.don-section +
div.don-content sections) is in article.sf-detail-body-wrapper - the selector
captures body only, headline is supplied from the API Title. Recurring DONs on
one event (e.g. 8 Ebola Bundibugyo updates) have distinct DonIds and URLs -
each becomes its own Report.

## Scope

Checked before dedup, so out-of-scope items cost no graph queries or renders.

- Items published more than 30 days ago are skipped (`max_age_days`, `WHO_DISEASE_OUTBREAK_NEWS_MAX_AGE_DAYS`; 0 = no limit).

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
text of the article page's content element, fetched with one plain GET only
when the Collector is configured). The returned type becomes
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
- One `report.create` per new article with the PDF attached inline (the file
  marked TLP:CLEAR via `filesMarkings`) and `update=False`, so there are no
  follow-up file uploads or upsert rewrites.
- Report descriptions are plain text, capped at 2,000 characters: the feed
  summary (minus any WordPress "The post ... appeared first on ..." line), or,
  when the feed has none, the article page's own meta description from one
  plain GET (the same GET the classifier text uses). Full text stays in the
  attached PDF. PDFs over 25 MB are not attached.

## Deduplication

An article counts as ingested when an External Reference with its URL exists
and some Report cites it. An article already ingested by any connector under
the same URL is therefore not duplicated, and a reference left
behind by a failed Report create does not block a retry.

## Failures

- Permanent (no date): skipped for the life of the process.
- Renderer unavailable (pdf-renderer down, busy, timed out, 5xx) or API error:
  transient. Nothing is written; retried on later polls while the item is in
  the feed, up to 5 polls.
- No usable article (pdf-renderer 422 or 403) or a PDF over 25 MB: the Report
  is created without a PDF and a WARNING is logged (house policy).
- If the dedup lookup fails, the whole poll is skipped (nothing written).
- If no item in a poll was already ingested, the connector warns that posts may
  have scrolled off the feed between polls.

## Running

Self-contained build; the shared `microservices/` package (pdf-renderer
client and Crucible classifier) is volume-mounted at `/microservices` (see
`docker-compose.yml`). The `pdf-renderer` service must be on the same Docker
network (`PDF_RENDERER_URL`, default `http://pdf-renderer:8000`):

```bash
docker compose -f who_disease_outbreak_news/docker-compose.yml build
```

Supply `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID` and
`CRUCIBLE_COLLECTOR_URL` through your uncommitted `docker-compose.override.yml`.
Set `WHO_DISEASE_OUTBREAK_NEWS_MAX_REPORTS=3` for a bounded first run and check the PDFs.

## Tests

```bash
python -m pytest -q test_main.py
```
