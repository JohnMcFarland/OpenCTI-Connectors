# Pew Research Center: Religion connector

External-import connector that creates one container-only OpenCTI **Report**
per Pew Research Center: Religion article, with the live article attached as one rendered PDF.
Added from the Crucible proposed-sources list.

| | |
|---|---|
| Source | `https://www.pewresearch.org/feed/` |
| Collection | Feed only, new posts only. No backfill. |
| Default poll | every 60 minutes |
| Dedup | Graph-driven by External Reference URL (cited by a Report). No state file. |
| PDF | One per Report, live article via the house `pdf-renderer` client (`microservices/make_pdf.py`, `PDF_RENDERER_URL`); content `article` |
| Author | `Pew Research Center` Organization |
| Marking / confidence | TLP:CLEAR / 50 |
| report_type | From the Crucible Collector (`CRUCIBLE_COLLECTOR_URL`); `open-source-reporting` when unset or on error |
| Graph objects | Report + External Reference + attached PDF only. No Labels, entities, Observables or Relationships. |

Pew has ONE site-wide RSS2 feed (100 items, ~34 days, ~2.9 items/day, excerpt
only, real dc:creator bylines); every religion/topic feed URL 301s to it.
Religion scope is done with category_allow = the full Religion category
subtree read from /wp-json/wp/v2/categories (parent 24, 46 names; generic
'Knowledge & Education' left out). In the sampled feed that keeps ~6 items/34
days: Religion-team reports (/religion/YYYY/MM/DD/...) plus short reads tagged
with religion terms. Multi-page reports publish each chapter as its own feed
item: chapters are kept, Acknowledgments/Methodology/Additional charts are
dropped by exclude_title. Religion Weekly newsletters (/newsletter/, no
categories) and quizzes are dropped. Container <article> holds kicker+date,
h1, subtitle, byline, body (charts render as text fallback) and footnotes.

## Scope

Checked before dedup, so out-of-scope items cost no graph queries or renders.

- Only feed categories: `Atheism & Agnosticism`, `Beliefs & Practices`, `Buddhism`, `Catholicism`, `Christianity`, `Comparison of Religions`, `Global Religious Demographics`, `Hinduism`, `International Religious Freedom & Restrictions`, `Interreligious Relations`, `Islam`, `Judaism`, `Latter-day Saint (Mormon)`, `Muslim Americans`, `Muslims Around the World`, `Non-Religion & Secularism`, `Orthodox Christianity`, `Other Religions`, `Pew-Templeton Global Religious Futures Project`, `Pope Benedict XVI`, `Pope Francis`, `Pope John Paul II`, `Pope Leo XIV`, `Protestantism`, `Religion`, `Religion & Abortion`, `Religion & Bioethics`, `Religion & Death Penalty`, `Religion & Government`, `Religion & LGBTQ Acceptance`, `Religion & Politics`, `Religion & Race`, `Religion & Science`, `Religion & Social Values`, `Religions`, `Religious Characteristics of Demographic Groups`, `Religious Commitment`, `Religious Demographics`, `Religious Freedom & Restrictions`, `Religious Identity & Affiliation`, `Religious Knowledge & Education`, `Religious Leaders & Institutions`, `Religious Typology`, `Religiously Unaffiliated`, `Size & Demographic Characteristics of Religious Groups`, `U.S. Religious Demographics`.
- Skipped titles matching `^(Acknowledge?ments|Methodology|Additional charts|Appendix\b.*|Detailed tables|Topline.*)$`.
- Skipped links matching `/newsletter/|/quiz/`.
- Items published more than 30 days ago are skipped (`max_age_days`, `PEW_RELIGION_MAX_AGE_DAYS`; 0 = no limit).

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
docker compose -f pew_religion/docker-compose.yml build
```

Supply `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID` and
`CRUCIBLE_COLLECTOR_URL` through your uncommitted `docker-compose.override.yml`.
Set `PEW_RELIGION_MAX_REPORTS=3` for a bounded first run and check the PDFs.

## Tests

```bash
python -m pytest -q test_main.py
```
