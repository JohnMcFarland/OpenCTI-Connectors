# arXiv OpenCTI Connector

External-import connector that ingests the **entire arXiv preprint corpus**
(all groups/categories, 1991 → present) from [arXiv](https://arxiv.org/) into
OpenCTI as Report containers, each with the paper's PDF attached.

## Functionality

arXiv exposes a first-class metadata API, so this connector does **not** scrape or
render pages (unlike the ScienceDaily connector). It uses two surfaces, each for
what it is best at:

1. **Metadata — OAI-PMH.** `GET https://oaipmh.arxiv.org/oai?verb=ListRecords&metadataPrefix=arXiv`
   returns pages of fully-structured records (id, created/updated dates, authors,
   title, categories, DOI, journal-ref, abstract), paginated with resumption
   tokens. No per-paper metadata round-trip is ever needed.
2. **PDF — direct fetch.** `GET https://arxiv.org/pdf/<id>` returns the genuine
   paper PDF. There is no browser/render step; the connector attaches the real
   artifact, not a screenshot.

Each Report carries the paper title, the submission date, the "arXiv" organization
as author, TLP:CLEAR marking, the `open-source-reporting` report-type, a Medium-band
confidence, and External References (see **Provenance**). The PDF is attached to the
Report unless `ARXIV_FETCH_PDF=false`.

## Collection cursor

Collection is driven by OAI-PMH state persisted in OpenCTI connector state
(`{resumption_token, last_datestamp}`):

- **First run (no state):** `ListRecords` with no `from` → the entire corpus,
  streamed page by page via resumption tokens.
- **Resumability:** each fully-processed page persists `(resumption_token,
  last_datestamp)`, so an interrupted backfill resumes at the next page rather than
  restarting.
- **Token expiry:** arXiv resumption tokens expire daily. If a persisted token is
  rejected (`badResumptionToken`), the harvest restarts from `from=last_datestamp`.
  arXiv streams a harvest in datestamp order, so this resumes near the interruption;
  the graph-dedup backstop makes any re-scan idempotent.
- **Steady state:** once the backfill drains, each poll harvests
  `from=last_datestamp` forward and picks up newly-announced papers. **One uniform
  code path** covers backfill and steady state.

## Provenance

arXiv **is the primary source** (the preprint server itself), so provenance is
simpler than ScienceDaily's secondary-aggregator chain:

- **The arXiv abstract page** is an External Reference (`source_name` = `arXiv`,
  `url` = `https://arxiv.org/abs/<id>`, `external_id` = the arXiv id). Authors,
  categories, journal-ref and comments are recorded in its description.
- **The published version**, when the metadata names one, is attached as one
  additional External Reference per DOI (`url` = `https://doi.org/<DOI>`,
  `external_id` = DOI, `source_name` = the journal reference), preserving the chain
  **preprint → published paper**.

No **Labels** are applied — by policy, labels are reserved for collection requirements.

## ⚠️ Scale

arXiv spans **all** disciplines (physics, math, CS, biology, economics, …), not just
computing. The full corpus is **~2.5M papers** and growing ~20k/month. With
`ARXIV_FETCH_PDF=true` a full backfill therefore means:

- **~2.5M PDF fetches.** arXiv **rate-limits direct crawling** and steers bulk
  full-text consumers to its [AWS S3 requester-pays bucket](https://info.arxiv.org/help/bulk_data_s3.html);
  direct `/pdf` crawling is sanctioned only for *"new content or a subset"*. At the
  polite floor (`ARXIV_REQUEST_DELAY=3`) a full backfill is a **months-long,
  interruptible crawl**, and arXiv may apply 503/Retry-After flow control (which the
  connector honours). **This deployment uses the direct-crawl path by deliberate
  choice** (no AWS dependency).
- **~6.5 TB of PDFs** (≈2.7 TB as of 2023 + ~100 GB/month) in OpenCTI's object
  store — ~10× the ScienceDaily footprint. Ensure the MinIO/S3 backing store has the
  capacity.

The graph stays clean at any scale (container-only); the cost is purely volume,
storage, and time. To scope the corpus down without code edits:

- `ARXIV_OAI_SET` — e.g. `cs` (all computer science) or `cs:cs:CR` (Cryptography &
  Security only). Empty = entire arXiv.
- `ARXIV_FROM_DATE` — e.g. `2020-01-01` to cap the backfill start.
- `ARXIV_MAX_REPORTS` — small value for a bounded test run.
- `ARXIV_FETCH_PDF=false` — metadata-only Reports (no PDF, no crawl cost).

## Design philosophy

**Container-only.** The connector creates Report containers and nothing else: no
Domain Objects, no Observables, no Relationships. A preprint mirror has no reliably-
extractable CTI entities, so a container-only design is both the correct shape per the
data model and a guarantee that the connector is purely additive and can never act as
a graph-contamination vector. NLP entity extraction (CVEs / malware / actors from
abstracts) is explicitly **out of scope**.

## Key decisions

- **Report, not Incident Response.** arXiv is third-party assertion (external
  intelligence), never first-hand observation by us. No Sightings.
- **Author is the "arXiv" organization**, never the connector service account.
- **TLP:CLEAR** — arXiv is open access.
- **OAI-PMH for metadata, direct fetch for PDFs.** No DOM scraping, no Playwright.
- **OAI cursor + graph-driven deduplication.** The persisted `{resumption_token,
  last_datestamp}` cursor is the efficiency layer; the arXiv abstract-page External
  Reference lookup is the correctness backstop (idempotent even if state is lost).
- **Confidence 50 (Medium).** arXiv is the *primary* source but preprints are **not
  peer-reviewed**; primary-but-unreviewed nets to Medium.
- **Failed PDF fetch means the paper is skipped** (logged), never a Report without
  its PDF (when `ARXIV_FETCH_PDF=true`).

## Configuration

All configuration is supplied via environment variables (in
`docker-compose.override.yml`). Environment variables take precedence over `config.yml`.

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | string | — | Platform URL (pycti `opencti.url`). |
| `OPENCTI_TOKEN` | string | — | Connector service-account token. |
| `CONNECTOR_ID` | uuid | — | Unique connector ID (`uuidgen`). |
| `CONNECTOR_TYPE` | string | `EXTERNAL_IMPORT` | Connector type. |
| `CONNECTOR_NAME` | string | `arXiv` | Connector name. |
| `CONNECTOR_SCOPE` | string | `arxiv` | Connector scope. |
| `CONNECTOR_LOG_LEVEL` | string | `info` | Log verbosity. |
| `ARXIV_OAI_BASE_URL` | string | `https://oaipmh.arxiv.org/oai` | OAI-PMH endpoint. |
| `ARXIV_SITE_BASE_URL` | string | `https://arxiv.org` | Root for `/abs/<id>` and `/pdf/<id>`. |
| `ARXIV_METADATA_PREFIX` | string | `arXiv` | OAI metadata format (rich: authors/DOI/journal-ref). |
| `ARXIV_OAI_SET` | string | `` (all) | OAI set selector. `cs` / `cs:cs:CR` to scope. |
| `ARXIV_FROM_DATE` | string | `` (beginning) | Lower datestamp bound (`YYYY-MM-DD`) for the backfill. |
| `ARXIV_POLL_INTERVAL` | int (s) | `86400` | Seconds between harvest runs (24h). |
| `ARXIV_REQUEST_DELAY` | int (s) | `3` | Delay between OAI pages / PDF fetches. Keep ≥3. |
| `ARXIV_MAX_REPORTS` | int | `0` | Per-run cap on new Reports. `0` = unlimited. |
| `ARXIV_FETCH_PDF` | bool | `true` | `false` = metadata-only Reports (no PDF attached). |
| `ARXIV_OAI_RETRIES` | int | `5` | OAI request attempts before failing the page. |
| `ARXIV_PDF_RETRIES` | int | `3` | PDF fetch attempts before skipping a paper. |
| `ARXIV_CONFIDENCE` | int | `50` | OpenCTI confidence 0-100 (Medium band). |
| `ARXIV_REPORT_TYPE` | string | `open-source-reporting` | report_type vocabulary value. |
| `ARXIV_TLP` | string | `TLP:CLEAR` | Marking applied to every Report. |

## Deployment

1. Place under `~/opencti-docker/connectors/custom/arxiv/`.
2. Add the service to `docker-compose.override.yml` with real values
   (`OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`).
3. Build with `--no-cache` and bring up; tail logs and watch for the resolved author
   and marking UUIDs, the OAI `Identify` repository name, and the
   `token=/from=` cursor progress.
4. Validate with a bounded test (`ARXIV_MAX_REPORTS=3`) before the full backfill
   (`=0`). To scope down, set `ARXIV_OAI_SET` and/or `ARXIV_FROM_DATE`.

## Known limitations

- **No category Labels.** By policy, labels are reserved for collection requirements,
  so Reports are not faceted by arXiv's category taxonomy.
- **DOI depends on the metadata.** The DOI / journal-ref is attached only when arXiv's
  record names a published version; pure preprints get only the arXiv reference.
- **Forward-only cursor.** A PDF that fails all retries is permanently skipped
  (logged). The coarse `from=last_datestamp` resume relies on arXiv streaming a
  harvest in datestamp order; the graph-dedup backstop makes any re-scan idempotent
  but the cursor does not actively revisit gaps.
- **Direct-crawl scale.** A full-corpus PDF backfill via direct crawl is months-long
  and subject to arXiv flow control. For a faster sanctioned bulk path, arXiv's S3
  requester-pays bucket would be required (not implemented here, by design).

## License note

arXiv metadata is openly available and most submissions carry permissive or arXiv
distribution licenses. Internal ingestion under TLP:CLEAR with attribution to arXiv is
consistent with fair use of public OSINT; any redistribution must respect arXiv's
[API Terms of Use](https://info.arxiv.org/help/api/tou.html) and the per-paper license.
