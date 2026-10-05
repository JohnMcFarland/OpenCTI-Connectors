# CONNECTOR_SCOPE — arXiv

Decision log for `connectors/arxiv/`. This file is the authoritative per-connector
record; it supersedes memory and conversation for this connector's locked decisions.

## Summary

External-import connector that mirrors the **entire arXiv preprint corpus** into
OpenCTI as **container-only Report** objects, each with the paper's PDF attached.
Adapts the ScienceDaily / DFIR / Bellingcat house style (flat layout, `config.yml` +
`get_config_variable`, container-only, graph-driven dedup via External Reference URL)
but is architecturally **simpler**: arXiv has a real metadata API and serves PDFs
directly, so there is **no sitemap scraping, no DOM extraction, and no Playwright**.

Built 2026-06-16.

## Locked decisions (confirmed with user)

1. **Scope: entire arXiv** — all groups/categories, from the earliest record. The
   user was shown the concrete scale (~2.5M papers, ~6.5 TB of PDFs, months-long
   direct crawl, mostly non-CTI physics/math) and the arXiv-specific constraint that
   arXiv discourages full-corpus PDF crawling in favour of S3 — and **explicitly chose
   the entire corpus**, consistent with the same full-breadth choice made on
   ScienceDaily. Do NOT "fix" the scope to a cyber subset in a future session; the
   breadth is intentional. `ARXIV_OAI_SET` (e.g. `cs:cs:CR`) and `ARXIV_FROM_DATE` are
   the levers to narrow it without code edits.
2. **PDF: attach the real arXiv PDF** — fetched directly from `arxiv.org/pdf/<id>`,
   the genuine paper (not a rendered page). `ARXIV_FETCH_PDF=false` switches to
   metadata-only Reports if ever wanted.
3. **PDF backend: direct crawl only** — NO AWS / S3 / boto3 dependency. The user
   explicitly declined the S3 requester-pays bulk path (which would be faster and
   arXiv-sanctioned for bulk but needs AWS credentials + ~$585 egress or an us-east-1
   host). Consequence accepted: a full backfill is a months-long polite crawl subject
   to 503/Retry-After flow control (honoured in code).
4. **Container-only** — one **Report** + PDF per paper. No Observables/SDOs/SROs. A
   preprint mirror has no reliably-extractable CTI entities; container-only is correct
   per the data model and keeps the connector non-contaminating at any scale. NLP
   entity extraction is explicitly **out of scope** (would be a separate Structural
   change).
5. **TLP:CLEAR**, author = "arXiv" Organization, report_type `open-source-reporting`,
   **confidence 50 (Medium)** — arXiv is the PRIMARY source but preprints are NOT
   peer-reviewed; primary-but-unreviewed nets to Medium (same band as ScienceDaily's
   secondary-but-reviewed). All configurable via `ARXIV_*` env / `arxiv.*` keys.

## Key divergences from ScienceDaily

1. **Enumeration = OAI-PMH, not sitemap/DOM.** `ListRecords` (metadataPrefix `arXiv`)
   with resumption-token pagination and date-selective `from`. Cursor =
   `{resumption_token, last_datestamp}` in `helper.get_state/set_state`, persisted per
   page. Steady state harvests `from=last_datestamp` forward. Token expiry (daily) →
   restart from `from=last_datestamp`; graph-dedup makes re-scan idempotent. One
   uniform code path for backfill + steady state.
2. **No render step.** PDFs are fetched directly (`requests`), validated by `%PDF-`
   magic / Content-Type. No Playwright, so the Dockerfile reverts to the
   **canonical `python:3.11-slim`** base (the project default) and `requirements.txt`
   drops `playwright` — this connector is *more* aligned with the standing base-image
   rule than its render-based siblings.
3. **Metadata fully structured from the API.** Title, abstract (→ description),
   authors, created date (→ published), categories, DOI, journal-ref all come from one
   OAI record. No extraction heuristics, no extra round-trip.
4. **Provenance is one step, not two.** arXiv IS the primary source: the abstract page
   is the primary External Reference (keyed by arXiv id); the DOI of a published
   version is attached as an additional reference when present.

## Convention notes / open items

- **`OPENCTI_URL` vs `OPENCTI_BASE_URL`:** this connector uses `OPENCTI_URL`, matching
  the adjacent ScienceDaily connector and pycti's `opencti.url`. This is *not* a silent
  resolution of the repo-wide naming decision flagged in CLAUDE.md — it is local
  consistency with the sibling connector. The repo-wide choice remains open.
- **OAI host:** `https://oaipmh.arxiv.org/oai` (the March-2025 host; the legacy
  `export.arxiv.org/oai2` is deprecated). Configurable via `ARXIV_OAI_BASE_URL`.

## Verification status

- `python -m py_compile main.py` — clean.
- Live read-only checks (no writes): OAI `GetRecord` returns the expected
  `{http://arxiv.org/OAI/arXiv/}` schema (id/created/updated/authors/title/categories/
  journal-ref/doi/abstract); `arxiv.org/pdf/0704.0001` returns HTTP 200,
  `application/pdf`, ~1.6 MB directly.
- Before first live run: deploy via `docker-compose.override.yml` with real
  OPENCTI_URL/TOKEN/CONNECTOR_ID; bounded `ARXIV_MAX_REPORTS=3` first, watch
  `token=/from=` cursor logs, then `=0` for the full backfill.
- Pending against the data-model gate: `relationship_validator` (no relationships are
  emitted, so a bundle validation is vacuously clean), `preflight.py`, `pytest`.
