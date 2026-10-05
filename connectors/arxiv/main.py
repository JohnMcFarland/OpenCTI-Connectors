"""
arXiv OpenCTI connector.

Purpose
-------
External-import connector that ingests the entire arXiv preprint corpus
(all groups/categories, 1991 -> present) and creates one OpenCTI Report
container per paper, with the paper's PDF attached.

Collection model
----------------
arXiv exposes a first-class metadata API -- OAI-PMH -- so this connector does
NOT scrape sitemaps or render the DOM (unlike the ScienceDaily connector). Two
surfaces are used, each for what it is best at:

  - Metadata: OAI-PMH ListRecords (https://oaipmh.arxiv.org/oai), metadataPrefix
    "arXiv". Date-selective (`from`) with resumption-token pagination. One
    request returns a page of fully-structured records (id, created, updated,
    authors, title, categories, DOI, journal-ref, abstract) -- no per-paper
    metadata round-trip is ever needed.
  - PDF: a direct GET of https://arxiv.org/pdf/<id>. The PDF already exists as a
    first-class artifact, so there is no browser/render step at all -- the
    connector fetches the genuine paper, not a screenshot of a web page.

arXiv steers *bulk* full-text consumers to its AWS S3 requester-pays bucket and
sanctions direct crawling of /pdf only for "new content or a subset". This
connector uses the direct-crawl path by deliberate operator choice (no AWS
dependency); it is therefore strictly rate-limited and honours HTTP 503 +
Retry-After flow control. A full-corpus backfill is consequently a months-long,
interruptible crawl -- see README "Scale".

Cursor / resumability
---------------------
Collection is driven by OAI-PMH state persisted in OpenCTI connector state:
{resumption_token, last_datestamp}.

  - First run (no state): ListRecords with no `from` -> the entire corpus,
    streamed page by page via resumption tokens.
  - Each fully-processed page persists (resumption_token, last_datestamp) so an
    interrupted backfill resumes at the next page rather than restarting.
  - arXiv resumption tokens expire daily. If a persisted token is rejected
    (badResumptionToken), the harvest restarts from `from=last_datestamp`. arXiv
    streams a full harvest in datestamp order, so this resumes near the
    interruption point; the graph-dedup backstop makes any re-scan idempotent.
  - Steady state: once the backfill drains, each poll harvests
    `from=last_datestamp` forward and picks up newly-announced papers. One
    uniform code path covers backfill and steady state.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects,
no Observables, no Relationships. A preprint mirror has no reliably-extractable
CTI entities (NLP entity extraction from abstracts is explicitly out of scope --
it is a structural, contamination-prone change), so a container-only design is
both the correct shape per the data model and a guarantee that the connector is
purely additive and can never act as a graph-contamination vector, even across
millions of papers.

Key decisions (see CONNECTOR_SCOPE.md)
--------------------------------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (open-access source).
- Author: an "arXiv" Organization identity. Never the connector account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (Medium band -- arXiv is the PRIMARY source
  but preprints are NOT peer-reviewed; primary-but-unreviewed nets to Medium).
- Provenance: arXiv IS the primary source. Each Report carries the arXiv abstract
  page as an External Reference (keyed by the arXiv id); when the metadata names
  a published version, the DOI is attached as an additional External Reference so
  the chain preprint -> published paper is preserved.
- Deduplication: graph-driven via External Reference URL lookup (the arXiv abs
  page), backed by the persisted OAI cursor. The graph lookup is the correctness
  backstop (idempotent even if state is lost); the cursor is the efficiency layer.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import time
import xml.etree.ElementTree as ET

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from microservices.classify_report import classify_report


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Descriptive User-Agent for BOTH the OAI client and the PDF fetcher. arXiv's API
# terms ask crawlers to identify themselves; a descriptive UA keeps the connector
# a good citizen and easy for arXiv operators to attribute.
DEFAULT_UA = (
    "OpenCTI-arXiv-connector/1.0 (external-import connector; +https://www.opencti.io)"
)

# OAI-PMH XML namespaces (ElementTree {namespace}tag form).
OAI_NS = "{http://www.openarchives.org/OAI/2.0/}"
ARXIV_NS = "{http://arxiv.org/OAI/arXiv/}"

# A DOI as it appears in an arXiv <doi> field (one paper may list several,
# whitespace-separated).
DOI_RE = re.compile(r"10\.\d{4,9}/[^\s\"'<>]+")


class _BadResumptionToken(Exception):
    """Raised when a persisted OAI resumption token is no longer valid.

    arXiv expires resumption tokens daily; a token persisted on a prior poll can
    be rejected with OAI error code 'badResumptionToken'. The run loop catches
    this and restarts the harvest from `from=last_datestamp`.
    """


def _truthy(value, default=True):
    """Coerce a config value to bool, tolerating env-var strings.

    get_config_variable returns a native bool from config.yml but the raw string
    from an environment variable -- and the string "false" is truthy in Python.
    This normalises both so ARXIV_FETCH_PDF=false actually disables PDF fetching.

    Args:
        value: the raw config value (bool, str, or None).
        default: value to use when None.

    Returns:
        bool.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _clean(value: str) -> str:
    """Collapse internal whitespace and trim a text fragment.

    Args:
        value: raw string (may be empty/None).

    Returns:
        Whitespace-normalised plain text.
    """
    if not value:
        return ""
    return re.sub(r"\s+", " ", value).strip()


def _stix_published(created: str, datestamp: str):
    """Derive a STIX publication timestamp for a paper.

    The arXiv <created> field (the original submission date, YYYY-MM-DD) is the
    natural publication date. The OAI header <datestamp> is the fallback when a
    record omits <created> (e.g. a malformed or deleted-then-restored record).

    Args:
        created: arXiv <created> value (YYYY-MM-DD) or "".
        datestamp: OAI header <datestamp> (YYYY-MM-DD) or "".

    Returns:
        ISO-8601 string with an explicit +00:00 offset, or None if neither input
        is a parseable date.
    """
    from datetime import datetime

    for candidate in (created, datestamp):
        candidate = (candidate or "").strip()
        if not candidate:
            continue
        try:
            dt = datetime.strptime(candidate[:10], "%Y-%m-%d")
            return dt.strftime("%Y-%m-%dT00:00:00+00:00")
        except ValueError:
            continue
    return None


class ArxivConnector:
    """External-import connector that mirrors arXiv papers into Reports."""

    def __init__(self):
        """Load configuration, build the OpenCTI helper, and prepare the HTTP
        client. Fixed graph references are resolved later in run() via
        _resolve_graph_references().
        """
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}
        else:
            config = {}

        self.helper = OpenCTIConnectorHelper(config)

        # --- Source configuration ------------------------------------------ #
        # OAI-PMH base endpoint (metadata). The March-2025 host; configurable so a
        # future arXiv migration needs no code change.
        self.oai_base_url = get_config_variable(
            "ARXIV_OAI_BASE_URL", ["arxiv", "oai_base_url"], config,
            default="https://oaipmh.arxiv.org/oai",
        ).rstrip("/")

        # Site root for abstract pages and PDFs. abs -> {root}/abs/{id};
        # pdf -> {root}/pdf/{id}.
        self.site_base_url = get_config_variable(
            "ARXIV_SITE_BASE_URL", ["arxiv", "site_base_url"], config,
            default="https://arxiv.org",
        ).rstrip("/")

        # OAI metadata format. "arXiv" carries separated authors, categories, DOI,
        # and journal-ref; oai_dc would lose those. Do not change without code edits.
        self.metadata_prefix = get_config_variable(
            "ARXIV_METADATA_PREFIX", ["arxiv", "metadata_prefix"], config,
            default="arXiv",
        )

        # OAI set selector. "" == entire arXiv (all groups/categories). The lever
        # to scope WITHOUT code edits: e.g. "cs" (all computer science) or
        # "cs:cs:CR" (Cryptography & Security only). See README.
        self.oai_set = get_config_variable(
            "ARXIV_OAI_SET", ["arxiv", "oai_set"], config, default="",
        ).strip()

        # Floor on the backfill start. "" == from the earliest record (full
        # corpus). Set e.g. "2015-01-01" to cap the backfill without code edits.
        self.from_date = get_config_variable(
            "ARXIV_FROM_DATE", ["arxiv", "from_date"], config, default="",
        ).strip()

        # Poll interval (seconds) between harvest runs.
        self.poll_interval = get_config_variable(
            "ARXIV_POLL_INTERVAL", ["arxiv", "poll_interval"], config,
            isNumber=True, default=86400,  # 24 hours
        )

        # Politeness delay (seconds) between successive OAI pages and PDF fetches.
        # arXiv rate-limits aggressively; keep >= 3s for direct crawling.
        self.request_delay = get_config_variable(
            "ARXIV_REQUEST_DELAY", ["arxiv", "request_delay"], config,
            isNumber=True, default=3,
        )

        # Per-run cap on new Reports. 0 == unlimited. Set small (e.g. 3) for a
        # bounded test before the full backfill.
        self.max_reports = get_config_variable(
            "ARXIV_MAX_REPORTS", ["arxiv", "max_reports"], config,
            isNumber=True, default=0,
        )

        # Whether to attach the PDF. True (operator choice) attaches the genuine
        # paper; False yields metadata-only Reports (abstract + arXiv reference).
        self.fetch_pdf = _truthy(
            get_config_variable(
                "ARXIV_FETCH_PDF", ["arxiv", "fetch_pdf"], config, default=True,
            ),
            default=True,
        )

        # Retry budgets for the two network surfaces.
        self.oai_retries = get_config_variable(
            "ARXIV_OAI_RETRIES", ["arxiv", "oai_retries"], config,
            isNumber=True, default=5,
        )
        self.pdf_retries = get_config_variable(
            "ARXIV_PDF_RETRIES", ["arxiv", "pdf_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        # OpenCTI confidence 0-100. Medium band: arXiv is the PRIMARY source but
        # preprints are not peer-reviewed.
        self.confidence = get_config_variable(
            "ARXIV_CONFIDENCE", ["arxiv", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "ARXIV_REPORT_TYPE", ["arxiv", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "ARXIV_TLP", ["arxiv", "tlp"], config, default="TLP:CLEAR",
        )

        self.user_agent = get_config_variable(
            "ARXIV_USER_AGENT", ["arxiv", "user_agent"], config, default=DEFAULT_UA,
        )

        # HTTP session shared by the OAI client and PDF fetcher.
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": self.user_agent, "Accept": "application/xml,text/xml,*/*"}
        )

        # Resolved graph references, populated by _resolve_graph_references().
        self.author_id = None      # "arXiv" Organization internal UUID
        self.marking_id = None     # TLP marking internal UUID

    # ------------------------------------------------------------------ #
    # URL helpers
    # ------------------------------------------------------------------ #

    def _abs_url(self, arxiv_id: str) -> str:
        """Abstract-page URL for an arXiv id (the dedup / provenance key)."""
        return f"{self.site_base_url}/abs/{arxiv_id}"

    def _pdf_url(self, arxiv_id: str) -> str:
        """Direct PDF URL for an arXiv id."""
        return f"{self.site_base_url}/pdf/{arxiv_id}"

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Resolve fixed graph objects and verify the OAI endpoint is reachable.

        Resolves internal OpenCTI UUIDs for the arXiv author identity and the TLP
        marking, registers the report_type vocabulary value, and confirms the OAI
        endpoint answers an Identify verb with a repository name.

        Raises:
            RuntimeError: if the marking cannot be resolved or the OAI endpoint is
                not reachable / not the expected shape.
        """
        # Author: identity.create is upsert-safe (returns existing if present).
        author = self.helper.api.identity.create(
            type="Organization",
            name="arXiv",
            description="Open-access repository of electronic preprints (arXiv.org). "
                        "Primary-source publisher for ingested preprints.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved arXiv author identity: {self.author_id}")

        # Marking: read to an internal UUID (TLP markings ship with the platform).
        marking = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [self.tlp_name]}],
                "filterGroups": [],
            }
        )
        if not marking:
            raise RuntimeError(
                f"Could not resolve marking '{self.tlp_name}'. Refusing to create "
                f"Reports without a resolved marking UUID."
            )
        self.marking_id = marking["id"]
        self.helper.log_info(f"Resolved marking {self.tlp_name}: {self.marking_id}")

        # report_type open-vocabulary registration. Idempotent; harmless failure
        # if the vocabulary is locked (operator adds it via Settings).
        try:
            self.helper.api.vocabulary.create(
                name=self.report_type,
                category="report_types_ov",
                description="Open-source reporting ingested from public OSINT publishers.",
            )
            self.helper.log_info(f"Ensured report_type vocabulary value: {self.report_type}")
        except Exception as exc:  # noqa: BLE001 - non-fatal, operator-actionable
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc}). "
                f"Add it under Settings -> Taxonomies -> Report types if missing."
            )

        # OAI reachability: confirm the enumeration surface is up.
        try:
            root = self._oai_request({"verb": "Identify"})
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"OAI endpoint unreachable at {self.oai_base_url} ({exc})."
            )
        name_el = root.find(f"{OAI_NS}Identify/{OAI_NS}repositoryName")
        if name_el is None:
            raise RuntimeError(
                f"OAI endpoint at {self.oai_base_url} did not answer Identify with a "
                f"repository name; refusing to run."
            )
        self.helper.log_info(
            f"OAI endpoint reachable: repository '{_clean(name_el.text)}'. "
            f"Set='{self.oai_set or 'ALL'}', from='{self.from_date or 'BEGINNING'}'."
        )

    # ------------------------------------------------------------------ #
    # OAI-PMH harvesting
    # ------------------------------------------------------------------ #

    def _oai_request(self, params):
        """Perform one OAI-PMH request with 503/Retry-After flow control.

        arXiv answers HTTP 503 with a Retry-After header when it wants the client
        to slow down; this honours that contract before falling back to bounded
        exponential backoff for transient transport errors.

        Args:
            params: OAI query parameters (verb + selectors or resumptionToken).

        Returns:
            xml.etree.ElementTree.Element: the parsed OAI-PMH root element.

        Raises:
            RuntimeError: if all retries are exhausted.
        """
        delay = self.request_delay
        for attempt in range(1, self.oai_retries + 1):
            try:
                resp = self.session.get(self.oai_base_url, params=params, timeout=120)
                if resp.status_code == 503:
                    retry_after = resp.headers.get("Retry-After", "")
                    wait = int(retry_after) if retry_after.isdigit() else delay
                    self.helper.log_info(
                        f"OAI 503 flow control; sleeping {wait}s "
                        f"(attempt {attempt}/{self.oai_retries})."
                    )
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                return ET.fromstring(resp.content)
            except Exception as exc:  # noqa: BLE001 - retried, then raised
                self.helper.log_warning(
                    f"OAI request failed (attempt {attempt}/{self.oai_retries}): {exc}"
                )
                if attempt < self.oai_retries:
                    time.sleep(delay)
                    delay *= 2
        raise RuntimeError(f"OAI request failed after {self.oai_retries} attempts.")

    def _initial_params(self, from_date):
        """Build first-page ListRecords params for a fresh (non-token) harvest.

        Args:
            from_date: lower datestamp bound (YYYY-MM-DD) or "" / None for the
                whole corpus.

        Returns:
            dict: OAI query parameters.
        """
        params = {"verb": "ListRecords", "metadataPrefix": self.metadata_prefix}
        if self.oai_set:
            params["set"] = self.oai_set
        if from_date:
            params["from"] = from_date
        return params

    def _iter_pages(self, resumption_token, from_date):
        """Yield successive OAI ListRecords pages.

        On the first iteration the request is keyed either by a persisted
        resumption token (resume mid-harvest) or by the fresh selectors
        (metadataPrefix/set/from). Thereafter it follows resumption tokens until
        the server stops issuing them.

        Args:
            resumption_token: a persisted token to resume from, or None to start
                a fresh harvest from `from_date`.
            from_date: lower datestamp bound for a fresh harvest.

        Yields:
            tuple[list[Element], str]: (record elements on this page, the
            resumption token to persist after the page is processed -- "" when
            this is the final page).

        Raises:
            _BadResumptionToken: if the initial token is rejected as expired/invalid.
            RuntimeError: on any other OAI error code.
        """
        if resumption_token:
            params = {"verb": "ListRecords", "resumptionToken": resumption_token}
            first_is_token = True
        else:
            params = self._initial_params(from_date)
            first_is_token = False

        while True:
            root = self._oai_request(params)

            error = root.find(f"{OAI_NS}error")
            if error is not None:
                code = (error.get("code") or "").strip()
                if code == "noRecordsMatch":
                    return  # nothing new since `from_date`; clean no-op.
                if code == "badResumptionToken" and first_is_token:
                    raise _BadResumptionToken(error.text or code)
                raise RuntimeError(
                    f"OAI error '{code}': {_clean(error.text or '')}"
                )

            list_records = root.find(f"{OAI_NS}ListRecords")
            if list_records is None:
                return

            records = list_records.findall(f"{OAI_NS}record")
            token_el = list_records.find(f"{OAI_NS}resumptionToken")
            token = (
                token_el.text.strip()
                if token_el is not None and token_el.text else ""
            )

            yield records, token

            if not token:
                return
            params = {"verb": "ListRecords", "resumptionToken": token}
            first_is_token = False
            time.sleep(self.request_delay)

    def _parse_record(self, record):
        """Parse one OAI <record> into a flat dict.

        Args:
            record: an OAI-PMH <record> element.

        Returns:
            dict: {
                "id", "deleted" (bool), "datestamp",
                "created", "updated", "title", "abstract",
                "authors" (str), "categories" (str),
                "journal_ref", "comments", "dois" (list[str]),
            }. For a deleted record only id/deleted/datestamp are meaningful.
        """
        header = record.find(f"{OAI_NS}header")
        status = (header.get("status") if header is not None else "") or ""
        datestamp_el = header.find(f"{OAI_NS}datestamp") if header is not None else None
        datestamp = _clean(datestamp_el.text) if datestamp_el is not None else ""

        meta = record.find(f"{OAI_NS}metadata")
        arxiv = meta.find(f"{ARXIV_NS}arXiv") if meta is not None else None

        if status == "deleted" or arxiv is None:
            ident = header.find(f"{OAI_NS}identifier") if header is not None else None
            raw_id = _clean(ident.text) if ident is not None else ""
            arxiv_id = raw_id.split(":")[-1] if raw_id else ""
            return {"id": arxiv_id, "deleted": True, "datestamp": datestamp}

        def _t(tag):
            el = arxiv.find(f"{ARXIV_NS}{tag}")
            return _clean(el.text) if el is not None and el.text else ""

        authors = []
        authors_el = arxiv.find(f"{ARXIV_NS}authors")
        if authors_el is not None:
            for author in authors_el.findall(f"{ARXIV_NS}author"):
                key = author.find(f"{ARXIV_NS}keyname")
                fore = author.find(f"{ARXIV_NS}forenames")
                name = " ".join(
                    p for p in [
                        _clean(fore.text) if fore is not None and fore.text else "",
                        _clean(key.text) if key is not None and key.text else "",
                    ] if p
                )
                if name:
                    authors.append(name)

        dois = []
        doi_raw = _t("doi")
        if doi_raw:
            dois = DOI_RE.findall(doi_raw)

        return {
            "id": _t("id"),
            "deleted": False,
            "datestamp": datestamp,
            "created": _t("created"),
            "updated": _t("updated"),
            "title": _t("title"),
            "abstract": _t("abstract"),
            "authors": ", ".join(authors),
            "categories": _t("categories"),
            "journal_ref": _t("journal-ref"),
            "comments": _t("comments"),
            "dois": dois,
        }

    def _already_ingested(self, abs_url):
        """Return True if this paper has already been ingested.

        Deduplication is graph-driven and keys off the arXiv abstract-page
        External Reference this connector creates for each paper. That reference
        is the first write in _create_report and is upsert-keyed on url, so its
        presence is the connector's idempotency marker -- which makes an
        interrupted backfill safe even if the cursor state is lost.

        Args:
            abs_url: arXiv abstract-page URL.

        Returns:
            bool: True if an External Reference with this url already exists.
        """
        existing_ref = self.helper.api.external_reference.read(
            filters={
                "mode": "and",
                "filters": [{"key": "url", "values": [abs_url]}],
                "filterGroups": [],
            }
        )
        return existing_ref is not None

    # ------------------------------------------------------------------ #
    # PDF fetching
    # ------------------------------------------------------------------ #

    def _fetch_pdf(self, arxiv_id):
        """Fetch a paper's PDF with 503/Retry-After flow control and backoff.

        Args:
            arxiv_id: arXiv id (e.g. "2106.12345" or "cs/9901001").

        Returns:
            bytes: the PDF on success, or None if all retries are exhausted or the
            response is not a valid PDF.
        """
        url = self._pdf_url(arxiv_id)
        delay = self.request_delay
        for attempt in range(1, self.pdf_retries + 1):
            try:
                resp = self.session.get(
                    url, timeout=180, headers={"Accept": "application/pdf"}
                )
                if resp.status_code == 503:
                    retry_after = resp.headers.get("Retry-After", "")
                    wait = int(retry_after) if retry_after.isdigit() else delay
                    self.helper.log_info(f"PDF 503 flow control; sleeping {wait}s.")
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                content = resp.content
                ctype = resp.headers.get("Content-Type", "")
                if not content.startswith(b"%PDF-") and "application/pdf" not in ctype:
                    raise RuntimeError(f"response is not a PDF (Content-Type: {ctype})")
                if len(content) < 1000:
                    raise RuntimeError("PDF suspiciously small (<1KB)")
                return content
            except Exception as exc:  # noqa: BLE001 - retried, then skipped
                self.helper.log_warning(
                    f"PDF fetch attempt {attempt}/{self.pdf_retries} failed for {url}: {exc}"
                )
                if attempt < self.pdf_retries:
                    time.sleep(delay)
                    delay *= 2
        return None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, paper, pdf_bytes):
        """Create one Report container for a paper and attach its PDF.

        Container-only: no object_refs, so the single-step report.create path is
        used. Provenance is carried on External References:
          1. the arXiv abstract page (the primary source we ingested), with the
             authors / categories / journal-ref recorded as context; and
          2. one reference per DOI when the metadata names a published version,
             preserving the chain preprint -> published paper.

        Args:
            paper: parsed record dict from _parse_record.
            pdf_bytes: the paper PDF, or None for a metadata-only Report.
        """
        arxiv_id = paper["id"]
        abs_url = self._abs_url(arxiv_id)
        name = paper.get("title") or arxiv_id
        description = paper.get("abstract") or ""

        published = _stix_published(paper.get("created", ""), paper.get("datestamp", ""))
        if not published:
            from datetime import datetime, timezone
            published = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
            self.helper.log_warning(
                f"Could not derive publication date for {arxiv_id}; using ingestion time."
            )

        # External Reference 1: the arXiv abstract page (primary source). Authors,
        # categories, and any journal reference are recorded as context.
        context_bits = []
        if paper.get("authors"):
            authors = paper["authors"]
            context_bits.append(
                f"Authors: {authors if len(authors) <= 1500 else authors[:1500] + ' et al.'}"
            )
        if paper.get("categories"):
            context_bits.append(f"Categories: {paper['categories']}")
        if paper.get("journal_ref"):
            context_bits.append(f"Journal reference: {paper['journal_ref']}")
        if paper.get("comments"):
            context_bits.append(f"Comments: {paper['comments']}")
        arxiv_description = "arXiv preprint abstract page."
        if context_bits:
            arxiv_description = (arxiv_description + " " + "; ".join(context_bits))[:5000]

        external_reference_ids = [
            self.helper.api.external_reference.create(
                source_name="arXiv",
                url=abs_url,
                external_id=arxiv_id,
                description=arxiv_description,
            )["id"]
        ]

        # External Reference(s) 2..n: the published version(s), keyed by DOI.
        for doi in paper.get("dois", []):
            ref_kwargs = {
                "source_name": (paper.get("journal_ref") or "Published version (DOI)")[:200],
                "url": f"https://doi.org/{doi}",
                "external_id": doi,
            }
            if paper.get("journal_ref"):
                ref_kwargs["description"] = paper["journal_ref"][:5000]
            external_reference_ids.append(
                self.helper.api.external_reference.create(**ref_kwargs)["id"]
            )

        _report_types = classify_report(
            title=name, description=description, content=description,
            source="arXiv", source_url=abs_url,
            default_types=[self.report_type],
        )

        report = self.helper.api.report.create(
            name=name,
            description=description,
            published=published,
            report_types=_report_types,
            confidence=self.confidence,
            createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=external_reference_ids,
            update=True,
        )

        if pdf_bytes is not None:
            file_name = f"arxiv-{arxiv_id.replace('/', '_')}.pdf"
            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=file_name,
                data=pdf_bytes,
                mime_type="application/pdf",
            )

        n_doi = len(paper.get("dois", []))
        self.helper.log_info(
            f"Created Report for {arxiv_id} ({name[:70]}); "
            f"{n_doi} DOI ref(s){'' if pdf_bytes is not None else '; metadata-only'}."
        )

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _harvest(self, work_id, resumption_token, from_date, counters):
        """Drive one OAI harvest: page through records, ingest, persist the cursor.

        Each fully-processed page persists (resumption_token, last_datestamp) so an
        interruption resumes at the next page. The max datestamp seen is tracked so
        steady-state polls can harvest `from=last_datestamp` forward.

        Args:
            work_id: active OpenCTI work id (for logging context only).
            resumption_token: token to resume from, or None for a fresh harvest.
            from_date: lower datestamp bound for a fresh harvest.
            counters: mutable dict accumulating processed/skipped/failed/deleted.

        Raises:
            _BadResumptionToken: propagated from _iter_pages when a persisted token
                is rejected; the caller restarts from `from=last_datestamp`.
        """
        state = self.helper.get_state() or {}
        last_datestamp = state.get("last_datestamp") or from_date or ""

        for records, next_token in self._iter_pages(resumption_token, from_date):
            for record in records:
                paper = self._parse_record(record)
                if paper["datestamp"] and paper["datestamp"] > last_datestamp:
                    last_datestamp = paper["datestamp"]

                if paper["deleted"] or not paper["id"]:
                    counters["deleted"] += 1
                    continue

                if self.max_reports and counters["processed"] >= self.max_reports:
                    self.helper.log_info(
                        f"Reached ARXIV_MAX_REPORTS={self.max_reports}; pausing run "
                        f"(cursor persisted; backfill resumes next poll)."
                    )
                    self.helper.set_state(
                        {"resumption_token": next_token or None,
                         "last_datestamp": last_datestamp}
                    )
                    counters["stopped"] = True
                    return

                abs_url = self._abs_url(paper["id"])
                if self._already_ingested(abs_url):
                    counters["skipped"] += 1
                    continue

                pdf_bytes = None
                if self.fetch_pdf:
                    pdf_bytes = self._fetch_pdf(paper["id"])
                    if pdf_bytes is None:
                        # Forward-only: a paper whose PDF cannot be fetched is
                        # skipped (logged), never a Report without its PDF.
                        counters["failed"] += 1
                        self.helper.log_warning(
                            f"Skipping {paper['id']}: PDF fetch failed after retries."
                        )
                        continue

                self._create_report(paper, pdf_bytes)
                counters["processed"] += 1
                time.sleep(self.request_delay)

            # Page fully processed -> persist the cursor for resumability.
            self.helper.set_state(
                {"resumption_token": next_token or None,
                 "last_datestamp": last_datestamp}
            )

    def _process(self):
        """Execute one harvest-and-ingest pass from the persisted OAI cursor.

        Resumes a persisted resumption token if present; if that token is rejected
        as expired, restarts the harvest from `from=last_datestamp`. With no token,
        harvests from the last datestamp (steady state) or from the configured
        floor / the beginning (first run / full backfill).
        """
        state = self.helper.get_state() or {}
        token = state.get("resumption_token")
        last_datestamp = state.get("last_datestamp")
        # Steady state resumes from the last datestamp; the very first run uses the
        # configured floor (or nothing == the whole corpus).
        from_date = last_datestamp or self.from_date or ""

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "arXiv OAI harvest run"
        )
        self.helper.log_info(
            f"Starting harvest: token={'yes' if token else 'no'}, "
            f"from={from_date or 'BEGINNING'}, set={self.oai_set or 'ALL'}."
        )

        counters = {"processed": 0, "skipped": 0, "failed": 0, "deleted": 0,
                    "stopped": False}
        try:
            if token:
                try:
                    self._harvest(work_id, token, from_date, counters)
                except _BadResumptionToken:
                    self.helper.log_warning(
                        "Persisted resumption token expired; restarting harvest "
                        f"from from={from_date or 'BEGINNING'}."
                    )
                    self.helper.set_state(
                        {"resumption_token": None, "last_datestamp": last_datestamp}
                    )
                    self._harvest(work_id, None, from_date, counters)
            else:
                self._harvest(work_id, None, from_date, counters)
        except Exception as exc:  # noqa: BLE001 - surface, then end the work cleanly
            self.helper.log_error(f"Harvest error: {exc}")

        message = (
            f"Run complete: {counters['processed']} created, "
            f"{counters['skipped']} already present, {counters['failed']} failed (PDF), "
            f"{counters['deleted']} deleted/empty"
            f"{'; paused at max_reports' if counters['stopped'] else ''}."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        """Connector entrypoint: resolve references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info("arXiv connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001 - keep the connector alive
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        ArxivConnector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
