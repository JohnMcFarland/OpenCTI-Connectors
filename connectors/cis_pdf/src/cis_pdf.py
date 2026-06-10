"""
cis_pdf.py

Final scope implementation for CIA CSI "Studies in Intelligence" PDF ingestion connector.

Behavior:
1) Seed (first run):
   - Read a local seed URL list (CIS_SEED_FILE; default /opt/connector/seeds_urls.txt)
   - For each URL not already in OpenCTI (dedupe by External Reference URL):
     - Download PDF
     - Create External Reference (dedupe by URL)
     - Create Report (published required) with createdBy=Author identity
     - Attach PDF to Report
   - Persist progress in /opt/connector/state/state.json and mark seed_complete=true when done.

2) Monthly check:
   - Once per CIS_MONTHLY_CHECK_DAYS (default 30), fetch CIA listing page
   - Extract PDF URLs, choose "most recent" = first PDF URL found
   - If not already in OpenCTI (dedupe by External Reference URL), ingest as above.
"""

import hashlib
import json
import os
import re
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.error import URLError, HTTPError

from pycti import OpenCTIConnectorHelper


CIA_LISTING_URL_DEFAULT = "https://www.cia.gov/resources/csi/studies-in-intelligence/?page=1&pageSize=-1"


# -----------------------
# Config + State
# -----------------------

@dataclass(frozen=True)
class Config:
    connector_name: str
    interval_seconds: int

    seed_file_path: str
    state_dir: str

    download_dir: str
    download_timeout_seconds: int

    author_name: str
    report_type: str

    listing_url: str
    monthly_check_days: int

    # Throughput controls (safety)
    max_ingest_per_cycle: int  # 0 means "no cap"

    @staticmethod
    def from_env() -> "Config":
        name = os.getenv("CONNECTOR_NAME", "cis_pdf_connector")

        interval = int(os.getenv("CONNECTOR_RUN_INTERVAL", "60"))
        if interval < 5:
            interval = 5

        seed_file = os.getenv("CIS_SEED_FILE", "/opt/connector/seeds_urls.txt").strip() or "/opt/connector/seeds_urls.txt"
        state_dir = os.getenv("CIS_STATE_DIR", "/opt/connector/state").strip() or "/opt/connector/state"

        download_dir = os.getenv("CIS_DOWNLOAD_DIR", "/opt/connector/downloads").strip() or "/opt/connector/downloads"
        timeout = int(os.getenv("CIS_DOWNLOAD_TIMEOUT_SECONDS", "60"))
        if timeout < 10:
            timeout = 10

        author_name = os.getenv("CIS_AUTHOR_NAME", "CIA Center for Intelligence Studies").strip() or "CIA Center for Intelligence Studies"
        report_type = os.getenv("CIS_REPORT_TYPE", "threat-report").strip() or "threat-report"

        listing_url = os.getenv("CIS_LISTING_URL", CIA_LISTING_URL_DEFAULT).strip() or CIA_LISTING_URL_DEFAULT
        monthly_days = int(os.getenv("CIS_MONTHLY_CHECK_DAYS", "30"))
        if monthly_days < 1:
            monthly_days = 30

        max_ingest = int(os.getenv("CIS_MAX_INGEST_PER_CYCLE", "10"))
        if max_ingest < 0:
            max_ingest = 0

        return Config(
            connector_name=name,
            interval_seconds=interval,
            seed_file_path=seed_file,
            state_dir=state_dir,
            download_dir=download_dir,
            download_timeout_seconds=timeout,
            author_name=author_name,
            report_type=report_type,
            listing_url=listing_url,
            monthly_check_days=monthly_days,
            max_ingest_per_cycle=max_ingest,
        )


class StateStore:
    """
    Minimal durable state to avoid re-processing the seed list forever.
    Platform dedupe is still the primary guard (External Reference URL lookup).
    """
    def __init__(self, state_dir: Path, logger) -> None:
        self.state_dir = state_dir
        self.path = state_dir / "state.json"
        self.log = logger
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.data = {
            "seed_complete": False,
            "seed_cursor": 0,
            "last_monthly_check_ts": 0,
        }
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.data.update(raw)
        except Exception as e:
            self.log.warning("Failed to load state.json; continuing with defaults.", {"error": str(e)})

    def save(self) -> None:
        try:
            self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        except Exception as e:
            self.log.error("Failed to write state.json.", {"error": str(e)})

    @property
    def seed_complete(self) -> bool:
        return bool(self.data.get("seed_complete", False))

    @seed_complete.setter
    def seed_complete(self, val: bool) -> None:
        self.data["seed_complete"] = bool(val)

    @property
    def seed_cursor(self) -> int:
        try:
            return int(self.data.get("seed_cursor", 0))
        except Exception:
            return 0

    @seed_cursor.setter
    def seed_cursor(self, val: int) -> None:
        self.data["seed_cursor"] = int(val)

    @property
    def last_monthly_check_ts(self) -> int:
        try:
            return int(self.data.get("last_monthly_check_ts", 0))
        except Exception:
            return 0

    @last_monthly_check_ts.setter
    def last_monthly_check_ts(self, val: int) -> None:
        self.data["last_monthly_check_ts"] = int(val)


# -----------------------
# Connector
# -----------------------

class CISPdfConnector:
    def __init__(self) -> None:
        self.cfg = Config.from_env()
        self.helper = OpenCTIConnectorHelper({})
        self.log = self.helper.connector_logger

        self.seed_file = Path(self.cfg.seed_file_path)
        self.download_path = Path(self.cfg.download_dir)
        self.state = StateStore(Path(self.cfg.state_dir), self.log)

        self.log.info(
            "cis_pdf_connector initialized (full scope)",
            {
                "seed_file": str(self.seed_file),
                "state_file": str(Path(self.cfg.state_dir) / "state.json"),
                "download_dir": str(self.download_path),
                "listing_url": self.cfg.listing_url,
                "monthly_check_days": self.cfg.monthly_check_days,
                "max_ingest_per_cycle": self.cfg.max_ingest_per_cycle,
                "author_name": self.cfg.author_name,
                "report_type": self.cfg.report_type,
            },
        )

    # -----------------------
    # Utilities
    # -----------------------

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _safe_filename_from_url(url: str) -> str:
        base = url.split("?")[0].rstrip("/").split("/")[-1].strip()
        if base.lower().endswith(".pdf") and len(base) >= 5:
            return base
        h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        return f"cis_seed_{h}.pdf"

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _report_title_from_pdf_path(pdf_path: Path) -> str:
        name = pdf_path.name
        if name.lower().endswith(".pdf"):
            name = name[:-4]
        return name.strip() or "CIA CSI Study"

    @staticmethod
    def _normalize_seed_line(line: str) -> Optional[str]:
        s = line.strip()
        if not s or s.startswith("#"):
            return None
        return s

    def load_seed_urls(self) -> List[str]:
        if not self.seed_file.exists() or not self.seed_file.is_file():
            self.log.error("Seed file missing or not a file.", {"seed_file": str(self.seed_file)})
            return []

        raw_lines = self.seed_file.read_text(encoding="utf-8", errors="replace").splitlines()
        urls: List[str] = []
        bad: List[str] = []

        for line in raw_lines:
            val = self._normalize_seed_line(line)
            if not val:
                continue
            if not (val.startswith("http://") or val.startswith("https://")):
                bad.append(val)
                continue
            urls.append(val)

        self.log.info(
            "Loaded seed URLs",
            {"seed_file": str(self.seed_file), "total_lines": len(raw_lines), "parsed_urls": len(urls), "invalid_lines": len(bad)},
        )
        if bad:
            self.log.warning("Some seed lines were invalid and ignored", {"invalid": bad[:10]})
        return urls

    # -----------------------
    # Download
    # -----------------------

    def download_pdf(self, url: str) -> Optional[Path]:
        self.download_path.mkdir(parents=True, exist_ok=True)
        fname = self._safe_filename_from_url(url)
        out_path = self.download_path / fname

        if out_path.exists() and out_path.is_file() and out_path.stat().st_size > 0:
            sha = self._sha256_file(out_path)
            self.log.info(
                "PDF already downloaded; using cached file",
                {"url": url, "path": str(out_path), "bytes": out_path.stat().st_size, "sha256": sha},
            )
            return out_path

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; OpenCTI-CIS-Connector/1.0)",
                "Accept": "application/pdf,*/*;q=0.8",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.cfg.download_timeout_seconds) as resp:
                data = resp.read()
            out_path.write_bytes(data)
            sha = self._sha256_file(out_path)
            self.log.info("Downloaded PDF", {"url": url, "path": str(out_path), "bytes": out_path.stat().st_size, "sha256": sha})
            return out_path
        except HTTPError as e:
            self.log.error("HTTP error downloading PDF", {"url": url, "status": getattr(e, "code", None), "reason": str(e)})
        except URLError as e:
            self.log.error("URL error downloading PDF", {"url": url, "reason": str(e)})
        except Exception as e:
            self.log.error(f"Unexpected error downloading PDF: {e}", {"url": url, "exc_info": True})
        return None

    # -----------------------
    # GraphQL helpers (schema-safe)
    # -----------------------

    @staticmethod
    def _filter_group_url_equals(url: str) -> dict:
        return {"mode": "and", "filters": [{"key": "url", "values": [url]}], "filterGroups": []}

    @staticmethod
    def _filter_group_name_equals(name: str) -> dict:
        return {"mode": "and", "filters": [{"key": "name", "values": [name]}], "filterGroups": []}

    def ensure_author_identity(self) -> Optional[str]:
        """
        Ensure the Author identity exists. Return its ID.
        Uses identity.list(...) with FilterGroup, then falls back to GraphQL organizationAdd.
        """
        try:
            if hasattr(self.helper.api, "identity") and hasattr(self.helper.api.identity, "list"):
                fg = self._filter_group_name_equals(self.cfg.author_name)
                results = self.helper.api.identity.list(filters=fg)
                if results and isinstance(results, dict):
                    edges = results.get("edges") or []
                    if edges and edges[0].get("node", {}).get("id"):
                        return edges[0]["node"]["id"]

            # Create via GraphQL
            mutation = """
            mutation OrganizationAdd($input: OrganizationAddInput!) {
              organizationAdd(input: $input) { id name }
            }
            """
            variables = {"input": {"name": self.cfg.author_name, "description": "Author identity for CIA Center for Intelligence Studies (connector-managed)."}}
            result = self.helper.api.query(mutation, variables)
            org = result.get("data", {}).get("organizationAdd")
            if org and org.get("id"):
                self.log.info("Created Author identity via GraphQL organizationAdd.", {"id": org["id"], "name": org.get("name")})
                return org["id"]

            self.log.error("Unable to ensure author identity.", {"result": result})
            return None
        except Exception as e:
            self.log.error(f"Failed to ensure author identity: {e}", {"exc_info": True})
            return None

    def ensure_marking_id(self, marking_definition: str = "TLP:CLEAR") -> Optional[str]:
        """
        Resolve the internal OpenCTI ID for a marking definition by definition name.
        Fetches all markings and matches client-side (server-side filter unreliable).
        """
        try:
            all_markings = self.helper.api.marking_definition.list()
            if isinstance(all_markings, list):
                for m in all_markings:
                    if (m.get("definition") or "").strip().lower() == marking_definition.strip().lower():
                        self.log.info(
                            "Resolved marking definition",
                            {"name": marking_definition, "id": m.get("id")}
                        )
                        return m.get("id")
            self.log.error("Marking definition not found", {"name": marking_definition})
        except Exception as e:
            self.log.error(f"Failed to resolve marking definition: {e}", {"exc_info": True})
        return None

    def get_external_reference_id_by_url(self, url: str) -> Optional[str]:
        """
        Dedupe primitive: if an External Reference with this URL exists, return its ID.
        """
        try:
            query = """
            query ExternalReferences($filters: FilterGroup) {
              externalReferences(filters: $filters) {
                edges { node { id url } }
              }
            }
            """
            variables = {"filters": self._filter_group_url_equals(url)}
            result = self.helper.api.query(query, variables)
            edges = result.get("data", {}).get("externalReferences", {}).get("edges") or []
            for e in edges:
                node = (e or {}).get("node") or {}
                if node.get("id") and (node.get("url") == url):
                    return node["id"]
            return None
        except Exception as e:
            self.log.error(f"External reference lookup failed: {e}", {"exc_info": True, "url": url})
            return None

    def create_external_reference(self, source_name: str, url: str, description: str) -> Optional[str]:
        """
        Create External Reference and return its ID.
        If already exists (by URL), returns existing ID.
        """
        existing = self.get_external_reference_id_by_url(url)
        if existing:
            return existing

        try:
            mutation = """
            mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) {
              externalReferenceAdd(input: $input) { id source_name url }
            }
            """
            variables = {"input": {"source_name": source_name, "url": url, "description": description}}
            result = self.helper.api.query(mutation, variables)
            ref = result.get("data", {}).get("externalReferenceAdd")
            if ref and ref.get("id"):
                return ref["id"]
            self.log.error("externalReferenceAdd did not return an id.", {"result": result})
            return None
        except Exception as e:
            self.log.error(f"externalReferenceAdd failed: {e}", {"exc_info": True, "url": url})
            return None

    def create_report(self, author_id: str, title: str, description: str, published_iso: str, external_reference_ids: List[str], marking_id: Optional[str] = None) -> Optional[str]:
        """
        Create Report via GraphQL. 'published' is required. externalReferences expects IDs.
        """
        try:
            mutation = """
            mutation ReportAdd($input: ReportAddInput!) {
              reportAdd(input: $input) { id name }
            }
            """
            report_input: Dict = {
                "name": title,
                "description": description,
                "report_types": [self.cfg.report_type],
                "createdBy": author_id,
                "published": published_iso,
                "externalReferences": external_reference_ids,
            }
            if marking_id:
                report_input["objectMarking"] = [marking_id]
            variables = {"input": report_input}
            result = self.helper.api.query(mutation, variables)
            rep = result.get("data", {}).get("reportAdd")
            if rep and rep.get("id"):
                return rep["id"]
            self.log.error("reportAdd did not return an id.", {"result": result})
            return None
        except Exception as e:
            self.log.error(f"reportAdd failed: {e}", {"exc_info": True})
            return None

    def attach_pdf_to_report(self, report_id: str, pdf_path: Path) -> bool:
        """
        Attach PDF to report. Your environment confirmed stix_domain_object.add_file works.
        """
        filename = pdf_path.name
        mime = "application/pdf"
        try:
            data = pdf_path.read_bytes()

            if hasattr(self.helper.api, "stix_domain_object") and hasattr(self.helper.api.stix_domain_object, "add_file"):
                self.helper.api.stix_domain_object.add_file(id=report_id, file_name=filename, data=data, mime_type=mime)
                self.log.info("Attached PDF to report.", {"report_id": report_id, "file": filename})
                return True

            # Fallbacks
            if hasattr(self.helper.api, "report") and hasattr(self.helper.api.report, "add_file"):
                self.helper.api.report.add_file(id=report_id, file_name=filename, data=data, mime_type=mime)
                self.log.info("Attached PDF to report (report.add_file).", {"report_id": report_id, "file": filename})
                return True

            self.log.error("No supported file-attachment method found.", {"report_id": report_id, "file": filename})
            return False
        except Exception as e:
            self.log.error(f"Failed attaching PDF to report: {e}", {"exc_info": True})
            return False

    # -----------------------
    # Ingest (dedupe by URL)
    # -----------------------

    def url_already_ingested(self, url: str) -> bool:
        """
        Primary platform dedupe: if an External Reference with this URL exists, we treat as ingested.
        """
        return self.get_external_reference_id_by_url(url) is not None

    def ingest_one_url(self, url: str, author_id: str, marking_id: Optional[str] = None) -> Tuple[bool, str]:
        """
        Returns (success, reason).
        """
        if self.url_already_ingested(url):
            return (True, "already_ingested")

        pdf_path = self.download_pdf(url)
        if pdf_path is None:
            return (False, "download_failed")

        ref_id = self.create_external_reference(
            source_name="CIA CSI Studies in Intelligence",
            url=url,
            description="Original CIA CSI source URL ingested by connector.",
        )
        if not ref_id:
            return (False, "external_reference_failed")

        title = self._report_title_from_pdf_path(pdf_path)
        description = f"Imported from CIA CSI Studies in Intelligence. Source URL: {url}"
        published = self._utc_now_iso()  # stable for schema; can be improved later

        report_id = self.create_report(
            author_id=author_id,
            title=title,
            description=description,
            published_iso=published,
            external_reference_ids=[ref_id],
            marking_id=marking_id,
        )
        if not report_id:
            return (False, "report_add_failed")

        if not self.attach_pdf_to_report(report_id, pdf_path):
            return (False, "attach_failed")

        self.log.info(
            "Ingested CIA CSI PDF",
            {
                "report_id": report_id,
                "title": title,
                "author_id": author_id,
                "url": url,
                "external_reference_id": ref_id,
                "pdf": str(pdf_path),
            },
        )
        return (True, "ingested")

    # -----------------------
    # Monthly check (listing scrape)
    # -----------------------

    def should_run_monthly_check(self) -> bool:
        now = int(time.time())
        interval = self.cfg.monthly_check_days * 24 * 3600
        return (now - self.state.last_monthly_check_ts) >= interval

    def fetch_listing_pdf_urls(self) -> List[str]:
        """
        Scrape CIA listing page for PDF URLs. We pick the first as "most recent".
        """
        req = urllib.request.Request(
            self.cfg.listing_url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; OpenCTI-CIS-Connector/1.0)"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.download_timeout_seconds) as resp:
                html = resp.read().decode("utf-8", errors="replace")

            # Collect absolute PDF URLs from href/src attributes
            # This captures both absolute and root-relative paths.
            pdf_links = re.findall(r'href="([^"]+\.pdf)"', html, flags=re.IGNORECASE)
            pdf_links += re.findall(r"href='([^']+\.pdf)'", html, flags=re.IGNORECASE)

            urls: List[str] = []
            for link in pdf_links:
                link = link.strip()
                if not link:
                    continue
                if link.startswith("http://") or link.startswith("https://"):
                    urls.append(link)
                elif link.startswith("/"):
                    urls.append("https://www.cia.gov" + link)

            # De-dupe preserving order
            seen = set()
            out: List[str] = []
            for u in urls:
                if u not in seen:
                    seen.add(u)
                    out.append(u)

            self.log.info("Listing scrape complete", {"pdf_urls_found": len(out)})
            return out
        except Exception as e:
            self.log.error(f"Failed to fetch/parse listing page: {e}", {"exc_info": True})
            return []

    def run_monthly_check(self, author_id: str, marking_id: Optional[str] = None) -> None:
        self.log.info("Running monthly check", {"listing_url": self.cfg.listing_url})
        pdf_urls = self.fetch_listing_pdf_urls()
        self.state.last_monthly_check_ts = int(time.time())
        self.state.save()

        if not pdf_urls:
            self.log.warning("Monthly check: no PDF URLs found.")
            return

        most_recent = pdf_urls[0]
        if self.url_already_ingested(most_recent):
            self.log.info("Monthly check: most recent already ingested.", {"url": most_recent})
            return

        ok, reason = self.ingest_one_url(most_recent, author_id, marking_id=marking_id)
        if ok:
            self.log.info("Monthly check: ingested most recent.", {"url": most_recent, "reason": reason})
        else:
            self.log.error("Monthly check: failed ingest.", {"url": most_recent, "reason": reason})

    # -----------------------
    # Seed ingestion
    # -----------------------

    def run_seed_ingestion(self, author_id: str, marking_id: Optional[str] = None) -> None:
        if self.state.seed_complete:
            return

        urls = self.load_seed_urls()
        if not urls:
            self.log.warning("Seed ingestion: no URLs to process.")
            return

        cursor = self.state.seed_cursor
        if cursor < 0:
            cursor = 0
        if cursor >= len(urls):
            self.state.seed_complete = True
            self.state.save()
            self.log.info("Seed ingestion already complete (cursor at end).")
            return

        remaining = urls[cursor:]
        if self.cfg.max_ingest_per_cycle == 0:
            batch = remaining
        else:
            batch = remaining[: self.cfg.max_ingest_per_cycle]

        self.log.info(
            "Seed ingestion batch starting",
            {"seed_cursor": cursor, "batch_size": len(batch), "remaining_total": len(remaining), "max_ingest_per_cycle": self.cfg.max_ingest_per_cycle},
        )

        processed = 0
        for u in batch:
            ok, reason = self.ingest_one_url(u, author_id, marking_id=marking_id)
            processed += 1
            cursor += 1
            self.state.seed_cursor = cursor
            self.state.save()

            # If a single ingest fails, continue; seed list is large and we want progress.
            if not ok:
                self.log.error("Seed ingest item failed", {"url": u, "reason": reason})
            else:
                # reduce log spam for "already_ingested"
                if reason != "already_ingested":
                    self.log.info("Seed ingest item ok", {"url": u, "reason": reason})

        if cursor >= len(urls):
            self.state.seed_complete = True
            self.state.save()
            self.log.info("Seed ingestion complete.", {"total_urls": len(urls)})

        self.log.info("Seed ingestion batch finished", {"processed_this_cycle": processed, "new_seed_cursor": cursor})

    # -----------------------
    # Main loop
    # -----------------------

    def run(self) -> None:
        self.log.info("cis_pdf_connector started (full scope).")

        author_id = self.ensure_author_identity()
        if not author_id:
            self.log.error("Cannot proceed without author identity ID.")
            while True:
                self.log.info("Heartbeat", {"iteration": 0})
                time.sleep(self.cfg.interval_seconds)

        # Resolve marking definition (TLP:CLEAR for all CIA CSI public documents)
        marking_id = self.ensure_marking_id("TLP:CLEAR")
        if not marking_id:
            self.log.warning("TLP:CLEAR marking not resolved — reports will have no marking definition")

        # Perform seed ingestion until complete (batched)
        self.run_seed_ingestion(author_id, marking_id=marking_id)

        # Perform monthly check if due
        if self.should_run_monthly_check():
            self.run_monthly_check(author_id, marking_id=marking_id)

        # Standard heartbeat loop
        n = 0
        while True:
            n += 1
            # Continue seed ingestion on subsequent cycles until done
            if not self.state.seed_complete:
                self.run_seed_ingestion(author_id, marking_id=marking_id)
            if self.should_run_monthly_check():
                self.run_monthly_check(author_id, marking_id=marking_id)

            self.log.info("Heartbeat", {"iteration": n, "seed_complete": self.state.seed_complete, "seed_cursor": self.state.seed_cursor})
            time.sleep(self.cfg.interval_seconds)
