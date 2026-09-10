"""
report_builder.py
Handles all OpenCTI API interactions for report creation.
Isolates the OpenCTI SDK calls from plugin business logic.

Marking definition IDs are instance-specific and sourced directly
from this OpenCTI instance via markingDefinitions query.
"""

from __future__ import annotations

import io
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)

# TLP levels to resolve at init time. The connector queries the platform
# for each marking definition by name rather than hard-coding UUIDs, which
# are instance-specific and break across deployments.
_TLP_LEVELS = [
    "TLP:CLEAR",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
]

# Default marking name for plugins that don't specify one.
DEFAULT_MARKING_NAME = "TLP:CLEAR"


class ReportBuilder:
    """
    Wraps the OpenCTI Python client and exposes the ingestion operations
    needed by connector.py.
    """

    def __init__(self, opencti_api, helper):
        self.api = opencti_api
        self.helper = helper
        self.log = logging.getLogger(__name__)
        self._identity_cache: dict[str, str] = {}
        self._marking_ids: dict[str, str] = {}
        for tlp_name in _TLP_LEVELS:
            resolved = self._resolve_marking_id(tlp_name)
            if resolved:
                self._marking_ids[tlp_name] = resolved
            else:
                self.log.warning(
                    "Could not resolve marking definition for '%s'", tlp_name
                )
        self._default_marking_id = self._marking_ids.get(DEFAULT_MARKING_NAME)
        if not self._default_marking_id:
            self.log.error(
                "Default marking '%s' could not be resolved — "
                "reports may be created without a marking", DEFAULT_MARKING_NAME
            )

    def _resolve_marking_id(self, tlp_name: str) -> str | None:
        """
        Query the platform for a marking definition by its definition name.
        Returns the internal UUID or None if not found.
        """
        try:
            result = self.helper.api.marking_definition.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "definition", "values": [tlp_name]}],
                    "filterGroups": [],
                }
            )
            if result:
                return result.get("id")
        except Exception as e:
            self.log.warning(
                "Failed to resolve marking '%s': %s", tlp_name, e
            )
        return None

    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------

    def ingest(self, enriched, plugin) -> Optional[str]:
        """
        Full ingestion pipeline for one EnrichedReport.

        Steps:
          1. Resolve or create the author Identity
          2. Check for existing report with this External Reference (dedup)
          3. Create the Report container
          4. Attach External Reference to the Report container
          5. Attach PDF if available

        Returns the OpenCTI report ID on success, None on skip or failure.
        """
        raw = enriched.raw

        # --- 1. Resolve author identity ------------------------------------
        author_name = enriched.author_name or plugin.author_name
        author_id = self._resolve_identity(author_name)
        if not author_id:
            self.log.error(
                "Could not resolve identity for '%s', skipping: %s", author_name, raw.url
            )
            return None

        # --- 2. Deduplication check ----------------------------------------
        if self._report_exists_for_url(raw.url):
            self.log.info("Report already exists for URL, skipping: %s", raw.url)
            return None

        # --- 3. Resolve metadata -------------------------------------------
        marking_name = enriched.marking or plugin.default_marking
        marking_id = self._marking_ids.get(marking_name, self._default_marking_id)
        report_type = enriched.report_type or plugin.report_type
        confidence = plugin.confidence
        published = enriched.resolved_published or raw.published or datetime.now(timezone.utc)
        published_str = published.strftime("%Y-%m-%dT%H:%M:%SZ")

        # --- 4. Create the Report container --------------------------------
        self.log.info("Creating report: %s", raw.title)
        try:
            report = self.api.report.create(
                name=raw.title,
                description=raw.summary or "",
                published=published_str,
                report_types=[report_type],
                createdBy=author_id,
                objectMarking=[marking_id],
                confidence=confidence,
                x_opencti_workflow_status="Draft",
                labels=enriched.labels or [],
            )
        except Exception as e:
            self.log.error("Failed to create report '%s': %s", raw.title, e)
            return None

        report_id = report["id"]
        self.log.info("Created report %s", report_id)

        # --- 5. Create External Reference and attach to Report container ---
        try:
            ext_ref = self.api.external_reference.create(
                source_name=author_name,
                url=raw.url,
                description=f"Source URL for: {raw.title}",
            )
            ext_ref_id = ext_ref["id"]
            self.api.stix_domain_object.add_external_reference(
                id=report_id,
                external_reference_id=ext_ref_id,
            )
            self.log.info(
                "Attached external reference %s to report %s", ext_ref_id, report_id
            )
        except Exception as e:
            self.log.warning(
                "Could not attach external reference to %s: %s", report_id, e
            )

        # --- 6. Attach PDF if available ------------------------------------
        if enriched.pdf_bytes:
            self._attach_pdf(
                report_id=report_id,
                pdf_bytes=enriched.pdf_bytes,
                filename=enriched.pdf_filename or self._url_to_filename(raw.url),
            )

        return report_id

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _resolve_identity(self, name: str) -> Optional[str]:
        """
        Look up or create an Organization identity in OpenCTI.
        Results are cached for the connector run lifetime.
        """
        if name in self._identity_cache:
            return self._identity_cache[name]

        try:
            existing = self.api.identity.read(filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [name]}],
                "filterGroups": [],
            })
            if existing:
                stix_id = existing["id"]
                self._identity_cache[name] = stix_id
                return stix_id

            created = self.api.identity.create(
                type="Organization",
                name=name,
                description="Publisher identity auto-created by IC Reports connector.",
            )
            stix_id = created["id"]
            self._identity_cache[name] = stix_id
            self.log.info("Created identity: %s (%s)", name, stix_id)
            return stix_id

        except Exception as e:
            self.log.error("Identity resolution failed for '%s': %s", name, e)
            return None

    def _report_exists_for_url(self, url: str) -> bool:
        """
        Check whether any report already has an External Reference pointing
        to this URL. Primary deduplication mechanism.
        """
        try:
            refs = self.api.external_reference.list(filters={
                "mode": "and",
                "filters": [{"key": "url", "values": [url]}],
                "filterGroups": [],
            })
            return bool(refs)
        except Exception as e:
            self.log.warning(
                "Dedup check failed for %s: %s — assuming exists to prevent duplicates", url, e
            )
            return True

    def _attach_pdf(self, report_id: str, pdf_bytes: bytes, filename: str) -> None:
        """Upload a PDF file to the report's Files tab."""
        try:
            file_obj = io.BytesIO(pdf_bytes)
            file_obj.name = filename
            self.api.stix_domain_object.add_file(
                id=report_id,
                file_name=filename,
                data=file_obj,
                mime_type="application/pdf",
                no_trigger_import=False,
            )
            self.log.info("Attached PDF '%s' to report %s", filename, report_id)
        except Exception as e:
            self.log.warning("Could not attach PDF to report %s: %s", report_id, e)

    @staticmethod
    def _url_to_filename(url: str) -> str:
        """Derive a reasonable filename from a URL."""
        path = urlparse(url).path
        filename = unquote(path.rstrip("/").split("/")[-1]).strip()
        if not filename or "." not in filename:
            filename = "report.pdf"
        if not filename.lower().endswith(".pdf"):
            filename = filename + ".pdf"
        return filename
