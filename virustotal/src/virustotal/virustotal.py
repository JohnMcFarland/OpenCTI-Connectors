# -*- coding: utf-8 -*-
"""
VirusTotal enrichment connector — data-model-compliant implementation.

TRIGGER GATE
------------
Enrichment is performed ONLY for observables that belong to a
Case-Incident (RFI) container. Observables in Reports, or without
any container, are skipped. This restricts VT API calls, graph
mutations, and Indicator creation to the analyst workbench context.

REMOVED FROM UPSTREAM
---------------------
  - Indicator creation for files / IPs / domains / URLs (threshold-based)
  - IndicatorConfig loading (VIRUSTOTAL_*_INDICATOR_* env vars are dead)
  - Direct x_opencti_score writes to observables
  - create_notes() raw markdown table output
  - update_labels() string-label approach

ADDED / CHANGED
---------------
  - RFI container gate in _process_message
  - Graph-registered VirusTotal Identity at startup
  - TLP:GREEN marking ID resolved at startup
  - create_entities_from_labels() for tag -> entity conversion
  - create_assessment_note() with note_types=["assessment"]
  - rfi_container_id and tlp_green_id passed into VirusTotalBuilder
  - Container scoping after bundle submission
"""

import datetime
from pathlib import Path
from typing import Dict, Optional

import stix2
import yaml
from pycti import Identity, OpenCTIConnectorHelper, get_config_variable

from .builder import VirusTotalBuilder
from .client import VirusTotalClient

# NOTE: indicator_config.py is no longer imported. The file is left on
# disk but its contents are unused post-refactor.


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL query — container membership lookup
# ─────────────────────────────────────────────────────────────────────────────

# Used by _get_rfi_container_id() to determine whether the enrichment target
# belongs to any Case-Incident container before processing proceeds.
_CONTAINERS_QUERY = """
query ContainersOfObservable($id: String!) {
    stixObjectOrStixRelationship(id: $id) {
        ... on StixCyberObservable {
            containers {
                edges {
                    node {
                        id
                        entity_type
                        created_at
                        updated_at
                    }
                }
            }
        }
    }
}
"""


class VirusTotalConnector:
    """
    VirusTotal internal enrichment connector.

    Enriches Observables by querying the VirusTotal v3 API and persisting
    derived STIX entities, relationships, notes, and YARA indicators into
    the OpenCTI knowledge graph — but only within RFI containers.

    Supported observable types: StixFile, Artifact, IPv4-Addr,
                                 Domain-Name, Hostname, Url
    """

    _SOURCE_NAME = "VirusTotal"
    _API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        # ── Config loading ────────────────────────────────────────────────────
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"
        config = (
            yaml.load(
                open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader
            )
            if config_file_path.is_file()
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=True)

        token = get_config_variable(
            "VIRUSTOTAL_TOKEN", ["virustotal", "token"], config
        )
        self.max_tlp = get_config_variable(
            "VIRUSTOTAL_MAX_TLP", ["virustotal", "max_tlp"], config
        )
        self.replace_with_lower_score = get_config_variable(
            "VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE",
            ["virustotal", "replace_with_lower_score"],
            config,
        )

        # ── VT API client ─────────────────────────────────────────────────────
        self.client = VirusTotalClient(self.helper, self._API_URL, token)

        # ── YARA ruleset cache ────────────────────────────────────────────────
        # Keyed by ruleset_id. Avoids redundant API calls within one connector
        # run when multiple files match rules from the same ruleset.
        self.yara_cache: dict = {}

        # ── VirusTotal Author Identity ─────────────────────────────────────────
        # Register (or resolve) the VirusTotal Organization Identity in the
        # OpenCTI graph so it is a stable, graph-anchored entity rather than
        # a transient stix2 object that only lives inside the bundle.
        # Using update=True makes this idempotent across restarts.
        vt_identity_response = self.helper.api.identity.create(
            type="Organization",
            name=self._SOURCE_NAME,
            description=(
                "VirusTotal — multi-engine malware analysis and "
                "threat intelligence platform."
            ),
            update=True,
        )
        self.helper.log_info(
            f"[VirusTotal] Author identity registered: "
            f"{vt_identity_response.get('id')}"
        )

        # Build the stix2.Identity object with a deterministic pycti-generated
        # ID. This is what gets embedded as created_by_ref in all bundle objects.
        self.author = stix2.Identity(
            id=Identity.generate_id(self._SOURCE_NAME, "organization"),
            name=self._SOURCE_NAME,
            identity_class="organization",
            description="VirusTotal",
            confidence=self.helper.connect_confidence_level,
        )

        # ── TLP:GREEN marking resolution ───────────────────────────────────────
        # All VT-derived objects receive TLP:GREEN. The marking definition ID
        # is instance-specific (not a fixed constant), so we resolve it from
        # the API at startup. A missing TLP:GREEN is a hard startup failure —
        # the connector cannot operate without it.
        tlp_green = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [
                    {"key": "definition", "values": ["TLP:GREEN"]}
                ],
                "filterGroups": [],
            }
        )
        if tlp_green is None:
            raise RuntimeError(
                "[VirusTotal] TLP:GREEN marking definition not found. "
                "Ensure TLP markings are initialised in this OpenCTI instance "
                "before starting the connector."
            )
        self.tlp_green_id: str = tlp_green["standard_id"]
        self.helper.log_info(
            f"[VirusTotal] TLP:GREEN marking resolved: {self.tlp_green_id}"
        )

        # ── Observable type-specific settings ─────────────────────────────────

        # File / Artifact settings.
        self.file_create_note_full_report = get_config_variable(
            "VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT",
            ["virustotal", "file_create_note_full_report"],
            config,
            default=True,
        )
        self.file_import_yara = get_config_variable(
            "VIRUSTOTAL_FILE_IMPORT_YARA",
            ["virustotal", "file_import_yara"],
            config,
            default=True,
        )
        self.file_upload_unseen_artifacts = get_config_variable(
            "VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS",
            ["virustotal", "file_upload_unseen_artifacts"],
            config,
            default=True,
        )

        # IP settings.
        self.ip_add_relationships = get_config_variable(
            "VIRUSTOTAL_IP_ADD_RELATIONSHIPS",
            ["virustotal", "ip_add_relationships"],
            config,
        )

        # Domain settings.
        self.domain_add_relationships = get_config_variable(
            "VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS",
            ["virustotal", "domain_add_relationships"],
            config,
        )

        # URL settings.
        self.url_upload_unseen = get_config_variable(
            "VIRUSTOTAL_URL_UPLOAD_UNSEEN",
            ["virustotal", "url_upload_unseen"],
            config,
            default=True,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    def resolve_default_value(self, stix_entity: dict) -> Optional[str]:
        """
        Extract the best available hash from a file/artifact STIX entity.

        Preference: SHA-256 > SHA-1 > MD5. Returns None if no hash is present.
        """
        for algo in ("SHA-256", "SHA-1", "MD5"):
            value = stix_entity.get("hashes", {}).get(algo)
            if value:
                return value
        return None

    def _retrieve_yara_ruleset(self, ruleset_id: str) -> dict:
        """
        Retrieve a YARA ruleset from the VT API, with in-memory caching.

        Caching is keyed by ruleset_id. Within a single connector run,
        multiple files can match rules in the same ruleset; the cache
        prevents redundant API calls.

        Parameters
        ----------
        ruleset_id : str
            VT ruleset identifier (from yara["ruleset_id"]).
        """
        if ruleset_id in self.yara_cache:
            self.helper.log_debug(
                f"[VirusTotal] Ruleset {ruleset_id} served from cache."
            )
            return self.yara_cache[ruleset_id]

        self.helper.log_debug(
            f"[VirusTotal] Fetching ruleset {ruleset_id} from VT API."
        )
        ruleset = self.client.get_yara_ruleset(ruleset_id)
        self.yara_cache[ruleset_id] = ruleset
        return ruleset

    def _get_rfi_container_id(self, entity_id: str) -> Optional[str]:
        """
        Query OpenCTI for the Case-Incident containers that own the given
        entity and return the ID of the first one found.

        This is the primary enforcement mechanism for the RFI-only trigger gate.
        If the observable is not in any Case-Incident container, enrichment
        is skipped and None is returned.

        Parameters
        ----------
        entity_id : str
            OpenCTI entity ID of the observable being enriched.

        Returns
        -------
        str or None
            OpenCTI ID of the first matching Case-Incident container,
            or None if the observable does not belong to any RFI.
        """
        try:
            result = self.helper.api.query(
                _CONTAINERS_QUERY, {"id": entity_id}
            )
        except Exception as exc:
            # A query failure is treated conservatively: skip enrichment
            # rather than proceeding without the gate check.
            self.helper.log_warning(
                f"[VirusTotal] Container membership query failed for {entity_id}: "
                f"{exc}. Treating as not in RFI and skipping."
            )
            return None

        edges = (
            result.get("data", {})
            .get("stixObjectOrStixRelationship", {})
            .get("containers", {})
            .get("edges", [])
        )

        for edge in edges:
            node = edge.get("node", {})
            # Case-Incident is OpenCTI's entity_type for Incident Response cases.
            if node.get("entity_type") == "Case-Rfi":
                self.helper.log_debug(
                    f"[VirusTotal] RFI container found: {node['id']} "
                    f"for entity {entity_id}"
                )
                return node["id"]

        # No Case-Incident container found.
        return None

    def _make_builder(
        self,
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        data: dict,
        rfi_container_id: str,
    ) -> VirusTotalBuilder:
        """
        Instantiate a VirusTotalBuilder with all shared connector dependencies.

        Centralises builder construction so the rfi_container_id and
        tlp_green_id are always injected consistently from a single point.
        """
        return VirusTotalBuilder(
            helper=self.helper,
            author=self.author,
            replace_with_lower_score=self.replace_with_lower_score,
            stix_objects=stix_objects,
            stix_entity=stix_entity,
            opencti_entity=opencti_entity,
            data=data,
            rfi_container_id=rfi_container_id,
            tlp_green_id=self.tlp_green_id,
        )

    def _parse_scan_date(self, attributes: dict) -> Optional[str]:
        """
        Extract and format the VT scan date from entity attributes.

        Returns None if no last_analysis_date is present so callers can
        pass None safely to create_assessment_note().
        """
        ts = attributes.get("last_analysis_date")
        if ts:
            return datetime.datetime.utcfromtimestamp(ts).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Observable type processors
    # ─────────────────────────────────────────────────────────────────────────

    def _process_file(
        self,
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        rfi_container_id: str,
    ) -> str:
        """
        Enrich a StixFile or Artifact observable using the VT /files endpoint.

        Enrichment steps:
          1. Fetch file info from VT (upload if unseen and configured to do so).
          2. Update hashes, file size, and names from VT canonical data.
          3. Convert VT tags to typed entities (Malware, Vulnerability, AttackPattern).
          4. Import crowdsourced YARA rules as Indicators (the ONLY Indicator type).
          5. Create a structured assessment note.
          6. Optionally create a full per-engine analysis note.
        """
        json_data = self.client.get_file_info(self.resolve_default_value(stix_entity))
        assert json_data

        # ── Upload unseen artifact if configured ───────────────────────────────
        if (
            "error" in json_data
            and json_data["error"]["code"] == "NotFoundError"
            and self.file_upload_unseen_artifacts
            and opencti_entity["entity_type"] == "Artifact"
        ):
            message = (
                f"File {self.resolve_default_value(stix_entity)} not found in VT. "
                "Uploading for analysis."
            )
            self.helper.api.work.to_received(self.helper.work_id, message)
            self.helper.log_debug(message)

            if not opencti_entity.get("importFiles"):
                return "No import files available for upload."

            if opencti_entity["importFiles"][0]["size"] > 33554432:
                raise ValueError(
                    "File exceeds VirusTotal's 32MB upload limit."
                )

            artifact_url = (
                f"{self.helper.opencti_url}/storage/get/"
                f"{opencti_entity['importFiles'][0]['id']}"
            )
            try:
                artifact = self.helper.api.fetch_opencti_file(
                    artifact_url, binary=True
                )
            except Exception as err:
                raise ValueError(
                    "[VirusTotal] Error fetching artifact from OpenCTI"
                ) from err

            try:
                analysis_id = self.client.upload_artifact(
                    opencti_entity["importFiles"][0]["name"], artifact
                )
                # Trigger immediate queue placement.
                self.client.get_file_info(self.resolve_default_value(stix_entity))
            except Exception as err:
                raise ValueError(
                    "[VirusTotal] Error uploading artifact to VirusTotal"
                ) from err

            try:
                self.client.check_upload_status(
                    "artifact",
                    self.resolve_default_value(stix_entity),
                    analysis_id,
                )
            except Exception as err:
                raise ValueError(
                    "[VirusTotal] Error waiting for VirusTotal analysis to complete"
                ) from err

            json_data = self.client.get_file_info(
                self.resolve_default_value(stix_entity)
            )
            assert json_data

        if "error" in json_data:
            if json_data["error"].get("code") == "NotFoundError":
                # VT has no record — create an informational note and exit cleanly.
                # This is a valid analytical outcome, not an error condition.
                self.helper.log_info(
                    f"[VirusTotal] No VT record for file "
                    f"{self.resolve_default_value(stix_entity)}. "
                    "Creating not-found note."
                )
                builder = self._make_builder(
                    stix_objects, stix_entity, opencti_entity,
                    {"attributes": {}, "links": {"self": ""}},
                    rfi_container_id,
                )
                builder.create_not_found_note()
                return builder.send_bundle()
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("Unexpected VT API response structure.")

        builder = self._make_builder(
            stix_objects, stix_entity, opencti_entity,
            json_data["data"], rfi_container_id
        )

        # ── Update observable fields in-place ─────────────────────────────────
        builder.update_hashes()
        if opencti_entity["entity_type"] == "StixFile":
            builder.update_size()
        builder.update_names(
            # Set main name only if the observable currently has no name.
            main=(
                opencti_entity["entity_type"] == "StixFile"
                and not opencti_entity.get("name")
            )
        )

        # ── Label-to-entity conversion ─────────────────────────────────────────
        # VT tags -> Malware / Vulnerability / AttackPattern entities.
        # Generic taxonomy tags are dropped (captured in assessment note).
        builder.create_entities_from_labels()

        # ── YARA Indicators ───────────────────────────────────────────────────
        # YARA rules are the ONLY Indicator type this connector creates.
        # Each matched rule becomes a stix2.Indicator (pattern_type="yara")
        # linked to the file observable via related-to.
        if self.file_import_yara:
            yara_results = json_data["data"]["attributes"].get(
                "crowdsourced_yara_results", []
            )
            self.helper.log_debug(
                f"[VirusTotal] Processing {len(yara_results)} YARA results."
            )
            for yara in yara_results:
                ruleset_id = yara.get("ruleset_id", "No ruleset id provided")
                ruleset = self._retrieve_yara_ruleset(ruleset_id)
                builder.create_yara(
                    yara,
                    ruleset,
                    json_data["data"]["attributes"].get("creation_date"),
                )

        # ── Assessment note ───────────────────────────────────────────────────
        builder.create_assessment_note(
            scan_date=self._parse_scan_date(json_data["data"]["attributes"])
        )

        # ── Optional full engine report note ──────────────────────────────────
        # Supplemental note with per-engine breakdown for analysts who want
        # the complete VT scan table. Controlled by
        # VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT.
        if self.file_create_note_full_report:
            attrs = json_data["data"]["attributes"]
            if "last_analysis_results" in attrs:
                stats = attrs["last_analysis_stats"]
                content = (
                    "| Total | Malicious | Suspicious | Undetected | "
                    "Harmless | Timeout | Confirmed Timeout | Failure | Unsupported |\n"
                    "|-------|-----------|------------|------------|"
                    "----------|---------|-------------------|---------|-------------|\n"
                    f"| {len(attrs['last_analysis_results'])} "
                    f"| {stats['malicious']} "
                    f"| {stats['suspicious']} "
                    f"| {stats['undetected']} "
                    f"| {stats['harmless']} "
                    f"| {stats['timeout']} "
                    f"| {stats['confirmed-timeout']} "
                    f"| {stats['failure']} "
                    f"| {stats['type-unsupported']} |\n\n"
                    "## Per-Engine Results\n\n"
                    "Falsy values shown as N/A.\n\n"
                    "| Engine | Version | Method | Category | Result |\n"
                    "|--------|---------|--------|----------|--------|\n"
                )
                for result in attrs["last_analysis_results"].values():
                    content += (
                        f"| {result.get('engine_name') or 'N/A'} "
                        f"| {result.get('engine_version') or 'N/A'} "
                        f"| {result.get('method') or 'N/A'} "
                        f"| {result.get('category') or 'N/A'} "
                        f"| {result.get('result') or 'N/A'} |\n"
                    )
                builder.create_note("VirusTotal Full Engine Report", content)

        return builder.send_bundle()

    def _process_ip(
        self,
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        rfi_container_id: str,
    ) -> str:
        """
        Enrich an IPv4-Addr observable using the VT /ip_addresses endpoint.

        Enrichment steps:
          1. Fetch IP data from VT.
          2. Optionally create ASN (belongs-to) and Country (located-at) relationships.
          3. Create a structured assessment note.
        """
        json_data = self.client.get_ip_info(opencti_entity["observable_value"])
        assert json_data
        if "error" in json_data:
            if json_data["error"].get("code") == "NotFoundError":
                self.helper.log_info(
                    f"[VirusTotal] No VT record for IP "
                    f"{opencti_entity['observable_value']}. "
                    "Creating not-found note."
                )
                builder = self._make_builder(
                    stix_objects, stix_entity, opencti_entity,
                    {"attributes": {}, "links": {"self": ""}},
                    rfi_container_id,
                )
                builder.create_not_found_note()
                return builder.send_bundle()
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("Unexpected VT API response structure.")

        builder = self._make_builder(
            stix_objects, stix_entity, opencti_entity,
            json_data["data"], rfi_container_id
        )

        if self.ip_add_relationships:
            # ASN: IP -> belongs-to -> AutonomousSystem
            builder.create_asn_belongs_to()
            # Country: IP -> located-at -> Location
            builder.create_location_located_at()

        builder.create_assessment_note(
            scan_date=self._parse_scan_date(json_data["data"]["attributes"])
        )
        return builder.send_bundle()

    def _process_domain(
        self,
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        rfi_container_id: str,
    ) -> str:
        """
        Enrich a Domain-Name or Hostname observable using the VT /domains endpoint.

        Enrichment steps:
          1. Fetch domain data from VT.
          2. Optionally create passive-DNS IPv4 observables with resolves-to
             relationships for each A record.
          3. Create a structured assessment note.

        NOTE: Full DNS record dicts are passed to create_ip_resolves_to()
        (not just the IP string) so the builder can extract any available
        temporal metadata from the record.
        """
        json_data = self.client.get_domain_info(opencti_entity["observable_value"])
        assert json_data
        if "error" in json_data:
            if json_data["error"].get("code") == "NotFoundError":
                self.helper.log_info(
                    f"[VirusTotal] No VT record for domain "
                    f"{opencti_entity['observable_value']}. "
                    "Creating not-found note."
                )
                builder = self._make_builder(
                    stix_objects, stix_entity, opencti_entity,
                    {"attributes": {}, "links": {"self": ""}},
                    rfi_container_id,
                )
                builder.create_not_found_note()
                return builder.send_bundle()
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("Unexpected VT API response structure.")

        builder = self._make_builder(
            stix_objects, stix_entity, opencti_entity,
            json_data["data"], rfi_container_id
        )

        if self.domain_add_relationships:
            a_records = [
                r
                for r in json_data["data"]["attributes"].get("last_dns_records", [])
                if r.get("type") == "A"
            ]
            self.helper.log_debug(
                f"[VirusTotal] Creating {len(a_records)} passive-DNS IPv4 observables "
                f"for {opencti_entity['observable_value']}"
            )
            for record in a_records:
                # Pass the full record dict — create_ip_resolves_to() uses
                # record["value"] for the IP and the entity-level
                # last_analysis_date for last-seen provenance.
                builder.create_ip_resolves_to(record)

        builder.create_assessment_note(
            scan_date=self._parse_scan_date(json_data["data"]["attributes"])
        )
        return builder.send_bundle()

    def _process_url(
        self,
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        rfi_container_id: str,
    ) -> str:
        """
        Enrich a Url observable using the VT /urls endpoint.

        Enrichment steps:
          1. Fetch (or submit) URL data from VT.
          2. Create a structured assessment note.
        """
        json_data = self.client.get_url_info(opencti_entity["observable_value"])
        assert json_data

        # ── Upload unseen URL if configured ────────────────────────────────────
        if (
            "error" in json_data
            and json_data["error"]["code"] == "NotFoundError"
            and self.url_upload_unseen
        ):
            message = (
                f"URL {opencti_entity['observable_value']} not found in VT. "
                "Submitting for analysis."
            )
            self.helper.api.work.to_received(self.helper.work_id, message)
            self.helper.log_debug(message)

            try:
                analysis_id = self.client.upload_url(
                    opencti_entity["observable_value"]
                )
            except Exception as err:
                raise ValueError(
                    "[VirusTotal] Error submitting URL to VirusTotal"
                ) from err

            try:
                self.client.check_upload_status(
                    "URL", opencti_entity["observable_value"], analysis_id
                )
            except Exception as err:
                raise ValueError(
                    "[VirusTotal] Error waiting for VirusTotal URL analysis"
                ) from err

            json_data = self.client.get_url_info(opencti_entity["observable_value"])
            assert json_data

        if "error" in json_data:
            if json_data["error"].get("code") == "NotFoundError":
                self.helper.log_info(
                    f"[VirusTotal] No VT record for URL "
                    f"{opencti_entity['observable_value']}. "
                    "Creating not-found note."
                )
                builder = self._make_builder(
                    stix_objects, stix_entity, opencti_entity,
                    {"attributes": {}, "links": {"self": ""}},
                    rfi_container_id,
                )
                builder.create_not_found_note()
                return builder.send_bundle()
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("Unexpected VT API response structure.")

        builder = self._make_builder(
            stix_objects, stix_entity, opencti_entity,
            json_data["data"], rfi_container_id
        )

        builder.create_assessment_note(
            scan_date=self._parse_scan_date(json_data["data"]["attributes"])
        )
        return builder.send_bundle()

    # ─────────────────────────────────────────────────────────────────────────
    # Main message handler
    # ─────────────────────────────────────────────────────────────────────────

    def _process_message(self, data: Dict) -> str:
        """
        Entry point for all INTERNAL_ENRICHMENT jobs dispatched by OpenCTI.

        Sequence:
          1. Increment metrics and check TLP ceiling.
          2. Query container membership — skip if not in any Case-Incident.
          3. Route to the type-specific processor.

        The RFI gate (step 2) is the primary policy enforcement point.
        All graph mutations, API calls, and object creation happen downstream
        of a confirmed Case-Incident container ID.

        Parameters
        ----------
        data : Dict
            Enrichment job payload from the OpenCTI connector framework.

        Returns
        -------
        str
            Human-readable result message.
        """
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        # ── TLP ceiling check ─────────────────────────────────────────────────
        # Refuse to send observable data to VT if its marking is higher than
        # the configured max TLP. This prevents restricted data from leaving
        # the instance via the VT API.
        tlp = "TLP:CLEAR"
        for marking in opencti_entity.get("objectMarking", []):
            if marking["definition_type"] == "TLP":
                tlp = marking["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                f"Observable TLP ({tlp}) exceeds connector max TLP ({self.max_tlp}). "
                "Enrichment skipped to prevent data leakage."
            )

        # ── RFI container gate ────────────────────────────────────────────────
        # Check that the observable belongs to at least one Case-Incident.
        # If it does not, skip enrichment entirely — no API calls, no mutations.
        # This restricts VT enrichment to the analyst workbench context.
        entity_id = opencti_entity["id"]
        rfi_container_id = self._get_rfi_container_id(entity_id)

        if rfi_container_id is None:
            observable_value = opencti_entity.get("observable_value", entity_id)
            self.helper.log_info(
                f"[VirusTotal] Observable '{observable_value}' (id: {entity_id}) "
                "is not in any RFI (Case-Incident) container. "
                "Skipping enrichment per RFI-only policy."
            )
            return "Observable not in RFI container — enrichment skipped."

        self.helper.log_debug(
            f"[VirusTotal] Enriching "
            f"'{opencti_entity.get('observable_value', entity_id)}' "
            f"(type: {opencti_entity['entity_type']}) "
            f"in RFI container {rfi_container_id}"
        )

        # ── Route to type-specific processor ─────────────────────────────────
        entity_type = opencti_entity["entity_type"]
        match entity_type:
            case "StixFile" | "Artifact":
                return self._process_file(
                    stix_objects, stix_entity, opencti_entity, rfi_container_id
                )
            case "IPv4-Addr":
                return self._process_ip(
                    stix_objects, stix_entity, opencti_entity, rfi_container_id
                )
            case "Domain-Name" | "Hostname":
                return self._process_domain(
                    stix_objects, stix_entity, opencti_entity, rfi_container_id
                )
            case "Url":
                return self._process_url(
                    stix_objects, stix_entity, opencti_entity, rfi_container_id
                )
            case _:
                raise ValueError(
                    f"Entity type '{entity_type}' is not supported by this connector."
                )

    def start(self):
        """Start the connector main loop and begin listening for enrichment jobs."""
        self.helper.metric.state("idle")
        self.helper.listen(message_callback=self._process_message)
