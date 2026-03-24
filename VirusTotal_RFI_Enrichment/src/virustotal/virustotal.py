# -*- coding: utf-8 -*-
"""
VirusTotal enrichment connector — Case-Rfi container-level implementation.

TRIGGER MODEL
-------------
The connector scope is Case-Rfi. When an analyst triggers enrichment on an
RFI container (or CONNECTOR_AUTO fires), the connector:
  1. Reads the last-run timestamp for this RFI from a persistent state file
  2. Queries all SCOs in the container added since that timestamp
  3. Filters to supported observable types
  4. Enriches each observable against the VT API with rate-limiting
  5. Writes the current timestamp back to the state file

This replaces the previous per-observable trigger model. Enrichment is now
initiated at the container level rather than the entity level.

STATE MANAGEMENT
----------------
A JSON file (VIRUSTOTAL_STATE_PATH) maps RFI container ID -> last run
timestamp. On first run against an RFI, timestamp defaults to None,
meaning all existing observables in the container are processed.

RATE LIMITING
-------------
A configurable delay (VIRUSTOTAL_REQUEST_DELAY_SECONDS) is applied between
each VT API call. Default 15 seconds is safe for the free-tier API limit
of 4 requests/minute. Set to 1 for premium API keys.

ERROR ISOLATION
---------------
Failures on individual observables are caught and logged as warnings.
Processing continues for remaining observables in the container.
The state file timestamp is only updated after full iteration completes.

TLP POLICY
----------
Per-observable TLP check: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT
are processed. TLP:RED observables are skipped individually — they do not
abort the full container run.
"""

import datetime
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

import stix2
import yaml
from pycti import Identity, OpenCTIConnectorHelper, get_config_variable

from .builder import VirusTotalBuilder
from .client import VirusTotalClient


# ─────────────────────────────────────────────────────────────────────────────
# Observable types this connector processes.
# Only SCOs in this set are enriched — all SDOs and unsupported SCO types
# are silently skipped during container iteration.
# ─────────────────────────────────────────────────────────────────────────────
_SUPPORTED_TYPES = frozenset({
    "StixFile",
    "Artifact",
    "IPv4-Addr",
    "Domain-Name",
    "Hostname",
    "Url",
})

# TLP definitions that are permitted to be sent to the VT API.
# TLP:RED is excluded — RED-marked observables are skipped individually.
_ALLOWED_TLP_DEFINITIONS = frozenset({
    "TLP:CLEAR",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
})

# ─────────────────────────────────────────────────────────────────────────────
# GraphQL query — fetch all objects from a Case-Rfi container.
# Filtering by created_at is performed in Python after retrieval since
# GraphQL datetime filtering on container object edges is not reliably
# supported across all OpenCTI 6.x patch versions.
# ─────────────────────────────────────────────────────────────────────────────
_RFI_OBJECTS_QUERY = """
query RfiObjects($id: String!) {
    caseRfi(id: $id) {
        id
        name
        objects(first: 500) {
            edges {
                node {
                    ... on StixCyberObservable {
                        id
                        standard_id
                        entity_type
                        observable_value
                        created_at
                        objectMarking {
                            definition
                            definition_type
                        }
                        x_opencti_description
                        x_opencti_score
                        ... on StixFile {
                            name
                            size
                            mime_type
                            magic_number_hex
                            x_opencti_additional_names
                            hashes {
                                algorithm
                                hash
                            }
                        }
                        ... on Artifact {
                            mime_type
                            hashes {
                                algorithm
                                hash
                            }
                        }
                        createdBy {
                            ... on Identity {
                                name
                                id
                                standard_id
                            }
                        }
                    }
                }
            }
        }
    }
}
"""


class VirusTotalConnector:
    """
    VirusTotal internal enrichment connector — Case-Rfi container scope.

    Triggered on Case-Rfi containers. Enriches all SCOs in the container
    that were added since the last run, using persistent per-container
    state tracking.

    Supported observable types:
        StixFile, Artifact, IPv4-Addr, Domain-Name, Hostname, Url
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
        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=False)

        token = get_config_variable(
            "VIRUSTOTAL_TOKEN", ["virustotal", "token"], config
        )
        self.replace_with_lower_score = get_config_variable(
            "VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE",
            ["virustotal", "replace_with_lower_score"],
            config,
            default=False,
        )

        # ── Rate limiting ─────────────────────────────────────────────────────
        # Delay in seconds between VT API calls within a single container run.
        # Default 15s is safe for the free-tier limit of 4 requests/minute.
        # Set to 1 for premium API keys.
        self.request_delay = float(get_config_variable(
            "VIRUSTOTAL_REQUEST_DELAY_SECONDS",
            ["virustotal", "request_delay_seconds"],
            config,
            isNumber=True,
            default=15,
        ))
        self.helper.log_info(
            f"[VirusTotal] Rate limit delay: {self.request_delay}s between calls"
        )

        # ── State file ────────────────────────────────────────────────────────
        # JSON file mapping RFI container ID -> last run ISO timestamp.
        # Requires a volume mount in Docker deployments.
        self.state_path = get_config_variable(
            "VIRUSTOTAL_STATE_PATH",
            ["virustotal", "state_path"],
            config,
            default="/opt/connector/state/virustotal_state.json",
        )
        self.helper.log_info(
            f"[VirusTotal] State file path: {self.state_path}"
        )

        # ── VT API client ─────────────────────────────────────────────────────
        self.client = VirusTotalClient(self.helper, self._API_URL, token)

        # ── YARA ruleset cache ────────────────────────────────────────────────
        # Keyed by ruleset_id. Avoids redundant API calls when multiple files
        # in the same container match rules from the same ruleset.
        self.yara_cache: dict = {}

        # ── VirusTotal Author Identity ─────────────────────────────────────────
        # Registered as a graph-persisted Organization entity at startup.
        # update=True makes this idempotent across restarts.
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

        # stix2.Identity object with deterministic pycti ID for created_by_ref.
        self.author = stix2.Identity(
            id=Identity.generate_id(self._SOURCE_NAME, "organization"),
            name=self._SOURCE_NAME,
            identity_class="organization",
            description="VirusTotal",
            confidence=self.helper.connect_confidence_level,
        )

        # ── TLP:GREEN marking resolution ───────────────────────────────────────
        # All VT-derived objects receive TLP:GREEN. Resolved from the API at
        # startup because marking IDs are instance-specific, not fixed constants.
        tlp_green = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": ["TLP:GREEN"]}],
                "filterGroups": [],
            }
        )
        if tlp_green is None:
            raise RuntimeError(
                "[VirusTotal] TLP:GREEN marking definition not found. "
                "Ensure TLP markings are initialised before starting the connector."
            )
        self.tlp_green_id: str = tlp_green["standard_id"]
        self.helper.log_info(
            f"[VirusTotal] TLP:GREEN marking resolved: {self.tlp_green_id}"
        )

        # ── Observable type-specific settings ─────────────────────────────────

        # File / Artifact
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
            default=False,
        )

        # IP
        self.ip_add_relationships = get_config_variable(
            "VIRUSTOTAL_IP_ADD_RELATIONSHIPS",
            ["virustotal", "ip_add_relationships"],
            config,
            default=True,
        )

        # Domain
        self.domain_add_relationships = get_config_variable(
            "VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS",
            ["virustotal", "domain_add_relationships"],
            config,
            default=True,
        )

        # URL
        self.url_upload_unseen = get_config_variable(
            "VIRUSTOTAL_URL_UPLOAD_UNSEEN",
            ["virustotal", "url_upload_unseen"],
            config,
            default=False,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # State management
    # ─────────────────────────────────────────────────────────────────────────

    def _read_state(self) -> dict:
        """
        Read the full state dict from the state file.

        Returns an empty dict if the file does not exist or cannot be parsed.
        State dict maps RFI container ID -> ISO timestamp string of last run.
        """
        try:
            with open(self.state_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            self.helper.log_debug(
                f"[VirusTotal] State file not found at {self.state_path}. "
                "Starting with empty state."
            )
            return {}
        except Exception as exc:
            self.helper.log_warning(
                f"[VirusTotal] Could not read state file: {exc}. "
                "Starting with empty state."
            )
            return {}

    def _write_state(self, state: dict) -> None:
        """
        Write the full state dict to the state file.

        Creates the parent directory if it does not exist.
        Writes atomically via a temp file + rename to prevent corruption
        if the connector is killed mid-write.
        """
        try:
            state_dir = os.path.dirname(self.state_path)
            if state_dir:
                os.makedirs(state_dir, exist_ok=True)

            tmp_path = self.state_path + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(state, f, indent=2)
            os.replace(tmp_path, self.state_path)

            self.helper.log_debug(
                f"[VirusTotal] State written to {self.state_path}"
            )
        except Exception as exc:
            self.helper.log_warning(
                f"[VirusTotal] Could not write state file: {exc}. "
                "State will not persist across this run."
            )

    def _get_last_run(self, rfi_id: str) -> Optional[datetime.datetime]:
        """
        Return the last-run datetime for a specific RFI container.

        Returns None if this RFI has never been processed, which causes
        the caller to process all existing observables (first-run behaviour).
        """
        state = self._read_state()
        ts_str = state.get(rfi_id)
        if ts_str is None:
            return None
        try:
            return datetime.datetime.fromisoformat(ts_str)
        except Exception:
            return None

    def _update_last_run(self, rfi_id: str, run_time: datetime.datetime) -> None:
        """
        Update the last-run timestamp for a specific RFI container.

        Reads the full state, updates only the entry for this RFI, and
        writes back — preserving all other container entries.
        """
        state = self._read_state()
        state[rfi_id] = run_time.isoformat()
        self._write_state(state)

    # ─────────────────────────────────────────────────────────────────────────
    # Container observation query
    # ─────────────────────────────────────────────────────────────────────────

    def _get_new_observables(
        self,
        rfi_id: str,
        since: Optional[datetime.datetime],
    ) -> List[dict]:
        """
        Query all SCOs in the RFI container and return those added since
        the given timestamp.

        If since is None (first run), all SCOs in the container are returned
        regardless of creation date.

        Filtering by entity_type and created_at is performed in Python after
        retrieval. Only types in _SUPPORTED_TYPES are returned.

        Parameters
        ----------
        rfi_id : str
            OpenCTI ID of the Case-Rfi container.
        since : datetime or None
            Lower bound for created_at filtering. None = return all.

        Returns
        -------
        list of dict
            Observable entity dicts filtered to supported types and
            (if since is set) created after that timestamp.
        """
        try:
            result = self.helper.api.query(
                _RFI_OBJECTS_QUERY, {"id": rfi_id}
            )
        except Exception as exc:
            self.helper.log_warning(
                f"[VirusTotal] Failed to query objects for RFI {rfi_id}: {exc}"
            )
            return []

        edges = (
            result.get("data", {})
            .get("caseRfi", {})
            .get("objects", {})
            .get("edges", [])
        )

        observables = []
        for edge in edges:
            node = edge.get("node", {})

            # Nodes without entity_type are SDOs or SROs that did not match
            # the StixCyberObservable inline fragment — skip them.
            entity_type = node.get("entity_type")
            if not entity_type:
                continue

            # Filter to supported observable types.
            if entity_type not in _SUPPORTED_TYPES:
                continue

            # Apply created_at filter if a last-run timestamp is available.
            if since is not None:
                created_at_str = node.get("created_at", "")
                try:
                    created_at = datetime.datetime.fromisoformat(
                        created_at_str.replace("Z", "+00:00")
                    )
                    # Normalise since to offset-aware for comparison.
                    since_aware = since.replace(tzinfo=datetime.timezone.utc)
                    if created_at <= since_aware:
                        continue
                except Exception:
                    # Cannot parse timestamp — include conservatively rather
                    # than silently dropping a potentially new observable.
                    self.helper.log_debug(
                        f"[VirusTotal] Could not parse created_at for "
                        f"{node.get('id')} — including conservatively."
                    )

            observables.append(node)

        return observables

    # ─────────────────────────────────────────────────────────────────────────
    # TLP check
    # ─────────────────────────────────────────────────────────────────────────

    def _get_observable_tlp(self, opencti_entity: dict) -> str:
        """
        Extract the TLP marking definition string from the observable.

        Returns 'TLP:CLEAR' if no TLP marking is present.
        """
        for marking in opencti_entity.get("objectMarking", []):
            if marking.get("definition_type") == "TLP":
                return marking["definition"]
        return "TLP:CLEAR"

    def _is_tlp_allowed(self, tlp: str) -> bool:
        """
        Return True if the TLP definition is within the permitted set.

        TLP:RED is excluded. All other standard TLP levels are permitted.
        """
        return tlp in _ALLOWED_TLP_DEFINITIONS

    # ─────────────────────────────────────────────────────────────────────────
    # Observable-level helpers
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

        Cache lives for the duration of one container run. Cleared at the
        start of each _process_message call.
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

        Centralises builder construction so rfi_container_id and tlp_green_id
        are always injected consistently from a single point.
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

        Returns None if no last_analysis_date is present.
        """
        ts = attributes.get("last_analysis_date")
        if ts:
            return datetime.datetime.utcfromtimestamp(ts).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
        return None

    def _build_stix_entity_from_opencti(self, opencti_entity: dict) -> dict:
        """
        Build a minimal STIX entity dict from the OpenCTI container query result.

        The type processors expect a stix_entity dict mirroring what pycti
        provides in a per-observable enrichment job. Container-level jobs do
        not supply this automatically — we construct it from the container
        query inline fragment fields.

        Fields populated:
          - id (standard_id / STIX ID)
          - type (lowercased entity_type)
          - x_opencti_id (OpenCTI internal UUID)
          - x_opencti_score
          - hashes (dict {algo: value} for file/artifact types)
          - name, size (file types)
          - value (IP, domain, URL types)
        """
        entity_type = opencti_entity.get("entity_type", "")
        standard_id = opencti_entity.get("standard_id", "")

        stix_entity = {
            "id": standard_id,
            "type": entity_type.lower().replace("_", "-"),
            "x_opencti_id": opencti_entity.get("id"),
            "x_opencti_score": opencti_entity.get("x_opencti_score"),
        }

        if entity_type in ("StixFile", "Artifact"):
            # opencti_entity hashes is a list [{algorithm, hash}].
            # Convert to dict {algo: hash} as expected by resolve_default_value
            # and builder.update_hashes().
            raw_hashes = opencti_entity.get("hashes") or []
            hashes = {}
            for h in raw_hashes:
                algo = h.get("algorithm", "")
                val = h.get("hash", "")
                if algo and val:
                    hashes[algo] = val
            stix_entity["hashes"] = hashes
            stix_entity["name"] = opencti_entity.get("name")
            stix_entity["size"] = opencti_entity.get("size")

        elif entity_type in ("IPv4-Addr", "Domain-Name", "Hostname", "Url"):
            stix_entity["value"] = opencti_entity.get("observable_value")

        return stix_entity

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

        Steps:
          1. Fetch file info from VT (upload if unseen and configured).
          2. Update hashes, size, and names from VT canonical data.
          3. Convert VT tags to typed entities (Malware, Vulnerability, AttackPattern).
          4. Import crowdsourced YARA rules as Indicators.
          5. Create a structured assessment note.
          6. Optionally create a full per-engine analysis note.
        """
        json_data = self.client.get_file_info(self.resolve_default_value(stix_entity))
        assert json_data

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
                raise ValueError("File exceeds VirusTotal's 32MB upload limit.")

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
                    "[VirusTotal] Error waiting for VirusTotal analysis"
                ) from err

            json_data = self.client.get_file_info(
                self.resolve_default_value(stix_entity)
            )
            assert json_data

        if "error" in json_data:
            if json_data["error"].get("code") == "NotFoundError":
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

        builder.update_hashes()
        if opencti_entity["entity_type"] == "StixFile":
            builder.update_size()
        builder.update_names(
            main=(
                opencti_entity["entity_type"] == "StixFile"
                and not opencti_entity.get("name")
            )
        )
        builder.create_entities_from_labels()

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

        builder.create_assessment_note(
            scan_date=self._parse_scan_date(json_data["data"]["attributes"])
        )

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
                    f"| {stats['malicious']} | {stats['suspicious']} "
                    f"| {stats['undetected']} | {stats['harmless']} "
                    f"| {stats['timeout']} | {stats['confirmed-timeout']} "
                    f"| {stats['failure']} | {stats['type-unsupported']} |\n\n"
                    "## Per-Engine Results\n\nFalsy values shown as N/A.\n\n"
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

        Steps:
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
                    f"{opencti_entity['observable_value']}. Creating not-found note."
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
            builder.create_asn_belongs_to()
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

        Steps:
          1. Fetch domain data from VT.
          2. Optionally create passive-DNS IPv4 observables with resolves-to
             relationships for each A record.
          3. Create a structured assessment note.
        """
        json_data = self.client.get_domain_info(opencti_entity["observable_value"])
        assert json_data

        if "error" in json_data:
            if json_data["error"].get("code") == "NotFoundError":
                self.helper.log_info(
                    f"[VirusTotal] No VT record for domain "
                    f"{opencti_entity['observable_value']}. Creating not-found note."
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
                f"[VirusTotal] Creating {len(a_records)} passive-DNS IPv4 "
                f"observables for {opencti_entity['observable_value']}"
            )
            for record in a_records:
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

        Steps:
          1. Fetch (or submit) URL data from VT.
          2. Create a structured assessment note.
        """
        json_data = self.client.get_url_info(opencti_entity["observable_value"])
        assert json_data

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
                    f"{opencti_entity['observable_value']}. Creating not-found note."
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

        When scope is Case-Rfi, the enrichment_entity is the RFI container
        itself. This method:
          1. Records run start time.
          2. Reads last-run timestamp for this RFI from the state file.
          3. Queries all new SCOs in the container since that timestamp.
          4. Iterates with per-observable TLP check, rate-limiting, and
             error isolation.
          5. Updates the state file on completion.

        The YARA ruleset cache is cleared at the start of each run to prevent
        stale ruleset data from persisting across container runs.

        Parameters
        ----------
        data : Dict
            Enrichment job payload from the OpenCTI connector framework.

        Returns
        -------
        str
            Human-readable result summary.
        """
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        # Clear YARA cache — valid within one run only.
        self.yara_cache = {}

        opencti_entity = data["enrichment_entity"]
        rfi_id = opencti_entity["id"]
        rfi_name = opencti_entity.get("name", rfi_id)

        self.helper.log_info(
            f"[VirusTotal] Processing RFI container: '{rfi_name}' ({rfi_id})"
        )

        # ── Record run start time ─────────────────────────────────────────────
        # Captured before any processing so observables added during this run
        # are picked up on the next run rather than missed due to clock drift.
        run_start_time = datetime.datetime.utcnow()

        # ── Read last-run state ───────────────────────────────────────────────
        last_run = self._get_last_run(rfi_id)
        if last_run is None:
            self.helper.log_info(
                f"[VirusTotal] First run for RFI '{rfi_name}' — "
                "processing all existing observables."
            )
        else:
            self.helper.log_info(
                f"[VirusTotal] Last run for RFI '{rfi_name}': "
                f"{last_run.isoformat()}. Processing new observables only."
            )

        # ── Query new observables ─────────────────────────────────────────────
        observables = self._get_new_observables(rfi_id, last_run)

        if not observables:
            self.helper.log_info(
                f"[VirusTotal] No new observables in RFI '{rfi_name}'."
            )
            # Advance the timestamp even when nothing is processed so future
            # runs do not re-scan the entire container.
            self._update_last_run(rfi_id, run_start_time)
            return f"No new observables to enrich in RFI '{rfi_name}'."

        self.helper.log_info(
            f"[VirusTotal] {len(observables)} new observable(s) to enrich "
            f"in RFI '{rfi_name}'."
        )

        # ── Iterate and enrich ────────────────────────────────────────────────
        processed = 0
        skipped_tlp = 0
        skipped_error = 0

        for i, observable in enumerate(observables):
            entity_type = observable.get("entity_type", "Unknown")
            observable_value = observable.get(
                "observable_value", observable.get("id", "unknown")
            )

            # ── Per-observable TLP check ──────────────────────────────────────
            # Each observable may carry a different TLP. TLP:RED is skipped
            # individually and does not abort the container run.
            tlp = self._get_observable_tlp(observable)
            if not self._is_tlp_allowed(tlp):
                self.helper.log_info(
                    f"[VirusTotal] Skipping {entity_type} '{observable_value}' "
                    f"— TLP:{tlp} not permitted for VT API submission."
                )
                skipped_tlp += 1
                continue

            self.helper.log_info(
                f"[VirusTotal] [{i+1}/{len(observables)}] Enriching "
                f"{entity_type} '{observable_value}' (TLP: {tlp})"
            )

            # Build stix_entity from container query result.
            stix_entity = self._build_stix_entity_from_opencti(observable)
            stix_objects = data.get("stix_objects", [])

            # ── Route to type-specific processor ─────────────────────────────
            try:
                match entity_type:
                    case "StixFile" | "Artifact":
                        self._process_file(
                            stix_objects, stix_entity, observable, rfi_id
                        )
                    case "IPv4-Addr":
                        self._process_ip(
                            stix_objects, stix_entity, observable, rfi_id
                        )
                    case "Domain-Name" | "Hostname":
                        self._process_domain(
                            stix_objects, stix_entity, observable, rfi_id
                        )
                    case "Url":
                        self._process_url(
                            stix_objects, stix_entity, observable, rfi_id
                        )
                    case _:
                        self.helper.log_debug(
                            f"[VirusTotal] No processor for type "
                            f"'{entity_type}' — skipping."
                        )
                        continue

                processed += 1

            except Exception as exc:
                # Per-observable error isolation.
                # Log as warning and continue — do not abort the container run.
                self.helper.log_warning(
                    f"[VirusTotal] Error enriching {entity_type} "
                    f"'{observable_value}': {exc}. Continuing with next observable."
                )
                skipped_error += 1

            # ── Rate limiting ─────────────────────────────────────────────────
            # Applied after each call except the last to respect VT API limits.
            # Applied regardless of success/failure so error cases do not cause
            # a burst of requests on the next observable.
            if i < len(observables) - 1:
                self.helper.log_debug(
                    f"[VirusTotal] Rate limit delay: {self.request_delay}s"
                )
                time.sleep(self.request_delay)

        # ── Update state file ─────────────────────────────────────────────────
        # Written after full iteration so the timestamp only advances when
        # the complete run finishes. A connector killed mid-run will
        # reprocess from the previous timestamp on next invocation.
        self._update_last_run(rfi_id, run_start_time)

        summary = (
            f"RFI '{rfi_name}': {processed} enriched, "
            f"{skipped_tlp} skipped (TLP:RED), "
            f"{skipped_error} skipped (error)."
        )
        self.helper.log_info(f"[VirusTotal] Run complete. {summary}")
        return summary

    def start(self):
        """Start the connector main loop and begin listening for enrichment jobs."""
        self.helper.metric.state("idle")
        self.helper.listen(message_callback=self._process_message)
