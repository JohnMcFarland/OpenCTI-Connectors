"""
URLHaus connector for OpenCTI.

Ingests active malware distribution URLs and associated payload hashes
from abuse.ch URLHaus into OpenCTI as a daily scoped threat-report container.

Data model compliance:
  - No Indicator objects created (createIndicator=False on all observables)
  - All objects contained within a daily Report container
  - Relationships validated against the Data Model Relationship Guide:
      Observable → related-to → Malware       (line 41)
      Observable → related-to → Tool          (Any → Any)
      Observable → related-to → Software      (Any → Any)
      Observable → related-to → Organization  (Any → Any)
      Observable → related-to → Observable    (Any → Any)
  - abuse.ch Identity resolved at startup; reused across ThreatFox and URLHaus
  - Large object_refs handled via report.create() + per-object
    add_stix_object_or_stix_relationship() — never via send_stix2_bundle

v1.0.3 changes:
  - TAG_TOOL_MAP: maps known abused-tool tags to Tool entity names.
    Tags in this map are removed from TAG_BLOCKLIST and instead produce
    Tool SDOs with related-to relationships to observables.
  - TAG_SOFTWARE_MAP: maps known sensor/framework tags to Software observable
    names. Tags in this map produce Software observables with related-to
    relationships to observables.
  - _get_or_create_tool() and _get_or_create_software() — TTL-aware cache
    and graph lookup/create pattern, parallel to _get_or_create_malware().
  - Tool and Software IDs are linked into the same daily Report container
    as URL, host, and Malware entities.
"""

import ipaddress
import os
import re
import time
from datetime import datetime, timezone

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from client import URLHausClient, URLHausAPIError

# ── Constants ────────────────────────────────────────────────────────────────

CONNECTOR_VERSION = "1.0.3"
CONFIDENCE = 75
OBSERVABLE_SCORE = 85
MALWARE_CACHE_TTL_SECONDS = 86400

# ── Tag-to-entity maps ───────────────────────────────────────────────────────
#
# Tags in TAG_TOOL_MAP produce Tool SDOs rather than Malware SDOs.
# Tags in TAG_SOFTWARE_MAP produce Software observables rather than Malware SDOs.
# Tags in either map must NOT appear in TAG_BLOCKLIST.
#
# Keys are the title-cased normalized form produced by normalize_tag() BEFORE
# the blocklist/map check — i.e., the exact string that would be compared.
# Values are the canonical entity names to look up or create in the graph.
#
# Design principle: Tool entities represent legitimate software abused by
# threat actors. Software entities represent specific tools or frameworks
# observed in the threat landscape (honeypots, sensors, etc.) that are not
# themselves malicious but are contextually relevant.

TAG_TOOL_MAP: dict[str, str] = {
    # ConnectWise — legitimate RMM platform, frequently abused for C2/persistence.
    # Normalized form of URLHaus tag 'connectwise'.
    "Connectwise": "ConnectWise",

    # Generic RMM category — used when the specific product is unidentified.
    # Normalized form of URLHaus tag 'rmm'.
    "Rmm": "Remote Monitoring and Management (RMM)",

    # GitHub — code hosting platform abused for payload staging and dead-drop.
    # Normalized form of URLHaus tag 'github'.
    "Github": "GitHub",

    # wget — command-line downloader abused in dropper chains.
    # Normalized form of URLHaus tag 'ua_wget' (title-cased: 'Ua Wget').
    "Ua Wget": "wget",
}

TAG_SOFTWARE_MAP: dict[str, str] = {
    # Cowrie — SSH/Telnet honeypot framework used as a URLHaus submission sensor.
    # Normalized form of URLHaus tag 'cowrie'.
    # Modeled as Software (observable) rather than Tool (SDO) because it is
    # detection infrastructure, not an offensive capability.
    "Cowrie": "Cowrie",
}

# ── Tag blocklist ─────────────────────────────────────────────────────────────
#
# Tags that must not produce ANY entity (Malware, Tool, or Software).
# Tags handled by TAG_TOOL_MAP or TAG_SOFTWARE_MAP must NOT be listed here.
#
# All entries must be title-cased strings. See normalize_tag() for the
# full filtering pipeline including prefix pattern matching.

TAG_BLOCKLIST: frozenset[str] = frozenset({
    # ── File type extensions ──────────────────────────────────────────────
    "Exe", "Dll", "Js", "Vbs", "Ps1", "Hta", "Bat", "Cmd", "Msi", "Jar",
    "Apk", "Elf", "Sh", "Zip", "Rar", "7Z", "Gz", "Tar", "Iso", "Img",
    "Doc", "Docx", "Xls", "Xlsx", "Ppt", "Pptx", "Pdf", "Lnk", "Cab", "Mz",
    # ── CPU architectures ─────────────────────────────────────────────────
    "Arm", "Mips", "Mipsel", "X86", "X86 64", "Powerpc", "Sparc",
    "M68K", "Superh", "32 Bit", "64 Bit",
    # ── Encoding / obfuscation descriptors ───────────────────────────────
    "Base64", "Ascii", "Encoded", "Encrypted",
    # ── Scripting languages ───────────────────────────────────────────────
    "Lua",
    # ── Hosting / delivery descriptors ───────────────────────────────────
    "Opendir", "Phishing", "Spam", "Malware", "Payload", "Botnetdomain",
    # ── Generic category labels ───────────────────────────────────────────
    # Note: Rat, Rmm, Honeypot, Github, Ua Wget, Cowrie, Connectwise are
    # intentionally absent — they are handled by TAG_TOOL_MAP / TAG_SOFTWARE_MAP.
    "Rat",        # Generic malware category acronym — too broad for a family name
    "Honeypot",   # Generic descriptor — specific honeypot frameworks (e.g., Cowrie)
                  # are in TAG_SOFTWARE_MAP; the generic label is suppressed
})

# Prefix patterns for tag families that cannot be enumerated statically.
_BLOCKLIST_PREFIXES: tuple[re.Pattern, ...] = (
    # 'Pw ' tags are URLHaus internal tracking artifacts.
    re.compile(r'^Pw\s+', re.IGNORECASE),
    # 'Dropped By X' labels describe dropper chain provenance, not family names.
    re.compile(r'^Dropped\s+By\s+', re.IGNORECASE),
)


# ── Utility functions ────────────────────────────────────────────────────────

def normalize_tag(raw: str) -> str | None:
    """
    Normalize a URLHaus threat tag. Returns the title-cased name, or None
    if the tag is empty, blocklisted, or matches a prefix pattern.

    Note: this function does NOT check TAG_TOOL_MAP or TAG_SOFTWARE_MAP.
    Callers are responsible for routing the returned name through those maps
    before falling through to Malware entity creation.
    """
    name = raw.replace("_", " ").replace("-", " ").strip().title()
    if not name:
        return None
    if name in TAG_BLOCKLIST:
        return None
    for pattern in _BLOCKLIST_PREFIXES:
        if pattern.match(name):
            return None
    return name


def parse_url_date(date_str: str) -> datetime | None:
    """Parse URLHaus URL date format: '2024-01-15 10:30:00 UTC'."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, TypeError):
        return None


def parse_payload_date(date_str: str) -> datetime | None:
    """Parse URLHaus payload date format: '2024-01-15 10:30:00' (implicit UTC)."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, TypeError):
        return None


def classify_host(value: str) -> str | None:
    """
    Return the correct STIX observable type for a URLHaus host field value.
    Returns 'IPv4-Addr', 'IPv6-Addr', 'Domain-Name', or None for empty input.
    """
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value)
        if isinstance(addr, ipaddress.IPv4Address):
            return "IPv4-Addr"
        if isinstance(addr, ipaddress.IPv6Address):
            return "IPv6-Addr"
    except ValueError:
        pass
    return "Domain-Name"


# ── Connector class ──────────────────────────────────────────────────────────

class URLHausConnector:

    def __init__(self) -> None:
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "config.yml"
        )
        config: dict = {}
        if os.path.isfile(config_path):
            with open(config_path) as fh:
                config = yaml.safe_load(fh) or {}

        self.helper = OpenCTIConnectorHelper(config)

        self.api_key: str = get_config_variable(
            "URLHAUS_API_KEY", ["urlhaus", "api_key"], config
        )
        self.interval_seconds: int = int(
            get_config_variable(
                "URLHAUS_INTERVAL_HOURS",
                ["urlhaus", "interval_hours"],
                config,
                default=24,
            )
        ) * 3600

        raw_run_on_startup = get_config_variable(
            "URLHAUS_RUN_ON_STARTUP",
            ["urlhaus", "run_on_startup"],
            config,
            default=False,
        )
        if isinstance(raw_run_on_startup, str):
            self.run_on_startup: bool = raw_run_on_startup.lower() == "true"
        else:
            self.run_on_startup = bool(raw_run_on_startup)

        self.client = URLHausClient(api_key=self.api_key)

        self._tlp_clear_id: str = self._resolve_tlp_clear()
        self._abuse_ch_id: str = self._resolve_abuse_ch_identity()

        # Per-type TTL-aware caches: normalized_name → (opencti_id, monotonic_ts)
        self._malware_cache:  dict[str, tuple[str, float]] = {}
        self._tool_cache:     dict[str, tuple[str, float]] = {}
        self._software_cache: dict[str, tuple[str, float]] = {}

        self.helper.connector_logger.info(
            "URLHaus tag routing active",
            {
                "tool_tags":     sorted(TAG_TOOL_MAP.keys()),
                "software_tags": sorted(TAG_SOFTWARE_MAP.keys()),
                "blocked_tags":  sorted(TAG_BLOCKLIST),
                "prefix_patterns": ["Pw *", "Dropped By *"],
            },
        )

    # ── Startup ───────────────────────────────────────────────────────────────

    def _resolve_tlp_clear(self) -> str:
        result = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": ["TLP:CLEAR"]}],
                "filterGroups": [],
            }
        )
        if not result:
            raise RuntimeError("TLP:CLEAR marking definition not found.")
        self.helper.connector_logger.info(
            "Resolved TLP:CLEAR marking definition", {"id": result["id"]}
        )
        return result["id"]

    def _resolve_abuse_ch_identity(self) -> str:
        existing = self.helper.api.identity.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": ["abuse.ch"]}],
                "filterGroups": [],
            }
        )
        if existing:
            self.helper.connector_logger.info(
                "Resolved existing abuse.ch identity", {"id": existing["id"]}
            )
            return existing["id"]

        created = self.helper.api.identity.create(
            type="Organization",
            name="abuse.ch",
            description=(
                "Swiss nonprofit tracking malicious internet infrastructure, "
                "including botnet C2 servers, malware distribution URLs, and "
                "phishing sites. Operates URLHaus, ThreatFox, Feodo Tracker, "
                "SSL Blacklist, and YARA."
            ),
            objectMarking=[self._tlp_clear_id],
            confidence=CONFIDENCE,
        )
        self.helper.connector_logger.info(
            "Created abuse.ch Organization identity", {"id": created["id"]}
        )
        return created["id"]

    # ── Run loop ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        self.helper.connector_logger.info(
            "URLHaus connector starting",
            {
                "version": CONNECTOR_VERSION,
                "interval_hours": self.interval_seconds // 3600,
                "run_on_startup": self.run_on_startup,
            },
        )

        if not self.run_on_startup:
            next_run_ts = datetime.now(timezone.utc).timestamp() + self.interval_seconds
            next_run_str = datetime.fromtimestamp(
                next_run_ts, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.helper.connector_logger.info(
                "RUN_ON_STARTUP is false — sleeping until next scheduled run",
                {"next_run_utc": next_run_str, "sleep_seconds": self.interval_seconds},
            )
            time.sleep(self.interval_seconds)

        while True:
            try:
                self._run_once()
            except Exception as exc:
                self.helper.connector_logger.error(
                    "Run cycle failed with unhandled exception", {"error": str(exc)}
                )
            time.sleep(self.interval_seconds)

    def _run_once(self) -> None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        container_name = f"URLHaus Feed \u2014 {today}"
        published_iso = f"{today}T00:00:00Z"

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, container_name
        )
        self.helper.connector_logger.info(
            "Initiating URLHaus ingestion run",
            {"date": today, "work_id": work_id, "container": container_name},
        )

        try:
            url_entries = self.client.get_recent_urls()
            payload_entries = self.client.get_recent_payloads()
            self.helper.connector_logger.info(
                "Fetched URLHaus data",
                {
                    "online_url_count": len(url_entries),
                    "payload_count": len(payload_entries),
                },
            )

            report_id = self._get_or_create_report(container_name, published_iso)
            self.helper.connector_logger.info(
                "Daily report container ready", {"report_id": report_id}
            )

            processed_url_ids: dict[str, str] = {}
            url_object_ids = self._process_url_entries(url_entries, processed_url_ids)
            payload_object_ids = self._process_payload_entries(
                payload_entries, processed_url_ids
            )

            all_object_ids = url_object_ids + payload_object_ids
            link_failures = 0
            for obj_id in all_object_ids:
                try:
                    self.helper.api.report.add_stix_object_or_stix_relationship(
                        id=report_id,
                        stixObjectOrStixRelationshipId=obj_id,
                    )
                except Exception as link_exc:
                    link_failures += 1
                    self.helper.connector_logger.warning(
                        "Failed to link object to report container",
                        {"object_id": obj_id, "error": str(link_exc)},
                    )

            self.helper.connector_logger.info(
                "URLHaus run complete",
                {
                    "container": container_name,
                    "total_objects": len(all_object_ids),
                    "link_failures": link_failures,
                },
            )
            self.helper.api.work.to_processed(
                work_id,
                f"URLHaus ingestion complete: {len(all_object_ids)} objects, "
                f"{link_failures} link failures.",
            )

        except URLHausAPIError as api_exc:
            self.helper.connector_logger.error(
                "URLHaus API error during run", {"error": str(api_exc)}
            )
            self.helper.api.work.to_processed(
                work_id, f"URLHaus API error: {api_exc}", in_error=True
            )
            raise
        except Exception as exc:
            self.helper.connector_logger.error(
                "Unhandled error during run", {"error": str(exc)}
            )
            self.helper.api.work.to_processed(work_id, f"Error: {exc}", in_error=True)
            raise

    # ── Report container ──────────────────────────────────────────────────────

    def _get_or_create_report(self, name: str, published: str) -> str:
        existing = self.helper.api.report.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [name]}],
                "filterGroups": [],
            }
        )
        if existing:
            self.helper.connector_logger.info(
                "Reusing existing daily report container",
                {"report_id": existing["id"], "name": name},
            )
            return existing["id"]

        result = self.helper.api.report.create(
            name=name,
            published=published,
            report_types=["threat-report"],
            createdBy=self._abuse_ch_id,
            objectMarking=[self._tlp_clear_id],
            confidence=CONFIDENCE,
            description=(
                "Automated daily ingestion of active malware distribution URLs "
                "and associated payload hashes from abuse.ch URLHaus. "
                "Scope: online-status URLs only at time of ingestion. "
                "Source: https://urlhaus.abuse.ch/"
            ),
        )
        self.helper.connector_logger.info(
            "Created daily report container",
            {"report_id": result["id"], "name": name},
        )
        return result["id"]

    # ── URL entry processing ──────────────────────────────────────────────────

    def _process_url_entries(
        self,
        entries: list[dict],
        processed_url_ids: dict[str, str],
    ) -> list[str]:
        all_ids: list[str] = []
        success = 0
        skipped = 0
        for entry in entries:
            try:
                ids = self._ingest_url_entry(entry, processed_url_ids)
                all_ids.extend(ids)
                success += 1
            except Exception as exc:
                skipped += 1
                self.helper.connector_logger.warning(
                    "Skipping URL entry due to ingestion error",
                    {"url": entry.get("url", "<unknown>"), "error": str(exc)},
                )
        self.helper.connector_logger.info(
            "URL entry processing complete",
            {"ingested": success, "skipped": skipped, "total_objects": len(all_ids)},
        )
        return all_ids

    def _ingest_url_entry(
        self,
        entry: dict,
        processed_url_ids: dict[str, str],
    ) -> list[str]:
        """
        Ingest a single URLHaus URL entry.

        Tag routing for each threat tag:
          1. normalize_tag() — returns None for blocked/empty tags (dropped)
          2. Check TAG_TOOL_MAP — if matched, resolve Tool SDO
          3. Check TAG_SOFTWARE_MAP — if matched, resolve Software observable
          4. Otherwise — resolve Malware SDO

        All resolved entity IDs receive related-to relationships from both
        the URL observable and the host observable (if present).
        """
        object_ids: list[str] = []

        url_value = (entry.get("url") or "").strip()
        if not url_value:
            return object_ids

        host = (entry.get("host") or "").strip()
        tags = [t for t in (entry.get("tags") or []) if t and t.strip()]
        threat = (entry.get("threat") or "unknown").strip()
        date_added = parse_url_date(entry.get("date_added", ""))
        date_added_iso = date_added.isoformat() if date_added else None

        # ── URL observable ───────────────────────────────────────────────────
        url_obs = self.helper.api.stix_cyber_observable.create(
            observableData={
                "type": "Url",
                "value": url_value,
                "x_opencti_score": OBSERVABLE_SCORE,
                "x_opencti_description": (
                    f"Active malware distribution URL submitted to abuse.ch URLHaus. "
                    f"Threat category: {threat}. Status at ingestion: online."
                ),
            },
            createdBy=self._abuse_ch_id,
            objectMarking=[self._tlp_clear_id],
            createIndicator=False,
        )
        url_id = url_obs["id"]
        object_ids.append(url_id)
        processed_url_ids[url_value] = url_id

        rel = self._create_rel("related-to", url_id, self._abuse_ch_id, date_added_iso)
        if rel:
            object_ids.append(rel)

        # ── Host observable ──────────────────────────────────────────────────
        host_id: str | None = None
        if host:
            obs_type = classify_host(host)
            if obs_type:
                host_id = self._get_or_create_host_observable(host, obs_type)
                if host_id:
                    object_ids.append(host_id)
                    rel = self._create_rel("related-to", url_id, host_id, date_added_iso)
                    if rel:
                        object_ids.append(rel)
                    rel = self._create_rel("related-to", host_id, self._abuse_ch_id, date_added_iso)
                    if rel:
                        object_ids.append(rel)

        # ── Tag routing ──────────────────────────────────────────────────────
        for tag in tags:
            # Step 1: normalize and apply blocklist + prefix filters.
            # Returns None for suppressed tags — skip entirely.
            name = normalize_tag(tag)
            if name is None:
                continue

            # Step 2: Tool map check.
            if name in TAG_TOOL_MAP:
                entity_id = self._get_or_create_tool(name)
                if entity_id:
                    if entity_id not in object_ids:
                        object_ids.append(entity_id)
                    rel = self._create_rel("related-to", url_id, entity_id, date_added_iso)
                    if rel:
                        object_ids.append(rel)
                    if host_id:
                        rel = self._create_rel("related-to", host_id, entity_id, date_added_iso)
                        if rel:
                            object_ids.append(rel)
                continue

            # Step 3: Software map check.
            if name in TAG_SOFTWARE_MAP:
                entity_id = self._get_or_create_software(name)
                if entity_id:
                    if entity_id not in object_ids:
                        object_ids.append(entity_id)
                    rel = self._create_rel("related-to", url_id, entity_id, date_added_iso)
                    if rel:
                        object_ids.append(rel)
                    if host_id:
                        rel = self._create_rel("related-to", host_id, entity_id, date_added_iso)
                        if rel:
                            object_ids.append(rel)
                continue

            # Step 4: Malware SDO (default path for unrecognized family tags).
            malware_id = self._get_or_create_malware(name)
            if malware_id:
                if malware_id not in object_ids:
                    object_ids.append(malware_id)
                rel = self._create_rel("related-to", url_id, malware_id, date_added_iso)
                if rel:
                    object_ids.append(rel)
                if host_id:
                    rel = self._create_rel("related-to", host_id, malware_id, date_added_iso)
                    if rel:
                        object_ids.append(rel)

        return object_ids

    # ── Payload entry processing ──────────────────────────────────────────────

    def _process_payload_entries(
        self,
        entries: list[dict],
        processed_url_ids: dict[str, str],
    ) -> list[str]:
        all_ids: list[str] = []
        success = 0
        skipped = 0
        for entry in entries:
            try:
                ids = self._ingest_payload_entry(entry, processed_url_ids)
                all_ids.extend(ids)
                success += 1
            except Exception as exc:
                skipped += 1
                self.helper.connector_logger.warning(
                    "Skipping payload entry due to ingestion error",
                    {"sha256": entry.get("sha256_hash", "<unknown>"), "error": str(exc)},
                )
        self.helper.connector_logger.info(
            "Payload entry processing complete",
            {"ingested": success, "skipped": skipped, "total_objects": len(all_ids)},
        )
        return all_ids

    def _ingest_payload_entry(
        self,
        entry: dict,
        processed_url_ids: dict[str, str],
    ) -> list[str]:
        """
        Ingest a single URLHaus payload entry.

        The signature field on payload entries is always routed through
        _get_or_create_malware() only. URLHaus payload signatures are
        malware family classifications assigned by the abuse.ch pipeline,
        not user-submitted tags, so Tool/Software routing does not apply.
        """
        object_ids: list[str] = []

        sha256 = (entry.get("sha256_hash") or "").strip()
        if not sha256:
            return object_ids

        md5 = (entry.get("md5_hash") or "").strip()
        signature = (entry.get("signature") or "").strip()
        file_type = (entry.get("file_type") or "").strip()
        file_size = entry.get("file_size")
        firstseen = parse_payload_date(entry.get("firstseen", ""))
        firstseen_iso = firstseen.isoformat() if firstseen else None

        obs_data: dict = {
            "type": "StixFile",
            "hashes": {"SHA-256": sha256},
            "x_opencti_score": OBSERVABLE_SCORE,
            "x_opencti_description": (
                f"URLHaus payload. File type: {file_type or 'unknown'}. "
                f"Malware signature: {signature or 'unclassified'}."
            ),
        }
        if md5:
            obs_data["hashes"]["MD5"] = md5
        if file_size:
            try:
                obs_data["size"] = int(file_size)
            except (ValueError, TypeError):
                pass

        file_obs = self.helper.api.stix_cyber_observable.create(
            observableData=obs_data,
            createdBy=self._abuse_ch_id,
            objectMarking=[self._tlp_clear_id],
            createIndicator=False,
        )
        file_id = file_obs["id"]
        object_ids.append(file_id)

        rel = self._create_rel("related-to", file_id, self._abuse_ch_id, firstseen_iso)
        if rel:
            object_ids.append(rel)

        if signature:
            malware_id = self._get_or_create_malware(signature)
            if malware_id:
                if malware_id not in object_ids:
                    object_ids.append(malware_id)
                rel = self._create_rel("related-to", file_id, malware_id, firstseen_iso)
                if rel:
                    object_ids.append(rel)

        for url_ref in (entry.get("urls_from_same_payload") or []):
            parent_url_value = (url_ref.get("url") or "").strip()
            if parent_url_value and parent_url_value in processed_url_ids:
                parent_url_id = processed_url_ids[parent_url_value]
                rel = self._create_rel("related-to", file_id, parent_url_id, firstseen_iso)
                if rel:
                    object_ids.append(rel)

        return object_ids

    # ── Shared entity helpers ─────────────────────────────────────────────────

    def _get_or_create_host_observable(self, host: str, obs_type: str) -> str | None:
        try:
            result = self.helper.api.stix_cyber_observable.create(
                observableData={
                    "type": obs_type,
                    "value": host,
                    "x_opencti_score": OBSERVABLE_SCORE,
                },
                createdBy=self._abuse_ch_id,
                objectMarking=[self._tlp_clear_id],
                createIndicator=False,
            )
            return result["id"]
        except Exception as exc:
            self.helper.connector_logger.warning(
                "Failed to create host observable",
                {"host": host, "type": obs_type, "error": str(exc)},
            )
            return None

    def _get_or_create_tool(self, tag_name: str) -> str | None:
        """
        Return the internal OpenCTI ID for a Tool SDO corresponding to the
        given normalized tag name.

        Looks up the canonical entity name from TAG_TOOL_MAP, then follows
        the standard resolution order: TTL-aware cache → graph lookup → create.

        Tool entities represent legitimate software abused by threat actors.
        They are created with confidence 75 and TLP:CLEAR.
        """
        canonical_name = TAG_TOOL_MAP.get(tag_name)
        if not canonical_name:
            return None

        # TTL-aware cache check
        if canonical_name in self._tool_cache:
            cached_id, cached_at = self._tool_cache[canonical_name]
            if time.monotonic() - cached_at < MALWARE_CACHE_TTL_SECONDS:
                return cached_id
            del self._tool_cache[canonical_name]

        # Graph lookup
        existing = self.helper.api.tool.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [canonical_name]}],
                "filterGroups": [],
            }
        )
        if existing:
            self._tool_cache[canonical_name] = (existing["id"], time.monotonic())
            return existing["id"]

        # Create
        try:
            result = self.helper.api.tool.create(
                name=canonical_name,
                createdBy=self._abuse_ch_id,
                objectMarking=[self._tlp_clear_id],
                confidence=CONFIDENCE,
            )
            self._tool_cache[canonical_name] = (result["id"], time.monotonic())
            self.helper.connector_logger.info(
                "Created Tool entity", {"name": canonical_name, "id": result["id"]}
            )
            return result["id"]
        except Exception as exc:
            self.helper.connector_logger.warning(
                "Failed to create Tool entity",
                {"name": canonical_name, "error": str(exc)},
            )
            return None

    def _get_or_create_software(self, tag_name: str) -> str | None:
        """
        Return the internal OpenCTI ID for a Software observable corresponding
        to the given normalized tag name.

        Looks up the canonical entity name from TAG_SOFTWARE_MAP, then follows
        the standard resolution order: TTL-aware cache → graph lookup → create.

        Software observables represent specific tools or frameworks observed in
        the threat landscape (honeypot frameworks, sensors) that are not
        themselves malicious but are contextually relevant.
        """
        canonical_name = TAG_SOFTWARE_MAP.get(tag_name)
        if not canonical_name:
            return None

        # TTL-aware cache check
        if canonical_name in self._software_cache:
            cached_id, cached_at = self._software_cache[canonical_name]
            if time.monotonic() - cached_at < MALWARE_CACHE_TTL_SECONDS:
                return cached_id
            del self._software_cache[canonical_name]

        # Graph lookup — Software is a StixCyberObservable, filter by name
        existing = self.helper.api.stix_cyber_observable.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [canonical_name]}],
                "filterGroups": [],
            }
        )
        if existing:
            self._software_cache[canonical_name] = (existing["id"], time.monotonic())
            return existing["id"]

        # Create
        try:
            result = self.helper.api.stix_cyber_observable.create(
                observableData={
                    "type": "Software",
                    "name": canonical_name,
                    "x_opencti_score": 0,
                    "x_opencti_description": (
                        f"Software entity created from URLHaus tag '{tag_name}'. "
                        f"Represents a tool or framework observed in the URLHaus "
                        f"submission context."
                    ),
                },
                createdBy=self._abuse_ch_id,
                objectMarking=[self._tlp_clear_id],
                createIndicator=False,
            )
            self._software_cache[canonical_name] = (result["id"], time.monotonic())
            self.helper.connector_logger.info(
                "Created Software entity",
                {"name": canonical_name, "id": result["id"]},
            )
            return result["id"]
        except Exception as exc:
            self.helper.connector_logger.warning(
                "Failed to create Software entity",
                {"name": canonical_name, "error": str(exc)},
            )
            return None

    def _get_or_create_malware(self, name: str) -> str | None:
        """
        Return the internal OpenCTI ID for a Malware SDO for the given
        normalized name. Caller is responsible for having already routed
        through TAG_TOOL_MAP and TAG_SOFTWARE_MAP before calling this.

        TTL-aware cache → graph lookup → create.
        Returns None on failure.
        """
        # TTL-aware cache check
        if name in self._malware_cache:
            cached_id, cached_at = self._malware_cache[name]
            if time.monotonic() - cached_at < MALWARE_CACHE_TTL_SECONDS:
                return cached_id
            self.helper.connector_logger.info(
                "Malware cache entry expired, refreshing from graph",
                {"name": name},
            )
            del self._malware_cache[name]

        # Graph lookup
        existing = self.helper.api.malware.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [name]}],
                "filterGroups": [],
            }
        )
        if existing:
            self._malware_cache[name] = (existing["id"], time.monotonic())
            return existing["id"]

        # Create
        try:
            result = self.helper.api.malware.create(
                name=name,
                is_family=True,
                createdBy=self._abuse_ch_id,
                objectMarking=[self._tlp_clear_id],
                confidence=CONFIDENCE,
            )
            self._malware_cache[name] = (result["id"], time.monotonic())
            self.helper.connector_logger.info(
                "Created Malware entity", {"name": name, "id": result["id"]}
            )
            return result["id"]
        except Exception as exc:
            self.helper.connector_logger.warning(
                "Failed to create Malware entity", {"name": name, "error": str(exc)}
            )
            return None

    def _create_rel(
        self,
        rel_type: str,
        from_id: str,
        to_id: str,
        start_time: str | None = None,
    ) -> str | None:
        """Create a STIX core relationship. Returns ID on success, None on failure."""
        try:
            kwargs: dict = {
                "fromId": from_id,
                "toId": to_id,
                "relationship_type": rel_type,
                "createdBy": self._abuse_ch_id,
                "objectMarking": [self._tlp_clear_id],
                "confidence": CONFIDENCE,
            }
            if start_time:
                kwargs["start_time"] = start_time
            result = self.helper.api.stix_core_relationship.create(**kwargs)
            return result["id"]
        except Exception as exc:
            self.helper.connector_logger.warning(
                "Failed to create relationship",
                {
                    "relationship_type": rel_type,
                    "from_id": from_id,
                    "to_id": to_id,
                    "error": str(exc),
                },
            )
            return None
