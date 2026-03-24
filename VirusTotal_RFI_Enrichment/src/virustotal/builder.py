# -*- coding: utf-8 -*-
"""
VirusTotal STIX bundle builder — data-model-compliant implementation.

All objects constructed here:
  - Are authored by the VirusTotal Identity (created_by_ref)
  - Carry TLP:GREEN object_marking_refs
  - Include the VT permalink as external_references where applicable
  - Are scoped into the originating RFI (Case-Incident) container after submission

Design decisions encoded here:
  - Indicators are ONLY created for YARA rules (not for positives threshold hits)
  - VT tags are converted to typed entities (Malware / Vulnerability / AttackPattern)
    rather than being stored as string labels
  - x_opencti_score is NOT written to observables (dropped per model decision)
  - Assessment notes are linked directly to the enriched observable via object_refs
  - All derived observables get description, first/last seen where available,
    and a related-to relationship back to the enrichment target
  - Container scoping is performed after bundle submission via the OpenCTI API
"""

import datetime
import json
import re
from typing import Optional

import plyara
import plyara.utils
import pycountry
import stix2
from pycti import (
    STIX_EXT_OCTI_SCO,
    AttackPattern,
    Indicator,
    Location,
    Malware,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixCoreRelationship,
    Vulnerability,
)

# ─────────────────────────────────────────────────────────────────────────────
# Tag classification constants
# ─────────────────────────────────────────────────────────────────────────────

# Matches CVE identifiers as returned by VT tags (e.g. "CVE-2021-44228").
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

# Matches MITRE ATT&CK technique IDs at the technique or sub-technique level
# (e.g. "T1059" or "T1059.003"). Used to create AttackPattern entities.
_ATTACK_PATTERN_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Tags that carry no entity-level meaning in the knowledge graph.
# These are dropped during label-to-entity conversion; their text is still
# preserved in the assessment note for analyst reference.
#
# Includes:
#   - Platform/architecture tags (windows, linux, 64bits, ...)
#   - Generic detection verdicts (pua, grayware, clean, ...)
#   - File-type tags (pdf, office, peexe, ...)
#   - Generic malware-class nouns that describe the enriched observable itself
#     rather than naming a distinct family (trojan, ransomware, ...). These
#     belong in an assessment annotation, not as standalone Malware entities.
#   - VT behavioral/static analysis tags that describe file characteristics
#     or sandbox-observed behaviors rather than naming a specific threat family.
#     These are VT's automated analysis vocabulary, not threat intelligence.
_GENERIC_TAGS: frozenset = frozenset({
    # Detection verdicts and file classification
    "grayware", "greyware", "pua", "pup", "adware", "clean", "legitimate",
    "software", "packed", "obfuscated", "encrypted", "runtime-modules",

    # Platform and architecture
    "windows", "linux", "macos", "android", "ios", "arm", "x86", "x64",
    "64bits", "32bits", "mips", "arm64",

    # File format and type
    "peexe", "pedll", "pe", "elf", "macho", "apk", "dex", "jar",
    "archive", "document", "pdf", "office", "script", "powershell",
    "batch", "vbs", "js", "html", "json", "xml", "zip", "rar", "7zip",
    "cab", "iso", "img", "lnk", "hta", "wsf", "jse", "vbe",

    # Generic malware class nouns — describe observable type, not a named family.
    # A file that IS a trojan is not the same as the Trojan threat family entity.
    "trojan", "ransomware", "worm", "backdoor", "spyware", "rootkit",
    "keylogger", "miner", "cryptominer", "banker", "stealer", "loader",
    "bot", "botnet", "rat", "virus", "dropper", "downloader", "installer",
    "injector", "spreader", "exploit", "overlay",

    # VT behavioral analysis tags — sandbox-observed behaviors and static
    # characteristics. These describe HOW a file behaves, not WHAT family it is.
    # Captured in the assessment note; not meaningful as standalone graph entities.
    "long-sleeps",           # Process sleeps to evade sandbox timeouts
    "detect-debug-environment",  # Anti-debug / anti-analysis checks
    "detect-virtual-machine",    # VM/sandbox detection
    "checks-network-adapters",   # Network adapter enumeration
    "checks-disk-space",         # Disk space checks (sandbox evasion)
    "checks-hostname",           # Hostname-based conditional execution
    "checks-username",           # Username-based conditional execution
    "checks-computer-name",      # Computer name checks
    "checks-registry",           # Registry enumeration
    "network-communication",     # Generic network activity
    "network-udp",               # UDP communication
    "network-dns",               # DNS queries
    "network-http",              # HTTP communication
    "network-smtp",              # SMTP communication
    "network-ftp",               # FTP communication
    "creates-files",             # File creation behavior
    "deletes-files",             # File deletion behavior
    "reads-files",               # File reading behavior
    "modifies-files",            # File modification behavior
    "creates-processes",         # Process creation
    "injects-code",              # Code injection
    "allocates-memory",          # Memory allocation
    "enumerates-processes",      # Process enumeration
    "enumerates-files",          # File system enumeration
    "modifies-registry",         # Registry modification
    "persistence",               # Generic persistence mechanism
    "autorun",                   # Autorun/startup persistence
    "spawns-processes",          # Child process spawning
    "reads-registry",            # Registry reading
    "windows-ui-interaction",    # GUI interaction
    "acquires-privileges",       # Privilege escalation behavior
    "anti-analysis",             # Generic anti-analysis
    "anti-sandbox",              # Sandbox evasion
    "anti-vm",                   # VM detection/evasion
    "anti-debug",                # Debug detection/evasion
    "packer",                    # File is packed
    "protector",                 # File uses a protector
    "compiler",                  # Compiler artifact
    "signed",                    # Has a digital signature
    "unsigned",                  # No digital signature
    "self-signed",               # Self-signed certificate
    "invalid-signature",         # Invalid digital signature
    "runtime-modules",           # Uses runtime modules
})


class VirusTotalBuilder:
    """
    Constructs and registers STIX objects derived from a VirusTotal API response.

    One builder instance is created per enrichment job. The builder accumulates
    STIX objects in self.bundle and tracks their IDs in self.new_object_ids.
    On send_bundle(), the bundle is submitted to OpenCTI workers and all new
    objects are scoped into the originating RFI container.

    Parameters
    ----------
    helper : OpenCTIConnectorHelper
    author : stix2.Identity
        Graph-registered VirusTotal Identity object.
    replace_with_lower_score : bool
        If True, overwrite a higher existing score with VT's lower value.
    stix_objects : list
        Existing STIX objects from the enrichment context bundle.
    stix_entity : dict
        STIX representation of the observable being enriched.
    opencti_entity : dict
        OpenCTI API representation of the observable being enriched.
    data : dict
        VT API response data object (i.e. json_data["data"]).
    rfi_container_id : str
        OpenCTI ID of the RFI container that owns the observable.
    tlp_green_id : str
        OpenCTI ID of the TLP:GREEN marking definition.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        replace_with_lower_score: bool,
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        data: dict,
        rfi_container_id: str,
        tlp_green_id: str,
    ) -> None:
        self.helper = helper
        self.author = author
        self.replace_with_lower_score = replace_with_lower_score
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.attributes = data["attributes"]
        self.rfi_container_id = rfi_container_id
        self.tlp_green_id = tlp_green_id

        # All new STIX object IDs created during this session.
        # Populated by _register_new_objects() and consumed by
        # _scope_to_rfi_container() after bundle submission.
        self.new_object_ids: list = []

        # Prime the bundle with context objects and the author identity.
        self.bundle = stix_objects + [self.author]

        # Compute VT detection score. Used only in assessment note content —
        # NOT written to the observable (x_opencti_score dropped per decision).
        # Guard against empty attributes (not-found path has no stats).
        if self.attributes.get("last_analysis_stats"):
            self.score = self._compute_score(self.attributes["last_analysis_stats"])
        else:
            # No VT data available — score is undefined for this enrichment.
            self.score = None

        # Extract the VT GUI permalink and attach it as an external reference
        # directly on the enriched observable's OCTI SCO extension.
        # This reference is also reused on all relationships and derived objects.
        # Guard against empty links (not-found path has no links).
        self_link = data.get("links", {}).get("self", "")
        link = self._extract_link(self_link) if self_link else None
        if link is not None:
            self.helper.log_debug(
                f"[VirusTotal] Attaching external reference to observable: {link}"
            )
            self.external_reference = self._create_external_reference(
                link,
                self.attributes.get("magic", "VirusTotal Report"),
            )
        else:
            self.external_reference = None
            if self_link:
                self.helper.log_debug(
                    "[VirusTotal] Could not extract VT permalink from response link."
                )

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_score(self, stats: dict) -> int:
        """
        Derive a 0-100 detection score from VT analysis stats.

        Formula: malicious / (harmless + undetected + malicious) * 100

        The result is stored as self.score and used only when composing the
        assessment note. It is intentionally NOT written to x_opencti_score.

        If replace_with_lower_score is False (default) and VT's score is
        lower than the existing score, the existing score is preserved and
        the discrepancy is noted in the debug log.
        """
        try:
            vt_score = round(
                (
                    stats["malicious"]
                    / (stats["harmless"] + stats["undetected"] + stats["malicious"])
                )
                * 100
            )
        except ZeroDivisionError as err:
            raise ValueError(
                "Cannot compute VT score — VT may have no record of this observable "
                "or it is currently being processed."
            ) from err

        # Retrieve the observable's current OpenCTI score for comparison.
        opencti_score = self.stix_entity.get(
            "x_opencti_score"
        ) or self.helper.api.get_attribute_in_extension("score", self.stix_entity)

        if opencti_score is not None and not self.replace_with_lower_score:
            if vt_score < opencti_score:
                self.helper.log_debug(
                    f"[VirusTotal] VT score ({vt_score}) is lower than existing "
                    f"score ({opencti_score}). Preserving existing score."
                )
                return opencti_score
        return vt_score

    def _create_external_reference(self, url: str, description: str) -> dict:
        """
        Build an external reference dict and attach it to the enriched observable.

        The reference is added to the observable's OCTI SCO extension via
        put_attribute_in_extension, causing it to appear on the entity's
        External References panel in the OpenCTI UI.

        The returned dict is also reused as external_references on all
        relationships and derived objects emitted by this builder.

        Parameters
        ----------
        url : str
            VT GUI permalink for this observable.
        description : str
            Human-readable label (e.g. file magic string or "VirusTotal Report").
        """
        external_reference = {
            "source_name": self.author["name"],
            "url": url,
            "description": description,
        }
        # Attach the reference to the enriched observable in-place.
        OpenCTIStix2.put_attribute_in_extension(
            self.stix_entity,
            STIX_EXT_OCTI_SCO,
            "external_references",
            external_reference,
            True,  # append=True, do not overwrite existing refs
        )
        return external_reference

    @staticmethod
    def _extract_link(link: str) -> Optional[str]:
        """
        Convert a VT API v3 resource URL into the equivalent GUI permalink.

        VT API links follow the pattern:
            https://www.virustotal.com/api/v3/<type>/<id>
        GUI links follow:
            https://www.virustotal.com/gui/<singular-type>/<id>

        Returns None if the resource type is not in the known mapping.
        """
        for api_segment, gui_segment in {
            "files": "file",
            "ip_addresses": "ip-address",
            "domains": "domain",
            "urls": "url",
        }.items():
            if api_segment in link:
                return link.replace("api/v3", "gui").replace(api_segment, gui_segment)
        return None

    def _classify_tag(self, tag: str) -> str:
        """
        Classify a single VT tag string into an entity-creation disposition.

        Returns
        -------
        str
            One of:
              "cve"            -> create stix2.Vulnerability
              "attack_pattern" -> create stix2.AttackPattern
              "malware"        -> create stix2.Malware (family name)
              "drop"           -> discard, captured in assessment note only
        """
        if _CVE_PATTERN.match(tag):
            return "cve"
        if _ATTACK_PATTERN_RE.match(tag):
            return "attack_pattern"
        if tag.lower() in _GENERIC_TAGS:
            # Generic taxonomy or platform tag — no entity value.
            return "drop"
        # Anything else (e.g. "Emotet", "Cobalt Strike", "RedLine") is
        # treated as a specific malware family name.
        return "malware"

    def _make_relationship(
        self,
        rel_type: str,
        source_id: str,
        target_id: str,
        description: str = "",
        start_time: Optional[datetime.datetime] = None,
        stop_time: Optional[datetime.datetime] = None,
    ) -> stix2.Relationship:
        """
        Construct a fully-populated STIX Relationship per the data model.

        Every relationship emitted by this builder:
          - Has created_by_ref = VirusTotal Identity
          - Carries TLP:GREEN object_marking_refs
          - Has the VT permalink appended to its description
          - Has external_references = [VT permalink] (if available)
          - Has start_time / stop_time populated when temporal data is available

        The description parameter should summarise the semantic meaning of
        the relationship. The VT permalink is appended automatically so the
        relationship is self-describing without requiring a separate Note.

        Parameters
        ----------
        rel_type : str
            STIX relationship type string (e.g. "related-to", "belongs-to").
        source_id : str
            STIX ID of the source object.
        target_id : str
            STIX ID of the target object.
        description : str
            Semantic description of the relationship.
        start_time : datetime, optional
            First-seen timestamp for the relationship.
        stop_time : datetime, optional
            Last-seen timestamp for the relationship.
        """
        # Append the VT permalink to the description so the relationship
        # carries its own provenance without requiring a lookup.
        if self.external_reference:
            permalink = self.external_reference["url"]
            description = (
                f"{description}\n\n[VT Source] {permalink}"
                if description
                else f"[VT Source] {permalink}"
            )

        kwargs = dict(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            relationship_type=rel_type,
            # VirusTotal Identity is the author of all enrichment relationships.
            created_by_ref=self.author,
            source_ref=source_id,
            target_ref=target_id,
            description=description or None,
            confidence=self.helper.connect_confidence_level,
            # TLP:GREEN on all VT-derived objects.
            object_marking_refs=[self.tlp_green_id],
            # VT permalink as external reference on the relationship itself,
            # in addition to the observable (per design spec section 6).
            external_references=(
                [self.external_reference] if self.external_reference else None
            ),
            allow_custom=True,
        )
        if start_time is not None:
            kwargs["start_time"] = self.helper.api.stix2.format_date(start_time)
        if stop_time is not None:
            kwargs["stop_time"] = self.helper.api.stix2.format_date(stop_time)

        return stix2.Relationship(**kwargs)

    def _register_new_objects(self, *objects):
        """
        Append one or more STIX objects to the bundle and record their IDs.

        IDs recorded here are used by _scope_to_rfi_container() after bundle
        submission to add all new objects to the originating RFI container.

        All objects created by this builder should be registered here rather
        than appended to self.bundle directly.
        """
        for obj in objects:
            self.bundle.append(obj)
            self.new_object_ids.append(obj["id"])

    # ─────────────────────────────────────────────────────────────────────────
    # Entity creation methods
    # ─────────────────────────────────────────────────────────────────────────

    def create_asn_belongs_to(self):
        """
        Create an AutonomousSystem observable and a 'belongs-to' relationship
        from the enriched IP observable to the AS.

        The AS observable is populated with:
          - number, name (as_owner), rir from VT attributes
          - TLP:GREEN marking
          - created_by_ref = VirusTotal Identity
          - x_opencti_description anchoring provenance

        The relationship carries:
          - description summarising the ASN context from VT
          - TLP:GREEN, created_by_ref, external_references (VT permalink)
        """
        if not self.attributes.get("asn"):
            self.helper.connector_logger.debug(
                "[VirusTotal] No ASN data in VT response — skipping AS creation.",
                {
                    "entity_id": self.stix_entity.get("id"),
                    "entity_value": self.stix_entity.get("value"),
                },
            )
            return

        asn = self.attributes["asn"]
        owner = self.attributes.get("as_owner", "unknown")
        self.helper.log_debug(
            f"[VirusTotal] Creating AutonomousSystem AS{asn} ({owner})"
        )

        as_stix = stix2.AutonomousSystem(
            number=asn,
            name=self.attributes.get("as_owner"),
            rir=self.attributes.get("regional_internet_registry"),
            object_marking_refs=[self.tlp_green_id],
            custom_properties={
                "created_by_ref": self.author.id,
                # Provenance description on the AS observable itself.
                "x_opencti_description": (
                    f"Autonomous System hosting "
                    f"{self.opencti_entity.get('observable_value', 'unknown')} "
                    f"as reported by VirusTotal."
                ),
            },
        )

        relationship = self._make_relationship(
            rel_type="belongs-to",
            source_id=self.stix_entity["id"],
            target_id=as_stix.id,
            description=(
                f"[VT] {self.opencti_entity.get('observable_value', 'unknown')} "
                f"belongs to AS{asn} ({owner}) per VirusTotal."
            ),
        )

        self._register_new_objects(as_stix, relationship)

    def create_ip_resolves_to(self, dns_record: dict):
        """
        Create an IPv4Address observable for a passive-DNS A record and link
        it to the domain observable with a 'resolves-to' relationship.

        The IPv4 observable is populated with:
          - value from the DNS record
          - TLP:GREEN marking
          - created_by_ref = VirusTotal Identity
          - x_opencti_description with provenance and last-seen date
          - NOTE: x_opencti_score is intentionally NOT written (dropped per decision)

        The relationship carries:
          - description noting the passive-DNS source
          - stop_time from VT's last_analysis_date (best available proxy for
            last-observed resolution, since VT's last_dns_records do not carry
            per-record timestamps in the standard response)

        Parameters
        ----------
        dns_record : dict
            Single DNS record dict from VT's last_dns_records list.
            Must contain a 'value' key with the IPv4 address string.
        """
        ipv4_value = dns_record["value"]
        self.helper.log_debug(
            f"[VirusTotal] Creating IPv4 observable from passive-DNS record: {ipv4_value}"
        )

        # VT's last_dns_records do not carry per-record timestamps. Use the
        # domain entity's last_analysis_date as the best available proxy.
        last_analysis_ts = self.attributes.get("last_analysis_date")
        last_seen: Optional[datetime.datetime] = (
            datetime.datetime.utcfromtimestamp(last_analysis_ts)
            if last_analysis_ts
            else None
        )

        ipv4_stix = stix2.IPv4Address(
            value=ipv4_value,
            object_marking_refs=[self.tlp_green_id],
            custom_properties={
                "created_by_ref": self.author.id,
                # Description: provenance only — threat behaviour belongs
                # in the relationship, not on the observable itself.
                "x_opencti_description": (
                    f"Resolved from VT passive DNS for "
                    f"{self.opencti_entity.get('observable_value', 'unknown')}"
                    + (
                        f", last observed {last_seen.strftime('%Y-%m-%d')}"
                        if last_seen
                        else ""
                    )
                    + "."
                ),
            },
        )

        relationship = self._make_relationship(
            rel_type="resolves-to",
            source_id=self.stix_entity["id"],
            target_id=ipv4_stix.id,
            description=(
                f"[VT] {self.opencti_entity.get('observable_value', 'unknown')} "
                f"resolved to {ipv4_value} per VirusTotal passive DNS."
            ),
            # Use last_analysis_date as stop_time — the most recent point at
            # which this resolution was confirmed by VT.
            stop_time=last_seen,
        )

        self._register_new_objects(ipv4_stix, relationship)

    def create_location_located_at(self):
        """
        Create a Location (Country) entity and a 'located-at' relationship
        from the IP observable to the country.

        The Location is created with a deterministic ID via pycti so that
        the same country does not produce duplicate nodes across enrichments.
        """
        if not self.attributes.get("country"):
            self.helper.connector_logger.debug(
                "[VirusTotal] No country data in VT response — skipping location creation.",
                {
                    "entity_id": self.stix_entity.get("id"),
                    "entity_value": self.stix_entity.get("value"),
                },
            )
            return

        alpha2 = self.attributes["country"]
        self.helper.log_debug(
            f"[VirusTotal] Creating Location for country code: {alpha2}"
        )

        # Resolve the alpha-2 code to a full country name using pycountry.
        # If the code is unrecognised (e.g. VT returns an invalid code),
        # fall back to the raw alpha-2 string so the object is still created.
        pycountry_entry = pycountry.countries.get(alpha_2=alpha2.upper())
        if pycountry_entry:
            country_name = pycountry_entry.name
            self.helper.log_debug(
                f"[VirusTotal] Resolved {alpha2} -> {country_name}"
            )
        else:
            country_name = alpha2
            self.helper.log_debug(
                f"[VirusTotal] Could not resolve country code '{alpha2}', "
                "using raw value as name."
            )

        location_stix = stix2.Location(
            # Use full country name as the primary identifier so OpenCTI
            # deduplicates correctly against existing Country entities that
            # were created with full names (e.g. from the MITRE connector).
            id=Location.generate_id(country_name, "Country"),
            created_by_ref=self.author,
            # name = full country name for display in the UI
            name=country_name,
            country=alpha2.upper(),
            object_marking_refs=[self.tlp_green_id],
            custom_properties={
                # Alpha-2 code stored as alias so analysts can search by
                # either the full name or the short code.
                "x_opencti_aliases": [alpha2.upper()],
            },
        )

        relationship = self._make_relationship(
            rel_type="located-at",
            source_id=self.stix_entity["id"],
            target_id=location_stix.id,
            description=(
                f"[VT] {self.opencti_entity.get('observable_value', 'unknown')} "
                f"is geolocated to {country_name} ({alpha2.upper()}) per VirusTotal."
            ),
        )

        self._register_new_objects(location_stix, relationship)

    def create_entities_from_labels(self):
        """
        Convert VT tags into typed STIX knowledge-graph entities.

        Classification rules (see _classify_tag):
          CVE-*   -> stix2.Vulnerability + external ref to NVD
          T####   -> stix2.AttackPattern + MITRE ATT&CK external ref
          other   -> stix2.Malware (family name, is_family=True)
          generic -> dropped (text still appears in assessment note)

        For each created entity a 'related-to' relationship is emitted
        from the enriched observable to the entity. The relationship
        description carries the VT permalink and tag context so it is
        self-describing without an additional Note.

        Entities are created with deterministic pycti-generated IDs so
        that the same malware family / CVE / technique does not create
        duplicate graph nodes across multiple enrichment runs.
        """
        tags = self.attributes.get("tags", [])
        if not tags:
            self.helper.log_debug(
                "[VirusTotal] No tags in VT response — skipping label-to-entity conversion."
            )
            return

        self.helper.log_debug(
            f"[VirusTotal] Converting {len(tags)} VT tags to entities: {tags}"
        )

        for tag in tags:
            disposition = self._classify_tag(tag)

            if disposition == "drop":
                # Generic taxonomy tag — no entity value. Content is preserved
                # verbatim in the assessment note.
                self.helper.log_debug(
                    f"[VirusTotal] Dropping generic tag (captured in note): '{tag}'"
                )
                continue

            elif disposition == "cve":
                # CVE -> Vulnerability
                self.helper.log_debug(
                    f"[VirusTotal] Creating Vulnerability for CVE tag: {tag}"
                )
                entity = stix2.Vulnerability(
                    id=Vulnerability.generate_id(tag.upper()),
                    name=tag.upper(),
                    description=(
                        "CVE identifier associated with this observable "
                        "per VirusTotal analysis."
                    ),
                    created_by_ref=self.author,
                    confidence=self.helper.connect_confidence_level,
                    object_marking_refs=[self.tlp_green_id],
                    external_references=[
                        {
                            # Use the canonical "cve" source name so OpenCTI
                            # can cross-reference against its CVE connector data.
                            "source_name": "cve",
                            "external_id": tag.upper(),
                        }
                    ],
                    allow_custom=True,
                )
                rel_description = (
                    f"[VT] {self.opencti_entity.get('observable_value', 'unknown')} "
                    f"is associated with {tag.upper()} per VirusTotal analysis."
                )

            elif disposition == "attack_pattern":
                # ATT&CK technique tag -> AttackPattern
                self.helper.log_debug(
                    f"[VirusTotal] Creating AttackPattern for ATT&CK tag: {tag}"
                )
                entity = stix2.AttackPattern(
                    id=AttackPattern.generate_id(tag, tag),
                    name=tag,
                    description=(
                        f"MITRE ATT&CK technique {tag} associated with this "
                        "observable per VirusTotal analysis."
                    ),
                    created_by_ref=self.author,
                    confidence=self.helper.connect_confidence_level,
                    object_marking_refs=[self.tlp_green_id],
                    external_references=[
                        {
                            "source_name": "mitre-attack",
                            "external_id": tag,
                            # Convert sub-technique dot notation to URL slash notation.
                            "url": (
                                f"https://attack.mitre.org/techniques/"
                                f"{tag.replace('.', '/')}"
                            ),
                        }
                    ],
                    allow_custom=True,
                )
                rel_description = (
                    f"[VT] {self.opencti_entity.get('observable_value', 'unknown')} "
                    f"is associated with ATT&CK technique {tag} per VirusTotal."
                )

            else:
                # Everything else -> Malware family
                # VT tags that survive the generic filter are treated as specific
                # malware family names (e.g. "Emotet", "RedLine", "Cobalt Strike").
                self.helper.log_debug(
                    f"[VirusTotal] Creating Malware family entity for tag: '{tag}'"
                )
                entity = stix2.Malware(
                    id=Malware.generate_id(tag),
                    name=tag,
                    # Mark as a family (not a sample), since VT tags name families.
                    is_family=True,
                    description="Malware family identified by VirusTotal analysis.",
                    created_by_ref=self.author,
                    confidence=self.helper.connect_confidence_level,
                    object_marking_refs=[self.tlp_green_id],
                    allow_custom=True,
                )
                rel_description = (
                    f"[VT] {self.opencti_entity.get('observable_value', 'unknown')} "
                    f"is related to malware family '{tag}' per VirusTotal."
                )

            # Emit related-to relationship: enriched observable -> entity.
            # The relationship description carries the VT permalink (via
            # _make_relationship) and tag context, making it self-describing.
            relationship = self._make_relationship(
                rel_type="related-to",
                source_id=self.stix_entity["id"],
                target_id=entity["id"],
                description=rel_description,
            )

            self._register_new_objects(entity, relationship)

    def _build_observable_header(self) -> str:
        """
        Build a markdown header block summarising the enriched observable's
        own fields from the OpenCTI entity payload.

        Included in all notes so the note is self-contained — an analyst
        reading it does not need to navigate to the entity to see what
        was enriched.

        Fields included per type:
          StixFile / Artifact : hashes, name(s), size, mime_type,
                                magic_number_hex, original author, ingested date
          IPv4-Addr / Domain  : observable value, original author, ingested date
          Url                 : observable value, original author, ingested date
        """
        entity_type = self.opencti_entity.get("entity_type", "Unknown")
        created_by = (
            self.opencti_entity.get("createdBy", {}) or {}
        ).get("name", "Unknown")
        created_at = self.opencti_entity.get("created_at", "Unknown")
        observable_value = self.opencti_entity.get("observable_value", "Unknown")

        lines = [
            "## Observable Summary\n",
            f"**Entity Type:** {entity_type}",
            f"**Original Author:** {created_by}",
            f"**Ingested:** {created_at}",
        ]

        if entity_type in ("StixFile", "Artifact"):
            # Hash values — include all available algorithms.
            # opencti_entity hashes is a list of {"algorithm": ..., "hash": ...} dicts.
            hashes = self.opencti_entity.get("hashes") or []
            if hashes:
                lines.append("\n### Hashes")
                for h in hashes:
                    algo = h.get("algorithm", "Unknown")
                    value = h.get("hash", "")
                    if value:
                        lines.append(f"- **{algo}:** `{value}`")

            # File name and additional names.
            name = self.opencti_entity.get("name")
            additional_names = self.opencti_entity.get("x_opencti_additional_names") or []
            if name:
                lines.append(f"\n**Primary Name:** {name}")
            if additional_names:
                lines.append(f"**Additional Names:** {', '.join(additional_names)}")

            # File metadata.
            size = self.opencti_entity.get("size")
            mime = self.opencti_entity.get("mime_type")
            magic = self.opencti_entity.get("magic_number_hex")
            if size is not None:
                lines.append(f"**Size:** {size} bytes")
            if mime:
                lines.append(f"**MIME Type:** {mime}")
            if magic:
                lines.append(f"**Magic Number:** {magic}")
        else:
            # For IPs, domains, URLs — the observable value is the primary identifier.
            lines.append(f"**Observable Value:** `{observable_value}`")

        return "\n".join(lines) + "\n"

    def create_not_found_note(self):
        """
        Create a note on the observable recording that VT has no record of it.

        This is a data point, not an error — the absence of a VT record is
        analytically meaningful (e.g. novel malware, internal tooling, or
        a hash that has never been submitted to VT).

        The note includes:
          - The observable summary header (all available entity fields)
          - The date/time the lookup was attempted
          - A clear statement that VT returned NotFoundError
          - Guidance for the analyst on next steps
        """
        import datetime
        lookup_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        header = self._build_observable_header()
        content = (
            f"{header}\n"
            "## VirusTotal Lookup Result\n\n"
            f"**Lookup Attempted:** {lookup_time}\n\n"
            "**Result:** VirusTotal has no record of this observable.\n\n"
            "### Analyst Notes\n"
            "A `NotFoundError` from VirusTotal may indicate:\n"
            "- The file has never been submitted to VirusTotal\n"
            "- The hash is from a novel or highly targeted sample\n"
            "- The observable is benign internal tooling\n"
            "- The observable was recently created and not yet indexed\n\n"
            "Consider submitting the sample directly to VirusTotal if available, "
            "or cross-referencing against other threat intelligence sources."
        )

        self.helper.log_debug(
            f"[VirusTotal] Creating not-found note for "
            f"{self.opencti_entity.get('observable_value', 'unknown')}"
        )

        note = stix2.Note(
            id=Note.generate_id(datetime.datetime.now().isoformat(), content),
            abstract="VirusTotal — No Record Found",
            content=content,
            created_by_ref=self.author,
            object_refs=[self.stix_entity["id"]],
            object_marking_refs=[self.tlp_green_id],
            confidence=self.helper.connect_confidence_level,
            custom_properties={
                "x_opencti_note_types": ["assessment"],
            },
            allow_custom=True,
        )
        self._register_new_objects(note)

    def create_assessment_note(self, scan_date: Optional[str] = None):
        """
        Create a structured assessment Note for this enrichment event and
        attach it directly to the enriched observable.

        The Note is structured to meet the data model's assessment-note
        requirement:
          - note_types = ["assessment"] (via x_opencti_note_types custom prop)
          - object_refs = [enriched observable's STIX ID]
          - created_by_ref = VirusTotal Identity
          - object_marking_refs = [TLP:GREEN]
          - content includes: scan date, stats table, score, and all raw tags

        If OpenCTI's API rejects a Note referencing an SCO in object_refs
        (SCOs are not SDOs — this is the known failure mode), the fallback
        is to embed the note content in the assessment relationship description.
        This behaviour is validated at test time.

        Parameters
        ----------
        scan_date : str, optional
            Human-readable scan date string (e.g. "2024-03-18 14:22 UTC").
        """
        stats = self.attributes.get("last_analysis_stats", {})
        tags = self.attributes.get("tags", [])

        # Compute totals for the stats table.
        total_engines = (
            len(self.attributes.get("last_analysis_results", {}))
            or sum(stats.values())
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        # Build the observable summary header — included in all notes so
        # each note is self-contained with full observable context.
        observable_header = self._build_observable_header()

        content_lines = [
            observable_header,
            "## VirusTotal Enrichment Assessment\n",
        ]

        if scan_date:
            content_lines.append(f"**Scan Date:** {scan_date}\n")

        content_lines += [
            "\n### Detection Statistics\n",
            "| Total Engines | Malicious | Suspicious | Harmless | Undetected |",
            "|---------------|-----------|------------|----------|------------|",
            f"| {total_engines} | {malicious} | {suspicious} | {harmless} | {undetected} |",
            f"\n**Detection Score:** {self.score} / 100\n" if self.score is not None else "\n**Detection Score:** N/A\n",
        ]

        if tags:
            content_lines.append(f"\n### VT Tags\n{', '.join(tags)}\n")

        if self.external_reference:
            content_lines.append(
                f"\n**Source:** {self.external_reference['url']}"
            )

        content = "\n".join(content_lines)

        self.helper.log_debug(
            f"[VirusTotal] Creating assessment note for "
            f"{self.opencti_entity.get('observable_value', 'unknown')}"
        )

        note = stix2.Note(
            id=Note.generate_id(datetime.datetime.now().isoformat(), content),
            abstract="VirusTotal Enrichment Assessment",
            content=content,
            created_by_ref=self.author,
            # Link the Note directly to the enriched observable so it appears
            # on the observable's Notes panel in OpenCTI.
            # NOTE: If OpenCTI rejects an SCO in object_refs, this will fail
            # silently at worker import time. Fall back is embedding content
            # in the relationship description — tested separately.
            object_refs=[self.stix_entity["id"]],
            object_marking_refs=[self.tlp_green_id],
            confidence=self.helper.connect_confidence_level,
            custom_properties={
                # OpenCTI note type classification — marks this as an assessment,
                # not a general note or analyst comment.
                "x_opencti_note_types": ["assessment"],
            },
            allow_custom=True,
        )

        self._register_new_objects(note)

    def create_yara(
        self, yara: dict, ruleset: dict, valid_from: Optional[float] = None
    ):
        """
        Create a YARA Indicator from a VT crowdsourced YARA match and link
        it to the enriched file observable.

        YARA rules are the ONLY Indicator type this connector creates.
        They are genuine STIX Indicators (pattern_type="yara"), not IOC
        observables being promoted to indicators based on a detection threshold.

        Objects created:
          stix2.Indicator (pattern_type="yara")
            - name = rule_name
            - description = structured JSON from ruleset metadata
            - created_by_ref = VirusTotal Identity
            - TLP:GREEN
            - external_references = [VT file permalink]

          stix2.Relationship (related-to: observable -> YARA Indicator)
            - description noting ruleset source
            - created_by_ref = VirusTotal Identity
            - TLP:GREEN, external_references = [VT permalink]

        Parameters
        ----------
        yara : dict
            Crowdsourced YARA match metadata from VT response attributes.
        ruleset : dict
            Full ruleset response object from VT ruleset API.
        valid_from : float, optional
            Unix timestamp for the file's creation_date (used as valid_from
            on the indicator).
        """
        rule_name = yara.get("rule_name", "No rule name provided")
        self.helper.log_debug(
            f"[VirusTotal] Processing YARA rule '{rule_name}' "
            f"from ruleset {yara.get('ruleset_name', 'unknown')}"
        )

        # Parse the full ruleset to extract the specific matching rule.
        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset["data"]["attributes"]["rules"])
        matching_rules = [r for r in rules if r["rule_name"] == rule_name]

        if not matching_rules:
            self.helper.log_warning(
                f"[VirusTotal] No parsed rule found for rule_name '{rule_name}'. "
                "The rule may have been renamed or removed from the ruleset. Skipping."
            )
            return

        # Use file creation_date as valid_from if provided.
        # datetime.min is used as a safe default when no timestamp is available.
        valid_from_date = (
            datetime.datetime.min
            if valid_from is None
            else datetime.datetime.utcfromtimestamp(valid_from)
        )

        # Build a structured description from all available ruleset metadata.
        # This is embedded in the indicator's description as JSON for
        # machine-readability and preserved in triple-backtick for UI display.
        ruleset_id = yara.get("id", "No ruleset id provided")
        yara_description_payload = {
            "description": yara.get("description", "No description provided"),
            # The 'author' field here is the YARA rule author (e.g. security researcher),
            # not the OpenCTI created_by_ref author (VirusTotal).
            "author": yara.get("author", "No author provided"),
            "source": yara.get("source", "No source provided"),
            "ruleset_id": ruleset_id,
            "ruleset_name": yara.get("ruleset_name", "No ruleset name provided"),
        }

        rebuilt_rule = plyara.utils.rebuild_yara_rule(matching_rules[0])

        # Collect external references for the YARA indicator.
        # VT file permalink is included so the indicator links back to the
        # file report that triggered the YARA match.
        indicator_ext_refs = (
            [self.external_reference] if self.external_reference else []
        )

        indicator = stix2.Indicator(
            id=Indicator.generate_id(rebuilt_rule),
            created_by_ref=self.author,
            name=rule_name,
            description=f"```\n{json.dumps(yara_description_payload, indent=2)}\n```",
            confidence=self.helper.connect_confidence_level,
            pattern=rebuilt_rule,
            pattern_type="yara",
            valid_from=self.helper.api.stix2.format_date(valid_from_date),
            object_marking_refs=[self.tlp_green_id],
            external_references=indicator_ext_refs or None,
            custom_properties={
                # Hint to OpenCTI about the observable type this indicator
                # is associated with — used for UI display and filtering.
                "x_opencti_main_observable_type": "StixFile",
            },
            allow_custom=True,
        )

        self.helper.log_debug(
            f"[VirusTotal] Created YARA indicator {indicator.id} for rule '{rule_name}'"
        )

        # Relationship: enriched file -> YARA Indicator (related-to).
        # Direction is observable -> indicator to mirror the data model convention
        # that observables are sources in enrichment-derived relationships.
        relationship = self._make_relationship(
            rel_type="related-to",
            source_id=self.stix_entity["id"],
            target_id=indicator["id"],
            description=(
                f"[VT] File {self.opencti_entity.get('observable_value', 'unknown')} "
                f"matched YARA rule '{rule_name}' "
                f"from ruleset '{yara.get('ruleset_name', 'unknown')}' "
                f"per VirusTotal crowdsourced analysis."
            ),
        )

        self._register_new_objects(indicator, relationship)

    def create_note(self, abstract: str, content: str):
        """
        Create a generic Note attached to the enriched observable.

        Retained for supplemental notes (e.g. the optional full engine
        report). For enrichment-primary notes, use create_assessment_note().

        Parameters
        ----------
        abstract : str
            Note title / abstract field.
        content : str
            Markdown-formatted note body.
        """
        self.helper.log_debug(
            f"[VirusTotal] Creating supplemental note: '{abstract}'"
        )
        note = stix2.Note(
            id=Note.generate_id(datetime.datetime.now().isoformat(), content),
            abstract=abstract,
            content=content,
            created_by_ref=self.author,
            object_refs=[self.stix_entity["id"]],
            object_marking_refs=[self.tlp_green_id],
            allow_custom=True,
        )
        self._register_new_objects(note)

    # ─────────────────────────────────────────────────────────────────────────
    # Observable mutation methods (modify the enriched entity in-place)
    # ─────────────────────────────────────────────────────────────────────────

    def update_hashes(self):
        """
        Update the hash values (MD5, SHA-1, SHA-256) on the enriched file
        entity with the canonical values returned by VT.

        VT is the authoritative source for normalised hashes. This ensures
        that if an artifact was ingested with only an MD5, SHA-256 is added.
        """
        for algo in ("MD5", "SHA-1", "SHA-256"):
            vt_key = algo.lower().replace("-", "")
            if vt_key in self.attributes:
                self.helper.log_debug(
                    f"[VirusTotal] Updating hash {algo}: {self.attributes[vt_key]}"
                )
                self.stix_entity["hashes"][algo] = self.attributes[vt_key]

    def update_names(self, main: bool = False):
        """
        Populate the observable's name and additional_names from VT's filename list.

        Parameters
        ----------
        main : bool
            If True, overwrite the primary name with the first name from VT.
            Used when the observable currently has no name (e.g. hash-only ingestion).
        """
        names = self.attributes.get("names", [])
        self.helper.log_debug(
            f"[VirusTotal] Updating names (set_main={main}): {names}"
        )

        if names and main:
            self.stix_entity["name"] = names[0]
            names = names[1:]

        if names:
            # Exclude the primary name from the additional_names list.
            if "name" in self.stix_entity:
                names = [n for n in names if n != self.stix_entity["name"]]
            for name in names:
                self.helper.api.stix2.put_attribute_in_extension(
                    self.stix_entity,
                    STIX_EXT_OCTI_SCO,
                    "additional_names",
                    name,
                    True,
                )

    def update_size(self):
        """Update the file size (bytes) on the enriched StixFile entity."""
        if "size" in self.attributes:
            self.helper.log_debug(
                f'[VirusTotal] Updating file size: {self.attributes["size"]} bytes'
            )
            self.stix_entity["size"] = self.attributes["size"]

    # ─────────────────────────────────────────────────────────────────────────
    # Bundle submission and RFI container scoping
    # ─────────────────────────────────────────────────────────────────────────

    def _scope_to_rfi_container(self):
        """
        Add all new objects created during this enrichment session to the
        originating RFI (Case-Incident) container.

        Enforces the containment principle: no entity or observable should
        exist outside a container. All VT-derived objects are scoped to the
        RFI container that was the trigger context for this enrichment.

        Called automatically by send_bundle() after bundle submission.

        TIMING NOTE: send_stix2_bundle() submits the bundle to the RabbitMQ
        queue and returns before workers process it. New objects may not exist
        in the database when this method runs. A retry loop with exponential
        backoff handles this — each object is retried up to MAX_ATTEMPTS times
        before being logged as a non-fatal warning.
        """
        import time

        # Maximum number of scoping attempts per object before giving up.
        MAX_ATTEMPTS = 5
        # Initial delay in seconds between retries. Doubles on each attempt.
        INITIAL_DELAY = 2
        if not self.rfi_container_id:
            self.helper.log_warning(
                "[VirusTotal] No RFI container ID — skipping container scoping. "
                "New objects will be uncontained."
            )
            return

        self.helper.log_debug(
            f"[VirusTotal] Scoping {len(self.new_object_ids)} new objects "
            f"to RFI container {self.rfi_container_id}"
        )

        for obj_id in self.new_object_ids:
            # Retry loop — workers may not have committed the object yet.
            # Each attempt doubles the wait time before the next retry.
            delay = INITIAL_DELAY
            scoped = False
            for attempt in range(1, MAX_ATTEMPTS + 1):
                try:
                    self.helper.api.case_incident.add_stix_object_or_stix_relationship(
                        id=self.rfi_container_id,
                        stixObjectOrStixRelationshipId=obj_id,
                    )
                    self.helper.log_debug(
                        f"[VirusTotal] Scoped {obj_id} -> RFI "
                        f"{self.rfi_container_id} (attempt {attempt})"
                    )
                    scoped = True
                    break
                except Exception as exc:
                    error_str = str(exc)
                    # internal_id undefined means the object does not exist
                    # in the database yet — wait and retry.
                    if "internal_id" in error_str and attempt < MAX_ATTEMPTS:
                        self.helper.log_debug(
                            f"[VirusTotal] Object {obj_id} not yet committed, "
                            f"retrying in {delay}s (attempt {attempt}/{MAX_ATTEMPTS})"
                        )
                        time.sleep(delay)
                        delay *= 2
                    else:
                        # Either a different error or we have exhausted retries.
                        # Non-fatal — log and continue with remaining objects.
                        self.helper.log_warning(
                            f"[VirusTotal] Failed to scope {obj_id} to RFI "
                            f"{self.rfi_container_id} after {attempt} attempt(s): {exc}"
                        )
                        break
            if not scoped:
                self.helper.log_warning(
                    f"[VirusTotal] Gave up scoping {obj_id} to RFI "
                    f"{self.rfi_container_id} after {MAX_ATTEMPTS} attempts. "
                    "Object may need to be added to the container manually."
                )

    def send_bundle(self) -> str:
        """
        Serialize and submit the STIX bundle to the OpenCTI workers,
        then scope all new objects into the originating RFI container.

        Returns
        -------
        str
            Human-readable result string.
        """
        self.helper.metric.state("idle")

        if not self.bundle:
            return "Nothing to attach."

        self.helper.log_debug(
            f"[VirusTotal] Sending bundle: {len(self.bundle)} objects, "
            f"{len(self.new_object_ids)} new."
        )
        self.helper.metric.inc("record_send", len(self.bundle))
        serialized_bundle = self.helper.stix2_create_bundle(self.bundle)
        bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)

        # Scope all new objects to the RFI container after submission.
        # See _scope_to_rfi_container() for timing caveats.
        self._scope_to_rfi_container()

        return f"Sent {len(bundles_sent)} stix bundle(s) for worker import."
