#!/usr/bin/env python3
"""
Synthient Enrichment Connector -- OpenCTI 6.9.13

Triggered manually on a Case-Rfi container. Iterates all IPv4-Addr and
IPv6-Addr observables within the RFI and enriches each one via the
Synthient IP Lookup API (https://v3api.synthient.com).

Synthient is a high-fidelity residential proxy, VPN, and anonymization
detection platform. The IP Lookup API returns network context (ASN, ISP,
org), geolocation (country, region, city), and IP reputation data
(risk score 0-100, proxy/VPN categories, behavioral flags).

Per observable, this connector writes back to OpenCTI:
  - Note       : ip_risk score, categories, behaviors, enriched providers
  - Score      : observable x_opencti_score set to ip_risk value (0-100)
  - ASN entity : AutonomousSystem SCO + IPv4 -> Belongs-to -> ASN
  - Org entity : Organization Identity + ASN -> Related-to -> Organization
  - Country    : IPv4 -> located-at -> Country (lookup by full name)

All created objects and relationships are added to the triggering RFI
container so they are scoped correctly and visible in context.

Data model relationships (all guide-confirmed):
  IPv4-Addr  -> belongs-to  -> Autonomous System
  ASN        -> related-to  -> Organization
  IPv4-Addr  -> located-at  -> Country

Known limitations:
  - IP observables only (Synthient API is IP-centric).
  - Country lookup uses pycountry name resolution. Some territories
    (e.g. HK, ES) may not resolve if OpenCTI stores them under a
    non-standard name variant. These are skipped with a WARNING log.
  - Organization entities are created from raw Synthient ISP/org strings.
    Minor name variations across runs may create near-duplicate org
    entities (e.g. "DigitalOcean, LLC" vs "DigitalOcean"). This is
    accepted as low-impact informational scaffolding.
"""

import os
import sys
import time
import traceback

import pycountry           # ISO country code -> full name resolution
import requests            # HTTP client for Synthient API calls
import stix2               # STIX 2.1 object construction
from pycti import (
    OpenCTIConnectorHelper,
    StixCoreRelationship,  # Deterministic STIX relationship ID generation
)

# ── API configuration ────────────────────────────────────────────────────────

LOOKUP_BASE = "https://v3api.synthient.com"   # Synthient v3 API base URL
AUTHOR_NAME = "Synthient"                      # Display name for the author identity

# ── Retry / backoff configuration ────────────────────────────────────────────
# Used for Synthient API calls. Exponential backoff handles rate limiting
# (HTTP 429) and quota errors (HTTP 402).

BACKOFF_INITIAL  = 5    # Seconds before first retry
BACKOFF_MAX      = 120  # Maximum backoff ceiling in seconds
BACKOFF_FACTOR   = 2    # Multiplier applied to delay on each retry
BACKOFF_RETRIES  = 5    # Maximum number of retry attempts per IP

# ── Worker resolution configuration ──────────────────────────────────────────
# OpenCTI's STIX bundle processing is asynchronous. After sending a bundle,
# we poll for the resulting internal IDs before attempting to use them
# (e.g. to add them to the RFI container).

RESOLVE_RETRIES = 6   # Maximum poll attempts when waiting for worker to process
RESOLVE_DELAY   = 3   # Seconds between poll attempts


class SynthientEnrichConnector:
    """
    Main connector class. Implements the OpenCTI INTERNAL_ENRICHMENT connector
    pattern: registers with the platform, listens on a RabbitMQ queue, and
    processes enrichment messages when triggered by an analyst on a Case-Rfi.
    """

    def __init__(self):
        """
        Initialise the connector by reading all configuration from environment
        variables and constructing the OpenCTIConnectorHelper.

        Required environment variables:
          OPENCTI_URL          OpenCTI instance base URL
          OPENCTI_TOKEN        API token for the connector service account
          CONNECTOR_ID         Unique UUID for this connector instance
          SYNTHIENT_API_KEY    Synthient v3 API key

        Optional environment variables (with defaults):
          CONNECTOR_NAME       Display name  (default: "Synthient Enrichment")
          CONNECTOR_LOG_LEVEL  Log verbosity (default: "info")
          SYNTHIENT_DAYS       Lookback window in days for Synthient data (default: 90)
          SYNTHIENT_TLP        TLP marking to apply to all created objects (default: TLP:AMBER+STRICT)
          SYNTHIENT_CONFIDENCE Confidence score 0-100 for created objects (default: 90)

        The author_id / tlp_id fields are resolved lazily at start() time
        because the OpenCTI API is not available during __init__.
        """
        config = {
            "opencti": {
                "url": os.environ["OPENCTI_URL"],
                "token": os.environ["OPENCTI_TOKEN"],
            },
            "connector": {
                "id": os.environ["CONNECTOR_ID"],
                "type": "INTERNAL_ENRICHMENT",
                "name": os.environ.get("CONNECTOR_NAME", "Synthient Enrichment"),
                "scope": "Case-Rfi",   # Only triggers on Case-Rfi entities
                "log_level": os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
                "auto": False,         # Manual trigger only -- never auto-enrich
            },
        }
        self.helper = OpenCTIConnectorHelper(config)
        self.api_key    = os.environ["SYNTHIENT_API_KEY"]
        self.days       = int(os.environ.get("SYNTHIENT_DAYS", "90"))
        self.tlp_string = os.environ.get("SYNTHIENT_TLP", "TLP:AMBER+STRICT")
        self.confidence = int(os.environ.get("SYNTHIENT_CONFIDENCE", "90"))

        # Resolved at start() time once the API is reachable
        self.author_id      = None   # OpenCTI internal UUID for the Synthient author org
        self.author_stix_id = None   # STIX ID for the Synthient author org
        self.tlp_id         = None   # OpenCTI internal UUID for the configured TLP marking
        self.tlp_stix_id    = None   # STIX ID for the configured TLP marking

    # ── Identity and marking resolution ──────────────────────────────────────

    def _resolve_author(self):
        """
        Ensure the Synthient author Organization identity exists in OpenCTI
        and return its internal UUID and STIX ID.

        Uses identity.create() which is idempotent -- if the entity already
        exists it returns the existing record. Both IDs are needed because:
          - internal UUID (id) is required by direct API calls (note.create, etc.)
          - STIX ID (standard_id) is required inside STIX bundle objects

        Returns:
            tuple: (internal_uuid: str, stix_id: str)
        """
        obj = self.helper.api.identity.create(
            type="Organization",
            name=AUTHOR_NAME,
            description=(
                "Synthient IP Intelligence Platform -- high-fidelity residential proxy, "
                "VPN, and anonymization detection. https://synthient.com"
            ),
        )
        return obj["id"], obj["standard_id"]

    def _resolve_tlp(self):
        """
        Look up the configured TLP marking definition and return its internal
        UUID and STIX ID.

        TLP markings are pre-populated by OpenCTI at startup. This connector
        does not create them -- it only reads the configured one. Raises
        ValueError if the marking is not found, which prevents the connector
        from starting with an invalid TLP configuration.

        Returns:
            tuple: (internal_uuid: str, stix_id: str)

        Raises:
            ValueError: If the configured TLP string does not match any
                        marking definition in the platform.
        """
        marking = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [self.tlp_string.upper()]}],
                "filterGroups": [],
            }
        )
        if not marking:
            raise ValueError(f"TLP marking '{self.tlp_string}' not found.")
        return marking["id"], marking["standard_id"]

    # ── Synthient API client ──────────────────────────────────────────────────

    def _lookup_ip(self, ip):
        """
        Call the Synthient IP Lookup API for a single IP address and return
        the parsed JSON response.

        Endpoint: GET /api/v3/lookup/ip/{ip}?days={N}
        Auth:     Authorization header with the API key (no Bearer prefix)

        Implements exponential backoff for rate limiting (HTTP 429) and quota
        errors (HTTP 402). Other non-200 responses are logged and return None.

        Args:
            ip (str): IPv4 or IPv6 address to look up.

        Returns:
            dict: Parsed API response, or None if the lookup failed or should
                  be skipped (400 Bad Request, exhausted retries, network error).

        Response structure (relevant fields):
            ip_data.ip_risk    int        Risk score 0-100
            ip_data.categories list[str]  Proxy/VPN category labels
            ip_data.behavior   list[str]  Behavioral flag labels
            ip_data.enriched   list[dict] Third-party provider enrichment hits
            ip_data.devices    list[dict] Device fingerprints seen from this IP
            network.asn        int        Autonomous system number
            network.isp        str        ISP name
            network.org        str        Organization name (may be None)
            network.type       str        Network type (DATACENTER, RESIDENTIAL, etc.)
            location.country   str        ISO alpha-2 country code
            location.state     str        Region/state code
            location.city      str        City name
        """
        url = f"{LOOKUP_BASE}/api/v3/lookup/ip/{ip}"
        headers = {"Authorization": self.api_key}
        params = {"days": self.days}
        delay = BACKOFF_INITIAL

        for attempt in range(1, BACKOFF_RETRIES + 1):
            try:
                resp = requests.get(url, headers=headers, params=params, timeout=30)

                if resp.status_code == 200:
                    return resp.json()

                if resp.status_code in (429, 402):
                    # Rate limited or quota exceeded -- back off and retry
                    self.helper.log_warning(
                        f"Rate limit (HTTP {resp.status_code}) for {ip}. "
                        f"Retry in {delay}s ({attempt}/{BACKOFF_RETRIES})"
                    )
                    time.sleep(delay)
                    delay = min(delay * BACKOFF_FACTOR, BACKOFF_MAX)
                    continue

                if resp.status_code == 400:
                    # Invalid IP format or unsupported address -- skip silently
                    self.helper.log_warning(f"Bad request for {ip} -- skipping.")
                    return None

                # Unexpected error -- log and abort
                self.helper.log_error(f"HTTP {resp.status_code} for {ip}: {resp.text[:200]}")
                return None

            except requests.RequestException as e:
                # Network-level error (timeout, DNS failure, etc.)
                self.helper.log_warning(f"Request error for {ip}: {e} ({attempt}/{BACKOFF_RETRIES})")
                time.sleep(delay)
                delay = min(delay * BACKOFF_FACTOR, BACKOFF_MAX)

        self.helper.log_error(f"All retries exhausted for {ip}.")
        return None

    # ── OpenCTI object resolution helpers ────────────────────────────────────

    def _resolve_observable_id(self, stix_id):
        """
        Poll OpenCTI until the STIX Cyber Observable with the given STIX ID
        has been processed by the worker and its internal UUID is available.

        AutonomousSystem objects are sent via STIX bundle and processed
        asynchronously. Before we can add the ASN to the RFI container or
        create a relationship from it, we need its internal UUID which is
        only available after the worker has committed it.

        Args:
            stix_id (str): STIX ID of the AutonomousSystem (or other SCO)
                           as generated by stix2.AutonomousSystem.

        Returns:
            str: Internal OpenCTI UUID if resolved, or None if all retries
                 were exhausted.
        """
        for _ in range(RESOLVE_RETRIES):
            try:
                obj = self.helper.api.stix_cyber_observable.read(id=stix_id)
                if obj:
                    return obj["id"]
            except Exception:
                pass
            time.sleep(RESOLVE_DELAY)
        return None

    def _resolve_rel_id(self, stix_id):
        """
        Poll OpenCTI until the STIX Core Relationship with the given STIX ID
        has been processed by the worker and its internal UUID is available.

        Relationships sent via STIX bundle are also processed asynchronously.
        Their internal UUIDs are required to add them to the RFI container.

        Args:
            stix_id (str): STIX ID of the relationship as generated by
                           StixCoreRelationship.generate_id().

        Returns:
            str: Internal OpenCTI UUID if resolved, or None if all retries
                 were exhausted.
        """
        for _ in range(RESOLVE_RETRIES):
            try:
                obj = self.helper.api.stix_core_relationship.read(id=stix_id)
                if obj:
                    return obj["id"]
            except Exception:
                pass
            time.sleep(RESOLVE_DELAY)
        return None

    # ── Note content builder ──────────────────────────────────────────────────

    def _build_note_content(self, ip, data):
        """
        Format the Synthient API response as a human-readable Note body.

        The Note is the primary analytical output of this connector -- it
        surfaces all relevant Synthient data in a structured, readable format
        so analysts can assess the IP without leaving OpenCTI.

        Args:
            ip   (str):  The IP address being documented.
            data (dict): Parsed Synthient API response for this IP.

        Returns:
            str: Formatted multi-line Note content string.

        Note sections:
          - Risk Score, Categories, Behaviors: headline threat context
          - Network block: ASN, ISP, Org, type, connection type
          - Location block: country code, region, city, timezone
          - Enriched Providers: third-party feeds that flagged this IP
          - Devices: fingerprinted device OS/versions seen from this IP
          - Lookback window: the configured days parameter for context
        """
        ip_data  = data.get("ip_data", {})
        network  = data.get("network", {}) or {}
        location = data.get("location", {}) or {}

        ip_risk    = ip_data.get("ip_risk", "N/A")
        categories = ", ".join(ip_data.get("categories", [])) or "None"
        behaviors  = ", ".join(ip_data.get("behavior", [])) or "None"

        enriched_lines = [
            f"  - {e.get('provider','?')}: {e.get('type','')} "
            f"(last seen: {e.get('last_seen','')})"
            for e in ip_data.get("enriched", [])
        ]
        enriched_block = "\n".join(enriched_lines) or "  None"

        device_count = ip_data.get("device_count", 0)
        device_lines = [
            f"  - {d.get('os','?')} {d.get('version','')}"
            for d in ip_data.get("devices", [])
        ]
        device_block = "\n".join(device_lines) or "  None reported"

        return (
            f"Synthient IP Intelligence -- {ip}\n\n"
            f"Risk Score: {ip_risk}/100\n"
            f"Categories: {categories}\n"
            f"Behaviors: {behaviors}\n\n"
            f"Network:\n"
            f"  ASN: AS{network.get('asn', 'N/A')}\n"
            f"  ISP: {network.get('isp', 'N/A')}\n"
            f"  Org: {network.get('org') or 'N/A'}\n"
            f"  Type: {network.get('type', 'N/A')}\n"
            f"  Connection: {network.get('connection_type') or 'N/A'}\n\n"
            f"Location:\n"
            f"  Country: {location.get('country', 'N/A')}\n"
            f"  Region: {location.get('state', '') or ''}\n"
            f"  City: {location.get('city', '') or ''}\n"
            f"  Timezone: {location.get('timezone', '') or ''}\n\n"
            f"Enriched Providers:\n{enriched_block}\n\n"
            f"Devices ({device_count} unique):\n{device_block}\n\n"
            f"Lookback window: {self.days} days"
        )

    # ── Per-observable enrichment logic ───────────────────────────────────────

    def _enrich_observable(self, observable_id, observable_value, observable_stix_id, data, container_refs):
        """
        Execute the full enrichment workflow for a single IP observable.

        This method is the core of the connector. For each IP it:
          1. Updates the observable's risk score
          2. Creates a Note with all Synthient intelligence
          3. Creates an AutonomousSystem entity and belongs-to relationship
          4. Creates an Organization entity and related-to relationship
          5. Looks up and links the country via a located-at relationship

        All created object and relationship internal UUIDs are appended to
        container_refs so the caller can bulk-add them to the RFI container.

        Args:
            observable_id      (str):  OpenCTI internal UUID of the IP observable.
            observable_value   (str):  The IP address string (e.g. "1.2.3.4").
            observable_stix_id (str):  STIX ID of the IP observable -- used as
                                       source_ref in STIX relationships.
            data               (dict): Parsed Synthient API response for this IP.
            container_refs     (list): Mutable list; internal UUIDs of all objects
                                       and relationships created here are appended
                                       to this list for later container addition.

        Implementation notes:
          - Score update and Note use direct pycti API calls (synchronous).
          - ASN, ASN->Org relationship, and Country relationship use STIX bundles
            (asynchronous) because AutonomousSystem is an SCO that must go
            through the worker pipeline, not the direct API.
          - After each bundle send, we poll for the internal IDs using
            _resolve_observable_id() and _resolve_rel_id() before proceeding.
          - Organization is created via direct API (identity.create is idempotent)
            but its relationship to the ASN goes through a bundle.
          - Country objects are never created -- only looked up by name.
            If no matching Country entity is found, located-at is skipped.
          - All exceptions are caught per-step so a failure in one step
            (e.g. country lookup) does not abort the remaining steps.
        """
        ip_data      = data.get("ip_data", {})
        network      = data.get("network", {}) or {}
        location     = data.get("location", {}) or {}

        ip_risk      = ip_data.get("ip_risk", 0)
        asn_number   = network.get("asn", 0)
        isp_name     = network.get("isp", "") or ""
        org_name     = network.get("org") or isp_name    # Fall back to ISP if org is null
        country_code = location.get("country", "")

        # ── Step 1: Update observable risk score ─────────────────────────────
        # Sets x_opencti_score on the IP observable to the Synthient ip_risk
        # value (0-100). This makes the score visible in the observable tile
        # and queryable via filters.
        try:
            self.helper.api.stix_cyber_observable.update_field(
                id=observable_id,
                input={"key": "x_opencti_score", "value": str(ip_risk)},
            )
        except Exception as e:
            self.helper.log_warning(f"Score update failed for {observable_value}: {e}")

        # ── Step 2: Create analysis Note ─────────────────────────────────────
        # The Note is linked to the observable and carries all Synthient
        # intelligence in human-readable format.
        try:
            note = self.helper.api.note.create(
                attribute_abstract=f"Synthient Enrichment -- {observable_value}",
                content=self._build_note_content(observable_value, data),
                note_types=["analysis"],
                confidence=self.confidence,
                createdBy=self.author_id,
                objectMarking=[self.tlp_id],
            )
            # Link Note to the observable it documents
            self.helper.api.note.add_stix_object_or_stix_relationship(
                id=note["id"],
                stixObjectOrStixRelationshipId=observable_id,
            )
            container_refs.append(note["id"])
        except Exception as e:
            self.helper.log_warning(f"Note failed for {observable_value}: {e}")

        # ── Step 3: AutonomousSystem + IPv4 -> belongs-to -> ASN ─────────────
        # AutonomousSystem is a STIX Cyber Observable (SCO). In OpenCTI 6.9.x,
        # SCOs cannot be created via direct API -- they must go through the
        # STIX bundle pipeline. The ASN's STIX ID is deterministic (derived
        # from its number field), so the same ASN seen across multiple enrichment
        # runs will always produce the same STIX ID and merge in the graph.
        asn_stix_obj   = None   # Kept in scope for Step 4
        asn_internal_id = None  # Kept in scope for Step 4

        if asn_number and asn_number != 0:
            asn_name = f"AS{asn_number}"
            try:
                asn_stix_obj = stix2.AutonomousSystem(
                    number=asn_number,
                    name=asn_name,
                    object_marking_refs=[self.tlp_stix_id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author_stix_id,
                        "x_opencti_score": 0,
                    },
                )
                # belongs-to relationship: IPv4 -> ASN
                # Deterministic ID ensures deduplication across enrichment runs
                rel_asn = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "belongs-to", observable_stix_id, asn_stix_obj.id
                    ),
                    relationship_type="belongs-to",
                    source_ref=observable_stix_id,
                    target_ref=asn_stix_obj.id,
                    description=(
                        f"{observable_value} belongs to {asn_name} "
                        f"({isp_name}) per Synthient enrichment."
                    ),
                    created_by_ref=self.author_stix_id,
                    object_marking_refs=[self.tlp_stix_id],
                    custom_properties={"x_opencti_confidence_level": self.confidence},
                )
                bundle = stix2.Bundle(objects=[asn_stix_obj, rel_asn], allow_custom=True)
                self.helper.send_stix2_bundle(bundle.serialize())

                # Poll for internal IDs -- worker processes the bundle asynchronously.
                # We need the ASN's internal ID for container membership (Step 5)
                # and to anchor the org relationship (Step 4).
                asn_internal_id = self._resolve_observable_id(asn_stix_obj.id)
                if asn_internal_id:
                    container_refs.append(asn_internal_id)
                else:
                    self.helper.log_warning(
                        f"Could not resolve ASN {asn_name} internal ID -- "
                        f"skipping org relationship for {observable_value}"
                    )

                rel_asn_internal = self._resolve_rel_id(rel_asn.id)
                if rel_asn_internal:
                    container_refs.append(rel_asn_internal)

                self.helper.log_debug(f"ASN {asn_name} bundle sent for {observable_value}")
            except Exception as e:
                self.helper.log_warning(f"ASN bundle failed for {observable_value}: {e}")

        # ── Step 4: Organization + ASN -> related-to -> Organization ─────────
        # Organization is an SDO (Identity) -- can be created via direct API.
        # identity.create() is idempotent by name so repeated enrichment runs
        # do not produce duplicate org entities for the same name string.
        # The relationship (ASN -> Organization) still goes through a bundle
        # because the source is an SCO (AutonomousSystem).
        #
        # Only proceeds if Step 3 successfully resolved the ASN internal ID.
        if asn_stix_obj and asn_internal_id and org_name:
            try:
                org_obj = self.helper.api.identity.create(
                    type="Organization",
                    name=org_name,
                    description=f"Network operator / ISP identified by Synthient for AS{asn_number}.",
                    createdBy=self.author_id,
                    objectMarking=[self.tlp_id],
                )
                # related-to relationship: ASN -> Organization
                rel_org = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", asn_stix_obj.id, org_obj["standard_id"]
                    ),
                    relationship_type="related-to",
                    source_ref=asn_stix_obj.id,
                    target_ref=org_obj["standard_id"],
                    description=(
                        f"AS{asn_number} operated by {org_name} per Synthient enrichment."
                    ),
                    created_by_ref=self.author_stix_id,
                    object_marking_refs=[self.tlp_stix_id],
                    custom_properties={"x_opencti_confidence_level": self.confidence},
                )
                bundle = stix2.Bundle(objects=[rel_org], allow_custom=True)
                self.helper.send_stix2_bundle(bundle.serialize())

                rel_org_internal = self._resolve_rel_id(rel_org.id)
                if rel_org_internal:
                    container_refs.append(rel_org_internal)
                container_refs.append(org_obj["id"])
                self.helper.log_debug(f"Org '{org_name}' related to AS{asn_number}")
            except Exception as e:
                self.helper.log_warning(f"Org relationship failed for AS{asn_number}: {e}")

        # ── Step 5: Country lookup + IPv4 -> located-at -> Country ───────────
        # Country entities are pre-populated by OpenCTI and are never created
        # by this connector. We look them up by full name using pycountry to
        # convert the ISO alpha-2 code from Synthient into the name variants
        # OpenCTI uses.
        #
        # Name resolution strategy:
        #   1. pycountry primary name (e.g. "United States")
        #   2. pycountry common_name if different (e.g. "Bolivia")
        #   3. pycountry official_name if different (e.g. "Republic of Korea")
        #
        # The location.read() filter uses name only (no entity_type filter).
        # The entity_type filter is not supported in OpenCTI 6.9.13 for
        # location queries and causes UNSUPPORTED_ERROR. Client-side validation
        # against entity_type == "Country" prevents accidentally linking to a
        # Region that shares the same name.
        #
        # Known gap: Some territories (HK -> "Hong Kong", ES -> "Spain") exist
        # in OpenCTI as Region objects rather than Country objects. These are
        # skipped with a WARNING. No located-at relationship is created.
        if country_code:
            try:
                country_name = None
                pc = pycountry.countries.get(alpha_2=country_code)
                if pc:
                    country_name = pc.name

                country_obj = None
                if country_name:
                    # Build ordered list of name variants to attempt
                    name_variants = [country_name]
                    if pc and hasattr(pc, "common_name") and pc.common_name != country_name:
                        name_variants.append(pc.common_name)
                    if pc and hasattr(pc, "official_name") and pc.official_name not in name_variants:
                        name_variants.append(pc.official_name)

                    for name_try in name_variants:
                        result = self.helper.api.location.read(
                            filters={
                                "mode": "and",
                                "filters": [
                                    {"key": "name", "values": [name_try]},
                                ],
                                "filterGroups": [],
                            }
                        )
                        # Only accept Country entities -- reject Regions that
                        # share the same name to avoid incorrect located-at links.
                        if result and result.get("entity_type") == "Country":
                            country_obj = result
                            country_name = name_try
                            break

                if country_obj:
                    # located-at relationship: IPv4 -> Country
                    rel_country = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "located-at", observable_stix_id, country_obj["standard_id"]
                        ),
                        relationship_type="located-at",
                        source_ref=observable_stix_id,
                        target_ref=country_obj["standard_id"],
                        description=(
                            f"{observable_value} geolocated to "
                            f"{country_name} ({country_code}) per Synthient enrichment."
                        ),
                        created_by_ref=self.author_stix_id,
                        object_marking_refs=[self.tlp_stix_id],
                        custom_properties={"x_opencti_confidence_level": self.confidence},
                    )
                    bundle = stix2.Bundle(objects=[rel_country], allow_custom=True)
                    self.helper.send_stix2_bundle(bundle.serialize())

                    rel_country_internal = self._resolve_rel_id(rel_country.id)
                    if rel_country_internal:
                        container_refs.append(rel_country_internal)
                    container_refs.append(country_obj["id"])
                    self.helper.log_debug(f"located-at {country_name} for {observable_value}")
                else:
                    self.helper.log_warning(
                        f"Country not found for '{country_code}' "
                        f"(resolved: {country_name}) -- skipping located-at "
                        f"for {observable_value}"
                    )
            except Exception as e:
                self.helper.log_warning(f"Country relationship failed for {observable_value}: {e}")

    # ── RFI observable retrieval ──────────────────────────────────────────────

    def _get_rfi_observables(self, rfi_id):
        """
        Retrieve all IPv4-Addr and IPv6-Addr observables from the given
        Case-Rfi container.

        OpenCTI 6.9.13 does not support filtering by entity_type on the
        objects list returned by case_rfi.read(). We retrieve the full
        object list and filter client-side.

        Args:
            rfi_id (str): OpenCTI internal UUID of the Case-Rfi.

        Returns:
            list[dict]: Filtered list of observable objects from the RFI,
                        each containing at minimum 'id', 'entity_type',
                        'value', and 'standard_id' fields.
                        Returns an empty list on failure.
        """
        ip_types = {"IPv4-Addr", "IPv6-Addr"}
        observables = []
        try:
            rfi = self.helper.api.case_rfi.read(id=rfi_id)
            if not rfi:
                self.helper.log_warning(f"RFI {rfi_id} not found.")
                return observables
            for obj in rfi.get("objects", []):
                if obj.get("entity_type", "") in ip_types:
                    observables.append(obj)
        except Exception as e:
            self.helper.log_error(f"Failed to retrieve observables from RFI: {e}")
        return observables

    # ── Main RFI processing ───────────────────────────────────────────────────

    def _process_rfi(self, entity_id):
        """
        Orchestrate enrichment for all IP observables in the given Case-Rfi.

        Workflow:
          1. Retrieve all IPv4/IPv6 observables from the RFI.
          2. For each observable, call _lookup_ip() then _enrich_observable().
          3. Collect all created object/relationship internal UUIDs.
          4. Bulk-add all collected UUIDs to the RFI container so enrichment
             output is scoped to the triggering case.

        Args:
            entity_id (str): OpenCTI internal UUID of the triggering Case-Rfi.

        Returns:
            str: Human-readable summary of enrichment results, used as the
                 work completion message in OpenCTI.
        """
        self.helper.log_info(f"Enrichment triggered on RFI: {entity_id}")

        observables = self._get_rfi_observables(entity_id)
        if not observables:
            msg = f"No IPv4/IPv6 observables found in RFI {entity_id}."
            self.helper.log_info(msg)
            return msg

        self.helper.log_info(f"Found {len(observables)} IP observable(s) -- starting enrichment")

        enriched_count = skipped_count = failed_count = 0
        all_container_refs = []  # Accumulates all internal UUIDs to add to the RFI

        for obs in observables:
            obs_id      = obs["id"]
            obs_stix_id = obs.get("standard_id") or obs.get("stixIds", [None])[0]
            obs_value   = obs.get("value") or obs.get("observable_value", "")

            if not obs_value:
                self.helper.log_warning(f"Observable {obs_id} has no value -- skipping")
                skipped_count += 1
                continue

            self.helper.log_info(f"Enriching: {obs_value}")
            data = self._lookup_ip(obs_value)

            if data is None:
                self.helper.log_warning(f"No data returned for {obs_value} -- skipping")
                failed_count += 1
                continue

            try:
                obs_refs = []  # Refs collected for this single observable
                self._enrich_observable(obs_id, obs_value, obs_stix_id, data, obs_refs)
                all_container_refs.extend(obs_refs)
                enriched_count += 1
                self.helper.log_info(
                    f"Enriched {obs_value} -- "
                    f"ip_risk={data.get('ip_data', {}).get('ip_risk', 'N/A')}"
                )
            except Exception:
                self.helper.log_error(
                    f"Enrichment failed for {obs_value}:\n{traceback.format_exc()}"
                )
                failed_count += 1

        # ── Add all created objects/relationships to the RFI container ────────
        # This is done in bulk after all enrichment is complete to minimize
        # sequential API round-trips during the enrichment loop. Duplicate
        # add attempts (e.g. same Country added by multiple IPs) are silently
        # handled by the OpenCTI API.
        added_count = 0
        for ref_id in all_container_refs:
            try:
                self.helper.api.case_rfi.add_stix_object_or_stix_relationship(
                    id=entity_id,
                    stixObjectOrStixRelationshipId=ref_id,
                )
                added_count += 1
            except Exception as e:
                self.helper.log_warning(f"Failed to add {ref_id} to RFI: {e}")

        self.helper.log_info(
            f"Added {added_count}/{len(all_container_refs)} objects to RFI container"
        )

        summary = (
            f"Synthient enrichment complete -- "
            f"enriched: {enriched_count} | skipped: {skipped_count} | "
            f"failed: {failed_count} | total: {len(observables)}"
        )
        self.helper.log_info(summary)
        return summary

    # ── Message handler ───────────────────────────────────────────────────────

    def _process_message(self, data):
        """
        OpenCTI enrichment message handler. Called by the helper's listen()
        loop each time an enrichment is triggered on a Case-Rfi.

        Extracts the entity_id from the message payload and delegates to
        _process_rfi(). The return value is used by the helper to report
        work completion status back to OpenCTI.

        Args:
            data (dict): Enrichment message payload from RabbitMQ.
                         Expected keys: entity_id (str).

        Returns:
            str: Completion summary from _process_rfi().

        Raises:
            ValueError: If entity_id is missing from the message payload.
        """
        entity_id = data.get("entity_id")
        if not entity_id:
            raise ValueError("No entity_id in enrichment message.")
        return self._process_rfi(entity_id)

    # ── Connector entrypoint ──────────────────────────────────────────────────

    def start(self):
        """
        Start the connector. Resolves the author identity and TLP marking
        at startup (both are idempotent and safe to call on every restart),
        then enters the blocking listen() loop to process enrichment messages.

        The listen() loop blocks indefinitely, processing one RFI per message.
        The connector is terminated by stopping the Docker container.
        """
        self.helper.log_info("Synthient Enrichment connector initialising...")
        self.author_id, self.author_stix_id = self._resolve_author()
        self.tlp_id, self.tlp_stix_id = self._resolve_tlp()
        self.helper.log_info(f"Author '{AUTHOR_NAME}' resolved: internal={self.author_id}")
        self.helper.log_info(f"TLP '{self.tlp_string}' resolved: internal={self.tlp_id}")
        self.helper.log_info(f"Lookback window: {self.days} days")
        self.helper.listen(self._process_message)


# ── Module entrypoint ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        SynthientEnrichConnector().start()
    except Exception:
        # Last-resort fallback: print full traceback to stdout before exit.
        # The helper logger may not be available if __init__ failed, so we
        # use print() here to ensure the error is captured in Docker logs.
        print(traceback.format_exc(), flush=True)
        sys.exit(1)
