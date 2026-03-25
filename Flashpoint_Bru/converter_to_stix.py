# =============================================================================
# flashpoint_connector/converter_to_stix.py
# =============================================================================
# STIX 2.1 object construction for all Flashpoint Ignite datasets.
#
# RESPONSIBILITIES:
#   - Convert Flashpoint API response dicts into lists of STIX 2.1 objects
#     ready for bundle creation and ingestion into OpenCTI
#   - Enforce all data model constraints at the conversion layer
#   - Ensure no Observable is ever orphaned (minimum floor relationship)
#   - Ensure no Relationship is ever created without a description
#   - Ensure no Indicator is created except for YARA and Sigma patterns
#
# HARD CONSTRAINTS (enforced in code, not just convention):
#   1. create_relation() raises ValueError if description is empty.
#      There is no way to call it without providing a description.
#   2. INDICATOR_PERMITTED_PATTERN_TYPES controls which patterns become
#      Indicators. All other patterns produce Observables only.
#   3. Every Observable that has no resolvable entity relationship is linked
#      to the Flashpoint author identity via _floor_relation(). The floor
#      relationship is the minimum required by the data model.
#   4. All containers use report_types=["activity-roundup"] universally.
#      There is no per-dataset Report type variation.
#
# DEFAULT TLP: TLP:AMBER+STRICT for all objects from all datasets.
# Dark web community content and credential data are not public; applying
# a lower marking by default would be a data governance error.
#
# DEVIATION FROM FILIGRAN:
#   - No fake intrusion-set placeholder ID in object_refs (see build_daily_report)
#   - report["body"] passed as string, not bytes (bytes breaks OpenCTI rendering)
#   - Empty relationship descriptions raise ValueError rather than silently
#     creating semantically useless edges
#   - TLP:GREEN default on communities replaced with TLP:AMBER+STRICT
#   - MediaContent observable replaced with Text observable
#   - Persona implemented (was a commented-out TODO in Filigran)
#   - alert_to_incident() replaced with bifurcated alert_to_report_objects()
#     and credential_alert_to_incident_objects()
#   - Grouping container type never created (MISP feed is dropped)
# =============================================================================

import base64 as _b64
import mimetypes
from datetime import datetime, timezone
from typing import Optional

import stix2
from dateparser import parse
from pycti import (
    AttackPattern,
    Channel,
    CustomObjectChannel,
    Identity,
    Incident,
    IntrusionSet,
    Location,
    Malware,
    MarkingDefinition,
    Report,
    StixCoreRelationship,
    ThreatActorGroup,
    ThreatActorIndividual,
    Tool,
)

# =============================================================================
# Module-level constants
# =============================================================================

# HARD CONSTRAINT: only these STIX pattern types are permitted to produce
# stix2.Indicator objects. All other types (ip, domain, hash, url, etc.)
# must be created as Observables only.
#
# RATIONALE: The OpenCTI data model prohibits manually created Indicators
# because they have no link to their source Observable, corrupt the detection
# pipeline, and cannot be automatically managed or expired. YARA and Sigma
# are the sole exceptions because they are complete detection rules in their
# own right — not raw indicators derived from observations.
INDICATOR_PERMITTED_PATTERN_TYPES = frozenset({"yara", "sigma"})

# Flashpoint injects these HTML-like tags into community post content and
# channel names to highlight matched search terms. They must be stripped
# before use in any OpenCTI field to avoid polluting entity names and
# observable values with markup.
_FP_HIGHLIGHT_OPEN = "<x-fp-highlight>"
_FP_HIGHLIGHT_CLOSE = "</x-fp-highlight>"


def _strip_highlight(s: str) -> str:
    """Remove Flashpoint search-highlight markup from a string."""
    return s.replace(_FP_HIGHLIGHT_OPEN, "").replace(_FP_HIGHLIGHT_CLOSE, "")


# =============================================================================
# ConverterToStix
# =============================================================================


class ConverterToStix:
    """
    Converts Flashpoint Ignite API response objects into lists of STIX 2.1
    objects ready for bundle creation.

    Each public convert_* method takes a raw API response dict and returns
    a list of STIX objects. The connector dispatcher is responsible for
    creating bundles and sending them — the converter does not call the API
    or interact with OpenCTI directly, except for:
      - Author identity resolution at __init__ (one API call)
      - _ensure_activity_roundup_vocabulary() at __init__ (one API call)
      - _guess_knowledge_graph() (N API calls per report — searches existing graph)

    THREAD SAFETY: This class is not thread-safe. It is instantiated once
    per connector run and used synchronously.
    """

    def __init__(self, helper, config):
        """
        Initialise the converter.

        Resolves the Flashpoint author identity (creating it if absent),
        constructs the TLP:AMBER+STRICT marking definition object, and
        registers the activity-roundup vocabulary entry.

        These three operations happen once at startup, not on every conversion.
        The author_id and marking objects are cached as instance attributes
        and reused for the connector's lifetime.

        :param helper: OpenCTIConnectorHelper for API access and logging
        :param config: ConfigConnector for confidence defaults
        """
        self.helper = helper
        self.config = config

        # Resolve and cache the Flashpoint author identity.
        # This is the standard_id of the "Flashpoint" Organization object in
        # OpenCTI. It is used as created_by_ref on all objects this connector
        # creates. Using a cached ID avoids repeated API lookups per object.
        self.author_id = self._resolve_author()

        # Build and cache the TLP:AMBER+STRICT marking definition.
        # This object is included in every bundle as a member and referenced
        # by ID in object_marking_refs on every object. It must be in the
        # bundle because OpenCTI's worker validates that all referenced
        # marking definitions are present in the bundle.
        self.marking = self._build_amber_strict()

        # Register activity-roundup in the report_types_ov vocabulary.
        # Must happen before any Report is created, otherwise the worker
        # may reject or coerce the custom report type.
        self._ensure_activity_roundup_vocabulary()

    # =========================================================================
    # Initialisation helpers
    # =========================================================================

    def _resolve_author(self) -> str:
        """
        Look up the "Flashpoint" Organization identity in OpenCTI, creating
        it if absent, and return its standard_id.

        Uses helper.api.identity.create() which is an upsert operation —
        if the identity already exists, the existing record is returned
        without creating a duplicate. This is safe to call on every startup.

        The returned standard_id is a deterministic STIX ID of the form
        identity--{uuid}. It is used as created_by_ref on all STIX objects
        this connector produces, establishing Flashpoint as the source
        organization for all ingested intelligence.

        :return: standard_id string of the Flashpoint Organization identity
        """
        identity = self.helper.api.identity.create(
            type="Organization",
            name="Flashpoint",
            description=(
                "Flashpoint is a data and intelligence company providing "
                "Business Risk Intelligence across cybercrime, fraud, "
                "physical security, and national security domains."
            ),
        )
        return identity["standard_id"]

    def _build_amber_strict(self) -> stix2.MarkingDefinition:
        """
        Construct the TLP:AMBER+STRICT marking definition STIX object.

        TLP:AMBER+STRICT is not a standard stix2 library constant (unlike
        TLP_GREEN, TLP_AMBER, etc.) and must be constructed manually as a
        custom MarkingDefinition using OpenCTI's custom properties.

        The ID is generated deterministically from ("TLP", "TLP:AMBER+STRICT")
        via MarkingDefinition.generate_id() — this produces the same ID
        every time, which is essential for deduplication. If two connectors
        both include this object in their bundles, OpenCTI's worker will
        upsert rather than duplicate.

        This object is:
          1. Included in every bundle (so the worker can resolve the reference)
          2. Referenced in object_marking_refs on every STIX object produced

        :return: stix2.MarkingDefinition for TLP:AMBER+STRICT
        """
        return stix2.MarkingDefinition(
            id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
            definition_type="statement",
            definition={"statement": "custom"},
            allow_custom=True,
            custom_properties={
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": "TLP:AMBER+STRICT",
            },
        )

    def _ensure_activity_roundup_vocabulary(self) -> None:
        """
        Register the 'activity-roundup' entry in the report_types_ov vocabulary.

        MUST be called before any Report with report_types=["activity-roundup"]
        is sent. If the vocabulary entry does not exist when a Report is
        ingested, the OpenCTI worker will reject the report_types field or
        coerce it to a default value.

        helper.api.vocabulary.create() is idempotent — if the entry already
        exists, the platform returns the existing record without error or
        creating a duplicate. This makes it safe to call on every connector
        startup without checking first.

        The call is wrapped in try/except because some OpenCTI versions may
        raise on duplicate rather than returning the existing record. In that
        case the warning is logged but startup continues — the vocabulary
        entry already exists and Reports will be accepted.
        """
        try:
            self.helper.api.vocabulary.create(
                name="activity-roundup",
                description=(
                    "Periodic activity summary report covering threat actor "
                    "operations, campaign developments, and intelligence "
                    "updates over a defined time window. Used for Flashpoint "
                    "finished intelligence reports and daily batch ingestion."
                ),
                category="report_types_ov",
            )
            self.helper.connector_logger.info(
                "[CONVERTER] activity-roundup vocabulary entry confirmed."
            )
        except Exception as exc:
            # Non-fatal — vocabulary likely already exists. Log and continue.
            self.helper.connector_logger.warning(
                f"[CONVERTER] activity-roundup vocabulary registration "
                f"(may already exist): {exc}"
            )

    # =========================================================================
    # Core relationship utilities
    # =========================================================================

    def create_relation(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        description: str,
        confidence: Optional[int] = None,
        start_time: Optional[str] = None,
        stop_time: Optional[str] = None,
    ) -> Optional[stix2.Relationship]:
        """
        Create a STIX Relationship object with a mandatory description.

        HARD CONSTRAINT: description is mandatory. Passing an empty string
        or whitespace-only string raises ValueError. This is intentional —
        a relationship without a description is a semantically empty assertion.
        It occupies a graph edge but provides no analytical value and cannot
        be traced to its source claim.

        The relationship ID is generated deterministically from
        (relation, source_id, target_id) via StixCoreRelationship.generate_id().
        This means attempting to create the same relationship twice produces
        the same STIX ID, enabling OpenCTI's worker to upsert rather than
        duplicate.

        If relationship creation fails (e.g. due to an invalid entity type
        combination), the error is logged and None is returned. Callers must
        check for None before appending to their object list.

        :param source_id: STIX ID of the source entity
        :param target_id: STIX ID of the target entity
        :param relation: relationship type string (e.g. "uses", "targets")
        :param description: human-readable explanation of what the source
                            asserts about this connection — MANDATORY
        :param confidence: optional OpenCTI confidence score 0–100
        :param start_time: optional ISO8601 start time for temporal scope
        :param stop_time: optional ISO8601 stop time for temporal scope
        :return: stix2.Relationship object, or None on construction failure
        :raises ValueError: if description is empty or whitespace-only
        """
        # Enforce the mandatory description constraint at the Python level.
        # This cannot be bypassed without modifying this method.
        if not description or not description.strip():
            raise ValueError(
                f"Relationship description is mandatory. "
                f"Attempted to create '{relation}' relationship from "
                f"'{source_id}' to '{target_id}' with an empty description. "
                f"Every relationship must explain what the source asserts "
                f"about the connection."
            )

        try:
            kwargs = dict(
                id=StixCoreRelationship.generate_id(relation, source_id, target_id),
                relationship_type=relation,
                created_by_ref=self.author_id,
                source_ref=source_id,
                target_ref=target_id,
                description=description,
                object_marking_refs=[self.marking.get("id")],
                allow_custom=True,
            )
            # Confidence is passed as a custom property because stix2.Relationship
            # does not have a native confidence field in STIX 2.1.
            if confidence is not None:
                kwargs["custom_properties"] = {"x_opencti_score": confidence}
            # Temporal scope — used when the source report specifies when a
            # relationship was active (e.g. "actor used this malware in 2023").
            if start_time:
                kwargs["start_time"] = start_time
            if stop_time:
                kwargs["stop_time"] = stop_time

            return stix2.Relationship(**kwargs)

        except Exception as exc:
            self.helper.connector_logger.error(
                f"[CONVERTER] create_relation failed: "
                f"'{relation}' {source_id} -> {target_id}: {exc}"
            )
            return None

    def _floor_relation(
        self,
        observable_id: str,
        description: str,
    ) -> Optional[stix2.Relationship]:
        """
        Create the minimum-floor Identity relationship for an Observable.

        DATA MODEL REQUIREMENT (§3.4j): Every Observable must have at minimum
        a related-to relationship to a named Identity object. This method
        creates that floor relationship using the Flashpoint Organization
        identity when no richer entity relationship can be resolved.

        This is not a fallback of last resort to be avoided — it is the
        correct behaviour when the source data does not provide enough context
        to link the Observable to a more specific entity. The floor relationship
        ensures the Observable is queryable by source, attributable to Flashpoint,
        and not orphaned in the graph.

        :param observable_id: STIX ID of the Observable needing a floor link
        :param description: description explaining the provenance context
        :return: stix2.Relationship or None on failure
        """
        return self.create_relation(
            source_id=observable_id,
            target_id=self.author_id,
            relation="related-to",
            description=description,
        )

    # =========================================================================
    # Knowledge graph resolution
    # =========================================================================

    def _guess_knowledge_graph(
        self,
        tags: list,
        source_context: str,
        confidence: int,
    ) -> tuple:
        """
        Resolve Flashpoint report tags and actor names against the existing
        OpenCTI knowledge graph and build inter-entity relationships.

        HOW IT WORKS:
        For each tag string, queries the OpenCTI platform for an existing
        entity whose name or x_mitre_id matches the tag. If a match is found,
        a minimal STIX stub for that entity is created (with only the ID and
        name populated) and relationships between co-occurring entities are
        built based on entity type pairs.

        WHY STUBS NOT FULL ENTITIES:
        We do not create full entity definitions from tags because we have
        no reliable source for the entity's fields (motivation, resource level,
        sophistication, etc.) from a tag string alone. Populating those fields
        without source citation would violate the Assessment Note requirement.
        Instead we create stub references — enough to populate the Report's
        object_refs and build relationships — leaving the full entity definition
        to be populated by whichever connector ingested that entity originally.

        RELATIONSHIP DESCRIPTIONS:
        All relationships created here use a standard description format:
        "Resolved from Flashpoint source tag '{tag}' in: {source_context}"
        This makes the source of the relationship traceable. An analyst
        reviewing the edge knows it was machine-resolved from a tag, not
        asserted by an analyst.

        WHAT THIS DOES NOT DO:
        - Does not create new entities not already in the graph
        - Does not populate vocabulary fields (motivation, role, etc.)
        - Does not create Assessment Notes (tags don't carry that level of detail)

        :param tags: list of tag/actor strings from Flashpoint report metadata
        :param source_context: human-readable description of the source
                               (e.g. report title) for relationship descriptions
        :param confidence: confidence score to apply to created relationships
        :return: tuple of (stix_objects list, object_ref_ids list)
        """
        all_stix_objects = []
        elements = {
            "threat_actors": [],
            "intrusion_sets": [],
            "malwares": [],
            "tools": [],
            "attack_patterns": [],
            "sectors": [],
            "countries": [],
            "regions": [],
        }

        for tag in tags:
            tag = tag.strip()
            if not tag:
                # Skip empty strings — split(",") on a trailing comma produces
                # an empty string element.
                continue

            try:
                # Query the platform for any entity whose name or MITRE ID
                # matches this tag. The broad type list ensures we catch all
                # relevant entity types.
                resolved = self.helper.api.stix_domain_object.list(
                    types=[
                        "Threat-Actor-Group",
                        "Threat-Actor-Individual",
                        "Intrusion-Set",
                        "Campaign",
                        "Malware",
                        "Tool",
                        "Attack-Pattern",
                        "Country",
                        "Region",
                        "Sector",
                    ],
                    filters={
                        "mode": "and",
                        "filters": [
                            {"key": ["name", "x_mitre_id"], "values": [tag]}
                        ],
                        "filterGroups": [],
                    },
                )
            except Exception as exc:
                self.helper.connector_logger.warning(
                    f"[CONVERTER] Tag resolution query failed for '{tag}': {exc}"
                )
                continue

            if not resolved:
                # No match in the graph — skip this tag.
                # We do not create new entities from unresolved tags.
                continue

            # Take the first match. If multiple entities share a name
            # (uncommon but possible), the first is the most likely intended
            # match due to OpenCTI's default scoring/recency ordering.
            entity = resolved[0]
            etype = entity["entity_type"]
            name = entity["name"]

            # Build the relationship description once per tag — reused for
            # all relationships created from this entity.
            rel_desc = (
                f"Resolved from Flashpoint source tag '{tag}' "
                f"in: {source_context}"
            )

            # Create a minimal STIX stub for the resolved entity.
            # The ID is generated deterministically from the entity name,
            # matching the ID OpenCTI uses internally. This allows the stub
            # to be referenced in object_refs without creating a duplicate
            # entity — the worker upserts based on ID.
            if etype == "Threat-Actor-Group":
                obj = stix2.ThreatActor(
                    id=ThreatActorGroup.generate_id(name),
                    name=name,
                    allow_custom=True,
                )
                elements["threat_actors"].append(obj)

            elif etype == "Threat-Actor-Individual":
                # ThreatActorIndividual uses resource_level="individual" as
                # the distinguishing property in OpenCTI's data model.
                obj = stix2.ThreatActor(
                    id=ThreatActorIndividual.generate_id(name),
                    name=name,
                    resource_level="individual",
                    allow_custom=True,
                )
                elements["threat_actors"].append(obj)

            elif etype == "Intrusion-Set":
                obj = stix2.IntrusionSet(
                    id=IntrusionSet.generate_id(name),
                    name=name,
                    allow_custom=True,
                )
                elements["intrusion_sets"].append(obj)

            elif etype == "Malware":
                # is_family=True because tags represent family names
                # (e.g. "Cobalt Strike", "Emotet"), not specific samples.
                # A specific sample would be identified by hash, not tag.
                obj = stix2.Malware(
                    id=Malware.generate_id(name),
                    name=name,
                    is_family=True,
                    allow_custom=True,
                )
                elements["malwares"].append(obj)

            elif etype == "Tool":
                obj = stix2.Tool(
                    id=Tool.generate_id(name),
                    name=name,
                    allow_custom=True,
                )
                elements["tools"].append(obj)

            elif etype == "Attack-Pattern":
                obj = stix2.AttackPattern(
                    id=AttackPattern.generate_id(name),
                    name=name,
                    allow_custom=True,
                )
                elements["attack_patterns"].append(obj)

            elif etype == "Country":
                obj = stix2.Location(
                    id=Location.generate_id(name, "Country"),
                    name=name,
                    country=name,
                    allow_custom=True,
                    custom_properties={"x_opencti_location_type": "Country"},
                )
                elements["countries"].append(obj)

            elif etype == "Region":
                obj = stix2.Location(
                    id=Location.generate_id(name, "Region"),
                    name=name,
                    region=name,
                    allow_custom=True,
                    custom_properties={"x_opencti_location_type": "Region"},
                )
                elements["regions"].append(obj)

            elif etype == "Sector":
                # Sectors are modeled as stix2.Identity with identity_class="class"
                # in OpenCTI's data model. This is the standard representation
                # for industry sectors.
                obj = stix2.Identity(
                    id=Identity.generate_id(name, "class"),
                    name=name,
                    identity_class="class",
                    allow_custom=True,
                )
                elements["sectors"].append(obj)

            # Unrecognised entity types are silently skipped — they cannot
            # be modelled without knowing the correct STIX type.

        # ── Build inter-entity relationships ──────────────────────────────────
        # The relationship model follows the data model guide:
        #   Threat Actor / Intrusion Set / Malware → uses → Attack Pattern
        #   Threat Actor / Intrusion Set → uses → Malware
        #   Threat Actor / Intrusion Set → uses → Tool
        #   Threat Actor / Intrusion Set / Malware → targets → Country/Region/Sector
        #
        # Relationships are only created between entities that co-occur in
        # the same tag/actor list. This is the correct inference: if a report
        # tags both APT29 and Cobalt Strike, the report asserts a uses
        # relationship between them for this context.

        threats = (
            elements["threat_actors"]
            + elements["intrusion_sets"]
            + elements["malwares"]
        )
        victims = (
            elements["regions"]
            + elements["countries"]
            + elements["sectors"]
        )

        # All relationship descriptions use the same rel_desc from the last
        # resolved tag. This is a simplification — in a full implementation
        # each relationship would carry the specific tags that informed it.
        # For tag-resolved relationships this level of granularity is acceptable.
        rel_desc = (
            f"Co-occurring entities resolved from Flashpoint source tags "
            f"in: {source_context}"
        )

        for attack_pattern in elements["attack_patterns"]:
            for threat in threats:
                rel = self.create_relation(
                    threat.id, attack_pattern.id, "uses",
                    description=rel_desc, confidence=confidence,
                )
                if rel:
                    all_stix_objects.append(rel)

        for malware in elements["malwares"]:
            # Only Threat Actors and Intrusion Sets use Malware.
            # Malware does not use other Malware (that would be a
            # delivers/drops relationship, which requires explicit source
            # assertion, not tag inference).
            for threat in elements["threat_actors"] + elements["intrusion_sets"]:
                rel = self.create_relation(
                    threat.id, malware.id, "uses",
                    description=rel_desc, confidence=confidence,
                )
                if rel:
                    all_stix_objects.append(rel)

        for tool in elements["tools"]:
            for threat in elements["threat_actors"] + elements["intrusion_sets"]:
                rel = self.create_relation(
                    threat.id, tool.id, "uses",
                    description=rel_desc, confidence=confidence,
                )
                if rel:
                    all_stix_objects.append(rel)

        for victim in victims:
            for threat in threats:
                rel = self.create_relation(
                    threat.id, victim.id, "targets",
                    description=rel_desc, confidence=confidence,
                )
                if rel:
                    all_stix_objects.append(rel)

        # Collect all entity stubs (not relationships — those are already added)
        all_entities = (
            elements["threat_actors"]
            + elements["intrusion_sets"]
            + elements["malwares"]
            + elements["tools"]
            + elements["attack_patterns"]
            + elements["regions"]
            + elements["countries"]
            + elements["sectors"]
        )
        all_stix_objects.extend(all_entities)

        # Build the object_refs list: entity IDs + relationship IDs.
        # Both entities and relationships are valid object_refs entries.
        object_ref_ids = [obj.id for obj in all_stix_objects]

        return all_stix_objects, object_ref_ids

    # =========================================================================
    # Finished Intelligence Reports
    # =========================================================================

    def convert_flashpoint_report(self, report: dict) -> list:
        """
        Convert a Flashpoint finished intelligence report dict into a list
        of STIX objects for bundle creation.

        CONTAINER: stix2.Report with report_types=["activity-roundup"]
        CONTAINMENT: All knowledge graph objects resolved from tags and actors
                     are members of the Report via object_refs.

        OBJECT_REFS HANDLING:
        The STIX spec requires at least one entry in object_refs. When
        _guess_knowledge_graph() resolves nothing (the report tags don't
        match any existing graph entities), object_refs would be empty.
        Rather than injecting a fake placeholder ID (the Filigran approach),
        we fall back to the author identity ID. The author identity always
        exists, and referencing it is semantically accurate — the Report
        is authored by Flashpoint. This avoids the phantom reference problem.

        BODY CONTENT:
        report["body"] is passed as a string to x_opencti_content.
        The Filigran connector encoded it as bytes (.encode("utf-8")), which
        breaks content rendering in the OpenCTI UI. The custom property
        expects a string.

        PUBLISHED DATE:
        Uses report["posted_at"] (the Flashpoint publication date), NOT the
        current date. Using the ingestion date as the published date corrupts
        all temporal queries and timeline analysis. If posted_at cannot be
        parsed, falls back to the current UTC time with a warning.

        :param report: Flashpoint report dict from get_reports()
        :return: list of STIX objects for bundle creation
        """
        confidence = self.config.report_confidence

        # Start the object list with the marking definition.
        # The marking must be in the bundle so the worker can resolve
        # object_marking_refs references.
        objects = [self.marking]

        # Extract tags and actors — both are used as inputs to knowledge
        # graph resolution. Tags are typically ATT&CK technique IDs, malware
        # family names, and sector names. Actors are threat actor designators.
        tags = report.get("tags") or []
        actors = report.get("actors") or []

        # Source context string for relationship descriptions — identifies
        # which report the tag was resolved from.
        source_context = report.get("title", "Flashpoint Intelligence Report")

        # Resolve tags and actors against the existing graph.
        # Returns stubs for matched entities and their relationships.
        graph_objects, object_ref_ids = self._guess_knowledge_graph(
            tags + actors, source_context, confidence
        )
        objects.extend(graph_objects)

        # External reference back to the original Flashpoint platform URL.
        # This is the chain of custody — it allows any analyst to navigate
        # directly to the source document in the Flashpoint Ignite UI.
        ext_ref = stix2.ExternalReference(
            source_name="Flashpoint",
            url=report.get("platform_url") or "",
        )

        # Parse the publication date. dateparser.parse() handles a wide
        # variety of date string formats from the Flashpoint API.
        # Fall back to current UTC time if parsing fails, with a warning.
        raw_posted_at = report.get("posted_at") or ""
        published = parse(raw_posted_at)
        if not published:
            self.helper.connector_logger.warning(
                f"[CONVERTER] Could not parse posted_at='{raw_posted_at}' "
                f"for report '{report.get('title')}' — using current time."
            )
            published = datetime.now(timezone.utc)

        # Report body content — passed as a plain string.
        # x_opencti_content is OpenCTI's custom property for storing the
        # full text of a report for display in the Content tab.
        body_content = report.get("body") or ""

        stix_report = stix2.Report(
            # Deterministic ID: same title + posted_at always produces the
            # same STIX ID, enabling upsert semantics if the report is
            # re-fetched (e.g. because it was updated on Flashpoint).
            id=Report.generate_id(report["title"], report["posted_at"]),
            name=report["title"],
            # All containers in this connector use activity-roundup.
            report_types=["activity-roundup"],
            published=published,
            # summary is the human-readable abstract. body is the full text
            # stored separately in x_opencti_content.
            description=report.get("summary") or "",
            external_references=[ext_ref],
            # Tags are propagated as labels for searchability in OpenCTI.
            labels=tags,
            created_by_ref=self.author_id,
            object_marking_refs=[self.marking.get("id")],
            # If no entities were resolved, fall back to author identity
            # rather than injecting a fake placeholder ID.
            object_refs=object_ref_ids if object_ref_ids else [self.author_id],
            allow_custom=True,
            custom_properties={
                # Full report text for display in the OpenCTI Content tab.
                "x_opencti_content": body_content,
                # Confidence from config — reflects Flashpoint's reliability
                # as a Tier-1 intelligence vendor.
                "x_opencti_score": confidence,
            },
        )
        objects.append(stix_report)
        return objects

    # =========================================================================
    # Alerts — keyword match (daily batch Report path)
    # =========================================================================

    def alert_to_report_objects(
        self,
        alert: dict,
        create_related_entities: bool = True,
    ) -> list:
        """
        Convert a keyword-match Flashpoint alert into STIX objects for
        accumulation into a daily batch Report container.

        IMPORTANT: This method does NOT create the Report container.
        It returns the member objects only. The connector dispatcher
        accumulates objects from all alerts for a given day and calls
        build_daily_report() to construct the container after all alerts
        for that day have been processed.

        ALERT SOURCE TYPES HANDLED:
          communities   — forum post keyword match
          media         — image/file keyword match
          data_exposure — code repository leak match

        For data_exposure alerts, a URL Observable is additionally created
        from the repository URL. This captures the specific location of the
        exposed data.

        If create_related_entities=False (minimal mode), only the Text
        Observable is created with a floor relationship to the Flashpoint
        author identity. This mode exists for cases where entity creation
        would create noise (e.g. very high alert volume).

        :param alert: processed alert dict from connector._process_alert()
        :param create_related_entities: if True (default), create Channel SDO
               and all relationships; if False, create Text Observable only
        :return: list of STIX objects (NO Report container — connector builds it)
        """
        confidence = self.config.alert_confidence
        objects = [self.marking]

        alert_id = alert.get("alert_id", "unknown")
        channel_name = alert.get("channel_name") or alert.get("channel_type", "")
        channel_type = alert.get("channel_type", "unknown")
        channel_aliases = alert.get("channel_aliases") or []
        channel_ref = alert.get("channel_ref")
        highlight_text = alert.get("highlight_text") or ""
        created_at = alert.get("created_at", "")
        alert_source = alert.get("alert_source", "")
        flashpoint_url = alert.get("flashpoint_url") or ""

        # ── Text Observable ───────────────────────────────────────────────────
        # The alert highlight_text is the post content or code snippet that
        # triggered the alert rule. Stored as a Text Observable so it is
        # accessible for analysis alongside the Channel context.
        # Observable description contains only technical provenance — the
        # actual threat behaviour (why this text is relevant) belongs in
        # the relationship description.
        text_obs = None
        if highlight_text:
            try:
                from pycti import CustomObservableText
                text_obs = CustomObservableText(
                    value=highlight_text,
                    object_marking_refs=[self.marking.get("id")],
                    custom_properties={
                        # Technical provenance only — not threat behaviour.
                        "x_opencti_description": (
                            f"Alert highlight text from {channel_type} "
                            f"source. Alert ID: {alert_id}. "
                            f"Captured: {created_at}."
                        ),
                        "x_opencti_score": confidence,
                        "created_by_ref": self.author_id,
                        "external_references": (
                            [
                                stix2.ExternalReference(
                                    source_name="Flashpoint",
                                    url=flashpoint_url,
                                )
                            ]
                            if flashpoint_url
                            else []
                        ),
                    },
                )
                objects.append(text_obs)
            except Exception as exc:
                self.helper.connector_logger.warning(
                    f"[CONVERTER] Text observable failed for alert {alert_id}: {exc}"
                )

        if not create_related_entities:
            # Minimal mode — apply floor relationship and return.
            if text_obs:
                floor = self._floor_relation(
                    text_obs.id,
                    f"Alert highlight text captured by Flashpoint alert "
                    f"{alert_id} via source: {channel_type}.",
                )
                if floor:
                    objects.append(floor)
            return objects

        # ── Channel SDO ───────────────────────────────────────────────────────
        # The Channel represents the forum, platform, or communication medium
        # where the alerting content was found. Channels accumulate across
        # ingestion runs — the same XSS Forum channel will be referenced by
        # many alerts over time, building a picture of actor activity there.
        channel_obj = None
        if channel_name:
            channel_obj = self._create_channel(
                channel_name=channel_name,
                channel_type=channel_type,
                channel_aliases=channel_aliases,
                channel_ref=channel_ref,
            )
            objects.append(channel_obj)

        # ── Text -> Channel relationship ──────────────────────────────────────
        # Data model §3.4j: Observable -> Related To -> Identity
        # Channel SDO is an Identity-type object in OpenCTI's model.
        if text_obs and channel_obj:
            rel = self.create_relation(
                source_id=text_obs.id,
                target_id=channel_obj.id,
                relation="related-to",
                description=(
                    f"Alert highlight text sourced from {channel_type} "
                    f"channel '{channel_name}'. "
                    f"Alert ID: {alert_id}, captured: {created_at}."
                ),
                confidence=confidence,
            )
            if rel:
                objects.append(rel)
        elif text_obs:
            # No Channel resolved — apply floor relationship to Flashpoint identity.
            floor = self._floor_relation(
                text_obs.id,
                f"Alert highlight text from Flashpoint alert {alert_id}, "
                f"source type: {channel_type}. No channel entity resolved.",
            )
            if floor:
                objects.append(floor)

        # ── URL Observable for data_exposure alerts ───────────────────────────
        # data_exposure alerts fire when Flashpoint detects content in a code
        # repository (GitHub, GitLab, Pastebin, etc.) matching your alert rules.
        # The flashpoint_url for these alerts is the repository/file URL,
        # not a Flashpoint platform URL — it points directly to the exposed content.
        if alert_source.startswith("data_exposure") and flashpoint_url:
            try:
                url_obs = stix2.URL(
                    value=flashpoint_url,
                    object_marking_refs=[self.marking.get("id")],
                    custom_properties={
                        "x_opencti_description": (
                            f"Code repository or data exposure URL from "
                            f"Flashpoint data_exposure alert {alert_id}. "
                            f"This URL points to the location of the exposed content."
                        ),
                        "x_opencti_score": confidence,
                        "created_by_ref": self.author_id,
                    },
                )
                objects.append(url_obs)

                # Link URL to Text if both exist — they are co-located evidence.
                if text_obs:
                    rel = self.create_relation(
                        source_id=url_obs.id,
                        target_id=text_obs.id,
                        relation="related-to",
                        description=(
                            f"Data exposure URL associated with the alert "
                            f"highlight text content. Alert ID: {alert_id}."
                        ),
                        confidence=confidence,
                    )
                    if rel:
                        objects.append(rel)
                else:
                    # No Text observable — apply floor to URL instead.
                    floor = self._floor_relation(
                        url_obs.id,
                        f"Data exposure URL from Flashpoint alert {alert_id}.",
                    )
                    if floor:
                        objects.append(floor)

            except Exception as exc:
                self.helper.connector_logger.warning(
                    f"[CONVERTER] URL observable for data_exposure alert "
                    f"{alert_id}: {exc}"
                )

        return objects

    # =========================================================================
    # Alerts — org-domain credential match (Incident Response path)
    # =========================================================================

    def credential_alert_to_incident_objects(self, alert: dict) -> list:
        """
        Convert an org-domain credential alert into STIX objects for
        an Incident Response container.

        This method is called when an alert matches a configured org domain,
        indicating the alert is directly relevant to the organisation and
        warrants IR treatment rather than the generic batch Report path.

        CONTAINER: The IR container (case_incident) is created by the
        connector dispatcher — this method returns only the member objects.

        OBJECTS CREATED:
          - stix2.Incident SDO — the primary container member representing
            the credential exposure event
          - Text Observable — the alert highlight text
          - URL Observable — the Flashpoint platform URL
          - Relationships linking each Observable to the Incident

        ALERT.MD ATTACHMENT:
        A Markdown summary of the alert metadata is generated and attached
        to the Incident via x_opencti_files. This gives analysts a
        human-readable summary of the alert directly in the OpenCTI UI
        without needing to navigate to Flashpoint Ignite.

        MEDIA ATTACHMENT:
        For media-source alerts (images, files), the binary content is
        attached alongside the Markdown summary if present in the alert dict.

        :param alert: processed alert dict from connector._process_alert()
        :return: list of STIX objects (NO IR container — connector builds it)
        """
        confidence = self.config.alert_org_confidence
        objects = [self.marking]

        alert_id = alert.get("alert_id", "unknown")
        created_at = alert.get("created_at") or ""
        channel_type = alert.get("channel_type") or ""
        alert_source = alert.get("alert_source") or ""
        alert_reason = alert.get("alert_reason") or ""
        flashpoint_url = alert.get("flashpoint_url") or ""
        highlight_text = alert.get("highlight_text") or ""

        # Incident name encodes the alert rule and ID for uniqueness.
        # The rule name makes it human-readable; the ID makes it unique.
        incident_name = (
            f"Flashpoint Alert — {alert_reason or 'Credential Exposure'} "
            f"— {alert_id}"
        )

        incident_description = (
            f"Potential credential or data exposure detected by Flashpoint "
            f"alert rule '{alert_reason}' on source '{alert_source}' "
            f"({channel_type}). "
            f"Alert ID: {alert_id}. Captured: {created_at}. "
            f"For full alert content see the attached alert.md file in "
            f"the Data tab."
        )

        # Build the Markdown content file — this is attached to the Incident
        # so analysts have a complete summary without needing to cross-reference.
        markdown = self._build_alert_markdown(alert)
        md_b64 = _b64.b64encode(markdown.encode("utf-8"))

        files = [
            {
                "name": "alert.md",
                "data": md_b64,
                "mime_type": "text/markdown",
                # no_trigger_import=False allows OpenCTI to process the
                # attached file through import connectors if configured.
                "no_trigger_import": False,
            }
        ]

        # If a media binary was fetched during alert processing, attach it.
        if alert.get("media_content"):
            files.append(
                {
                    "name": alert.get("media_name") or "attachment",
                    "data": alert["media_content"],
                    "mime_type": alert.get(
                        "media_type", "application/octet-stream"
                    ),
                    "no_trigger_import": False,
                }
            )

        ext_ref = (
            stix2.ExternalReference(
                source_name="Flashpoint",
                url=flashpoint_url,
            )
            if flashpoint_url
            else None
        )

        # Incident ID is deterministic — same name + created_at always
        # produces the same STIX ID, preventing duplicate Incidents if the
        # same alert is re-processed (e.g. after a connector restart during
        # an alert processing run).
        stix_incident = stix2.Incident(
            id=Incident.generate_id(name=incident_name, created=created_at),
            name=incident_name,
            created=created_at,
            description=incident_description,
            created_by_ref=self.author_id,
            # incident_type="alert" indicates this originated from a
            # rule-based alert, not a manually opened case.
            incident_type="alert",
            # Severity "medium" for org-domain credential alerts — they are
            # directly relevant to the org but not yet confirmed as exploited.
            severity="medium",
            labels=[
                # Label encodes the alert rule name for filtering.
                f"rule:{alert_reason.lower()}",
                # Label encodes the data source type for filtering.
                alert_source,
            ],
            object_marking_refs=[self.marking.get("id")],
            external_references=[ext_ref] if ext_ref else [],
            allow_custom=True,
            custom_properties={
                "x_opencti_files": files,
                "x_opencti_score": confidence,
                # Source field for display in OpenCTI incident views.
                "source": f"Flashpoint — {alert_source}",
            },
        )
        objects.append(stix_incident)

        # ── Text Observable ───────────────────────────────────────────────────
        if highlight_text:
            try:
                from pycti import CustomObservableText
                text_obs = CustomObservableText(
                    value=highlight_text,
                    object_marking_refs=[self.marking.get("id")],
                    custom_properties={
                        "x_opencti_description": (
                            f"Alert highlight text from Flashpoint credential "
                            f"alert {alert_id}. Source: {alert_source}."
                        ),
                        "x_opencti_score": confidence,
                        "created_by_ref": self.author_id,
                    },
                )
                objects.append(text_obs)

                # Link Text to Incident — the text is evidence of the exposure.
                rel = self.create_relation(
                    source_id=text_obs.id,
                    target_id=stix_incident.id,
                    relation="related-to",
                    description=(
                        f"Alert highlight text is the content that triggered "
                        f"the Flashpoint credential alert {alert_id} "
                        f"from source: {alert_source}."
                    ),
                    confidence=confidence,
                )
                if rel:
                    objects.append(rel)
            except Exception as exc:
                self.helper.connector_logger.warning(
                    f"[CONVERTER] Text observable for credential alert "
                    f"{alert_id}: {exc}"
                )

        # ── URL Observable ────────────────────────────────────────────────────
        # The Flashpoint platform URL links back to the specific alert in
        # the Ignite UI. Stored as a URL Observable so analysts can pivot
        # directly from OpenCTI to Flashpoint.
        if flashpoint_url:
            try:
                url_obs = stix2.URL(
                    value=flashpoint_url,
                    object_marking_refs=[self.marking.get("id")],
                    custom_properties={
                        "x_opencti_description": (
                            f"Flashpoint Ignite platform URL for credential "
                            f"exposure alert {alert_id}. Navigate here to "
                            f"view the full alert in Flashpoint."
                        ),
                        "x_opencti_score": confidence,
                        "created_by_ref": self.author_id,
                    },
                )
                objects.append(url_obs)

                rel = self.create_relation(
                    source_id=url_obs.id,
                    target_id=stix_incident.id,
                    relation="related-to",
                    description=(
                        f"Flashpoint platform URL for credential alert "
                        f"{alert_id} — links to the source alert in Ignite."
                    ),
                    confidence=confidence,
                )
                if rel:
                    objects.append(rel)
            except Exception as exc:
                self.helper.connector_logger.warning(
                    f"[CONVERTER] URL observable for credential alert "
                    f"{alert_id}: {exc}"
                )

        return objects

    # =========================================================================
    # Communities
    # =========================================================================

    def convert_communities_result(self, result: dict, query: str) -> list:
        """
        Convert a single Flashpoint Communities search result into STIX
        objects for accumulation into a daily batch Report container.

        OBJECT MODEL:
          Channel → the forum or platform where the post appeared
          Persona → the actor handle who posted (if available)
          Text    → the raw post content

        RELATIONSHIP MODEL (per data model §3.4j):
          Text → related-to → Persona  (Observable → Related To → Identity)
          Persona → related-to → Channel
          Channel → publishes → Text   (preferred; falls back to related-to
                                        if platform rejects at runtime)

        PERSONA NOTE:
        Persona objects are created where a handle is present in the source
        data. No Individual SDO is linked to the Persona because Flashpoint
        community data provides only the handle — we have no confirmed
        real-world identity behind it. The data model requires a confirmed
        identity to justify the Persona → Related-To → Individual edge.
        Creating that edge from a handle alone would be an unsourced
        attribution assertion.

        CHANNEL NOTE:
        Channel names are stripped of Flashpoint's <x-fp-highlight> markup
        before use. The markup is injected to highlight search matches and
        must not appear in entity names.

        FLOOR RELATIONSHIPS:
        If a Persona cannot be created (no handle), the Text Observable
        receives a floor relationship to the Flashpoint author identity.
        If a Channel cannot be created (no name), the Persona receives
        a floor relationship to the Flashpoint author identity.

        :param result: community post dict from communities_search()
        :param query: the search query term that produced this result
        :return: list of STIX objects (NO Report container)
        """
        confidence = self.config.communities_confidence
        objects = [self.marking]

        doc_id = result.get("id") or "unknown"
        site = result.get("site") or "unknown"
        post_date = result.get("date") or ""
        message = result.get("message") or ""

        # Strip Flashpoint highlight markup from channel name before use.
        raw_container = (
            result.get("container_name") or result.get("site_title") or ""
        )
        channel_name = _strip_highlight(raw_container)
        site_source_uri = result.get("site_source_uri")

        # Actor handle from the nested site_actor structure.
        site_actor = result.get("site_actor") or {}
        handle = site_actor.get("names", {}).get("handle") or ""
        aliases = result.get("site_actor_alias") or []

        # Canonical Flashpoint platform URL for this post.
        fp_url = (
            "https://app.flashpoint.io/search/context/communities/" + doc_id
        )

        # ── Channel SDO ───────────────────────────────────────────────────────
        channel_obj = None
        if channel_name:
            channel_obj = self._create_channel(
                channel_name=channel_name,
                channel_type=site,
                channel_aliases=[],  # Channel-level aliases not in communities API
                channel_ref=site_source_uri,
            )
            objects.append(channel_obj)

        # ── Persona Observable ────────────────────────────────────────────────
        # Persona represents the online handle/moniker used by the actor.
        # It is distinct from an Individual (the real person) — the Persona
        # is the digital mask, not the person behind it.
        persona_obj = None
        if handle:
            try:
                from pycti import CustomObservablePersona
                persona_obj = CustomObservablePersona(
                    name=handle,
                    aliases=aliases,
                    object_marking_refs=[self.marking.get("id")],
                    custom_properties={
                        # Technical provenance only in description.
                        "x_opencti_description": (
                            f"Dark web forum persona observed on {site} "
                            f"via Flashpoint Communities query '{query}'. "
                            f"Post date: {post_date}. Post ID: {doc_id}."
                        ),
                        "x_opencti_score": confidence,
                        "created_by_ref": self.author_id,
                        "external_references": [
                            stix2.ExternalReference(
                                source_name="Flashpoint",
                                url=fp_url,
                            )
                        ],
                    },
                )
                objects.append(persona_obj)
            except Exception as exc:
                self.helper.connector_logger.warning(
                    f"[CONVERTER] Persona creation for doc {doc_id}: {exc}. "
                    f"CustomObservablePersona may not be available in this "
                    f"pycti version — check pycti==6.9.13."
                )

        # ── Text Observable ───────────────────────────────────────────────────
        # The raw post content. Value field holds the actual text.
        # Description holds only provenance metadata.
        text_obs = None
        if message:
            try:
                from pycti import CustomObservableText
                text_obs = CustomObservableText(
                    value=message,
                    object_marking_refs=[self.marking.get("id")],
                    custom_properties={
                        "x_opencti_description": (
                            f"Dark web forum post content captured by "
                            f"Flashpoint Communities search. "
                            f"Query: '{query}', site: {site}. "
                            f"Post ID: {doc_id}."
                        ),
                        "x_opencti_score": confidence,
                        "created_by_ref": self.author_id,
                        "external_references": [
                            stix2.ExternalReference(
                                source_name="Flashpoint",
                                url=fp_url,
                            )
                        ],
                    },
                )
                objects.append(text_obs)
            except Exception as exc:
                self.helper.connector_logger.warning(
                    f"[CONVERTER] Text observable for doc {doc_id}: {exc}"
                )

        # ── Relationships ─────────────────────────────────────────────────────

        # Text -> related-to -> Persona
        # Data model §3.4j: Observable -> Related To -> Identity (Persona is SCO)
        # The Persona is the Identity-type anchor for the Text observable.
        if text_obs and persona_obj:
            rel = self.create_relation(
                source_id=text_obs.id,
                target_id=persona_obj.id,
                relation="related-to",
                description=(
                    f"Post content authored by persona '{handle}' on {site}. "
                    f"Captured via Flashpoint Communities query '{query}', "
                    f"post date: {post_date}."
                ),
                confidence=confidence,
            )
            if rel:
                objects.append(rel)
        elif text_obs:
            # No Persona available — floor relationship to Flashpoint identity.
            floor = self._floor_relation(
                text_obs.id,
                f"Dark web post content from {site} captured via Flashpoint "
                f"Communities query '{query}'. Post ID: {doc_id}. "
                f"No actor handle available.",
            )
            if floor:
                objects.append(floor)

        # Persona -> related-to -> Channel
        # Data model §3.4j: Persona -> related-to -> Channel
        if persona_obj and channel_obj:
            rel = self.create_relation(
                source_id=persona_obj.id,
                target_id=channel_obj.id,
                relation="related-to",
                description=(
                    f"Persona '{handle}' observed operating on channel "
                    f"'{channel_name}' ({site}). Captured via Flashpoint "
                    f"Communities query '{query}'."
                ),
                confidence=confidence,
            )
            if rel:
                objects.append(rel)
        elif persona_obj:
            # No Channel — floor to Flashpoint identity.
            floor = self._floor_relation(
                persona_obj.id,
                f"Persona '{handle}' observed on {site} via Flashpoint "
                f"Communities query '{query}'. No channel name resolved.",
            )
            if floor:
                objects.append(floor)

        # Channel -> publishes -> Text
        # This relationship type is attempted here. If the OpenCTI platform
        # does not support 'publishes' between Channel and Text (the relationship
        # is not in the Filigran data model guide), the worker will reject
        # only this edge. The rest of the bundle still lands. The connector
        # cannot detect this rejection synchronously (send_stix2_bundle is
        # asynchronous) — check worker logs after first communities run to
        # confirm whether the edge is accepted.
        if channel_obj and text_obs:
            rel = self.create_relation(
                source_id=channel_obj.id,
                target_id=text_obs.id,
                relation="publishes",
                description=(
                    f"Channel '{channel_name}' ({site}) published this post "
                    f"on {post_date}. Captured via Flashpoint Communities "
                    f"query '{query}'."
                ),
                confidence=confidence,
            )
            if rel:
                objects.append(rel)

        return objects

    # =========================================================================
    # Compromised Credentials — STUB
    # =========================================================================

    def convert_credential_record(self, record: dict) -> list:  # noqa: ARG002
        """
        Convert a compromised credential record into STIX objects.

        !! NOT IMPLEMENTED !!

        This method is a stub. It raises NotImplementedError unconditionally.

        What is needed before this can be implemented:
          - Response schema from the Credentials endpoint, specifically:
            * Field name for the exposed email/username
            * Field name for the domain (for org-domain bifurcation)
            * Field name for the source type (stealer log, forum, marketplace)
            * Field name for the discovery/first-seen timestamp
            * Field name for the source URL (if present)

        Expected object model once implemented:
          - stix2.Incident SDO (for org-domain records going to IR)
          - User-Account Observable (credential username/email)
          - Domain-Name Observable (domain extracted from email)
          - URL Observable (source location if present)
          - Relationships: each Observable -> related-to -> Incident
          - For non-org-domain: batch Report member objects instead of IR

        See CONNECTOR_SCOPE.md open items and DESIGN.md §3.3.6.

        :param record: credential record dict from get_credentials()
        :raises NotImplementedError: always
        """
        raise NotImplementedError(
            "convert_credential_record() is not yet implemented. "
            "The Flashpoint Compromised Credentials response schema must "
            "be confirmed from docs.flashpoint.io. "
            "See CONNECTOR_SCOPE.md open items."
        )

    # =========================================================================
    # Daily batch Report builder
    # =========================================================================

    def build_daily_report(
        self,
        name: str,
        date_str: str,
        member_objects: list,
        confidence: int,
        extra_external_refs: Optional[list] = None,
    ) -> stix2.Report:
        """
        Build a daily batch Report container from accumulated member objects.

        DETERMINISTIC ID:
        Report.generate_id(name, published.isoformat()) produces the same
        STIX ID for the same name+date combination every time this method
        is called. This means:
          - If the connector runs twice in the same day, the second run
            produces a Report with the same ID as the first.
          - OpenCTI's worker upserts (updates) the existing Report rather
            than creating a duplicate.
          - The second run's objects are added to the existing container.
        This is the correct behaviour for a daily batch accumulator.

        OBJECT_REFS FLOOR:
        If member_objects is empty (all conversions failed for a day), the
        Report references the author identity as the sole object_ref. This
        satisfies the STIX spec requirement for non-empty object_refs while
        avoiding the phantom placeholder ID anti-pattern.

        EXTERNAL REFERENCES:
        A base Flashpoint platform reference is always included. Additional
        per-alert or per-event references (e.g. specific Flashpoint Ignite
        URLs for each contributing alert) can be passed via extra_external_refs.
        These allow analysts to navigate from the batch Report directly to
        individual source alerts in Flashpoint Ignite.

        :param name: Report name (determines ID alongside date — must be
                     consistent across runs for upsert to work correctly)
        :param date_str: YYYY-MM-DD string for the batch date
        :param member_objects: list of STIX objects to include in object_refs
        :param confidence: confidence score for the Report
        :param extra_external_refs: additional stix2.ExternalReference objects
               to include (e.g. per-contributing-alert Flashpoint URLs)
        :return: stix2.Report object ready for bundle inclusion
        """
        # Published date is midnight UTC on the batch date.
        # Using midnight UTC rather than the current time ensures the
        # published date is consistent regardless of when in the day the
        # connector runs, and that it accurately reflects when the content
        # was originally posted (not when it was ingested).
        published = datetime.strptime(date_str, "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )

        # Build object_refs from member objects.
        # Exclude MarkingDefinition objects — they are bundle members but
        # not content members of the Report's knowledge base.
        object_ref_ids = [
            obj.id
            for obj in member_objects
            if hasattr(obj, "id")
            and not isinstance(obj, stix2.MarkingDefinition)
        ]

        if not object_ref_ids:
            # No valid members — use author identity as floor.
            # This is preferable to an empty object_refs (invalid STIX)
            # or a fake placeholder ID (misleading graph entry).
            object_ref_ids = [self.author_id]

        # Always include a base Flashpoint reference so the container has
        # a clear chain of custody back to its source.
        ext_refs = [
            stix2.ExternalReference(
                source_name="Flashpoint",
                url="https://app.flashpoint.io",
            )
        ]
        if extra_external_refs:
            ext_refs.extend(extra_external_refs)

        return stix2.Report(
            id=Report.generate_id(name, published.isoformat()),
            name=name,
            report_types=["activity-roundup"],
            published=published,
            description=(
                f"Flashpoint intelligence batch for {date_str}. "
                f"Automatically generated by the Flashpoint connector."
            ),
            created_by_ref=self.author_id,
            object_marking_refs=[self.marking.get("id")],
            object_refs=object_ref_ids,
            external_references=ext_refs,
            allow_custom=True,
            custom_properties={"x_opencti_score": confidence},
        )

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _create_channel(
        self,
        channel_name: str,
        channel_type: str,
        channel_aliases: list,
        channel_ref: Optional[str],
    ) -> CustomObjectChannel:
        """
        Construct a Channel SDO from name, type, aliases, and optional URL.

        The channel name is formatted as "[{type}] — {name}" to make the
        platform source immediately visible in the OpenCTI entity list view
        without needing to open the entity. For example:
          "[Telegram] — APT_Leaks" rather than just "APT_Leaks".

        The Channel ID is generated deterministically from the formatted name
        via Channel.generate_id(). The same channel appearing across multiple
        alerts or communities results will always produce the same ID,
        causing OpenCTI to upsert rather than create duplicate Channel entities.
        This is how the channel accumulates activity over time.

        :param channel_name: the name of the specific channel/forum/thread
        :param channel_type: the platform type (e.g. "Telegram", "XSS Forum")
        :param channel_aliases: list of known alternative names for this channel
        :param channel_ref: URL of the channel/thread if available
        :return: CustomObjectChannel STIX object
        """
        ext_refs = []
        if channel_ref:
            ext_refs.append(
                stix2.ExternalReference(
                    # Source name identifies the platform for the reference.
                    source_name=f"{channel_type} — {channel_name}",
                    url=channel_ref,
                )
            )

        # Prefix format makes the platform type visible at a glance.
        formatted_name = f"[{channel_type}] — {channel_name}"

        return CustomObjectChannel(
            id=Channel.generate_id(name=formatted_name),
            name=formatted_name,
            aliases=aliases if (aliases := channel_aliases) else [],
            channel_types=[channel_type],
            external_references=ext_refs,
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author_id,
        )

    @staticmethod
    def _build_alert_markdown(alert: dict) -> str:
        """
        Generate a Markdown-formatted summary of an alert for attachment.

        This file is attached to Incident objects via x_opencti_files so
        analysts have a human-readable summary of the alert metadata and
        content directly in the OpenCTI UI, without needing to navigate
        to Flashpoint Ignite for basic context.

        The alert.md file is structured with two sections:
          ### Metadata — administrative fields (IDs, dates, rule name)
          ### Post     — the actual content that triggered the alert

        :param alert: processed alert dict
        :return: Markdown string
        """
        return (
            f"### Metadata\n"
            f"- **Alert ID**: {alert.get('alert_id')}\n"
            f"- **Created**: {alert.get('created_at')}\n"
            f"- **Site**: {alert.get('channel_type')}\n"
            f"- **Channel**: {alert.get('channel_name')}\n"
            f"- **Author**: {alert.get('author')}\n"
            f"- **Status**: {alert.get('alert_status')}\n"
            f"- **Source**: {alert.get('alert_source')}\n"
            f"- **Rule**: {alert.get('alert_reason')}\n"
            f"- **URL**: {alert.get('flashpoint_url')}\n\n"
            f"### Post\n"
            f"```\n"
            f"{alert.get('highlight_text') or ''}\n"
            f"```\n"
        )
