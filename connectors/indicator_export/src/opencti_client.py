"""All OpenCTI reads and writes.

Reads go through pycti's list and read methods with getAll, so nothing is
silently cut off at a page boundary. Writes do nothing in dry-run mode, and
raise on failure so the caller counts the error and retries next cycle.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pycti import Grouping, Identity

GROUPING_CONTEXT = "suspicious-activity"

MARKING_FIELDS = "objectMarking { id standard_id definition definition_type }"

# Name fragments match the ones pycti itself queries on relationship endpoints.
_NAMED_TYPES = (
    "AttackPattern Campaign CourseOfAction Individual Organization Sector System "
    "Indicator Infrastructure IntrusionSet Position City Country Region Malware "
    "ThreatActor Tool Vulnerability Incident Event Channel Narrative Language "
    "DataComponent DataSource Case"
).split()

_ENDPOINT_FIELDS = (
    """
    ... on BasicObject { id entity_type parent_types }
    ... on StixDomainObject { %s }
    """
    % MARKING_FIELDS
    + "\n".join(f"... on {name} {{ name }}" for name in _NAMED_TYPES)
)

_OBSERVABLE_FIELDS = (
    """
    ... on StixCyberObservable {
        id
        entity_type
        observable_value
        %s
        objectLabel { id value }
        ... on IPv4Addr { value }
        ... on IPv6Addr { value }
        ... on DomainName { value }
        ... on Url { value }
        ... on EmailAddr { value }
        ... on MacAddr { value }
        ... on Mutex { name }
        ... on WindowsRegistryKey { attribute_key }
        ... on UserAccount { user_id account_login }
        ... on AutonomousSystem { number }
        ... on Directory { path }
        ... on Software { name }
        ... on StixFile { name hashes { algorithm hash } }
        ... on X509Certificate { hashes { algorithm hash } serial_number }
    }
    """
    % MARKING_FIELDS
)

_QUALIFYING_ATTRIBUTES = """
    id
    created_at
    from { %s }
    to { ... on AttackPattern { id name } }
""" % _OBSERVABLE_FIELDS

_RELATED_ATTRIBUTES = """
    id
    relationship_type
    %s
    from { %s }
    to { %s }
""" % (MARKING_FIELDS, _ENDPOINT_FIELDS, _ENDPOINT_FIELDS)

_BASED_ON_ATTRIBUTES = """
    id
    to { %s }
""" % _OBSERVABLE_FIELDS

_INDICATES_ATTRIBUTES = """
    id
    to { ... on AttackPattern { id } }
"""

INDICATOR_ATTRIBUTES = """
    id
    standard_id
    name
    pattern
    pattern_type
    confidence
    x_opencti_score
    created
    modified
    valid_from
    valid_until
    revoked
    indicator_types
    x_opencti_main_observable_type
    %s
    objectLabel { id value }
    createdBy { ... on Identity { id } }
""" % MARKING_FIELDS


def creator_id(indicator: Dict[str, Any]) -> Optional[str]:
    return (indicator.get("createdBy") or {}).get("id")


class OpenCTIClient:
    def __init__(self, helper: Any, author_name: str, dry_run: bool) -> None:
        self.helper = helper
        self.api = helper.api
        self.author_name = author_name
        self.dry_run = dry_run

    def _would(self, action: str) -> None:
        self.helper.connector_logger.debug(f"[DRY RUN] Would {action}")

    # -- reads -------------------------------------------------------------

    def resolve_author(self) -> Optional[str]:
        """Return the id of the author that marks Indicators as ours.

        Dry-run only looks it up, so the result is None until the first live
        run creates it. The name is deliberately independent of CONNECTOR_NAME.
        """
        if self.dry_run:
            stix_id = Identity.generate_id(self.author_name, "organization")
            found = self.api.identity.read(id=stix_id)
            return found["id"] if found else None
        author = self.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Creates and maintains Indicators promoted from Observables.",
        )
        return author["id"]

    def marking_definitions(self) -> List[Dict[str, Any]]:
        return self.api.marking_definition.list()

    def default_marking(self) -> Dict[str, Any]:
        """Fetch the TLP:AMBER+STRICT definition used for unmarked observables.

        pycti's marking list ignores server-side filters, so match here. Raises
        if it is missing, rather than creating unmarked Indicators.
        """
        for marking in self.marking_definitions():
            if marking.get("definition") == "TLP:AMBER+STRICT":
                return marking
        raise RuntimeError("TLP:AMBER+STRICT marking definition not found.")

    def qualifying_relationships(self) -> List[Dict[str, Any]]:
        """Every related-to Attack Pattern relationship.

        Sources that are not observables come back with an empty "from" and are
        skipped by the caller. Filtering on the abstract observable type here
        is not reliable on relationship queries.
        """
        return self.api.stix_core_relationship.list(
            relationship_type="related-to",
            toTypes=["Attack-Pattern"],
            customAttributes=_QUALIFYING_ATTRIBUTES,
            getAll=True,
        )

    def observable_relationships(self, observable_id: str) -> List[Dict[str, Any]]:
        return self.api.stix_core_relationship.list(
            fromOrToId=observable_id,
            customAttributes=_RELATED_ATTRIBUTES,
            getAll=True,
        )

    def owned_indicators(self, author_id: Optional[str]) -> List[Dict[str, Any]]:
        """All Indicators we authored, revoked included so revocations export."""
        if author_id is None:
            return []
        return self.api.indicator.list(
            filters={
                "mode": "and",
                "filters": [{"key": "createdBy", "values": [author_id]}],
                "filterGroups": [],
            },
            customAttributes=INDICATOR_ATTRIBUTES,
            getAll=True,
        )

    def read_indicator(self, stix_id: str) -> Optional[Dict[str, Any]]:
        return self.api.indicator.read(id=stix_id, customAttributes=INDICATOR_ATTRIBUTES)

    def based_on_observable(self, indicator_id: str) -> Optional[Dict[str, Any]]:
        relationships = self.api.stix_core_relationship.list(
            fromId=indicator_id,
            relationship_type="based-on",
            customAttributes=_BASED_ON_ATTRIBUTES,
            getAll=True,
        )
        for relationship in relationships:
            observable = relationship.get("to") or {}
            if observable.get("id"):
                return observable
        return None

    def indicates_edges(self, indicator_id: str) -> Dict[str, str]:
        """Map Attack Pattern id to relationship id for an Indicator."""
        relationships = self.api.stix_core_relationship.list(
            fromId=indicator_id,
            relationship_type="indicates",
            toTypes=["Attack-Pattern"],
            customAttributes=_INDICATES_ATTRIBUTES,
            getAll=True,
        )
        edges: Dict[str, str] = {}
        for relationship in relationships:
            target = (relationship.get("to") or {}).get("id")
            if target:
                edges[target] = relationship["id"]
        return edges

    # -- writes ------------------------------------------------------------

    def create_indicator(self, **fields: Any) -> Optional[Dict[str, Any]]:
        if self.dry_run:
            self._would(f"create Indicator {fields.get('pattern')}")
            return None
        created = self.api.indicator.create(pattern_type="stix", **fields)
        if not created:
            raise RuntimeError(f"Indicator create returned nothing: {fields.get('name')}")
        return created

    def create_relationship(
        self,
        from_id: str,
        to_id: str,
        relationship_type: str,
        confidence: int,
        author_id: Optional[str],
        marking_ids: List[str],
    ) -> None:
        if self.dry_run:
            self._would(f"link {from_id} {relationship_type} {to_id}")
            return
        self.api.stix_core_relationship.create(
            fromId=from_id,
            toId=to_id,
            relationship_type=relationship_type,
            confidence=confidence,
            createdBy=author_id,
            objectMarking=marking_ids,
        )

    def delete_relationship(self, relationship_id: str) -> None:
        if self.dry_run:
            self._would(f"delete relationship {relationship_id}")
            return
        self.api.stix_core_relationship.delete(id=relationship_id)

    def add_marking(self, indicator_id: str, marking_id: str) -> None:
        if self.dry_run:
            self._would(f"add marking {marking_id} to {indicator_id}")
            return
        self.api.stix_domain_object.add_marking_definition(
            id=indicator_id, marking_definition_id=marking_id
        )

    def _patch(self, indicator_id: str, edits: List[Dict[str, Any]]) -> None:
        if self.dry_run:
            self._would(f"patch {indicator_id}: {edits}")
            return
        self.api.indicator.update_field(id=indicator_id, input=edits)

    def update_assessment(
        self, indicator_id: str, score: int, indicator_types: List[str]
    ) -> None:
        self._patch(
            indicator_id,
            [
                {"key": "x_opencti_score", "value": [score]},
                {"key": "confidence", "value": [score]},
                {"key": "indicator_types", "value": indicator_types},
            ],
        )

    def ensure_grouping(
        self, name: str, author_id: Optional[str], marking_ids: List[str]
    ) -> str:
        """Create the Grouping, or return the existing one for that name.

        The id comes from the name and context, so every cycle in a day lands
        on the same Grouping.
        """
        grouping = self.api.grouping.create(
            stix_id=Grouping.generate_id(name, GROUPING_CONTEXT),
            name=name,
            context=GROUPING_CONTEXT,
            description="Indicators created or exported on this date (US Eastern).",
            createdBy=author_id,
            objectMarking=marking_ids,
        )
        if not grouping:
            raise RuntimeError(f"Grouping create returned nothing: {name}")
        return grouping["id"]

    def add_to_grouping(self, grouping_id: str, indicator_id: str) -> None:
        self.api.grouping.add_stix_object_or_stix_relationship(
            id=grouping_id, stixObjectOrStixRelationshipId=indicator_id
        )

    def set_valid_until(self, indicator_id: str, value: Optional[str]) -> None:
        self._patch(
            indicator_id,
            [{"key": "valid_until", "value": [value] if value else []}],
        )

    def revoke(self, indicator_id: str) -> None:
        self._patch(indicator_id, [{"key": "revoked", "value": [True]}])
