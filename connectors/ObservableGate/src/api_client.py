"""
api_client.py — ObservableGate OpenCTI API Client

Encapsulates all OpenCTI API interactions for the ObservableGate connector.
Mixes pycti helper methods (for CRUD on well-supported entity types) with
raw GraphQL queries and mutations (where pycti does not expose the required
filter combinations or mutation signatures for OpenCTI 6.9.13).

Key OpenCTI 6.9.x constraints encoded here:
- marking_definition.list() ignores server-side filters; client-side matching
  by definition name is required.
- stixCoreRelationshipDelete takes fromId, toId, relationship_type — not an id.
- entity_type on relationship endpoints requires inline fragments:
  ... on BasicObject { entity_type }
- PageInfo uses globalCount (not totalCount) in 6.9.x.
- Identity lookup by standard_id is unreliable; use name + entity_type filter.

All write operations are suppressed in dry_run mode, logging the would-be
action instead. Callers can branch on the return value (True in dry_run)
without needing to know about dry_run themselves.
"""

from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# GraphQL query definitions
# ---------------------------------------------------------------------------

# Fetch all stixCoreRelationships where a StixCyberObservable is the source
# and an Attack Pattern is the target (Observable -> related-to -> Attack Pattern).
# Includes all observable type-specific value fields needed for pattern
# construction, avoiding secondary per-observable lookups.
_QUERY_OBSERVABLE_AP_RELS = """
query ObservableGateAPRels($filters: FilterGroup, $first: Int, $after: ID) {
  stixCoreRelationships(filters: $filters, first: $first, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
      globalCount
    }
    edges {
      node {
        id
        confidence
        created_at
        from {
          ... on StixCyberObservable {
            id
            entity_type
            objectMarking { id definition }
            objectLabel { id value }
            ... on IPv4Addr      { value }
            ... on IPv6Addr      { value }
            ... on DomainName    { value }
            ... on Url           { value }
            ... on EmailAddr     { value }
            ... on MacAddr       { value }
            ... on Mutex         { name }
            ... on WindowsRegistryKey { attribute_key }
            ... on UserAccount   { user_id account_login }
            ... on AutonomousSystem  { number }
            ... on Directory     { path }
            ... on Software      { name }
            ... on StixFile      { name hashes { algorithm hash } }
            ... on X509Certificate {
              hashes { algorithm hash }
              serial_number
            }
          }
        }
        to {
          ... on AttackPattern {
            id
            name
          }
        }
      }
    }
  }
}
"""

# Fetch all relationships touching a specific entity (as source or target),
# used for adversary/victim context determination. elementId matches
# regardless of relationship direction.
_QUERY_ENTITY_ALL_RELS = """
query ObservableGateEntityRels($filters: FilterGroup, $first: Int) {
  stixCoreRelationships(filters: $filters, first: $first) {
    pageInfo { globalCount }
    edges {
      node {
        from { ... on BasicObject { id entity_type } }
        to   { ... on BasicObject { id entity_type } }
      }
    }
  }
}
"""

# Fetch all connector-owned non-revoked Indicators for the reconciliation pass.
_QUERY_CONNECTOR_INDICATORS = """
query ObservableGateIndicators($filters: FilterGroup, $first: Int, $after: ID) {
  indicators(filters: $filters, first: $first, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
      globalCount
    }
    edges {
      node {
        id
        name
        pattern
        confidence
        valid_from
        valid_until
        revoked
        indicator_types
        objectMarking { id definition }
        createdBy { id name }
      }
    }
  }
}
"""

# Fetch relationships for an Indicator (based-on and indicates).
# Filtered by fromId so only outbound relationships are returned.
_QUERY_INDICATOR_RELS = """
query ObservableGateIndicatorRels($filters: FilterGroup, $first: Int) {
  stixCoreRelationships(filters: $filters, first: $first) {
    edges {
      node {
        id
        relationship_type
        from { ... on BasicObject { id entity_type } }
        to   { ... on BasicObject { id entity_type } }
      }
    }
  }
}
"""

# Fetch Observable -> Attack Pattern related-to relationships for a specific
# observable. Used in the reconciliation pass to get the current AP set
# for a given observable, independently of the bulk promotion query.
_QUERY_OBSERVABLE_AP_RELS_FOR_ID = """
query ObservableGateObsAPRels($filters: FilterGroup, $first: Int) {
  stixCoreRelationships(filters: $filters, first: $first) {
    edges {
      node {
        to { ... on BasicObject { id entity_type } }
      }
    }
  }
}
"""

# Delete a STIX core relationship by the full triplet.
# OpenCTI 6.9.x requires fromId + toId + relationship_type; deletion by
# relationship id is not supported by stixCoreRelationshipDelete.
_MUTATION_DELETE_REL = """
mutation ObservableGateDeleteRel(
  $fromId: StixRef!
  $toId: StixRef!
  $relationship_type: String!
) {
  stixCoreRelationshipDelete(
    fromId: $fromId
    toId: $toId
    relationship_type: $relationship_type
  )
}
"""

# Resolve the connector's own identity from the authenticated token.
_QUERY_ME = """
query ObservableGateMe {
  me { id name entity_type }
}
"""

# Find the Organization Identity SDO created for this connector by name.
# The me query returns a User account ID, which the platform rejects for
# createdBy. createdBy requires an Organization or Individual Identity SDO.
# The connector auto-creates an Organization named "[E]<ConnectorName>" on
# first registration — this query finds it by matching on both the plain
# name and the [E]-prefixed variant.
_QUERY_FIND_CONNECTOR_ORG = """
query ObservableGateFindOrg($filters: FilterGroup) {
  identities(filters: $filters, first: 10) {
    edges {
      node { id name entity_type }
    }
  }
}
"""

# Pagination page size for all paginated list queries.
_PAGE_SIZE = 100

# Maximum relationships to retrieve per entity in adversary/victim check.
# Observables with more than this number of relationships are unusual;
# logging a warning rather than failing is the appropriate response.
_MAX_ENTITY_RELS = 500


class ObservableGateAPIClient:
    """
    All OpenCTI API interactions for the ObservableGate connector.

    Provides methods corresponding to each distinct API operation needed by
    the promotion and reconciliation passes. Abstracts the distinction between
    pycti helper calls and raw GraphQL, presenting a uniform interface to
    the connector logic.

    In dry_run mode all write methods log their would-be action and return
    a success value, allowing the connector logic to run without branching
    on dry_run status.

    Args:
        helper: Initialized OpenCTIConnectorHelper instance.
        config: ObservableGateConfig instance.
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        # Cached after first resolution; None until get_connector_identity_id() called.
        self._identity_id: Optional[str] = None

    # ------------------------------------------------------------------
    # Identity resolution
    # ------------------------------------------------------------------

    def get_connector_identity_id(self) -> str:
        """
        Resolve and cache the connector's Organization Identity SDO ID.

        OpenCTI's createdBy field requires an Organization or Individual
        Identity SDO — not a user account ID. The me query returns the
        connector's user account ID, which the platform rejects for createdBy
        with "CreatedBy relation must be an Identity entity".

        When a connector registers, OpenCTI auto-creates an Organization
        named "[E]<ConnectorName>". This method finds that Organization by
        querying identities filtered to the connector name (both plain and
        [E]-prefixed variants), matching client-side.

        Falls back to the me query ID if the Organization cannot be found,
        logging a warning so the failure is visible.

        Returns:
            The connector Organization Identity SDO's internal UUID.

        Raises:
            RuntimeError: If neither the Organization nor the me query
                          identity can be resolved.
        """
        if self._identity_id is not None:
            return self._identity_id

        connector_name = self.config.connector_name
        prefixed_name = f"[E]{connector_name}"

        # Search for the Organization Identity SDO by name. Try both the
        # plain connector name and the [E]-prefixed variant that OpenCTI
        # applies to external connector Organizations.
        for candidate_name in [prefixed_name, connector_name]:
            try:
                filters = {
                    "mode": "and",
                    "filters": [
                        {
                            "key": "name",
                            "values": [candidate_name],
                            "operator": "eq",
                            "mode": "or",
                        }
                    ],
                    "filterGroups": [],
                }
                response = self.helper.api.query(
                    _QUERY_FIND_CONNECTOR_ORG, {"filters": filters}
                )
                edges = (
                    (response or {})
                    .get("data", {})
                    .get("identities", {})
                    .get("edges", [])
                )
                for edge in edges:
                    node = edge.get("node", {})
                    # Validate client-side: name must match exactly and
                    # entity_type must be Organization.
                    if (
                        node.get("name") == candidate_name
                        and node.get("entity_type") == "Organization"
                    ):
                        self._identity_id = node["id"]
                        self.helper.log_info(
                            f"Connector identity resolved: "
                            f"{node['name']} ({self._identity_id})"
                        )
                        return self._identity_id
            except Exception as e:
                self.helper.log_warning(
                    f"Identity lookup for '{candidate_name}' failed: {e}"
                )

        # Fallback: me query. Will likely be rejected by createdBy but
        # logged clearly so the failure is traceable.
        self.helper.log_warning(
            f"Could not find Organization Identity for connector "
            f"'{connector_name}'. Falling back to me query ID — "
            "this will likely fail createdBy validation."
        )
        result = self.helper.api.query(_QUERY_ME, {})
        me = (result or {}).get("data", {}).get("me")
        if not me or not me.get("id"):
            raise RuntimeError(
                "Failed to resolve connector identity via fallback me query. "
                "Verify that OPENCTI_TOKEN is valid and the connector user exists."
            )
        self._identity_id = me["id"]
        self.helper.log_info(
            f"Connector identity (fallback): {me.get('name')} ({self._identity_id})"
        )
        return self._identity_id

    # ------------------------------------------------------------------
    # Pass 1 — Qualifying observable discovery
    # ------------------------------------------------------------------

    def get_qualifying_observables(self) -> Dict[str, Dict[str, Any]]:
        """
        Query all Observables with at least one Related To -> Attack Pattern
        relationship, aggregated by observable ID.

        Paginates through all stixCoreRelationships where:
        - relationship_type = "related-to"
        - target type = "Attack-Pattern"

        Observable is always the source per the data model:
        Observable -> related-to -> Attack Pattern.

        Excluded observable types (Network-Traffic, and any additional types
        from GATE_EXCLUDED_OBSERVABLE_TYPES) are filtered client-side after
        retrieval. Server-side entity_type filtering on relationship queries
        is not reliable across all OpenCTI 6.9.x deployments.

        Returns:
            Dict mapping observable_id -> {
                "observable":        Raw observable dict (entity_type + value fields).
                "attack_patterns":   List of {"id": str, "name": str} dicts.
                "min_rel_confidence": Minimum confidence across all AP relationships,
                                      reserved for future threshold logic.
                "earliest_rel_date": ISO string of earliest AP relationship
                                     created_at, used for Indicator valid_from.
            }
        """
        filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "relationship_type",
                    "values": ["related-to"],
                    "operator": "eq",
                    "mode": "or",
                },
                {
                    "key": "toTypes",
                    "values": ["Attack-Pattern"],
                    "operator": "eq",
                    "mode": "or",
                },
            ],
            "filterGroups": [],
        }

        result: Dict[str, Dict[str, Any]] = {}
        # Track observable IDs already excluded to suppress duplicate skip log
        # lines. The exclusion check runs per-edge; an observable with multiple
        # AP relationships would otherwise log once per edge rather than once.
        excluded_logged: set = set()
        cursor: Optional[str] = None
        page = 0

        while True:
            page += 1
            variables = {"filters": filters, "first": _PAGE_SIZE, "after": cursor}
            response = self.helper.api.query(_QUERY_OBSERVABLE_AP_RELS, variables)

            data = (response or {}).get("data", {}).get("stixCoreRelationships", {})
            edges = data.get("edges", [])
            page_info = data.get("pageInfo", {})

            self.helper.log_info(
                f"[Pass 1] AP relationship page {page}: {len(edges)} edges "
                f"(total: {page_info.get('globalCount', '?')})"
            )

            for edge in edges:
                node = edge.get("node", {})
                from_entity = node.get("from") or {}
                to_entity = node.get("to") or {}

                # Skip edges where either endpoint resolved to null (can occur
                # when an entity has been soft-deleted between the relationship
                # and the query).
                if not from_entity.get("id") or not to_entity.get("id"):
                    continue

                observable_id: str = from_entity["id"]
                ap_id: str = to_entity["id"]
                entity_type: str = from_entity.get("entity_type", "")

                # Apply type exclusions client-side. Log only on first
                # encounter per observable to avoid per-edge duplicate lines.
                if entity_type in self.config.excluded_observable_types:
                    if observable_id not in excluded_logged:
                        self.helper.log_info(
                            f"[Pass 1] Skipping excluded type '{entity_type}' "
                            f"(observable {observable_id})"
                        )
                        excluded_logged.add(observable_id)
                    continue

                # Apply label exclusions client-side. Log only on first encounter.
                # objectLabel is fetched in the query response; no secondary
                # lookup needed. Any match on an excluded label skips the
                # observable regardless of its AP relationships.
                if self.config.excluded_labels:
                    obs_labels = {
                        lbl.get("value", "")
                        for lbl in (from_entity.get("objectLabel") or [])
                    }
                    matched = obs_labels & self.config.excluded_labels
                    if matched:
                        if observable_id not in excluded_logged:
                            self.helper.log_info(
                                f"[Pass 1] Skipping observable {observable_id} "
                                f"({entity_type}): excluded label(s) {matched}"
                            )
                            excluded_logged.add(observable_id)
                        continue

                # Initialise entry on first encounter of this observable.
                if observable_id not in result:
                    result[observable_id] = {
                        "observable": from_entity,
                        "attack_patterns": [],
                        "min_rel_confidence": node.get("confidence", 50),
                        "earliest_rel_date": node.get("created_at"),
                    }

                entry = result[observable_id]

                # Accumulate Attack Patterns, deduplicated by ID.
                ap_entry = {"id": ap_id, "name": to_entity.get("name", "")}
                if ap_entry not in entry["attack_patterns"]:
                    entry["attack_patterns"].append(ap_entry)

                # Track minimum confidence across all qualifying AP relationships.
                rel_confidence = node.get("confidence") or 50
                if rel_confidence < entry["min_rel_confidence"]:
                    entry["min_rel_confidence"] = rel_confidence

                # Track earliest AP relationship date for Indicator valid_from.
                rel_date = node.get("created_at")
                if rel_date and (
                    not entry["earliest_rel_date"]
                    or rel_date < entry["earliest_rel_date"]
                ):
                    entry["earliest_rel_date"] = rel_date

            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")

        self.helper.log_info(
            f"[Pass 1] Qualifying observable count: {len(result)}"
        )
        return result

    def has_adversary_or_victim(self, observable_id: str) -> bool:
        """
        Determine whether an observable has a relationship to an adversary
        or victim entity type, used to select confidence floor vs. ceiling.

        Adversary types: Malware, Intrusion-Set, Threat-Actor-Group
        Victim types: Organization, Individual

        Tool is excluded from the adversary set. Tool lacks inherent adversary
        character without an Attack Pattern, and Attack Pattern is already
        the mandatory base condition for Indicator promotion. Including Tool
        would add no additional signal beyond what the mandatory AP condition
        already provides.

        Queries all relationships touching the observable regardless of
        direction (elementId filter), then filters connected entity types
        client-side. Direction-agnostic because adversary relationships in
        the data model are typically entity-as-source pointing at the
        observable (e.g. Malware -> related-to -> Observable), while
        victim relationships may occur in either direction.

        Args:
            observable_id: Internal ID of the observable to check.

        Returns:
            True if any connected entity is of an adversary or victim type.
        """
        qualifying_types = (
            self.config.ADVERSARY_ENTITY_TYPES | self.config.VICTIM_ENTITY_TYPES
        )

        filters = {
            "mode": "and",
            "filters": [],
            "filterGroups": [
                {
                    "mode": "or",
                    "filters": [
                        {
                            "key": "fromId",
                            "values": [observable_id],
                            "operator": "eq",
                            "mode": "or",
                        },
                        {
                            "key": "toId",
                            "values": [observable_id],
                            "operator": "eq",
                            "mode": "or",
                        },
                    ],
                    "filterGroups": [],
                }
            ],
        }

        response = self.helper.api.query(
            _QUERY_ENTITY_ALL_RELS,
            {"filters": filters, "first": _MAX_ENTITY_RELS},
        )

        data = (response or {}).get("data", {}).get("stixCoreRelationships", {})
        global_count = data.get("pageInfo", {}).get("globalCount", 0)

        if global_count > _MAX_ENTITY_RELS:
            self.helper.log_warning(
                f"Observable {observable_id} has {global_count} relationships. "
                f"Only the first {_MAX_ENTITY_RELS} were checked for adversary/victim "
                "context. Confidence may be underestimated if qualifying relationships "
                "fall beyond this window."
            )

        for edge in data.get("edges", []):
            node = edge.get("node", {})
            for end in ("from", "to"):
                entity = node.get(end) or {}
                if entity.get("entity_type") in qualifying_types:
                    return True

        return False

    # ------------------------------------------------------------------
    # Pass 1 — Existing indicator lookup
    # ------------------------------------------------------------------

    def get_existing_indicator(
        self, observable_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check whether a connector-owned Indicator already exists for this
        observable, identified by a based-on relationship from the Indicator
        to the observable.

        Queries inbound based-on relationships on the observable (toId =
        observable_id, relationship_type = "based-on"), then verifies
        connector ownership via createdBy match against the connector's
        identity ID. This prevents the connector from treating indicators
        created by analysts or other connectors as its own.

        Args:
            observable_id: Internal ID of the observable.

        Returns:
            Full Indicator dict if a connector-owned based-on Indicator exists,
            else None.
        """
        identity_id = self.get_connector_identity_id()

        filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "toId",
                    "values": [observable_id],
                    "operator": "eq",
                    "mode": "or",
                },
                {
                    "key": "relationship_type",
                    "values": ["based-on"],
                    "operator": "eq",
                    "mode": "or",
                },
            ],
            "filterGroups": [],
        }

        response = self.helper.api.query(
            _QUERY_INDICATOR_RELS,
            {"filters": filters, "first": 50},
        )

        edges = (
            (response or {})
            .get("data", {})
            .get("stixCoreRelationships", {})
            .get("edges", [])
        )

        for edge in edges:
            node = edge.get("node", {})
            from_entity = node.get("from") or {}
            if from_entity.get("entity_type") == "Indicator":
                indicator_id = from_entity.get("id")
                if not indicator_id:
                    continue
                # Read the full indicator to verify createdBy ownership.
                indicator = self.helper.api.indicator.read(id=indicator_id)
                if indicator:
                    creator = (indicator.get("createdBy") or {}).get("id")
                    if creator == identity_id:
                        return indicator

        return None

    # ------------------------------------------------------------------
    # Pass 1 — Indicator and relationship creation
    # ------------------------------------------------------------------

    def create_indicator(
        self,
        name: str,
        pattern: str,
        valid_from: str,
        confidence: int,
        indicator_types: List[str],
        main_observable_type: str,
        marking_ids: List[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Create an Indicator entity in OpenCTI.

        The pattern string drives the STIX ID via deterministic hashing.
        Identical patterns on repeated runs produce identical IDs, causing
        the platform to merge rather than duplicate — this is the primary
        deduplication mechanism alongside the based-on relationship check.

        In dry_run mode, logs the would-be creation and returns a synthetic
        dict so callers can proceed without branching on dry_run status.

        Args:
            name:                  Human-readable name for the Indicator.
            pattern:               STIX 2.1 pattern string.
            valid_from:            ISO 8601 datetime string.
            confidence:            Confidence score (0-100).
            indicator_types:       STIX indicator_types list.
            main_observable_type:  OpenCTI x_opencti_main_observable_type,
                                   used for display and filtering.
            marking_ids:           List of marking definition internal UUIDs.

        Returns:
            Created Indicator dict with at minimum an 'id' field, or None
            on API failure.
        """
        identity_id = self.get_connector_identity_id()

        if self.config.dry_run:
            self.helper.log_info(
                f"[DRY RUN] Would create Indicator: name='{name}' "
                f"| pattern='{pattern}' | confidence={confidence} "
                f"| types={indicator_types}"
            )
            # Return a synthetic dict so callers can continue normally.
            return {"id": f"dry-run-{abs(hash(pattern))}"}

        try:
            indicator = self.helper.api.indicator.create(
                name=name,
                pattern=pattern,
                pattern_type="stix",
                valid_from=valid_from,
                confidence=confidence,
                createdBy=identity_id,
                objectMarking=marking_ids,
                indicator_types=indicator_types,
                x_opencti_main_observable_type=main_observable_type,
            )
            return indicator
        except Exception as e:
            self.helper.log_error(f"create_indicator failed for '{name}': {e}")
            return None

    def create_relationship(
        self,
        from_id: str,
        to_id: str,
        relationship_type: str,
        confidence: int,
        marking_ids: List[str],
    ) -> bool:
        """
        Create a STIX core relationship between two entities.

        Used for both:
        - based-on: Indicator (from) -> Observable (to)
        - indicates: Indicator (from) -> Attack Pattern (to)

        In dry_run mode, logs and returns True.

        Args:
            from_id:           Source entity internal ID.
            to_id:             Target entity internal ID.
            relationship_type: STIX relationship type string.
            confidence:        Relationship confidence score.
            marking_ids:       List of marking definition internal UUIDs.

        Returns:
            True on success or dry_run, False on API failure.
        """
        identity_id = self.get_connector_identity_id()

        if self.config.dry_run:
            self.helper.log_info(
                f"[DRY RUN] Would create relationship: "
                f"{from_id} --[{relationship_type}]--> {to_id}"
            )
            return True

        try:
            self.helper.api.stix_core_relationship.create(
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
                confidence=confidence,
                createdBy=identity_id,
                objectMarking=marking_ids,
            )
            return True
        except Exception as e:
            self.helper.log_error(
                f"create_relationship failed: "
                f"{from_id} --[{relationship_type}]--> {to_id}: {e}"
            )
            return False

    def delete_relationship(
        self,
        from_id: str,
        to_id: str,
        relationship_type: str,
    ) -> bool:
        """
        Delete a STIX core relationship by the full fromId/toId/type triplet.

        OpenCTI 6.9.x does not support relationship deletion by id field alone;
        the stixCoreRelationshipDelete mutation requires the full triplet.

        Args:
            from_id:           Source entity internal ID.
            to_id:             Target entity internal ID.
            relationship_type: STIX relationship type string.

        Returns:
            True on success or dry_run, False on failure.
        """
        if self.config.dry_run:
            self.helper.log_info(
                f"[DRY RUN] Would delete relationship: "
                f"{from_id} --[{relationship_type}]--> {to_id}"
            )
            return True

        try:
            self.helper.api.query(
                _MUTATION_DELETE_REL,
                {
                    "fromId": from_id,
                    "toId": to_id,
                    "relationship_type": relationship_type,
                },
            )
            return True
        except Exception as e:
            self.helper.log_error(
                f"delete_relationship failed: "
                f"{from_id} --[{relationship_type}]--> {to_id}: {e}"
            )
            return False

    # ------------------------------------------------------------------
    # Pass 2 — Reconciliation queries
    # ------------------------------------------------------------------

    def get_connector_indicators(self) -> List[Dict[str, Any]]:
        """
        Retrieve all non-revoked Indicators created by this connector.

        This is the full working set for the reconciliation pass. Paginated
        using the same cursor pattern as the promotion pass queries.

        Returns:
            List of Indicator dicts, each including id, pattern, confidence,
            valid_from, valid_until, revoked, indicator_types, objectMarking,
            and createdBy.
        """
        identity_id = self.get_connector_identity_id()

        filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "createdBy",
                    "values": [identity_id],
                    "operator": "eq",
                    "mode": "or",
                },
                {
                    "key": "revoked",
                    "values": ["false"],
                    "operator": "eq",
                    "mode": "or",
                },
            ],
            "filterGroups": [],
        }

        indicators: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        page = 0

        while True:
            page += 1
            variables = {"filters": filters, "first": _PAGE_SIZE, "after": cursor}
            response = self.helper.api.query(_QUERY_CONNECTOR_INDICATORS, variables)

            data = (response or {}).get("data", {}).get("indicators", {})
            edges = data.get("edges", [])
            page_info = data.get("pageInfo", {})

            self.helper.log_info(
                f"[Pass 2] Connector indicator page {page}: {len(edges)} indicators "
                f"(total: {page_info.get('globalCount', '?')})"
            )

            indicators.extend(
                edge["node"] for edge in edges if edge.get("node")
            )

            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")

        return indicators

    def get_indicator_based_on_observable(
        self, indicator_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Resolve the Observable linked to an Indicator via the based-on relationship.

        Queries outbound relationships from the Indicator filtered to
        relationship_type = "based-on". Returns the target (Observable) entity,
        or None if the based-on link is absent or the observable was deleted.

        A connector-owned Indicator should always have exactly one based-on link.
        Multiple links are anomalous and logged; the first is returned.

        Args:
            indicator_id: Internal ID of the Indicator.

        Returns:
            Observable dict with 'id' and 'entity_type', or None.
        """
        filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "fromId",
                    "values": [indicator_id],
                    "operator": "eq",
                    "mode": "or",
                },
                {
                    "key": "relationship_type",
                    "values": ["based-on"],
                    "operator": "eq",
                    "mode": "or",
                },
            ],
            "filterGroups": [],
        }

        response = self.helper.api.query(
            _QUERY_INDICATOR_RELS, {"filters": filters, "first": 10}
        )
        edges = (
            (response or {})
            .get("data", {})
            .get("stixCoreRelationships", {})
            .get("edges", [])
        )

        if not edges:
            return None

        if len(edges) > 1:
            self.helper.log_warning(
                f"Indicator {indicator_id} has {len(edges)} based-on links. "
                "Expected exactly 1. Using the first."
            )

        return (edges[0].get("node") or {}).get("to")

    def get_indicator_indicates_aps(
        self, indicator_id: str
    ) -> List[Dict[str, Any]]:
        """
        Retrieve all Attack Patterns linked to an Indicator via indicates.

        Used in the reconciliation pass to determine which AP edges are
        current and which have become stale (no longer present on the
        source observable).

        Args:
            indicator_id: Internal ID of the Indicator.

        Returns:
            List of dicts with 'id' and 'entity_type' for each Attack Pattern
            target. Filters to Attack-Pattern entity type only.
        """
        filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "fromId",
                    "values": [indicator_id],
                    "operator": "eq",
                    "mode": "or",
                },
                {
                    "key": "relationship_type",
                    "values": ["indicates"],
                    "operator": "eq",
                    "mode": "or",
                },
            ],
            "filterGroups": [],
        }

        response = self.helper.api.query(
            _QUERY_INDICATOR_RELS, {"filters": filters, "first": 200}
        )
        edges = (
            (response or {})
            .get("data", {})
            .get("stixCoreRelationships", {})
            .get("edges", [])
        )

        return [
            edge["node"]["to"]
            for edge in edges
            if (edge.get("node") or {}).get("to", {}).get("entity_type")
            == "Attack-Pattern"
        ]

    def get_observable_ap_relationships(
        self, observable_id: str
    ) -> List[Dict[str, Any]]:
        """
        Retrieve the current Attack Patterns related-to a specific observable.

        Used in the reconciliation pass to get the authoritative current AP set
        for a given observable, independently of the bulk Pass 1 query.
        Allows Pass 2 to detect AP relationships removed since Pass 1 ran.

        Args:
            observable_id: Internal ID of the observable.

        Returns:
            List of Attack Pattern dicts with 'id' and 'entity_type'.
        """
        filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "fromId",
                    "values": [observable_id],
                    "operator": "eq",
                    "mode": "or",
                },
                {
                    "key": "relationship_type",
                    "values": ["related-to"],
                    "operator": "eq",
                    "mode": "or",
                },
                {
                    "key": "toTypes",
                    "values": ["Attack-Pattern"],
                    "operator": "eq",
                    "mode": "or",
                },
            ],
            "filterGroups": [],
        }

        response = self.helper.api.query(
            _QUERY_OBSERVABLE_AP_RELS_FOR_ID,
            {"filters": filters, "first": 200},
        )
        edges = (
            (response or {})
            .get("data", {})
            .get("stixCoreRelationships", {})
            .get("edges", [])
        )

        return [
            edge["node"]["to"]
            for edge in edges
            if (edge.get("node") or {}).get("to", {}).get("entity_type")
            == "Attack-Pattern"
        ]

    # ------------------------------------------------------------------
    # Indicator field updates
    # ------------------------------------------------------------------

    def update_indicator_confidence(
        self, indicator_id: str, confidence: int
    ) -> bool:
        """
        Update the confidence score on an existing connector-owned Indicator.

        Called when the adversary/victim context of the source Observable
        changes, causing the Indicator's confidence to move between floor
        and ceiling.

        Args:
            indicator_id: Internal ID of the Indicator.
            confidence:   New confidence value.

        Returns:
            True on success or dry_run, False on failure.
        """
        if self.config.dry_run:
            self.helper.log_info(
                f"[DRY RUN] Would update confidence on {indicator_id} -> {confidence}"
            )
            return True
        try:
            self.helper.api.indicator.update_field(
                id=indicator_id,
                input={"key": "confidence", "value": confidence},
            )
            return True
        except Exception as e:
            self.helper.log_error(
                f"update_indicator_confidence failed on {indicator_id}: {e}"
            )
            return False

    def set_indicator_valid_until(
        self, indicator_id: str, valid_until: str
    ) -> bool:
        """
        Set valid_until on an Indicator, entering the decay state.

        The presence of valid_until on a connector-owned Indicator is the
        canonical decay marker. Indicators created by this connector never
        have valid_until set at creation time; any Indicator with valid_until
        set is by definition in the decay lifecycle.

        Downstream TAXII consumers receive the valid_until date, giving them
        advance notice of the detection rule's sunset before revocation occurs.

        Args:
            indicator_id: Internal ID of the Indicator.
            valid_until:  ISO 8601 datetime string for the decay expiry.

        Returns:
            True on success or dry_run, False on failure.
        """
        if self.config.dry_run:
            self.helper.log_info(
                f"[DRY RUN] Would set valid_until on {indicator_id} -> {valid_until}"
            )
            return True
        try:
            self.helper.api.indicator.update_field(
                id=indicator_id,
                input={"key": "valid_until", "value": valid_until},
            )
            return True
        except Exception as e:
            self.helper.log_error(
                f"set_indicator_valid_until failed on {indicator_id}: {e}"
            )
            return False

    def clear_indicator_valid_until(self, indicator_id: str) -> bool:
        """
        Clear valid_until on an Indicator, restoring it to fully active state.

        Called when the qualifying condition is re-met during the decay window.
        Clearing valid_until removes the sunset signal from the TAXII feed,
        indicating to downstream consumers that the detection rule is current.

        Args:
            indicator_id: Internal ID of the Indicator to restore.

        Returns:
            True on success or dry_run, False on failure.
        """
        if self.config.dry_run:
            self.helper.log_info(
                f"[DRY RUN] Would clear valid_until on {indicator_id}"
            )
            return True
        try:
            self.helper.api.indicator.update_field(
                id=indicator_id,
                input={"key": "valid_until", "value": None},
            )
            return True
        except Exception as e:
            self.helper.log_error(
                f"clear_indicator_valid_until failed on {indicator_id}: {e}"
            )
            return False

    def revoke_indicator(self, indicator_id: str, reason: str) -> bool:
        """
        Revoke an Indicator by setting revoked=True.

        Terminal lifecycle action after the decay window elapses. The Indicator
        remains in the graph with revoked=True, preserving the historical
        record and propagating the STIX revocation signal to TAXII consumers.
        Hard deletion is not used: the audit trail of what the platform
        asserted (and when it stopped asserting it) is analytically valuable.

        Args:
            indicator_id: Internal ID of the Indicator to revoke.
            reason:       Reason code string for the log record.

        Returns:
            True on success or dry_run, False on failure.
        """
        if self.config.dry_run:
            self.helper.log_info(
                f"[DRY RUN] Would revoke {indicator_id} (reason: {reason})"
            )
            return True
        try:
            self.helper.api.indicator.update_field(
                id=indicator_id,
                input={"key": "revoked", "value": True},
            )
            self.helper.log_warning(
                f"TERMINAL: Revoked indicator {indicator_id} | reason: {reason}"
            )
            return True
        except Exception as e:
            self.helper.log_error(
                f"revoke_indicator failed on {indicator_id}: {e}"
            )
            return False

    # ------------------------------------------------------------------
    # Marking helpers
    # ------------------------------------------------------------------

    def get_most_restrictive_marking_ids(
        self, markings: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Select the single most restrictive TLP marking from a list, falling
        back to TLP:AMBER+STRICT if the list is empty.

        Restrictiveness order (least to most):
        TLP:WHITE < TLP:GREEN < TLP:AMBER < TLP:AMBER+STRICT < TLP:RED

        Non-TLP markings (Limited, Restricted, Highly Restricted, Sensitive)
        are treated as maximally restrictive — they are internal markings that
        must always propagate to derived objects.

        Returns a list for compatibility with objectMarking on create calls.

        Args:
            markings: List of marking dicts with 'id' and 'definition' fields.

        Returns:
            Single-element list with the most restrictive marking's ID,
            or TLP:AMBER+STRICT as the fallback default.
        """
        if not markings:
            return self._amber_strict_marking_id()

        tlp_order = [
            "TLP:WHITE",
            "TLP:GREEN",
            "TLP:AMBER",
            "TLP:AMBER+STRICT",
            "TLP:RED",
        ]

        best: Optional[Dict[str, Any]] = None
        best_score = -1

        for marking in markings:
            definition = marking.get("definition", "")
            try:
                score = tlp_order.index(definition)
            except ValueError:
                # Non-TLP internal marking: treat as maximally restrictive.
                score = len(tlp_order)

            if score > best_score:
                best_score = score
                best = marking

        return [best["id"]] if best else self._amber_strict_marking_id()

    def _amber_strict_marking_id(self) -> List[str]:
        """
        Retrieve the TLP:AMBER+STRICT marking definition ID.

        OpenCTI 6.9.x: marking_definition.list() ignores server-side filters.
        Client-side matching by definition name is required.

        Returns:
            Single-element list with TLP:AMBER+STRICT marking ID,
            or empty list with a warning if not found.
        """
        try:
            all_markings = self.helper.api.marking_definition.list()
            for m in all_markings:
                if m.get("definition") == "TLP:AMBER+STRICT":
                    return [m["id"]]
            self.helper.log_warning(
                "TLP:AMBER+STRICT marking definition not found in platform. "
                "Indicator will be created without a marking."
            )
        except Exception as e:
            self.helper.log_error(
                f"Failed to retrieve marking definitions: {e}"
            )
        return []
