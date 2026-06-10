"""
graph_fetcher.py — Container Graph Fetcher
==========================================
Fetches all data needed to render an Obsidian note for an OpenCTI container:
container metadata, all contained objects grouped by entity type, and all
relationships between those objects.

Design decisions:
  - Entity type routing: type-specific pycti API methods are used where
    possible (helper.api.intrusion_set.read(), etc.) because they return
    richer field sets than the generic fallback methods. Generic
    stix_domain_object.read() and stix_cyber_observable.read() are used for
    unrecognized types to ensure forward compatibility with future OpenCTI
    entity types without requiring a connector update.

  - Relationship batch query: relationships are fetched in two passes
    (fromId filter, then toId filter) rather than one OR-filter pass, because
    OpenCTI 6.9.x's filter API may not support OR-mode filters across large
    value lists reliably. Results are merged and deduplicated by relationship ID.
    Only relationships where BOTH endpoints are in the container's object set
    are retained — this excludes relationships to external entities not part
    of this report.

  - objects field normalization: pycti report.read() may return the objects
    field as a flat list or as a GraphQL edges/node structure depending on
    pycti version. Both forms are handled.

  - Error isolation: failures on individual entity fetches are logged at
    WARNING and skipped rather than aborting the export. A partially
    complete note is preferable to no note.
"""

from collections import defaultdict

# ---------------------------------------------------------------------------
# Entity type classification sets
# ---------------------------------------------------------------------------

# SCO (STIX Cyber Observable Object) entity type strings as used by OpenCTI
# 6.9.x internally. These are fetched via helper.api.stix_cyber_observable.read()
# rather than type-specific SDO methods.
OBSERVABLE_ENTITY_TYPES: set[str] = {
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Url",
    "StixFile",           # OpenCTI's internal name for File (hash container) observables
    "Email-Addr",
    "Email-Message",
    "Network-Traffic",
    "Windows-Registry-Key",
    "Mutex",
    "User-Account",
    "X509-Certificate",
    "Bank-Account",
    "Cryptocurrency-Wallet",
    "Autonomous-System",
    "Software",           # Software is a SCO in OpenCTI's model despite being SDO in STIX 2.1
    "Text",
    "Process",
    "User-Agent",
    "Hostname",
    "Payment-Card",
    "Persona",            # OpenCTI custom SCO — represents online handles/monikers
    "Indicator",          # Included here to skip manually-created indicators gracefully
}

# Identity-family SDOs: fetched via helper.api.identity.read()
IDENTITY_ENTITY_TYPES: set[str] = {
    "Organization",
    "Individual",
    "Sector",
    "System",
}

# Location-family SDOs: fetched via helper.api.location.read()
LOCATION_ENTITY_TYPES: set[str] = {
    "Country",
    "Region",
    "City",
    "Position",
    "Administrative-Area",
}


class GraphFetcher:
    """
    Fetches the complete knowledge graph for an OpenCTI container entity.

    Used by the Obsidian Export connector to retrieve all data needed for
    Markdown note generation in a single coordinated fetch sequence.
    """

    def __init__(self, helper, max_objects: int = 500):
        """
        Args:
            helper:      OpenCTIConnectorHelper instance. Used for all API calls
                         and logging throughout the fetch sequence.
            max_objects: Maximum number of contained objects to fetch. Objects
                         beyond this cap are truncated with a warning. The cap
                         limits maximum query payload size and prevents memory
                         issues on very large containers. Default 500 covers
                         the vast majority of real-world reports.
        """
        self.helper = helper
        self.max_objects = max_objects

    def fetch_container(
        self,
        entity_id: str,
        entity_type: str,
        include_observables: bool = True,
    ) -> dict:
        """
        Fetch all data needed to render an Obsidian note for a container.

        Executes three sequential fetch phases:
          1. Container entity (metadata + contained object references)
          2. Full entity details for each contained object
          3. All relationships between contained objects (batch query)

        Args:
            entity_id:           OpenCTI entity ID (STIX format or internal UUID)
            entity_type:         OpenCTI entity type string
            include_observables: If False, SCO Observables are skipped in phase 2.
                                 Relationships to/from observables are still fetched
                                 but will not appear in the note output.

        Returns:
            dict with keys:
              container       — raw container entity dict from pycti
              entity_type     — the entity_type argument, passed through
              objects_by_type — dict: entity_type_str -> list of entity dicts
              relationships   — list of relationship dicts (both endpoints in container)
              object_id_set   — set of all contained object IDs (used by NoteBuilder
                               for relationship endpoint validation)

        Raises:
            ValueError: If the container entity cannot be fetched (not found or
                        API error). Upstream export job will be marked as failed.
        """
        self.helper.log_info(
            f"GraphFetcher: fetching container {entity_type} {entity_id}"
        )

        # Phase 1: fetch container with contained object references
        container = self._fetch_container_entity(entity_id, entity_type)
        if not container:
            raise ValueError(
                f"Container not found or fetch failed: {entity_type} {entity_id}"
            )

        # Phase 2: extract object references from the container's objects field.
        # pycti may return this as a flat list or as a GraphQL edges/node structure.
        raw_objects = container.get("objects") or []
        if isinstance(raw_objects, dict):
            # GraphQL edge structure: {"edges": [{"node": {...}}, ...]}
            raw_objects = [
                edge.get("node", edge)
                for edge in raw_objects.get("edges", [])
            ]
        # Flatten any remaining edge wrappers (defensive)
        object_refs = []
        for item in raw_objects:
            if isinstance(item, dict) and "node" in item:
                object_refs.append(item["node"])
            elif isinstance(item, dict) and "id" in item:
                object_refs.append(item)

        if len(object_refs) > self.max_objects:
            self.helper.log_warning(
                f"Container has {len(object_refs)} objects — "
                f"capping at {self.max_objects}. "
                f"Increase EXPORT_MAX_OBJECTS to include all objects."
            )
            object_refs = object_refs[: self.max_objects]

        # Build ID set for relationship filtering in phase 4
        object_id_set: set[str] = {
            obj["id"] for obj in object_refs if obj.get("id")
        }

        self.helper.log_info(
            f"Container has {len(object_refs)} objects — fetching full details"
        )

        # Phase 3: fetch full entity details for each contained object
        objects_by_type: dict[str, list] = defaultdict(list)
        fetch_errors = 0

        for obj_ref in object_refs:
            obj_id = obj_ref.get("id")
            obj_type = obj_ref.get("entity_type")
            if not obj_id or not obj_type:
                continue

            # Skip Indicators — they are auto-generated from Observables and
            # should not appear in the note as standalone entities
            if obj_type == "Indicator":
                continue

            # Skip Observables if include_observables flag is False
            if not include_observables and obj_type in OBSERVABLE_ENTITY_TYPES:
                continue

            full_obj = self._fetch_entity(obj_id, obj_type)
            if full_obj:
                # Ensure entity_type is present on the fetched object
                # (some pycti versions omit it from the returned dict)
                if "entity_type" not in full_obj:
                    full_obj["entity_type"] = obj_type
                objects_by_type[obj_type].append(full_obj)
            else:
                fetch_errors += 1

        if fetch_errors:
            self.helper.log_warning(
                f"{fetch_errors} entity fetch(es) failed — "
                "those entities will be absent from the note"
            )

        # Phase 4: fetch all relationships between container objects in a
        # single batch query to avoid N+1 per-entity relationship lookups
        relationships = self._fetch_relationships(object_id_set)

        n_objects = sum(len(v) for v in objects_by_type.values())
        self.helper.log_info(
            f"GraphFetcher complete — {n_objects} objects across "
            f"{len(objects_by_type)} types, {len(relationships)} relationships"
        )

        return {
            "container": container,
            "entity_type": entity_type,
            "objects_by_type": dict(objects_by_type),
            "relationships": relationships,
            "object_id_set": object_id_set,
        }

    # ---------------------------------------------------------------------------
    # Container fetch
    # ---------------------------------------------------------------------------

    def _fetch_container_entity(
        self, entity_id: str, entity_type: str
    ) -> dict | None:
        """
        Fetch the container entity with its metadata and contained object list.

        Routes to the type-specific pycti method. Falls back to the generic
        stix_domain_object read for unrecognized container types.

        Args:
            entity_id:   OpenCTI entity ID
            entity_type: OpenCTI entity type string

        Returns:
            Container entity dict, or None if fetch fails.
        """
        try:
            if entity_type == "Report":
                return self.helper.api.report.read(id=entity_id)
            elif entity_type == "Case-Incident":
                return self.helper.api.case_incident.read(id=entity_id)
            elif entity_type == "Case-Rfi":
                return self.helper.api.case_rfi.read(id=entity_id)
            elif entity_type == "Case-Rft":
                return self.helper.api.case_rft.read(id=entity_id)
            elif entity_type == "Grouping":
                return self.helper.api.grouping.read(id=entity_id)
            else:
                self.helper.log_warning(
                    f"Unrecognized container type '{entity_type}' — "
                    "attempting generic stix_domain_object read"
                )
                return self.helper.api.stix_domain_object.read(id=entity_id)
        except Exception as exc:
            self.helper.log_error(
                f"Container fetch failed for {entity_type} {entity_id}: {exc}"
            )
            return None

    # ---------------------------------------------------------------------------
    # Entity fetch routing
    # ---------------------------------------------------------------------------

    def _fetch_entity(self, entity_id: str, entity_type: str) -> dict | None:
        """
        Fetch full entity details for a contained object.

        Routes to the appropriate pycti API method based on entity_type.
        Type-specific methods return richer field sets (aliases, malware_types,
        implementation_languages, etc.) that are used by NoteBuilder for
        context lines and wikilink generation.

        Falls back to generic stix_domain_object or stix_cyber_observable for
        unrecognized entity types — this ensures new OpenCTI entity types
        degrade gracefully rather than raising errors.

        Args:
            entity_id:   OpenCTI entity ID
            entity_type: OpenCTI entity type string

        Returns:
            Entity dict with at minimum: id, name (or value), entity_type.
            Returns None if all fetch attempts fail.
        """
        try:
            # --- Threat entities ---
            if entity_type == "Threat-Actor-Group":
                return self.helper.api.threat_actor_group.read(id=entity_id)
            elif entity_type == "Threat-Actor-Individual":
                # Threat-Actor-Individual may not exist in all pycti 6.9.x builds;
                # fall through to generic on AttributeError
                return self.helper.api.threat_actor_individual.read(id=entity_id)
            elif entity_type == "Intrusion-Set":
                return self.helper.api.intrusion_set.read(id=entity_id)
            elif entity_type == "Campaign":
                return self.helper.api.campaign.read(id=entity_id)

            # --- Capability entities ---
            elif entity_type == "Malware":
                return self.helper.api.malware.read(id=entity_id)
            elif entity_type == "Tool":
                return self.helper.api.tool.read(id=entity_id)
            elif entity_type == "Attack-Pattern":
                return self.helper.api.attack_pattern.read(id=entity_id)
            elif entity_type == "Infrastructure":
                return self.helper.api.infrastructure.read(id=entity_id)
            elif entity_type == "Vulnerability":
                return self.helper.api.vulnerability.read(id=entity_id)
            elif entity_type == "Course-Of-Action":
                return self.helper.api.course_of_action.read(id=entity_id)

            # --- Information operations entities ---
            elif entity_type == "Channel":
                return self.helper.api.channel.read(id=entity_id)
            elif entity_type == "Narrative":
                return self.helper.api.narrative.read(id=entity_id)

            # --- Identity entities (Organization, Individual, Sector, System) ---
            elif entity_type in IDENTITY_ENTITY_TYPES:
                return self.helper.api.identity.read(id=entity_id)

            # --- Location entities (Country, Region, City, etc.) ---
            elif entity_type in LOCATION_ENTITY_TYPES:
                return self.helper.api.location.read(id=entity_id)

            # --- Event entities ---
            elif entity_type == "Incident":
                return self.helper.api.incident.read(id=entity_id)

            # --- Analysis entities ---
            elif entity_type == "Malware-Analysis":
                return self.helper.api.malware_analysis.read(id=entity_id)

            # --- Observable entities ---
            elif entity_type in OBSERVABLE_ENTITY_TYPES:
                return self.helper.api.stix_cyber_observable.read(id=entity_id)

            # --- Unknown type: try SDO, then SCO, then give up ---
            else:
                self.helper.log_debug(
                    f"Unknown entity type '{entity_type}' — "
                    "trying generic SDO read"
                )
                result = self.helper.api.stix_domain_object.read(id=entity_id)
                if result:
                    return result
                # Entity may be a SCO not in our known set
                self.helper.log_debug(
                    f"SDO read returned None for '{entity_type}' — "
                    "trying SCO read"
                )
                return self.helper.api.stix_cyber_observable.read(id=entity_id)

        except AttributeError as exc:
            # Handle the case where a type-specific pycti method does not exist
            # in this version (e.g. threat_actor_individual in some builds)
            self.helper.log_warning(
                f"pycti method not found for entity type '{entity_type}': {exc} — "
                "falling back to generic SDO read"
            )
            try:
                return self.helper.api.stix_domain_object.read(id=entity_id)
            except Exception:
                return None

        except Exception as exc:
            self.helper.log_warning(
                f"Failed to fetch {entity_type} {entity_id}: {exc}"
            )
            return None

    # ---------------------------------------------------------------------------
    # Relationship fetch
    # ---------------------------------------------------------------------------

    def _fetch_relationships(self, object_id_set: set[str]) -> list[dict]:
        """
        Fetch all relationships between the container's contained objects.

        Executes two queries: one filtered by fromId across all object IDs,
        one filtered by toId. Results are merged and deduplicated. Only
        relationships where BOTH endpoints are in the container's object set
        are kept — this prevents relationships to external entities (e.g.
        an Intrusion Set targeting organizations not in this report) from
        appearing in the export note.

        Args:
            object_id_set: Set of entity IDs that are members of this container.

        Returns:
            List of relationship dicts. Each dict has at minimum:
              id, relationship_type, fromId, toId,
              from: {id, name, entity_type},
              to:   {id, name, entity_type}
            May also include: description, confidence, start_time, stop_time.
        """
        if not object_id_set:
            self.helper.log_debug("No objects in container — skipping relationship fetch")
            return []

        object_ids = list(object_id_set)

        try:
            # Fetch relationships where source is in the container object set
            from_rels: list[dict] = (
                self.helper.api.stix_core_relationship.list(
                    fromId=object_ids,
                    getAll=True,
                    withPagination=False,
                )
                or []
            )
            self.helper.log_debug(f"Relationship query (fromId): {len(from_rels)} results")

            # Fetch relationships where target is in the container object set
            to_rels: list[dict] = (
                self.helper.api.stix_core_relationship.list(
                    toId=object_ids,
                    getAll=True,
                    withPagination=False,
                )
                or []
            )
            self.helper.log_debug(f"Relationship query (toId): {len(to_rels)} results")

            # Merge and deduplicate by relationship ID
            all_rels: dict[str, dict] = {
                r["id"]: r for r in from_rels + to_rels if r.get("id")
            }

            # Filter to only intra-container relationships: both endpoints must be
            # members of this container. This excludes relationships that span
            # beyond the report's scope (e.g. an actor targeting external orgs).
            filtered: list[dict] = []
            for rel in all_rels.values():
                from_id = (
                    (rel.get("from") or {}).get("id")
                    or rel.get("fromId")
                    or ""
                )
                to_id = (
                    (rel.get("to") or {}).get("id")
                    or rel.get("toId")
                    or ""
                )
                if from_id in object_id_set and to_id in object_id_set:
                    filtered.append(rel)

            self.helper.log_debug(
                f"Relationship filter: {len(all_rels)} unique -> "
                f"{len(filtered)} intra-container"
            )
            return filtered

        except Exception as exc:
            self.helper.log_error(
                f"Relationship fetch failed: {exc} — "
                "note will be generated without relationship prose"
            )
            return []
