from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from util.graph import (
    extract_relationship_endpoints,
    normalize_rel_type,
    obj_display_name,
    resolve_endpoint,
    safe_get,
)

# Observable types that MUST have a related-to link to a named Identity
# per the ingestion manual's observable-to-Identity rule.
_OBSERVABLE_TYPES = frozenset({
    "IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "File",
    "Email-Addr", "Email-Message", "Autonomous-System", "Windows-Registry-Key",
    "Mutex", "User-Account", "Network-Traffic", "Process", "X509-Certificate",
    "Directory", "Software", "Persona", "Mac-Addr",
})

# Identity types that satisfy the observable-to-Identity rule
_IDENTITY_TYPES = frozenset({
    "Threat-Actor", "Intrusion-Set", "Campaign", "Organization",
    "Individual", "System", "Incident",
})


def qa_contextualization(
    report_internal_id: str,
    resolved_objects: Dict[str, Dict[str, Any]],
    relationship_ids: List[str],
    read_relationship_fn: Callable,
    read_any_object_fn: Callable,
) -> Dict[str, Any]:
    """
    Requirements:
      1. Every entity in scope MUST be contextualized by at least one relationship.
      2. Relationships MUST have descriptions.
      3. Every Observable MUST have at least one 'related-to' relationship
         linking it to a named Identity (manual: observable-to-Identity rule).

    Cross-scope relationships count as valid contextualization for in-scope endpoints.
    """
    adjacency: Dict[str, int] = {}
    rel_missing_desc_rows: List[Tuple[str, str, str, str]] = []

    # Track observable -> identity related-to links
    # obs_id -> set of target entity_types it is related-to
    obs_identity_links: Dict[str, Set[str]] = {}

    for rid in relationship_ids:
        rel = read_relationship_fn(rid)
        if not rel:
            continue

        rtype = normalize_rel_type(
            str(safe_get(rel, "relationship_type", "relationshipType") or "(unknown)")
        )
        from_id, to_id, from_inline, to_inline = extract_relationship_endpoints(rel)

        # Adjacency — cross-scope counts
        if from_id:
            adjacency[from_id] = adjacency.get(from_id, 0) + 1
        if to_id:
            adjacency[to_id] = adjacency.get(to_id, 0) + 1

        # Resolve endpoints for display and observable check
        src_obj = from_inline or resolve_endpoint(read_any_object_fn, resolved_objects, from_id)
        tgt_obj = to_inline or resolve_endpoint(read_any_object_fn, resolved_objects, to_id)
        src_name = obj_display_name(src_obj, fallback_id=from_id)
        tgt_name = obj_display_name(tgt_obj, fallback_id=to_id)

        # Description check
        desc = safe_get(rel, "description")
        if not desc or not str(desc).strip():
            rel_missing_desc_rows.append((
                src_name, rtype, tgt_name,
                "Relationship missing description (required for contextualization).",
            ))

        # Observable-to-Identity check (#4)
        # The observable must be the SOURCE of a related-to relationship
        if rtype == "related-to" and from_id:
            src_et = (
                safe_get(src_obj or {}, "entity_type", "entityType") or ""
            ).strip()
            tgt_et = (
                safe_get(tgt_obj or {}, "entity_type", "entityType") or ""
            ).strip()

            if src_et in _OBSERVABLE_TYPES and tgt_et in _IDENTITY_TYPES:
                if from_id not in obs_identity_links:
                    obs_identity_links[from_id] = set()
                obs_identity_links[from_id].add(tgt_et)

    # Uncontextualized entities
    unctx_rows: List[Tuple[str, str, str, str]] = []
    orphaned_obs_rows: List[Tuple[str, str, str, str]] = []

    for oid, obj in resolved_objects.items():
        et = (safe_get(obj, "entity_type", "entityType") or "").strip()
        if et.lower() == "report":
            continue

        name = obj_display_name(obj, fallback_id=oid)

        # General contextualization
        if adjacency.get(oid, 0) == 0:
            unctx_rows.append((
                name, "uncontextualized", name,
                "Entity has no relationships to any other entity in this report container.",
            ))

        # Observable-to-Identity rule (#4)
        if et in _OBSERVABLE_TYPES:
            if oid not in obs_identity_links:
                orphaned_obs_rows.append((
                    name, "missing-identity-link", name,
                    (
                        f"{et} observable MUST have a 'related-to' relationship "
                        "linking it to a named Identity (Threat-Actor, Intrusion-Set, "
                        "Campaign, Organization, Individual, or System). "
                        "The observable must be the source of the relationship."
                    ),
                ))

    rows = unctx_rows + rel_missing_desc_rows + orphaned_obs_rows

    if not rows:
        return {
            "section": "Contextualization",
            "severity": "INFO",
            "code": "QA.CONTEXT.001",
            "title": "Contextualization satisfied",
            "norm": (
                "All entities MUST be contextualized by relationships with descriptive text. "
                "All observables MUST have a related-to link to a named Identity."
            ),
            "rows": [],
            "evidence": {"report_internal_id": report_internal_id},
            "metrics": {
                "contextualization_gaps": 0,
                "relationships_missing_description": 0,
                "orphaned_observables": 0,
            },
        }

    # Severity: orphaned observables and uncontextualized entities are WARN,
    # missing descriptions alone are also WARN.
    severity = "WARN"

    return {
        "section": "Contextualization",
        "severity": severity,
        "code": "QA.CONTEXT.002",
        "title": "Contextualization deficiencies",
        "norm": (
            "All entities MUST be contextualized by relationships with descriptive text. "
            "All observables MUST have a related-to link to a named Identity."
        ),
        "rows": rows,
        "evidence": {
            "report_internal_id": report_internal_id,
            "uncontextualized_entities": len(unctx_rows),
            "relationships_missing_description": len(rel_missing_desc_rows),
            "orphaned_observables": len(orphaned_obs_rows),
        },
        "metrics": {
            "contextualization_gaps": len(unctx_rows),
            "relationships_missing_description": len(rel_missing_desc_rows),
            "orphaned_observables": len(orphaned_obs_rows),
        },
    }
