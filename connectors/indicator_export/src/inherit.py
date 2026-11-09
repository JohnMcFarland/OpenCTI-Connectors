"""inherit.py - relationships an Indicator inherits from its observable.

An Indicator mirrors its observable's direct links to adversary and
capability entities, using the verbs Data_Model_Relationship_Guide5.csv
permits for indicator-sourced edges (Guide5 rows added 2026-11-07 for
malware, threat-actor-group, threat-actor-individual, campaign and
infrastructure). Attack Patterns are handled by the qualifying rule, not
here. Every other entity type stays reachable through based-on.

Marker: IE-INHERIT-EDGES-V1
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, Iterable, Set, Tuple

# OpenCTI entity_type -> relationship type the Indicator gets (Guide5).
INHERITED_RELATIONSHIPS: Dict[str, str] = {
    "Malware": "indicates",
    "Threat-Actor-Group": "indicates",
    "Threat-Actor-Individual": "indicates",
    "Campaign": "indicates",
    "Infrastructure": "indicates",
    "Tool": "indicates",
    "Intrusion-Set": "related-to",
}

# What the edge query has to cover, per relationship type.
MANAGED_TARGET_TYPES: Dict[str, Tuple[str, ...]] = {
    "indicates": ("Attack-Pattern",) + tuple(
        sorted(t for t, r in INHERITED_RELATIONSHIPS.items() if r == "indicates")
    ),
    "related-to": tuple(
        sorted(t for t, r in INHERITED_RELATIONSHIPS.items() if r == "related-to")
    ),
}

EdgeKey = Tuple[str, str]  # (relationship_type, target internal id)


def inherited_edges(
    observable_id: str, relationships: Iterable[Dict[str, Any]]
) -> Dict[EdgeKey, FrozenSet[str]]:
    """Map each inheritable target to the markings of its source edge(s).

    Relationships are read in both directions. Revoked source edges are not
    inherited. When several edges reach the same target, their markings are
    unioned, so the Indicator's edge is never less restricted than any path.
    """
    found: Dict[EdgeKey, Set[str]] = {}
    for relationship in relationships:
        if relationship.get("revoked"):
            continue
        source = relationship.get("from") or {}
        target = relationship.get("to") or {}
        other = target if source.get("id") == observable_id else source
        if not other.get("id") or other.get("id") == observable_id:
            continue
        verb = INHERITED_RELATIONSHIPS.get(other.get("entity_type") or "")
        if verb is None:
            continue
        markings = {m["id"] for m in relationship.get("objectMarking") or [] if m.get("id")}
        found.setdefault((verb, other["id"]), set()).update(markings)
    return {key: frozenset(ids) for key, ids in found.items()}
