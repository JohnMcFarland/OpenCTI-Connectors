"""Turns an observable's relationships into outbound labels.

These labels exist only on the exported copy of an Indicator. They are never
written to OpenCTI, where labels are reserved for collection requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Set, Tuple

from .markings import within_ceiling

ADVERSARY_ENTITY_TYPES = frozenset(["Malware", "Intrusion-Set", "Threat-Actor-Group"])
VICTIM_ENTITY_TYPES = frozenset(["Organization", "Individual"])

# Same prefixes as QA.LABELS.001 in report_model_qa. These are the only labels
# that exist in OpenCTI by policy, so they pass through unfiltered.
COLLECTION_REQUIREMENT_PREFIXES = ("CR-", "REQ-", "COLREQ-")

# Lower tiers survive when an observable exceeds the label limit.
_TIER_BY_TYPE: Dict[str, int] = {
    "Intrusion-Set": 0,
    "Threat-Actor-Group": 0,
    "Threat-Actor-Individual": 0,
    "Campaign": 0,
    "Malware": 1,
    "Attack-Pattern": 2,
    "Tool": 2,
    "Vulnerability": 2,
    "Infrastructure": 3,
}
_DEFAULT_TIER = 4


@dataclass(frozen=True)
class RelatedEntity:
    entity_type: str
    name: str
    entity_markings: Tuple[Dict[str, Any], ...]
    relationship_markings: Tuple[Dict[str, Any], ...]


@dataclass(frozen=True)
class ObservableContext:
    entities: Tuple[RelatedEntity, ...] = ()
    has_adversary_or_victim: bool = False


@dataclass(frozen=True)
class LabelPolicy:
    marking_ceiling: str
    max_labels: int
    excluded_entity_types: FrozenSet[str]


@dataclass(frozen=True)
class LabelResult:
    labels: Tuple[str, ...]
    dropped: Dict[str, int] = field(default_factory=dict)


def _is_entity(end: Dict[str, Any]) -> bool:
    """True for domain objects. Observables, Indicators and containers are not
    the entities the labels describe."""
    parents = end.get("parent_types") or []
    return (
        "Stix-Domain-Object" in parents
        and "Container" not in parents
        and end.get("entity_type") != "Indicator"
    )


def build_context(
    observable_id: str, relationships: Iterable[Dict[str, Any]]
) -> ObservableContext:
    """Collect the entity on the far side of each relationship.

    Relationships are read in both directions, because the allow-list has
    edges pointing either way (ipv4-addr related-to malware, malware
    communicates-with url).
    """
    entities: List[RelatedEntity] = []
    has_context = False
    for relationship in relationships:
        source = relationship.get("from") or {}
        target = relationship.get("to") or {}
        other = target if source.get("id") == observable_id else source
        if other.get("id") == observable_id:
            continue
        entity_type = other.get("entity_type") or ""
        if entity_type in ADVERSARY_ENTITY_TYPES | VICTIM_ENTITY_TYPES:
            has_context = True
        if not _is_entity(other):
            continue
        entities.append(
            RelatedEntity(
                entity_type=entity_type,
                name=str(other.get("name") or "").strip(),
                entity_markings=tuple(other.get("objectMarking") or ()),
                relationship_markings=tuple(relationship.get("objectMarking") or ()),
            )
        )
    return ObservableContext(tuple(entities), has_context)


def is_collection_requirement(label: str) -> bool:
    return label.startswith(COLLECTION_REQUIREMENT_PREFIXES)


def format_label(entity_type: str, name: str) -> str:
    """Prefix with the type, because names repeat across types."""
    return f"{entity_type.lower()}:{name}"


def build_labels(
    context: ObservableContext,
    inherited_labels: Iterable[str],
    policy: LabelPolicy,
) -> LabelResult:
    """Apply the type, marking and limit rules.

    An entity reached by several relationships is kept if any one of them
    passes the ceiling, since that path alone already permits disclosing it.
    Dropped counts never name the entity, so they are safe to export.
    """
    requirements = sorted(
        {label for label in inherited_labels if is_collection_requirement(label)}
    )

    kept: Dict[str, int] = {}
    over_ceiling: Set[str] = set()
    excluded: Set[str] = set()
    unnamed = 0

    for entity in context.entities:
        if not entity.name:
            unnamed += 1
            continue
        label = format_label(entity.entity_type, entity.name)
        if entity.entity_type in policy.excluded_entity_types:
            excluded.add(label)
        elif within_ceiling(
            entity.entity_markings, policy.marking_ceiling
        ) and within_ceiling(entity.relationship_markings, policy.marking_ceiling):
            kept[label] = _TIER_BY_TYPE.get(entity.entity_type, _DEFAULT_TIER)
        else:
            over_ceiling.add(label)

    over_ceiling -= set(kept)
    ranked = sorted(kept, key=lambda label: (kept[label], label))
    selected = ranked[: policy.max_labels]

    dropped = {
        "marking": len(over_ceiling),
        "excluded_type": len(excluded),
        "limit": len(ranked) - len(selected),
        "unnamed": unnamed,
    }
    return LabelResult(
        labels=tuple(requirements + selected),
        dropped={reason: count for reason, count in dropped.items() if count},
    )
