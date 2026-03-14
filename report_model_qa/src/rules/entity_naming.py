from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from util.graph import safe_get

# ---------------------------------------------------------------------------
# Duplicate entity detection
# ---------------------------------------------------------------------------
# Checks for entities of the same type with identical normalised names within
# the report scope. Duplicates contaminate the graph and produce misleading
# relationship counts.

def _normalise_name(name: str) -> str:
    return re.sub(r"\s+", " ", (name or "").strip().lower())


def qa_duplicate_entities(
    resolved_objects: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Detect entities of the same type with identical or near-identical names
    within the report scope.
    """
    # Build: entity_type -> {normalised_name -> [display_name, ...]}
    type_name_map: Dict[str, Dict[str, List[str]]] = {}

    for obj in resolved_objects.values():
        et = (safe_get(obj, "entity_type", "entityType") or "").strip()
        name = (safe_get(obj, "name") or "").strip()
        if not et or not name:
            continue
        norm = _normalise_name(name)
        if not norm:
            continue
        if et not in type_name_map:
            type_name_map[et] = {}
        if norm not in type_name_map[et]:
            type_name_map[et][norm] = []
        type_name_map[et][norm].append(name)

    rows: List[Tuple[str, str, str, str]] = []
    for et, name_map in type_name_map.items():
        for norm, display_names in name_map.items():
            if len(display_names) >= 2:
                rows.append((
                    et,
                    "duplicate",
                    display_names[0],
                    f"Duplicate {et} entity: {len(display_names)} objects share "
                    f"normalised name '{norm}'. "
                    f"Variants: {display_names}. "
                    "Merge into a single entity to prevent graph fragmentation.",
                ))

    if not rows:
        return None

    return {
        "section": "Completeness",
        "severity": "WARN",
        "code": "QA.COMPLETENESS.003",
        "title": "Duplicate entity names detected",
        "norm": (
            "Each named entity MUST exist as a single object in the graph. "
            "Duplicate entities with the same name fragment the knowledge graph "
            "and produce incorrect relationship counts."
        ),
        "rows": rows,
        "evidence": {"duplicate_groups": len(rows)},
        "metrics": {"duplicate_entities": len(rows)},
    }


# ---------------------------------------------------------------------------
# Intrusion Set naming convention
# ---------------------------------------------------------------------------
# Per data model convention, Intrusion Sets that are NOT authored by the
# report's own organisation should be named:
#   "Intrusion Set Name (Author Name)"
#
# This ensures provenance is encoded in the entity name for graph clarity.
# Intrusion Sets authored by the report's own organisation (createdBy matches
# report author) are exempt — they are the primary source.

_KNOWN_VENDOR_NAMES = {
    # Common vendor/author name variants that typically author their own clusters
    "mandiant", "google", "crowdstrike", "microsoft", "sentinelone",
    "paloalto", "palo alto", "unit 42", "secureworks", "talos", "cisco",
    "recordedfuture", "recorded future", "fireeye", "symantec", "broadcom",
    "trendmicro", "trend micro", "kaspersky", "eset", "withsecure",
    "checkpoint", "check point", "proofpoint", "secureworks", "reliaquest",
    "dragos", "claroty", "tenable", "qualys",
}

_AUTHOR_SUFFIX_RE = re.compile(r"\(([^)]+)\)\s*$")


def _get_report_author_name(report: Dict[str, Any]) -> str:
    cb = safe_get(report, "createdBy") or {}
    if isinstance(cb, dict):
        return (cb.get("name") or "").strip().lower()
    return ""


def _intrusion_set_has_author_suffix(name: str) -> bool:
    """Check if name already ends with (Author Name) pattern."""
    return bool(_AUTHOR_SUFFIX_RE.search(name.strip()))


def qa_intrusion_set_naming(
    report: Dict[str, Any],
    resolved_objects: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Validate Intrusion Set naming convention.

    An Intrusion Set that:
    - Is NOT authored by the report author (createdBy differs)
    - Does NOT already have an (Author) suffix in its name
    - Is authored by a known external vendor/organisation

    ...should be named "Cluster Name (Author Name)" to encode provenance.
    """
    report_author_name = _get_report_author_name(report)

    rows: List[Tuple[str, str, str, str]] = []

    for obj in resolved_objects.values():
        et = (safe_get(obj, "entity_type", "entityType") or "").strip()
        if et != "Intrusion-Set":
            continue

        name = (safe_get(obj, "name") or "").strip()
        if not name:
            continue

        # If name already has (Author) suffix, compliant
        if _intrusion_set_has_author_suffix(name):
            continue

        # Get the entity's author
        cb = safe_get(obj, "createdBy") or {}
        if not isinstance(cb, dict):
            continue
        entity_author_name = (cb.get("name") or "").strip()
        entity_author_norm = entity_author_name.lower()

        # If no author recorded, skip (can't enforce)
        if not entity_author_name:
            continue

        # If the entity author matches the report author, it's the primary source — exempt
        if report_author_name and entity_author_norm == report_author_name:
            continue

        # If authored by a known external vendor, flag the naming convention
        authored_by_external = any(
            v in entity_author_norm for v in _KNOWN_VENDOR_NAMES
        ) or (report_author_name and entity_author_norm != report_author_name)

        if authored_by_external:
            expected_name = f"{name} ({entity_author_name})"
            rows.append((
                f"Intrusion-Set:{name}",
                "naming-convention",
                f"Intrusion-Set:{expected_name}",
                (
                    f"Intrusion Set '{name}' is authored by '{entity_author_name}' "
                    f"(not the report author '{report_author_name or 'unknown'}'). "
                    f"Per naming convention, rename to: '{expected_name}'. "
                    "This encodes provenance and distinguishes vendor-defined clusters "
                    "from internally-assessed attributions."
                ),
            ))

    if not rows:
        return None

    return {
        "section": "Completeness",
        "severity": "WARN",
        "code": "QA.COMPLETENESS.004",
        "title": "Intrusion Set naming convention violation",
        "norm": (
            "Intrusion Sets authored by an external source MUST be named "
            "'Cluster Name (Author Name)' to encode provenance. "
            "Example: 'APT29 (Mandiant)', 'UNC1549 (Google)'. "
            "Intrusion Sets authored by the report's own organisation are exempt."
        ),
        "rows": rows,
        "evidence": {
            "report_author": report_author_name or "(unknown)",
            "violations": len(rows),
        },
        "metrics": {"intrusion_set_naming_violations": len(rows)},
    }
