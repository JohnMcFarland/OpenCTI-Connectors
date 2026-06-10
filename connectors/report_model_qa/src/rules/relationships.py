from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from util.graph import extract_relationship_endpoints, normalize_rel_type, obj_display_name, resolve_endpoint, safe_get
from util.relationship_policy import is_allowed


def qa_relationship_policy(
    resolved_objects: Dict[str, Dict[str, Any]],
    relationship_ids: List[str],
    read_relationship_fn,
    read_any_object_fn,
) -> Dict[str, Any]:
    rows: List[Tuple[str, str, str, str]] = []
    violations = 0
    not_evaluable = 0

    for rid in relationship_ids:
        rel = read_relationship_fn(rid)
        if not rel:
            rows.append((rid, "unreadable", rid, "Relationship unreadable; cannot evaluate policy."))
            not_evaluable += 1
            continue

        rtype = normalize_rel_type(str(safe_get(rel, "relationship_type", "relationshipType") or "(unknown)"))
        from_id, to_id, from_inline, to_inline = extract_relationship_endpoints(rel)

        src_obj = from_inline or resolve_endpoint(read_any_object_fn, resolved_objects, from_id)
        tgt_obj = to_inline or resolve_endpoint(read_any_object_fn, resolved_objects, to_id)

        src_type = safe_get(src_obj or {}, "entity_type", "entityType") or ""
        tgt_type = safe_get(tgt_obj or {}, "entity_type", "entityType") or ""

        src_name = obj_display_name(src_obj, fallback_id=from_id)
        tgt_name = obj_display_name(tgt_obj, fallback_id=to_id)

        if not src_type or not tgt_type:
            rows.append((src_name, rtype, tgt_name, "Policy not evaluated: endpoint type(s) unreadable."))
            not_evaluable += 1
            continue

        decision = is_allowed(str(src_type), str(rtype), str(tgt_type))
        if not decision.allowed:
            rows.append((src_name, rtype, tgt_name, decision.reason))
            violations += 1

    if violations == 0 and not_evaluable == 0:
        return {
            "section": "Relationships",
            "severity": "INFO",
            "code": "QA.RELATIONSHIPS.001",
            "title": "Relationship correctness (policy legitimacy)",
            "norm": "Relationships MUST conform to the hard-coded relationship legitimacy policy.",
            "rows": [],
            "metrics": {"policy_violations": 0, "policy_not_evaluable": 0},
        }

    sev = "WARN" if violations > 0 else "INFO"
    msg_title = "Relationship correctness (policy legitimacy)"
    return {
        "section": "Relationships",
        "severity": sev,
        "code": "QA.RELATIONSHIPS.001",
        "title": msg_title,
        "norm": "Relationships MUST conform to the hard-coded relationship legitimacy policy.",
        "rows": rows,
        "metrics": {"policy_violations": violations, "policy_not_evaluable": not_evaluable},
    }
