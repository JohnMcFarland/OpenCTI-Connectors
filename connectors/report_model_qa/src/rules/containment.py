from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def qa_containment(
    report_internal_id: str,
    obj_ids: List[str],
    unreadable_ids: List[str],
) -> Optional[Dict[str, Any]]:
    if not obj_ids:
        return {
            "section": "Containment",
            "severity": "BLOCKER",
            "code": "QA.CONTAINMENT.001",
            "title": "Report scope is empty",
            "norm": "A Report container MUST contain scoped entities/observables and/or relationships.",
            "rows": [(report_internal_id, "contains", "(none)", "Report has zero referenced objects.")],
            "evidence": {"ref_count": 0, "report_internal_id": report_internal_id},
        }

    if unreadable_ids:
        rows = [(u, "unresolved", u, "Could not be read as object or relationship") for u in unreadable_ids]
        return {
            "section": "Containment",
            "severity": "WARN",
            "code": "QA.CONTAINMENT.002",
            "title": "Unresolvable references in scope",
            "norm": "All scoped references SHOULD be resolvable as objects or relationships.",
            "rows": rows,
            "evidence": {"unreadable_count": len(unreadable_ids), "report_internal_id": report_internal_id},
        }

    return None
