from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from util.graph import extract_relationship_endpoints, normalize_rel_type, obj_display_name, resolve_endpoint, safe_get


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        s = ts.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _is_report_scoped(rel_created_at: Optional[str], report_published: Optional[str], grace_hours: int) -> bool:
    """
    Returns True if the relationship was created within the grace window of
    the report's published date — i.e. it was likely created for this report.

    Returns True (enforce) when:
      - Either timestamp is unparseable (fail safe: enforce)
      - rel created_at >= report published - grace_hours

    Returns False (skip provenance check) when:
      - rel created_at predates report published by more than grace_hours
        (pre-existing shared relationship)
    """
    rel_dt = _parse_iso(rel_created_at)
    pub_dt = _parse_iso(report_published)

    if not rel_dt or not pub_dt:
        return True  # can't determine — enforce conservatively

    # Ensure both are timezone-aware
    if rel_dt.tzinfo is None:
        rel_dt = rel_dt.replace(tzinfo=timezone.utc)
    if pub_dt.tzinfo is None:
        pub_dt = pub_dt.replace(tzinfo=timezone.utc)

    cutoff = pub_dt - timedelta(hours=grace_hours)
    return rel_dt >= cutoff


def qa_relationship_provenance(
    report: Dict[str, Any],
    resolved_objects: Dict[str, Dict[str, Any]],
    relationship_ids: List[str],
    read_relationship_fn,
    read_any_object_fn,
) -> Dict[str, Any]:
    """
    Provenance check: relationship author and markings must match the report
    container, BUT only for relationships that were created in the context of
    this report (i.e. created_at is within the grace window of report.published).

    Pre-existing relationships shared across multiple reports are skipped —
    their author reflects the original ingestion context, not this report.
    """
    try:
        grace_hours = int(os.environ.get("QA_PROVENANCE_GRACE_HOURS", "24"))
    except Exception:
        grace_hours = 24

    report_published = (
        safe_get(report, "published")
        or safe_get(report, "published_at")
        or safe_get(report, "created_at")
    )

    report_author_id = (
        safe_get(report, "createdById")
        or safe_get(safe_get(report, "createdBy") or {}, "id")
    )

    report_marking_ids: Set[str] = set(safe_get(report, "objectMarkingIds", "objectMarkingIDs") or [])
    report_marking_objs = safe_get(report, "objectMarking") or []
    if isinstance(report_marking_objs, list):
        for mo in report_marking_objs:
            if isinstance(mo, dict) and mo.get("id"):
                report_marking_ids.add(mo["id"])

    rows: List[Tuple[str, str, str, str]] = []
    mismatches = 0
    skipped_preexisting = 0

    for rid in relationship_ids:
        rel = read_relationship_fn(rid)
        if not rel:
            rows.append((rid, "unreadable", rid, "Relationship unreadable; cannot validate provenance."))
            mismatches += 1
            continue

        rtype = normalize_rel_type(str(safe_get(rel, "relationship_type", "relationshipType") or "(unknown)"))
        from_id, to_id, from_inline, to_inline = extract_relationship_endpoints(rel)

        src_obj = from_inline or resolve_endpoint(read_any_object_fn, resolved_objects, from_id)
        tgt_obj = to_inline or resolve_endpoint(read_any_object_fn, resolved_objects, to_id)

        src_name = obj_display_name(src_obj, fallback_id=from_id)
        tgt_name = obj_display_name(tgt_obj, fallback_id=to_id)

        # Skip provenance check for pre-existing relationships
        rel_created_at = safe_get(rel, "created_at", "createdAt")
        if not _is_report_scoped(rel_created_at, report_published, grace_hours):
            skipped_preexisting += 1
            continue

        rel_author_id = (
            safe_get(rel, "createdById")
            or safe_get(safe_get(rel, "createdBy") or {}, "id")
        )

        rel_marking_ids: Set[str] = set(safe_get(rel, "objectMarkingIds", "objectMarkingIDs") or [])
        rel_marking_objs = safe_get(rel, "objectMarking") or []
        if isinstance(rel_marking_objs, list):
            for mo in rel_marking_objs:
                if isinstance(mo, dict) and mo.get("id"):
                    rel_marking_ids.add(mo["id"])

        if report_author_id and rel_author_id and rel_author_id != report_author_id:
            rows.append((
                src_name, rtype, tgt_name,
                f"Author mismatch: relationship author {rel_author_id} != report author {report_author_id}. "
                f"Relationship created_at={rel_created_at}, report published={report_published}.",
            ))
            mismatches += 1

        if report_marking_ids and rel_marking_ids != report_marking_ids:
            rows.append((
                src_name, rtype, tgt_name,
                f"Marking mismatch: relationship markings {sorted(rel_marking_ids)} != "
                f"report markings {sorted(report_marking_ids)}.",
            ))
            mismatches += 1

    base_evidence = {
        "grace_hours": grace_hours,
        "report_published": report_published,
        "skipped_preexisting": skipped_preexisting,
        "relationships_evaluated": len(relationship_ids) - skipped_preexisting,
        "relationships_total": len(relationship_ids),
    }

    if mismatches == 0:
        return {
            "section": "Categorization",
            "severity": "INFO",
            "code": "QA.CATEGORIZATION.002",
            "title": "Relationship provenance checks",
            "norm": (
                "Relationships created in the context of this report MUST align with the "
                "container author and markings. Pre-existing shared relationships are exempt."
            ),
            "rows": [],
            "evidence": base_evidence,
            "metrics": {"provenance_mismatches": 0},
        }

    return {
        "section": "Categorization",
        "severity": "WARN",
        "code": "QA.CATEGORIZATION.002",
        "title": "Relationship provenance checks",
        "norm": (
            "Relationships created in the context of this report MUST align with the "
            "container author and markings. Pre-existing shared relationships are exempt."
        ),
        "rows": rows,
        "evidence": base_evidence,
        "metrics": {"provenance_mismatches": mismatches},
    }
