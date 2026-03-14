from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from util.graph import (
    extract_relationship_endpoints,
    normalize_rel_type,
    obj_display_name,
    resolve_endpoint,
    safe_get,
)

# ---------------------------------------------------------------------------
# Description quality scoring
# ---------------------------------------------------------------------------

_MIN_DESC_WORDS = 8
_SELF_REF_PATTERNS = re.compile(
    r"^(uses|targets|related|related-to|attributed|attributed-to|"
    r"communicates|delivers|exploits|indicates|based-on|part-of|belongs-to)$",
    re.IGNORECASE,
)


def _score_description(desc: str, src_name: str, tgt_name: str) -> Tuple[bool, str]:
    if not desc or not desc.strip():
        return False, "description is empty"
    stripped = desc.strip()
    words = stripped.split()
    if len(words) < _MIN_DESC_WORDS:
        return False, (
            f"description too short ({len(words)} words, minimum {_MIN_DESC_WORDS}); "
            "must provide analytical context, not just label the relationship"
        )
    if _SELF_REF_PATTERNS.match(stripped):
        return False, (
            f"description is self-referential ('{stripped}'); "
            "must explain how and why the relationship exists"
        )
    src_norm  = (src_name or "").strip().lower()
    tgt_norm  = (tgt_name or "").strip().lower()
    desc_norm = stripped.lower()
    if src_norm and desc_norm == src_norm:
        return False, "description is identical to source entity name"
    if tgt_norm and desc_norm == tgt_norm:
        return False, "description is identical to target entity name"
    return True, ""


# ---------------------------------------------------------------------------
# Temporal coherence
# ---------------------------------------------------------------------------

def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
    except Exception:
        return None


def _check_temporal_coherence(
    rel: Dict[str, Any],
    src_obj: Optional[Dict[str, Any]],
    tgt_obj: Optional[Dict[str, Any]],
) -> List[str]:
    issues: List[str] = []
    now = datetime.now(timezone.utc)

    rel_first = _parse_iso(safe_get(rel, "first_seen", "start_time"))
    rel_last  = _parse_iso(safe_get(rel, "last_seen",  "stop_time"))

    if rel_first and rel_last and rel_last < rel_first:
        issues.append(
            f"last_seen ({rel_last.date()}) is before first_seen ({rel_first.date()})"
        )
    if rel_last and rel_last > now:
        issues.append(f"last_seen ({rel_last.date()}) is in the future")

    src_first = _parse_iso(safe_get(src_obj or {}, "first_seen", "start_time", "created_at"))
    tgt_first = _parse_iso(safe_get(tgt_obj or {}, "first_seen", "start_time", "created_at"))
    if rel_first and src_first and tgt_first:
        earliest = min(src_first, tgt_first)
        if rel_first < earliest:
            issues.append(
                f"relationship first_seen ({rel_first.date()}) predates both "
                f"endpoints' earliest first_seen ({earliest.date()})"
            )
    return issues


# ---------------------------------------------------------------------------
# Report field checks
# ---------------------------------------------------------------------------

def _check_markings_present(report: Dict[str, Any]) -> bool:
    mids = safe_get(report, "objectMarkingIds", "objectMarkingIDs") or []
    mobs = safe_get(report, "objectMarking") or []
    return bool(mids) or bool(mobs)


def qa_report_fields(report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    missing: List[str] = []
    rid = safe_get(report, "id") or "(report)"

    title    = safe_get(report, "name")
    desc     = safe_get(report, "description")
    created_by = safe_get(report, "createdBy") or safe_get(report, "createdById")

    if not title or not str(title).strip():
        missing.append("name")
    if not desc or not str(desc).strip():
        missing.append("description")
    if not created_by:
        missing.append("author/createdBy")
    if not _check_markings_present(report):
        missing.append("marking definitions")

    if not missing:
        return None

    rows = [(rid, "missing", m, "Report required field missing.") for m in missing]
    return {
        "section":  "Completeness",
        "severity": "ERROR",
        "code":     "QA.COMPLETENESS.001",
        "title":    "Report required fields",
        "norm":     "A Report MUST contain the minimum required fields and markings.",
        "rows":     rows,
        "metrics":  {"report_required_missing": len(missing)},
    }


# ---------------------------------------------------------------------------
# Relationship field checks
# ---------------------------------------------------------------------------

def _relationship_required_fields(rel: Dict[str, Any]) -> List[str]:
    missing: List[str] = []
    cb   = safe_get(rel, "createdBy")
    cbid = safe_get(rel, "createdById")
    if not cb and not cbid:
        missing.append("author")
    ts = safe_get(rel, "created_at", "created", "updated_at", "modified")
    if not ts:
        missing.append("timestamp")
    return missing


def qa_relationship_fields(
    resolved_objects: Dict[str, Dict[str, Any]],
    relationship_ids: List[str],
    read_relationship_fn,
    read_any_object_fn,
) -> Optional[Dict[str, Any]]:
    if not relationship_ids:
        return None

    # Read threshold from env — proportion of relationships that may have poor
    # descriptions before the finding escalates to ERROR/FAIL.
    # Default 0.50 (more than half missing = ERROR).
    try:
        fail_threshold = float(
            os.environ.get("QA_REL_DESC_FAIL_THRESHOLD", "0.50")
        )
        fail_threshold = max(0.0, min(1.0, fail_threshold))
    except Exception:
        fail_threshold = 0.50

    rows:           List[Tuple[str, str, str, str]] = []
    missing_count   = 0
    quality_count   = 0
    temporal_count  = 0
    total_evaluated = 0

    for rid in relationship_ids:
        rel = read_relationship_fn(rid)
        if not rel:
            rows.append((rid, "unreadable", rid,
                         "Relationship unreadable; cannot validate required fields."))
            missing_count += 1
            continue

        total_evaluated += 1
        rtype = normalize_rel_type(
            str(safe_get(rel, "relationship_type", "relationshipType") or "(unknown)")
        )
        from_id, to_id, from_inline, to_inline = extract_relationship_endpoints(rel)

        src_obj  = from_inline or resolve_endpoint(read_any_object_fn, resolved_objects, from_id)
        tgt_obj  = to_inline   or resolve_endpoint(read_any_object_fn, resolved_objects, to_id)
        src_name = obj_display_name(src_obj, fallback_id=from_id)
        tgt_name = obj_display_name(tgt_obj, fallback_id=to_id)

        # Required field presence
        missing = _relationship_required_fields(rel)
        if missing:
            rows.append((src_name, rtype, tgt_name,
                         f"Missing required fields: {', '.join(missing)}."))
            missing_count += 1

        # Description quality
        desc = safe_get(rel, "description") or ""
        passes, quality_reason = _score_description(desc, src_name, tgt_name)
        if not passes:
            rows.append((src_name, rtype, tgt_name,
                         f"Description quality insufficient: {quality_reason}."))
            quality_count += 1

        # Temporal coherence
        for issue in _check_temporal_coherence(rel, src_obj, tgt_obj):
            rows.append((src_name, rtype, tgt_name,
                         f"Temporal coherence violation: {issue}."))
            temporal_count += 1

    if not rows:
        return None

    # Determine severity based on description quality threshold
    desc_fail_count = quality_count
    desc_fail_rate  = desc_fail_count / total_evaluated if total_evaluated > 0 else 0.0
    threshold_breached = desc_fail_rate > fail_threshold

    severity = "ERROR" if threshold_breached else "WARN"

    threshold_pct = int(fail_threshold * 100)
    actual_pct    = int(desc_fail_rate * 100)

    norm_suffix = (
        f" Currently {actual_pct}% of relationships have insufficient descriptions "
        f"(threshold: {threshold_pct}% → "
        + ("FAIL" if threshold_breached else f"would FAIL above {threshold_pct}%")
        + ")."
    )

    return {
        "section":  "Completeness",
        "severity": severity,
        "code":     "QA.COMPLETENESS.002",
        "title":    "Relationship required fields",
        "norm": (
            "Relationships MUST contain descriptive metadata with sufficient analytical "
            f"context (minimum {_MIN_DESC_WORDS} words), correct authorship, and "
            "temporally coherent dates." + norm_suffix
        ),
        "rows": rows,
        "evidence": {
            "total_relationships_evaluated": total_evaluated,
            "desc_fail_count":   desc_fail_count,
            "desc_fail_rate_pct": actual_pct,
            "fail_threshold_pct": threshold_pct,
            "threshold_breached": threshold_breached,
        },
        "metrics": {
            "relationships_missing_required":    missing_count,
            "relationships_poor_description":    quality_count,
            "relationships_temporal_violations": temporal_count,
        },
    }
