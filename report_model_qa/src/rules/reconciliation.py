from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from util.graph import safe_get

logger = logging.getLogger(__name__)

_WARN_TYPES = frozenset({
    "Malware", "Tool", "Intrusion-Set", "Threat-Actor", "Campaign",
    "Attack-Pattern", "Vulnerability", "Infrastructure", "Channel",
    "Course-Of-Action",
})

_INFO_TYPES = frozenset({
    "IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "File",
    "Email-Addr", "Email-Message", "Autonomous-System", "Windows-Registry-Key",
    "Mutex", "User-Account", "Network-Traffic", "Process", "X509-Certificate",
    "Directory", "Software", "Persona",
})

# Deterministic extraction source tags — these are unambiguous structured
# identifiers (UNC cluster, CVE ID, ATT&CK T-code, etc.) and always ERROR
# when a named threat intel type is missing from scope.
_DETERMINISTIC_REASONS = frozenset({
    "UNC pattern found in extracted text.",
    "CVE identifier found in extracted text.",
    "ATT&CK technique ID found in extracted text.",
    "ATT&CK mitigation ID found in extracted text.",
    "CAPEC identifier found in extracted text.",
})

# Smart-parse confidence threshold above which a missing named threat intel
# entity escalates to ERROR. Below this threshold it remains WARN.
_SMART_PARSE_ERROR_CONFIDENCE = 0.80

_HIGH_FREQ_THRESHOLD = 5
_MED_FREQ_THRESHOLD  = 2


def _entity_type_from_candidate(candidate: str) -> str:
    if ":" in candidate:
        return candidate.split(":", 1)[0].strip()
    return ""


def _value_from_candidate(candidate: str) -> str:
    if ":" in candidate:
        return candidate.split(":", 1)[1].strip()
    return candidate.strip()


def _in_scope_names(
    resolved_objects: Dict[str, Dict[str, Any]],
) -> Dict[str, Set[str]]:
    in_scope: Dict[str, Set[str]] = {}
    for obj in resolved_objects.values():
        et = (safe_get(obj, "entity_type", "entityType") or "").strip()
        if not et:
            continue
        name = (
            safe_get(obj, "name", "value", "observable_value", "observableValue") or ""
        ).strip().lower()
        if not name:
            continue
        if et not in in_scope:
            in_scope[et] = set()
        in_scope[et].add(name)
        aliases = obj.get("aliases") or []
        if isinstance(aliases, list):
            for a in aliases:
                if isinstance(a, str) and a.strip():
                    in_scope[et].add(a.strip().lower())
    return in_scope


def _extract_occurrences_from_reason(reason: str) -> int:
    m = re.search(r"occurrences=(\d+)", reason)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            pass
    return 1


def _extract_confidence_from_reason(reason: str) -> Optional[float]:
    m = re.search(r"confidence=([\d.]+)", reason)
    if m:
        try:
            return float(m.group(1))
        except Exception:
            pass
    return None


def _is_deterministic_reason(reason: str) -> bool:
    """Return True if this candidate came from an unambiguous deterministic extractor."""
    return any(tag in reason for tag in _DETERMINISTIC_REASONS)


def _severity_for_gap(
    et: str,
    occurrences: int,
    confidence: Optional[float],
    is_deterministic: bool,
) -> str:
    """
    Severity rules for a missing named entity:

    ERROR (FAIL-triggering):
      - Deterministic extraction (CVE, UNC, T-code) + named threat intel type
      - Smart-parse confidence >= _SMART_PARSE_ERROR_CONFIDENCE + named threat intel type
      - Named threat intel type mentioned >= HIGH_FREQ_THRESHOLD times

    WARN:
      - Named threat intel type, KB match or smart-parse < 0.80, 2–4 mentions

    INFO:
      - Observable types (always — may be intentionally excluded)
      - Named threat intel type, single mention, low confidence
    """
    if et in _INFO_TYPES:
        return "INFO"
    if et not in _WARN_TYPES:
        return "INFO"

    # Deterministic = unambiguous structural identifier → always ERROR
    if is_deterministic:
        return "ERROR"

    # Smart-parse with high confidence → ERROR
    if confidence is not None and confidence >= _SMART_PARSE_ERROR_CONFIDENCE:
        return "ERROR"

    # High-frequency mention without structural ID → ERROR
    if occurrences >= _HIGH_FREQ_THRESHOLD:
        return "ERROR"

    # Medium-frequency → WARN
    if occurrences >= _MED_FREQ_THRESHOLD:
        return "WARN"

    # Low confidence smart-parse or KB match, single mention → INFO
    return "INFO"


def qa_reconciliation(
    resolved_objects: Dict[str, Dict[str, Any]],
    doc_suggestion_rows: List[Tuple[str, str, str, str]],
    kb_scan_matches: List[Dict[str, Any]],
    smart_parse_candidates: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Compare document candidates against graph scope.

    Severity:
      ERROR — deterministic structured ID (CVE/UNC/T-code), smart-parse ≥ 0.80,
              or ≥ 5 mentions of a named threat intel entity
      WARN  — KB match or smart-parse < 0.80, 2–4 mentions
      INFO  — observables, single-mention low-confidence candidates
    """
    in_scope = _in_scope_names(resolved_objects)

    sp_confidence: Dict[str, float] = {}
    if smart_parse_candidates:
        for c in smart_parse_candidates:
            name = (c.get("name") or "").lower()
            conf = c.get("confidence")
            if name and conf is not None:
                sp_confidence[name] = float(conf)

    error_rows: List[Tuple[str, str, str, str]] = []
    warn_rows:  List[Tuple[str, str, str, str]] = []
    info_rows:  List[Tuple[str, str, str, str]] = []
    seen: Set[str] = set()

    def _add_gap(
        et: str,
        val: str,
        candidate_label: str,
        base_reason: str,
        occurrences: int,
        confidence: Optional[float],
        is_deterministic: bool,
    ) -> None:
        dedup_key = f"{et}:{val}"
        if dedup_key in seen:
            return
        seen.add(dedup_key)
        if val in (in_scope.get(et) or set()):
            return

        sev = _severity_for_gap(et, occurrences, confidence, is_deterministic)

        freq_note = ""
        if occurrences >= _HIGH_FREQ_THRESHOLD:
            freq_note = f" [mentioned {occurrences}x — appears central to this report]"
        elif occurrences >= _MED_FREQ_THRESHOLD:
            freq_note = f" [mentioned {occurrences}x]"

        conf_note = ""
        if confidence is not None:
            conf_note = f" [extraction confidence: {confidence:.2f}]"

        det_note = " [deterministic — unambiguous structured identifier]" if is_deterministic else ""

        reason = f"{base_reason}{freq_note}{conf_note}{det_note}"
        row = ("document", "missing-from-scope", candidate_label, reason)

        if sev == "ERROR":
            error_rows.append(row)
        elif sev == "WARN":
            warn_rows.append(row)
        else:
            info_rows.append(row)

    # Deterministic + smart-parse rows
    for origin, signal, candidate, reason in doc_suggestion_rows:
        if signal != "suggests":
            continue
        et  = _entity_type_from_candidate(candidate)
        val = _value_from_candidate(candidate).lower()
        if not et or not val:
            continue

        occurrences    = _extract_occurrences_from_reason(reason)
        confidence     = _extract_confidence_from_reason(reason)
        if confidence is None:
            confidence = sp_confidence.get(val)
        is_deterministic = _is_deterministic_reason(reason)

        base_reason = f"Found in document but not in report scope as {et}."
        _add_gap(et, val, candidate, base_reason, occurrences, confidence, is_deterministic)

    # KB scan matches — KB matches are WARN at most (not deterministic,
    # no confidence score, entity was matched by name in live graph)
    for match in kb_scan_matches:
        et           = match.get("entity_type") or ""
        name         = (match.get("name") or "").strip()
        matched_term = (match.get("matched_term") or name).lower()
        mitre_id     = match.get("mitre_id")
        snippet      = match.get("snippet") or ""
        if not et or not name:
            continue

        scope_names = in_scope.get(et) or set()
        if matched_term in scope_names or name.lower() in scope_names:
            continue
        if mitre_id and mitre_id.lower() in scope_names:
            continue

        base_reason = f"Named entity '{name}' ({et}) found in document but not in report scope."
        if mitre_id:
            base_reason += f" MITRE ID: {mitre_id}."
        if snippet:
            base_reason += f" Context: \"{snippet[:120]}\""

        # KB matches: never deterministic, no confidence → frequency-only severity
        _add_gap(et, matched_term, f"{et}:{name}", base_reason, 1, None, False)

    total = len(error_rows) + len(warn_rows) + len(info_rows)

    if total == 0:
        return {
            "section":  "Reconciliation",
            "severity": "INFO",
            "code":     "QA.RECONCILIATION.001",
            "title":    "Document-to-graph reconciliation",
            "norm":     "All named entities identified in the source document SHOULD be represented in the report scope.",
            "rows":     [],
            "evidence": {
                "candidates_evaluated": len(doc_suggestion_rows) + len(kb_scan_matches),
                "missing_error": 0, "missing_warn": 0, "missing_info": 0,
            },
            "metrics": {"reconciliation_gaps": 0, "reconciliation_errors": 0},
        }

    overall_sev = "ERROR" if error_rows else ("WARN" if warn_rows else "INFO")

    return {
        "section":  "Reconciliation",
        "severity": overall_sev,
        "code":     "QA.RECONCILIATION.001",
        "title":    "Document-to-graph reconciliation",
        "norm":     "All named entities identified in the source document SHOULD be represented in the report scope.",
        "rows":     error_rows + warn_rows + info_rows,
        "evidence": {
            "candidates_evaluated":       len(doc_suggestion_rows) + len(kb_scan_matches),
            "missing_error":              len(error_rows),
            "missing_warn":               len(warn_rows),
            "missing_info":               len(info_rows),
            "deterministic_error_policy": "CVE/UNC/T-code identifiers for named threat intel types always ERROR",
            "smart_parse_error_threshold": _SMART_PARSE_ERROR_CONFIDENCE,
            "severity_logic": (
                f"ERROR = deterministic ID or smart-parse ≥ {_SMART_PARSE_ERROR_CONFIDENCE} "
                f"or ≥ {_HIGH_FREQ_THRESHOLD} mentions; "
                f"WARN = KB match or smart-parse < {_SMART_PARSE_ERROR_CONFIDENCE} "
                f"or {_MED_FREQ_THRESHOLD}–{_HIGH_FREQ_THRESHOLD-1} mentions; "
                "INFO = observable or single low-confidence mention"
            ),
        },
        "metrics": {
            "reconciliation_gaps":   total,
            "reconciliation_errors": len(error_rows),
        },
    }
