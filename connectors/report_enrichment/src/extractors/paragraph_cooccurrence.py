from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from qa.relationship_policy import is_allowed

_PARA_SPLIT_RE = re.compile(r"\n{2,}|\r\n\r\n")
_HEADER_RE     = re.compile(r"^[A-Z0-9 :\-]{4,60}$|.{0,80}:$")
_MIN_PARA_LEN  = 80

_COOCCURRENCE_RULES: List[Tuple[str, str, str, float]] = [
    ("Intrusion-Set",  "uses",       "Malware",        0.65),
    ("Intrusion-Set",  "uses",       "Tool",           0.65),
    ("Intrusion-Set",  "uses",       "Attack-Pattern", 0.60),
    ("Intrusion-Set",  "uses",       "Infrastructure", 0.60),
    ("Threat-Actor",   "uses",       "Malware",        0.65),
    ("Threat-Actor",   "uses",       "Tool",           0.65),
    ("Campaign",       "uses",       "Malware",        0.65),
    ("Campaign",       "uses",       "Tool",           0.65),
    ("Malware",        "uses",       "Attack-Pattern", 0.60),
    ("Intrusion-Set",  "targets",    "Organization",   0.60),
    ("Intrusion-Set",  "targets",    "Sector",         0.60),
    ("Threat-Actor",   "targets",    "Organization",   0.60),
    ("Campaign",       "targets",    "Organization",   0.60),
    ("Malware",        "exploits",   "Vulnerability",  0.65),
    ("Intrusion-Set",  "targets",    "Vulnerability",  0.60),
    ("Infrastructure", "delivers",   "Malware",        0.60),
    ("IPv4-Addr",      "related-to", "Intrusion-Set",  0.55),
    ("Domain-Name",    "related-to", "Intrusion-Set",  0.55),
    ("IPv4-Addr",      "related-to", "Malware",        0.55),
    ("Domain-Name",    "related-to", "Malware",        0.55),
]

_RULE_INDEX: Dict[str, List[Tuple[str, str, float]]] = {}
for _src, _rel, _tgt, _conf in _COOCCURRENCE_RULES:
    _RULE_INDEX.setdefault(_src, []).append((_rel, _tgt, _conf))


def segment_paragraphs(text: str) -> List[str]:
    """Split document text into paragraphs, filtering headers and short fragments."""
    if not text:
        return []
    result: List[str] = []
    for p in _PARA_SPLIT_RE.split(text):
        stripped = p.strip()
        if len(stripped) < _MIN_PARA_LEN:
            continue
        if _HEADER_RE.match(stripped):
            continue
        result.append(stripped)
    return result


def _find_entity_in_para(para: str, name: str) -> bool:
    if not name or len(name) < 3:
        return False
    try:
        return bool(re.search(r"\b" + re.escape(name) + r"\b", para, re.IGNORECASE))
    except re.error:
        return False


def infer_paragraph_relationships(
    paragraphs: List[str],
    candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Infer relationships from entity co-occurrence within the same paragraph.
    Confidence is capped at 0.75 — co-occurrence is never as strong as explicit assertion.
    All relationships are gated through the data model policy.
    """
    if not paragraphs or not candidates:
        return []

    results: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for para in paragraphs:
        present = [c for c in candidates if _find_entity_in_para(para, c.get("name") or "")]
        if len(present) < 2:
            continue

        for src_cand in present:
            src_type = src_cand.get("entity_type") or ""
            src_name = (src_cand.get("name") or "").strip()
            if not src_type or not src_name:
                continue

            rules_for_src = _RULE_INDEX.get(src_type, [])
            if not rules_for_src:
                continue

            for tgt_cand in present:
                if tgt_cand is src_cand:
                    continue
                tgt_type = tgt_cand.get("entity_type") or ""
                tgt_name = (tgt_cand.get("name") or "").strip()
                if not tgt_type or not tgt_name:
                    continue

                for rel_type, expected_tgt_type, base_conf in rules_for_src:
                    if tgt_type != expected_tgt_type:
                        continue
                    if not is_allowed(src_type, rel_type, tgt_type).allowed:
                        continue

                    dedup_key = f"{src_name.lower()}|{rel_type}|{tgt_name.lower()}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    results.append({
                        "source_type": src_type,
                        "source_name": src_name,
                        "rel_type":    rel_type,
                        "target_type": tgt_type,
                        "target_name": tgt_name,
                        "confidence":  min(base_conf, 0.75),
                        "evidence":    re.sub(r"\s+", " ", para).strip()[:300],
                        "basis":       "paragraph_cooccurrence",
                    })

    return results
