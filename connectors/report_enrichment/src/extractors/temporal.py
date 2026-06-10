from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

_MONTH_NAMES = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)
_MONTH_ABBR = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MONTH_RE_PART = "|".join(_MONTH_NAMES + _MONTH_ABBR)

_MONTH_YEAR_RE = re.compile(
    r"\b(?P<month>" + _MONTH_RE_PART + r")\.?\s+(?P<year>20\d{2})\b",
    re.IGNORECASE,
)
_QUARTER_RE = re.compile(r"\bQ(?P<quarter>[1-4])\s+(?P<year>20\d{2})\b", re.IGNORECASE)
_YEAR_ONLY_RE = re.compile(
    r"\b(?:in|during|since|throughout|by|from|after|before|around|circa)\s+(?P<year>20\d{2})\b",
    re.IGNORECASE,
)
_EARLY_LATE_RE = re.compile(
    r"\b(?:early|mid|late)-?\s*(?P<year>20\d{2})\b",
    re.IGNORECASE,
)

_QUARTER_MONTH = {1: 1, 2: 4, 3: 7, 4: 10}
_PROXIMITY_WINDOW = 300


def _month_num(name: str) -> int:
    n = name.strip().rstrip(".").lower()
    for i, full in enumerate(_MONTH_NAMES, 1):
        if n == full.lower() or n == full[:3].lower():
            return i
    return 1


def _to_iso(year: int, month: Optional[int], day: Optional[int]) -> str:
    if month and day:
        return f"{year:04d}-{month:02d}-{day:02d}T00:00:00Z"
    if month:
        return f"{year:04d}-{month:02d}-01T00:00:00Z"
    return f"{year:04d}-01-01T00:00:00Z"


def _extract_dates(text: str) -> List[Dict[str, Any]]:
    dates: List[Dict[str, Any]] = []
    seen_spans: set = set()

    def _add(m: re.Match, iso: str, precision: str) -> None:
        span = (m.start(), m.end())
        if span in seen_spans:
            return
        seen_spans.add(span)
        dates.append({"iso_date": iso, "span": span, "precision": precision, "raw": m.group(0)})

    for m in _MONTH_YEAR_RE.finditer(text):
        _add(m, _to_iso(int(m.group("year")), _month_num(m.group("month")), None), "month")

    for m in _QUARTER_RE.finditer(text):
        _add(m, _to_iso(int(m.group("year")), _QUARTER_MONTH[int(m.group("quarter"))], None), "quarter")

    for m in _EARLY_LATE_RE.finditer(text):
        _add(m, _to_iso(int(m.group("year")), None, None), "year")

    for m in _YEAR_ONLY_RE.finditer(text):
        span = (m.start(), m.end())
        overlap = any(abs(span[0] - d["span"][0]) < 20 and d["precision"] in ("month", "quarter") for d in dates)
        if not overlap and span not in seen_spans:
            seen_spans.add(span)
            dates.append({"iso_date": _to_iso(int(m.group("year")), None, None),
                          "span": span, "precision": "year", "raw": m.group(0)})

    return sorted(dates, key=lambda d: d["span"][0])


def extract_temporal_hints(
    text: str,
    candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Associate extracted date strings with nearby entity mentions.
    Returns hint records with entity_name, entity_type, iso_date, precision,
    raw_date, context, and confidence fields.
    """
    if not text or not candidates:
        return []

    dates = _extract_dates(text)
    if not dates:
        return []

    entity_offsets: Dict[str, List[Tuple[str, int, int]]] = {}
    for cand in candidates:
        name  = (cand.get("name") or "").strip()
        etype = (cand.get("entity_type") or "").strip()
        if not name or len(name) < 4:
            continue
        try:
            for m in re.finditer(re.escape(name), text, re.IGNORECASE):
                key = name.lower()
                if key not in entity_offsets:
                    entity_offsets[key] = []
                entity_offsets[key].append((etype, m.start(), m.end()))
        except re.error:
            continue

    if not entity_offsets:
        return []

    hints: List[Dict[str, Any]] = []
    seen: set = set()

    for date_record in dates:
        date_start, date_end = date_record["span"]
        for norm_name, occurrences in entity_offsets.items():
            best_dist, best_occ = None, None
            for etype, ent_start, ent_end in occurrences:
                dist = min(abs(ent_end - date_start), abs(date_end - ent_start))
                if best_dist is None or dist < best_dist:
                    best_dist, best_occ = dist, (etype, ent_start, ent_end)

            if best_occ is None or best_dist > _PROXIMITY_WINDOW:
                continue

            dedup_key = f"{norm_name}:{date_record['iso_date']}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            etype, ent_start, ent_end = best_occ
            proximity_score = max(0.0, 1.0 - (best_dist / _PROXIMITY_WINDOW))
            precision_score = {"month": 1.0, "quarter": 0.7, "year": 0.4}.get(date_record["precision"], 0.4)
            confidence = round((proximity_score + precision_score) / 2, 2)

            ctx_start = max(0, ent_start - 80)
            ctx_end   = min(len(text), ent_end + 80)
            context   = re.sub(r"\s+", " ", text[ctx_start:ctx_end]).strip()

            hints.append({
                "entity_name": text[ent_start:ent_end],
                "entity_type": etype,
                "iso_date":    date_record["iso_date"],
                "precision":   date_record["precision"],
                "raw_date":    date_record["raw"],
                "context":     context[:240],
                "confidence":  confidence,
            })

    return hints
