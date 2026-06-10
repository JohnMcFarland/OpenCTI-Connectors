from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Confidence and likelihood vocabulary
# ---------------------------------------------------------------------------

# Maps explicit confidence phrases to OpenCTI integer confidence values (0-100).
_CONFIDENCE_MAP: Dict[str, int] = {
    "high confidence":     85,
    "high-confidence":     85,
    "moderate confidence": 50,
    "medium confidence":   50,
    "low confidence":      15,
    "low-confidence":      15,
}

# Maps likelihood vocabulary (per Intelligence Production Standard) to
# OpenCTI Assessment Note likelihood field values and approximate probability.
_LIKELIHOOD_MAP: Dict[str, Dict[str, Any]] = {
    "almost certainly not": {"likelihood": "Very Low",  "confidence": 5},
    "probably not":         {"likelihood": "Low",       "confidence": 25},
    "likely not":           {"likelihood": "Low",       "confidence": 25},
    "unlikely":             {"likelihood": "Low",       "confidence": 25},
    "may not":              {"likelihood": "Low",       "confidence": 25},
    "possibly":             {"likelihood": "Medium",    "confidence": 50},
    "may":                  {"likelihood": "Medium",    "confidence": 50},
    "probably":             {"likelihood": "High",      "confidence": 80},
    "likely":               {"likelihood": "High",      "confidence": 80},
    "almost certainly":     {"likelihood": "Very High", "confidence": 95},
}

# Confidence phrase pattern — matched within the assessment sentence.
_CONF_RE = re.compile(
    r"\bwith\s+(?P<level>high|moderate|medium|low)(?:\s*-\s*|\s+)confidence\b",
    re.IGNORECASE,
)

# Likelihood phrase pattern — ordered longest-match first to avoid partial hits.
_LIKELIHOOD_TERMS = sorted(_LIKELIHOOD_MAP.keys(), key=len, reverse=True)
_LIKELIHOOD_RE = re.compile(
    r"\b(?P<term>" + "|".join(re.escape(t) for t in _LIKELIHOOD_TERMS) + r")\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Assessment cue patterns
# ---------------------------------------------------------------------------

_PATTERNS = [
    re.compile(
        r"(?P<subject>[A-Z][^.!?]{2,60}?)\s+assess(?:es|ed)?\s+"
        r"(?:with\s+(?P<confidence>high|moderate|medium|low)(?:\s*-\s*|\s+)confidence\s+)?"
        r"that\s+(?P<claim>[^.!?]{10,400}[.!?])",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<subject>[A-Z][^.!?]{2,60}?)\s+assess(?:es|ed)?\s+"
        r"it\s+is\s+(?P<likelihood>" + "|".join(re.escape(t) for t in _LIKELIHOOD_TERMS) + r")\s+"
        r"that\s+(?P<claim>[^.!?]{10,400}[.!?])",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<subject>(?:we|our\s+team|our\s+analysts?|our\s+researchers?))\s+"
        r"assess(?:es|ed)?\s+"
        r"(?:with\s+(?P<confidence>high|moderate|medium|low)(?:\s*-\s*|\s+)confidence\s+)?"
        r"that\s+(?P<claim>[^.!?]{10,400}[.!?])",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<subject>[A-Z][^.!?]{2,60}?)\s+"
        r"(?:judge(?:s|d)?|conclude(?:s|d)?|believe(?:s|d)?|determine(?:s|d)?)\s+"
        r"(?:with\s+(?P<confidence>high|moderate|medium|low)(?:\s*-\s*|\s+)confidence\s+)?"
        r"that\s+(?P<claim>[^.!?]{10,400}[.!?])",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<subject>[A-Z][^.!?]{2,60}?)\s+(?:assess(?:es|ed)?|judge(?:s|d)?)\s+"
        r"(?P<claim>[^.!?]{10,400}[.!?])",
        re.IGNORECASE,
    ),
]

_FIRST_PERSON_SUBJECTS = frozenset({"we", "our team", "our analysts", "our analyst",
                                     "our researchers", "our researcher"})


def _map_confidence(conf_word: Optional[str], likelihood_word: Optional[str]) -> int:
    if conf_word:
        key = f"{conf_word.lower()} confidence"
        if key in _CONFIDENCE_MAP:
            return _CONFIDENCE_MAP[key]
    if likelihood_word:
        entry = _LIKELIHOOD_MAP.get(likelihood_word.lower())
        if entry:
            return entry["confidence"]
    return 50


def _map_likelihood(likelihood_word: Optional[str]) -> Optional[str]:
    if not likelihood_word:
        return None
    entry = _LIKELIHOOD_MAP.get(likelihood_word.lower())
    return entry["likelihood"] if entry else None


def _clean_subject(raw: str) -> str:
    return raw.strip().rstrip(",.;:")


def extract_assessments(
    text: str,
    report_author: str,
) -> List[Dict[str, Any]]:
    """
    Scan extracted document text for analytic assessment language and return
    a list of assessment records.

    Each record contains:
      subject     — the assessing entity name (substituted with report_author
                    when first-person language is detected)
      claim       — the text of the analytic judgment
      confidence  — integer 0-100 mapped from explicit confidence or likelihood language
      likelihood  — canonical likelihood string if present, else None
      sentence    — the full matched sentence for note content
      pattern_idx — which pattern matched (for diagnostics)
    """
    if not text:
        return []

    results: List[Dict[str, Any]] = []
    seen_claims: set = set()

    for idx, pattern in enumerate(_PATTERNS):
        for m in pattern.finditer(text):
            subject_raw = m.group("subject") if "subject" in pattern.groupindex else ""
            claim_raw   = m.group("claim")   if "claim"   in pattern.groupindex else ""

            subject_clean = _clean_subject(subject_raw or "")
            claim_clean   = (claim_raw or "").strip()

            if not subject_clean or not claim_clean:
                continue

            dedup_key = claim_clean[:80].lower()
            if dedup_key in seen_claims:
                continue
            seen_claims.add(dedup_key)

            if subject_clean.lower() in _FIRST_PERSON_SUBJECTS:
                subject_clean = report_author or "Authoring Organisation"

            conf_word       = m.group("confidence") if "confidence" in pattern.groupindex else None
            likelihood_word = m.group("likelihood") if "likelihood" in pattern.groupindex else None

            if not conf_word:
                cm = _CONF_RE.search(claim_clean + " " + subject_clean)
                if cm:
                    conf_word = cm.group("level")
            if not likelihood_word:
                lm = _LIKELIHOOD_RE.search(claim_clean)
                if lm:
                    likelihood_word = lm.group("term")

            confidence = _map_confidence(conf_word, likelihood_word)
            likelihood = _map_likelihood(likelihood_word)
            sentence   = m.group(0).strip()

            results.append({
                "subject":     subject_clean,
                "claim":       claim_clean,
                "confidence":  confidence,
                "likelihood":  likelihood,
                "sentence":    sentence,
                "pattern_idx": idx,
            })

    return results
