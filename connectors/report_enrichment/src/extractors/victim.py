from __future__ import annotations

import re
from typing import Any, Dict, List

_PRIMARY_CUES = re.compile(
    r"\b(?P<cue>"
    r"targeted\s+(?:an?|the|several|multiple|various)?\s*"
    r"|targeting\s+(?:an?|the|several|multiple|various)?\s*"
    r"|compromised\s+(?:an?|the|systems?\s+at|networks?\s+(?:of|at|belonging\s+to))?\s*"
    r"|attacked\s+(?:an?|the)?\s*"
    r"|breached\s+(?:an?|the|systems?\s+at)?\s*"
    r"|intrusion\s+at\s+(?:an?|the)?\s*"
    r"|breach\s+of\s+(?:an?|the)?\s*"
    r"|attack\s+on\s+(?:an?|the)?\s*"
    r"|victim\s+(?:organization|organisation|company|entity|network)?[,:\s]+(?:an?|the)?\s*"
    r"|victims?\s+included?\s+(?:an?|the)?\s*"
    r"|deployed\s+(?:against|at|to)\s+(?:an?|the)?\s*"
    r")",
    re.IGNORECASE,
)

_SECONDARY_CUES = re.compile(
    r"\b(?P<cue>"
    r"impacted\s+(?:an?|the)?\s*"
    r"|affected\s+(?:an?|the)?\s*"
    r"|infiltrated\s+(?:an?|the)?\s*"
    r"|exfiltrated\s+from\s+(?:an?|the)?\s*"
    r")",
    re.IGNORECASE,
)

# Organisation-indicator terms: presence boosts confidence and unlocks
# the higher word-count limit.
_ORG_INDICATORS = re.compile(
    r"\b(?:inc(?:orporated)?|ltd|llc|gmbh|corp(?:oration)?|plc|co\.|s\.a\.|"
    r"ministry|department|agency|authority|bureau|commission|institute|"
    r"university|college|hospital|bank|group|holdings|international|national|"
    r"federal|government|defence|defense|energy|finance|telecom|media|"
    r"court|courts|municipality|council|authority|exchange)\b",
    re.IGNORECASE,
)

# Prepositions and verbals that signal the org name phrase has ended.
# Extraction stops when one of these is encountered after the first
# content word has been captured.
_EXTRACTION_STOP_WORDS = frozenset({
    "in", "at", "on", "for", "from", "by", "with", "into", "within",
    "of", "and", "or", "but", "nor", "yet",
    "that", "which", "where", "when", "after", "before", "since",
    "resulting", "referenced", "related", "according", "including",
    "following", "using", "via", "through",
    "multiple", "several", "various", "numerous", "three", "two", "four",
    "five", "six", "seven", "eight", "nine", "ten", "many", "some", "any",
    "additional", "other", "another",
    # Adverbs and qualifiers that signal the org name phrase has ended.
    "notably", "specifically", "particularly", "primarily", "mainly",
    "especially", "reportedly", "allegedly", "apparently", "previously",
    "recently", "historically", "currently", "successfully",
})

# Words that cannot start a valid organisation name.
_LEADING_STOP_WORDS = frozenset({
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "by",
    "to", "of", "with", "from", "for", "its", "their", "this", "that",
    "these", "those", "three", "two", "four", "five", "six", "several",
    "multiple", "various", "numerous", "some", "any", "other", "both",
    "all", "each", "every", "such",
})

# Single-word candidates that are geography terms, not organisations.
_GEOGRAPHY_STOP_WORDS = frozenset({
    "tehran", "dubai", "beijing", "moscow", "washington", "london",
    "berlin", "paris", "tokyo", "seoul", "ankara", "riyadh", "jerusalem",
    "regions", "region", "countries", "country", "nations", "nation",
    "states", "areas", "territories", "territory", "zones",
    "sector", "sectors", "industry", "industries",
})

# Generic single words that are not organisation names.
_GENERIC_STOP_WORDS = frozenset({
    "systems", "system", "infrastructure", "network", "networks",
    "targets", "target", "victims", "victim", "organizations",
    "organisations", "entities", "entity", "companies", "company",
    "agencies", "agency", "authorities", "authority", "officials",
    "government", "governments", "calculus", "operations", "personnel",
})

# Generic descriptor nouns: if a multi-word candidate ends with one of
# these AND contains no org-indicator term, it is too generic to be a
# named organisation (e.g. "Israeli engineering", "UAE government organizations").
_GENERIC_DESCRIPTOR_WORDS = frozenset({
    "engineering", "organizations", "organisations", "entities",
    "companies", "firms", "groups", "officials", "personnel",
    "forces", "troops", "services", "industry", "sector",
    "market", "economy", "networks", "assets", "targets", "victims",
})

# Country names and abbreviations. Single-word candidates matching these
# are Location entities, not Organisations — reject them from victim extraction.
# Multi-word candidates consisting entirely of country names/abbreviations
# (e.g. "UAE Bahrain") are also rejected.
_COUNTRY_WORDS = frozenset({
    "israel", "iran", "uae", "bahrain", "saudi", "qatar", "kuwait",
    "oman", "jordan", "egypt", "syria", "iraq", "turkey", "russia",
    "china", "usa", "america", "france", "germany", "britain",
    "england", "canada", "australia", "india", "pakistan", "ukraine",
    "nato", "gcc", "eu", "un", "us", "uk",
})

# Max words in a candidate without an org-indicator term (4 words).
# Max words with an org-indicator term (7 words).
_MAX_WORDS_WITHOUT_INDICATOR = 4
_MAX_WORDS_WITH_INDICATOR    = 7
_MAX_CHARS = 80


def _extract_after_cue(text: str, cue_end: int) -> str:
    """
    Extract the candidate organisation name following a victim cue phrase.

    Key improvement over naive word-limit: stops at _EXTRACTION_STOP_WORDS
    once the first content word is captured, preventing prose fragments
    like "three UAE government organizations referenced in the" from being
    accepted — both "in" and "referenced" are stop words.

    Also enforces a word-count ceiling based on whether an org-indicator
    term appears in the candidate, preventing long unannotated fragments.
    """
    tail = text[cue_end: cue_end + 300]

    # Hard stops at sentence terminators and clause boundaries.
    for sep in ("\n", ".", ":", ";", " — ", " - "):
        if sep in tail:
            tail = tail.split(sep, 1)[0]

    words = tail.strip().split()
    out: List[str] = []
    has_indicator = False

    for word in words:
        clean = word.strip(".,;:()[]\"'")
        if not clean:
            continue

        # Stop at extraction-stop words once we have content.
        if clean.lower() in _EXTRACTION_STOP_WORDS and out:
            break

        if _ORG_INDICATORS.search(clean):
            has_indicator = True

        out.append(clean)

        limit = _MAX_WORDS_WITH_INDICATOR if has_indicator else _MAX_WORDS_WITHOUT_INDICATOR
        if len(out) >= limit:
            break

    candidate = " ".join(out).strip()

    # Strip leading stop words.
    words = candidate.split()
    while words and words[0].lower() in _LEADING_STOP_WORDS:
        words = words[1:]
    candidate = " ".join(words)

    return candidate[:_MAX_CHARS].strip()


def _is_valid_candidate(candidate: str) -> bool:
    """
    Structural validation for a victim extraction candidate.

    Rejects:
      - Empty or too short (< 3 chars)
      - Does not start with a capital letter (not a proper noun)
      - Entirely lowercase
      - Purely numeric
      - Single word matching geography or generic stop lists
      - More than _MAX_WORDS_WITHOUT_INDICATOR words without an org indicator
    """
    if not candidate or len(candidate) < 3:
        return False
    if not candidate[0].isupper():
        return False
    if candidate.lower() == candidate:
        return False
    if candidate.replace(" ", "").isdigit():
        return False

    words = candidate.split()
    if len(words) == 1 and candidate.lower() in _GEOGRAPHY_STOP_WORDS:
        return False
    if len(words) == 1 and candidate.lower() in _GENERIC_STOP_WORDS:
        return False
    if len(words) > _MAX_WORDS_WITHOUT_INDICATOR and not _ORG_INDICATORS.search(candidate):
        return False

    # Reject generic descriptor patterns: multi-word candidate whose last
    # word is a generic noun. For most generic words, an org-indicator term
    # in the candidate overrides the rejection. But unconditionally generic
    # plurals ("organizations", "organisations", "entities", "companies")
    # are always rejected — they are never specific enough to be a named
    # organisation regardless of what precedes them.
    _UNCONDITIONAL_GENERICS = frozenset({
        "organizations", "organisations", "entities", "companies",
        "firms", "agencies", "authorities", "officials", "personnel",
        "forces", "services", "targets", "victims",
    })
    if len(words) >= 2:
        last_word = words[-1].lower()
        if last_word in _UNCONDITIONAL_GENERICS:
            return False
        if last_word in _GENERIC_DESCRIPTOR_WORDS and not _ORG_INDICATORS.search(candidate):
            return False

    # Reject multi-word geographic concatenations where every token is a
    # country name or abbreviation (e.g. "UAE Bahrain", "Israel Iran").
    if len(words) >= 2:
        if all(w.lower().rstrip(".,;:") in _COUNTRY_WORDS for w in words):
            return False

    # Reject bare country names — they are Location entities, not Organisations.
    if len(words) == 1 and candidate.lower() in _COUNTRY_WORDS:
        return False

    return True


def _confidence_for(candidate: str, cue_text: str, is_primary: bool, text: str) -> float:
    """
    Compute extraction confidence for a validated victim candidate.

    Factors: primary vs secondary cue, org-indicator presence,
    capitalisation, and frequency of mention in the full text.
    All values clamped to [0, 0.92].
    """
    base = 0.70 if is_primary else 0.50

    if _ORG_INDICATORS.search(candidate):
        base = min(base + 0.15, 0.92)
    if candidate and candidate[0].isupper():
        base = min(base + 0.05, 0.92)

    try:
        count = len(re.findall(re.escape(candidate), text, re.IGNORECASE))
        if count >= 3:
            base = min(base + 0.10, 0.92)
    except re.error:
        pass

    return round(base, 2)


def extract_victims(text: str) -> List[Dict[str, Any]]:
    """
    Scan pre-processed document text for victim organisation mentions.

    Input must have passed through preprocess.preprocess_for_extraction()
    so that HTML markup is stripped and defanged indicators are rehydrated.

    Returns candidate records with:
      name        — organisation name in fanged canonical form
      confidence  — float 0-1
      cue_phrase  — the matched cue phrase
      is_primary  — True for primary (high-confidence) cue phrases
      snippet     — surrounding text (defanging is caller's responsibility)
    """
    if not text:
        return []

    results: List[Dict[str, Any]] = []
    seen: set = set()

    def _process(m: re.Match, is_primary: bool) -> None:
        candidate = _extract_after_cue(text, m.end())
        if not _is_valid_candidate(candidate):
            return
        norm = candidate.lower()
        if norm in seen:
            return
        seen.add(norm)

        confidence = _confidence_for(candidate, m.group("cue"), is_primary, text)
        ctx_start  = max(0, m.start() - 60)
        ctx_end    = min(len(text), m.end() + len(candidate) + 80)
        snippet    = re.sub(r"\s+", " ", text[ctx_start:ctx_end]).strip()[:260]

        results.append({
            "name":       candidate,
            "confidence": confidence,
            "cue_phrase": m.group("cue").strip(),
            "is_primary": is_primary,
            "snippet":    snippet,
        })

    for m in _PRIMARY_CUES.finditer(text):
        _process(m, is_primary=True)
    for m in _SECONDARY_CUES.finditer(text):
        _process(m, is_primary=False)

    return results
