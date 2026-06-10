from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from qa.relationship_policy import is_allowed

_CUE_DEFS: List[Dict[str, Any]] = [
    {
        "pattern":       re.compile(r"\battributed\s+to\b", re.IGNORECASE),
        "before_type":   "Intrusion-Set",
        "after_type":    "Threat-Actor",
        "rel_type":      "attributed-to",
        "reversed":      False,
        "confidence":    0.80,
        "vendor_suffix": False,
    },
    {
        "pattern":       re.compile(r"\b(?:operated|directed|sponsored|funded|controlled)\s+by\b", re.IGNORECASE),
        "before_type":   "Intrusion-Set",
        "after_type":    "Threat-Actor",
        "rel_type":      "attributed-to",
        "reversed":      False,
        "confidence":    0.75,
        "vendor_suffix": False,
    },
    {
        "pattern":       re.compile(r"\b(?:linked|associated)\s+(?:to|with)\b", re.IGNORECASE),
        "before_type":   "Intrusion-Set",
        "after_type":    "Threat-Actor",
        "rel_type":      "related-to",
        "reversed":      False,
        "confidence":    0.65,
        "vendor_suffix": False,
    },
    {
        "pattern":       re.compile(r"\btracked\s+as\b", re.IGNORECASE),
        "before_type":   "Intrusion-Set",
        "after_type":    "Intrusion-Set",
        "rel_type":      "related-to",
        "reversed":      False,
        "confidence":    0.85,
        "vendor_suffix": True,
    },
    {
        "pattern":       re.compile(r"\b(?:also\s+)?known\s+as\b|\bdubbed\b|\bdesignated\s+as\b", re.IGNORECASE),
        "before_type":   "Intrusion-Set",
        "after_type":    "Intrusion-Set",
        "rel_type":      "related-to",
        "reversed":      False,
        "confidence":    0.80,
        "vendor_suffix": True,
    },
    {
        "pattern":       re.compile(r"\bdeployed\s+by\b", re.IGNORECASE),
        "before_type":   "Malware",
        "after_type":    "Intrusion-Set",
        "rel_type":      "uses",
        "reversed":      True,
        "confidence":    0.75,
        "vendor_suffix": False,
    },
    {
        "pattern":       re.compile(r"\bused\s+by\b", re.IGNORECASE),
        "before_type":   "Malware",
        "after_type":    "Intrusion-Set",
        "rel_type":      "uses",
        "reversed":      True,
        "confidence":    0.70,
        "vendor_suffix": False,
    },
    {
        "pattern":       re.compile(r"\btarget(?:ing|ed)\b", re.IGNORECASE),
        "before_type":   "Intrusion-Set",
        "after_type":    "Organization",
        "rel_type":      "targets",
        "reversed":      False,
        "confidence":    0.65,
        "vendor_suffix": False,
    },
    {
        "pattern":       re.compile(r"\bexploit(?:ing|ed|s)?\b", re.IGNORECASE),
        "before_type":   "Malware",
        "after_type":    "Vulnerability",
        "rel_type":      "exploits",
        "reversed":      False,
        "confidence":    0.75,
        "vendor_suffix": False,
    },
]

_MAX_BEFORE_WORDS    = 8
_MAX_AFTER_WORDS     = 8
_INLINE_STOPS        = re.compile(r"[,;:]|\s{2,}|\)|\]|—|–")
_HEAD_STOP_WORDS     = frozenset({
    "the", "a", "an", "and", "or", "but", "in", "on",
    "at", "by", "to", "of", "with", "from", "for", "its",
    "their", "this", "that", "these", "those",
})
_PROPER_NOUN_INTERIOR = frozenset({"of", "and", "the", "for", "in"})

# Words that are capitalised at sentence start but are not entity names.
# _extract_before returns "" when the entire extracted phrase reduces to
# one of these — preventing sentence openers from becoming Intrusion Set stubs.
_SENTENCE_OPENER_STOP = frozenset({
    "while", "following", "after", "before", "during", "when", "if",
    "although", "though", "because", "since", "once", "until",
    "western", "eastern", "northern", "southern", "central",
    "threat", "scape", "summary", "analysis", "note", "context",
    "background", "overview", "introduction", "conclusion",
    "additionally", "furthermore", "however", "therefore", "thus",
    "notably", "specifically", "particularly", "importantly",
    "recently", "previously", "currently", "historically",
    "according", "based", "given", "despite", "beyond",
    "across", "throughout", "ai", "ml",
})

# Org-indicator terms used to gate the after-side word-count ceiling.
# Mirrors the logic in victim.py — candidates with an indicator may be
# longer before being rejected.
_AFTER_ORG_INDICATORS = re.compile(
    r"\b(?:inc(?:orporated)?|ltd|llc|gmbh|corp(?:oration)?|plc|"
    r"ministry|department|agency|authority|bureau|commission|institute|"
    r"university|hospital|bank|group|holdings|international|national|"
    r"federal|government|court|courts|council|exchange)\b",
    re.IGNORECASE,
)

# After-side word-count ceilings — same rationale as victim.py.
_MAX_AFTER_WITHOUT_INDICATOR = 4
_MAX_AFTER_WITH_INDICATOR    = 7

# Words that signal the entity name phrase has ended on the after-side.
_AFTER_TAIL_STOPS = frozenset({
    "the", "a", "an", "and", "or", "in", "of", "at", "for",
    "to", "its", "their", "which", "that", "this", "since",
    "after", "before", "during", "as", "when", "where",
})


def _clean(s: str) -> str:
    return s.strip(" \t\r\n\"'.,;:()")


def _extract_before(text: str, cue_start: int) -> str:
    """
    Extract the entity name from text immediately BEFORE a cue phrase.

    Anchors on capitalised (proper noun) words rather than taking the
    last N words blindly. This prevents prose fragments like
    "by Handala Hack a persona reportedly" from being accepted when
    the cue fires mid-sentence with no clean preceding entity name.

    Algorithm:
      1. Narrow to the current sentence.
      2. Take the last _MAX_BEFORE_WORDS words.
      3. Walk right-to-left: collect capitalised words and interior
         connectors ("of", "and") that bridge capitalised words.
      4. Stop at the first non-capitalised, non-connector word once
         a proper phrase has been started.
      5. Strip trailing connectors and leading stop words.
      6. Return "" if no capitalised word was found.
    """
    prefix = text[:cue_start]
    for sep in (".", "!", "?", "\n"):
        last = prefix.rfind(sep)
        if last != -1 and (cue_start - last) < 400:
            prefix = prefix[last + 1:]
            break

    raw_words = prefix.strip().split()
    window = [w.strip(",.;:()[]\"'") for w in raw_words[-_MAX_BEFORE_WORDS:]]

    proper_phrase: List[str] = []
    found_capital = False

    for word in reversed(window):
        if not word:
            continue
        if word[0].isupper() or word.isupper():
            proper_phrase.insert(0, word)
            found_capital = True
        elif word.lower() in _PROPER_NOUN_INTERIOR and found_capital:
            proper_phrase.insert(0, word)
        else:
            if found_capital:
                break

    if not proper_phrase or not found_capital:
        return ""

    while proper_phrase and proper_phrase[-1].lower() in _PROPER_NOUN_INTERIOR:
        proper_phrase.pop()

    result = _clean(" ".join(proper_phrase))
    words  = result.split()
    while words and words[0].lower() in _HEAD_STOP_WORDS:
        words = words[1:]
    result = " ".join(words)

    # Reject sentence-opener words that happen to be capitalised but are
    # not entity names. A single-word result in _SENTENCE_OPENER_STOP is
    # a clear false positive (e.g. "While", "Following", "Western").
    if not result:
        return ""
    first_word = result.split()[0].lower()
    if first_word in _SENTENCE_OPENER_STOP:
        return ""

    return result


def _validate_after(candidate: str) -> bool:
    """
    Structural validation for after-side cue-phrase extraction.

    Mirrors _is_valid_candidate in victim.py. Rejects:
      - Empty / too short
      - Does not start with a capital letter
      - Exceeds word-count ceiling without an org-indicator term
      - Ends with a clause-continuation word (date fragment, preposition)
    """
    if not candidate or len(candidate) < 3:
        return False
    if not candidate[0].isupper():
        return False
    words = candidate.split()
    if len(words) > _MAX_AFTER_WITHOUT_INDICATOR and not _AFTER_ORG_INDICATORS.search(candidate):
        return False
    last = words[-1].lower().rstrip(".,;:")
    if last in _AFTER_TAIL_STOPS:
        return False
    return True


def _extract_after(text: str, cue_end: int) -> str:
    """Extract the entity name from text immediately AFTER a cue phrase."""
    tail = text[cue_end: cue_end + 300].strip()
    m = _INLINE_STOPS.search(tail)
    if m and m.start() < 120:
        tail = tail[:m.start()]
    for sep in (".", "!", "?", "\n"):
        if sep in tail:
            tail = tail.split(sep, 1)[0]
    words     = tail.strip().split()
    out:      List[str] = []
    has_ind   = False
    for w in words:
        clean = w.strip(",.;:()[]\"'")
        if clean.lower() in _HEAD_STOP_WORDS and not out:
            continue
        if not clean:
            continue
        if _AFTER_ORG_INDICATORS.search(clean):
            has_ind = True
        out.append(clean)
        limit = _MAX_AFTER_WITH_INDICATOR if has_ind else _MAX_AFTER_WITHOUT_INDICATOR
        if len(out) >= limit:
            break
    result = _clean(" ".join(out))
    # Structural validation — same gate as victim extraction.
    if not _validate_after(result):
        return ""
    return result


def _evidence_snippet(text: str, cue_start: int, cue_end: int) -> str:
    a = max(0, cue_start - 100)
    b = min(len(text), cue_end + 200)
    return re.sub(r"\s+", " ", text[a:b]).strip()[:300]


def extract_cue_relations(text: str, report_author: str) -> List[Dict[str, Any]]:
    """
    Scan pre-processed text for cue phrases and extract typed relationship
    candidates from both sides of each match.

    Input text must have passed through preprocess.preprocess_for_extraction()
    so defanged indicators are rehydrated and HTML is stripped.

    Candidates where _extract_before() returns "" are silently discarded —
    an empty before-side means the cue fired in prose with no clean entity
    name preceding it (the key fix for prose-fragment extraction).

    For vendor-suffix cues (tracked_as, known_as): the AFTER entity is
    flagged vendor_suffix=True; the caller creates it as
    "{name}({report_author})" and links it to the canonical BEFORE entity.
    """
    if not text:
        return []

    results: List[Dict[str, Any]] = []
    seen: set = set()

    for cue_def in _CUE_DEFS:
        pattern       = cue_def["pattern"]
        before_type   = cue_def["before_type"]
        after_type    = cue_def["after_type"]
        rel_type      = cue_def["rel_type"]
        reversed_     = cue_def["reversed"]
        confidence    = cue_def["confidence"]
        vendor_suffix = cue_def["vendor_suffix"]

        for m in pattern.finditer(text):
            before_name = _extract_before(text, m.start())
            after_name  = _extract_after(text, m.end())

            if not before_name or len(before_name) < 3:
                continue
            if not after_name or len(after_name) < 3:
                continue

            if reversed_:
                src_name, src_type = after_name,  after_type
                tgt_name, tgt_type = before_name, before_type
            else:
                src_name, src_type = before_name, before_type
                tgt_name, tgt_type = after_name,  after_type

            if not is_allowed(src_type, rel_type, tgt_type).allowed:
                continue

            dedup_key = f"{src_name.lower()}|{rel_type}|{tgt_name.lower()}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            results.append({
                "source_name":   src_name,
                "source_type":   src_type,
                "rel_type":      rel_type,
                "target_name":   tgt_name,
                "target_type":   tgt_type,
                "confidence":    confidence,
                "evidence":      _evidence_snippet(text, m.start(), m.end()),
                "basis":         "cue_phrase_relation",
                "vendor_suffix": vendor_suffix,
                "report_author": report_author,
            })

    return results


_RESOLVES_RE = re.compile(
    r"\b(?P<domain>[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.[a-zA-Z]{2,})\b"
    r".{0,60}"
    r"\b(?:resolv(?:es?|ed|ing)\s+to|resolved?\s+to|pointing\s+to|points?\s+to)\b"
    r".{0,60}"
    r"\b(?P<ip>(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\b",
    re.IGNORECASE,
)

_BELONGS_RE = re.compile(
    r"\b(?P<ip>(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\b"
    r".{0,80}"
    r"\b(?:belongs?\s+to|registered\s+(?:to|under)|part\s+of|in|within)\b"
    r".{0,80}"
    r"\b(?P<asn>AS\d{1,10})\b",
    re.IGNORECASE,
)


def extract_observable_chains(text: str) -> List[Dict[str, Any]]:
    """
    Detect DNS resolution (Domain → IP) and ASN membership (IP → ASN)
    patterns. Input must be refanged — defanged [.] notation will not match.
    Confidence 0.90 reflecting near-determinism of these sentence patterns.
    """
    if not text:
        return []

    results: List[Dict[str, Any]] = []
    seen: set = set()

    for m in _RESOLVES_RE.finditer(text):
        domain = m.group("domain").lower()
        ip     = m.group("ip")
        key    = f"domain→ip:{domain}:{ip}"
        if key in seen:
            continue
        seen.add(key)
        ctx_a    = max(0, m.start() - 60)
        ctx_b    = min(len(text), m.end() + 60)
        evidence = re.sub(r"\s+", " ", text[ctx_a:ctx_b]).strip()[:280]
        results.append({
            "source_name": domain, "source_type": "Domain-Name",
            "rel_type": "resolves-to",
            "target_name": ip, "target_type": "IPv4-Addr",
            "confidence": 0.90, "evidence": evidence,
            "basis": "observable_chain_resolves", "vendor_suffix": False,
        })

    for m in _BELONGS_RE.finditer(text):
        ip  = m.group("ip")
        asn = m.group("asn").upper()
        key = f"ip→asn:{ip}:{asn}"
        if key in seen:
            continue
        seen.add(key)
        ctx_a    = max(0, m.start() - 60)
        ctx_b    = min(len(text), m.end() + 60)
        evidence = re.sub(r"\s+", " ", text[ctx_a:ctx_b]).strip()[:280]
        results.append({
            "source_name": ip, "source_type": "IPv4-Addr",
            "rel_type": "belongs-to",
            "target_name": asn, "target_type": "Autonomous-System",
            "confidence": 0.90, "evidence": evidence,
            "basis": "observable_chain_asn", "vendor_suffix": False,
        })

    return results
