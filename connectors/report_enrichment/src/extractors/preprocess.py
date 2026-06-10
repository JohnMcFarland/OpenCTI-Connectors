from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# HTML stripping
# ---------------------------------------------------------------------------

# Matches any HTML tag — opening, closing, self-closing, with or without
# attributes. Bounded by > to prevent catastrophic backtracking.
_HTML_TAG_RE = re.compile(r"<[^>]+>", re.DOTALL)

# Common HTML entities found in CTI report HTML exports.
_HTML_ENTITIES: dict = {
    "&amp;":   "&",
    "&lt;":    "<",
    "&gt;":    ">",
    "&quot;":  '"',
    "&apos;":  "'",
    "&#39;":   "'",
    "&#x27;":  "'",
    "&nbsp;":  " ",
    "&mdash;": "—",
    "&ndash;": "–",
    "&hellip;": "...",
}

# Block-level HTML element endings that should become newlines to preserve
# paragraph boundaries for the downstream paragraph segmenter.
_BLOCK_END_RE = re.compile(
    r"</(?:p|div|li|h[1-6]|blockquote|section|article|header|footer|tr|td|th)>"
    r"|<br\s*/?>",
    re.IGNORECASE,
)


# Markdown bold/italic markers and heading prefixes that survive HTML
# stripping when source documents are rendered from markdown or contain
# markdown-formatted sections. These produce artifacts like "**Scape:**"
# that get accepted as entity names by the cue-phrase extractor.
_MD_INLINE_RE = re.compile(r"[*_]{1,3}")
_MD_HEADING_RE = re.compile(r"^#{1,6}\s+", re.MULTILINE)


def strip_markdown(text: str) -> str:
    """
    Remove inline markdown formatting markers and heading prefixes.
    Runs after strip_html — handles markdown artifacts that HTML stripping
    does not address (e.g. **bold**, *italic*, ## Heading).
    """
    if not text:
        return text
    text = _MD_HEADING_RE.sub("", text)
    text = _MD_INLINE_RE.sub("", text)
    return text


def strip_html(text: str) -> str:
    """
    Remove HTML markup from extracted document text.

    Processing order:
      1. Replace block-level closing tags with newlines to preserve
         paragraph boundaries.
      2. Decode common HTML entities to Unicode equivalents.
      3. Strip all remaining HTML tags.
      4. Normalise whitespace, preserving intentional newlines.
    """
    if not text:
        return text

    text = _BLOCK_END_RE.sub("\n", text)

    for entity, replacement in _HTML_ENTITIES.items():
        text = text.replace(entity, replacement)

    text = _HTML_TAG_RE.sub(" ", text)

    lines = text.split("\n")
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in lines]
    text  = "\n".join(lines)
    text  = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


# ---------------------------------------------------------------------------
# Defang rehydration (refanging)
# ---------------------------------------------------------------------------

# Order matters: longer / more specific patterns before shorter ones.
_REFANG_RULES: list = [
    (re.compile(r"\bhxxps://", re.IGNORECASE), "https://"),
    (re.compile(r"\bhxxp://",  re.IGNORECASE), "http://"),
    (re.compile(r"\[://\]"),                   "://"),
    (re.compile(r"\[\.\]"),                    "."),
    (re.compile(r"\(\.\)"),                    "."),
    (re.compile(r"\[:\]"),                     ":"),
    (re.compile(r"\[/\]"),                     "/"),
    (re.compile(r"\[at\]",  re.IGNORECASE),    "@"),
    (re.compile(r"\[@\]"),                     "@"),
]


def refang(text: str) -> str:
    """
    Rehydrate defanged indicators to their canonical fanged forms.

    CTI reports routinely defang indicators to prevent accidental navigation.
    Before pattern matching for entity extraction, all defanging must be
    reversed so that IPs, domains, and URLs are recognised by downstream
    regex extractors.

    The output is used exclusively for entity extraction and graph storage.
    Note output re-defangs values via defang.py before display to analysts.
    """
    if not text:
        return text
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# Combined preprocessing entry point
# ---------------------------------------------------------------------------

def preprocess_for_extraction(text: str) -> str:
    """
    Apply the full preprocessing pipeline to document text before extraction.

    Pipeline:
      1. strip_html  — remove markup, preserve paragraph structure
      2. refang      — rehydrate defanged indicators to canonical form

    All downstream extractors receive the output of this function.
    Entity values stored in the graph come from this clean fanged text.
    Note output defangs those values via defang.py before display.
    """
    text = strip_html(text)
    text = strip_markdown(text)
    text = refang(text)
    return text
