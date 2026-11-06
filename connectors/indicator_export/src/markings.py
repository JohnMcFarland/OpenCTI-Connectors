"""The export marking rule: everything may leave except blocked markings.

Terms match anywhere in the definition, ignoring case, so "Sensitive" also
catches "Highly Sensitive". Blocking too much is the safer way to be wrong.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable


def is_blocked(markings: Iterable[Dict[str, Any]], blocked_terms: Iterable[str]) -> bool:
    """True if any marking matches a blocked term.

    A marking with no definition cannot be checked, so it counts as blocked.
    An object with no markings at all has nothing to block.
    """
    terms = [term.lower() for term in blocked_terms]
    for marking in markings or []:
        definition = str(marking.get("definition") or "").strip().lower()
        if not definition or any(term in definition for term in terms):
            return True
    return False
