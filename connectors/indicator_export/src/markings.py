"""TLP ordering and the marking ceiling check.

Anything that is not a recognised TLP marking ranks above every ceiling, so it
can never leave. An object with no marking at all is treated as the data
model's default, TLP:AMBER+STRICT.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Iterable

DEFAULT_MARKING = "TLP:AMBER+STRICT"

_TLP_RANK: Dict[str, int] = {
    "TLP:CLEAR": 0,
    "TLP:WHITE": 0,  # TLP 1.0 name for TLP:CLEAR
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}


def is_known_tlp(definition: str) -> bool:
    return definition in _TLP_RANK


def rank(definition: Any) -> float:
    """Rank one marking definition. Unknown definitions rank as infinity."""
    return _TLP_RANK.get(str(definition or "").strip().upper(), math.inf)


def highest_rank(markings: Iterable[Dict[str, Any]]) -> float:
    """Rank a marking list by its most restrictive entry."""
    ranks = [rank(marking.get("definition")) for marking in markings or []]
    return max(ranks) if ranks else rank(DEFAULT_MARKING)


def within_ceiling(markings: Iterable[Dict[str, Any]], ceiling: str) -> bool:
    return highest_rank(markings) <= rank(ceiling)
