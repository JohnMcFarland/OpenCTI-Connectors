"""MITRE ATT&CK software lookup: maps tag names to MITRE S-numbers and type.

Loads a pre-built lookup table from data/mitre_attack_software.json.
To regenerate: python build_mitre_cache.py
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CACHE_PATH = Path(__file__).parent.parent / "data" / "mitre_attack_software.json"


class MitreLookup:
    """Case-insensitive lookup for MITRE ATT&CK software (malware + tools)."""

    def __init__(self):
        if not CACHE_PATH.exists():
            raise FileNotFoundError(
                f"MITRE ATT&CK cache not found at {CACHE_PATH}. "
                "Run 'python build_mitre_cache.py' to generate it."
            )
        with open(CACHE_PATH) as f:
            self._lookup: dict[str, dict] = json.load(f)
        logger.info("Loaded MITRE ATT&CK software cache (%d entries)", len(self._lookup))

    def get(self, name: str) -> Optional[dict]:
        key = name.lower()
        result = self._lookup.get(key)
        if result:
            return result
        return self._lookup.get(key.replace(" ", ""))

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def __len__(self) -> int:
        return len({v["external_id"] for v in self._lookup.values()})
