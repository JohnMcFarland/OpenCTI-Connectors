"""Read-only lookups of objects that must already exist in OpenCTI.

Kept apart from the STIX builder so all OpenCTI API access sits behind one small
seam that tests can replace. Nothing here creates anything.
"""

from __future__ import annotations


class OpenCTILookup:
    def __init__(self, helper) -> None:
        self.api = helper.api
        self.log = helper.connector_logger
        self._attack_patterns: dict[str, str | None] = {}

    def begin_run(self) -> None:
        """Forget misses so techniques loaded since the last run (e.g. by the MITRE
        connector) are picked up; hits stay cached for the life of the process."""
        self._attack_patterns = {k: v for k, v in self._attack_patterns.items() if v}

    def marking(self, definition: str) -> str | None:
        """Standard id of the marking, else None (the caller refuses to start)."""
        try:
            return self._read(self.api.marking_definition, "definition", definition)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("Marking lookup failed", {"marking": definition, "error": str(exc)})
            return None

    def attack_pattern(self, mitre_id: str) -> str | None:
        """Standard id of the existing Attack Pattern with this MITRE ID, else None.
        API errors propagate: a miss is reported as "not in OpenCTI", which would be
        false, and the search must fail and retry rather than lose the link for good."""
        if mitre_id not in self._attack_patterns:
            self._attack_patterns[mitre_id] = self._read(
                self.api.attack_pattern, "x_mitre_id", mitre_id)
        return self._attack_patterns[mitre_id]

    @staticmethod
    def _read(entity_api, key: str, value: str) -> str | None:
        found = entity_api.read(filters={
            "mode": "and",
            "filters": [{"key": key, "values": [value]}],
            "filterGroups": [],
        })
        return found["standard_id"] if found else None
