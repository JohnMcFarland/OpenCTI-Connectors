"""Read-only lookups of objects that must already exist in OpenCTI.

All OpenCTI API reads sit behind this one seam. Nothing here creates anything, and
every result is cached, so a run costs one query per distinct country / CVE rather
than one per event (v0.4.2 searched before every single write).
"""

from __future__ import annotations

import pycountry


class OpenCTILookup:
    def __init__(self, helper) -> None:
        self.api = helper.api
        self.log = helper.connector_logger
        self._countries: dict[str, str | None] = {}
        self._vulns: dict[str, str | None] = {}

    def begin_run(self) -> None:
        """Forget misses so entities loaded since the last run (e.g. by the CVE
        connector) are picked up; hits stay cached for the life of the process."""
        self._countries = {k: v for k, v in self._countries.items() if v}
        self._vulns = {k: v for k, v in self._vulns.items() if v}

    def vulnerability(self, cve: str) -> str | None:
        """Existing Vulnerability named `cve`, else None. Never created here."""
        if cve not in self._vulns:
            self._vulns[cve] = self._read(self.api.vulnerability, "name", cve)
        return self._vulns[cve]

    def marking(self, definition: str) -> str | None:
        try:
            return self._read(self.api.marking_definition, "definition", definition)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("Marking lookup failed", {"marking": definition, "error": str(exc)})
            return None

    def country(self, iso2: str) -> str | None:
        """Existing Country whose alias is this ISO code (the OpenCTI location import
        carries ISO codes as aliases). Never created here."""
        if len(iso2) != 2 or not iso2.isalpha():
            return None
        if iso2 not in self._countries:
            found = self._country_by("x_opencti_aliases", iso2)
            if not found:  # fall back to the full English name (pycountry)
                c = pycountry.countries.get(alpha_2=iso2)
                if c:
                    found = self._country_by("name", c.name)
            self._countries[iso2] = found["standard_id"] if found else None
        return self._countries[iso2]

    def _country_by(self, key: str, value: str) -> dict | None:
        return self.api.location.read(filters={
            "mode": "and",
            "filters": [{"key": "entity_type", "values": ["Country"]},
                        {"key": key, "values": [value]}],
            "filterGroups": [],
        })

    @staticmethod
    def _read(entity_api, key: str, value: str) -> str | None:
        found = entity_api.read(filters={
            "mode": "and",
            "filters": [{"key": key, "values": [value]}],
            "filterGroups": [],
        })
        return found["standard_id"] if found else None
