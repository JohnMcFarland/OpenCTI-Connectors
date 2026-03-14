from __future__ import annotations

from typing import Any, Dict, List

from .base import Rule, RuleContext

# Concrete entity_type strings OpenCTI returns for observables.
# Must stay in sync with _OBSERVABLES in util/relationship_policy.py.
_OBSERVABLE_TYPES = frozenset({
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Url",
    "StixFile",
    "File",
    "Email-Addr",
    "Email-Message",
    "Mac-Addr",
    "Network-Traffic",
    "Process",
    "Windows-Registry-Key",
    "X509-Certificate",
    "Autonomous-System",
    "Directory",
    "Mutex",
    "Software",
    "User-Account",
    "Cryptocurrency-Wallet",
    "Bank-Account",
    "Phone-Number",
    "Text",
    "Hostname",
    "User-Agent",
    "Payment-Card",
    "Persona",
})


def _display_name(o: Dict[str, Any]) -> str:
    for k in ("name", "value", "observable_value"):
        v = o.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return o.get("standard_id") or o.get("id") or "(unnamed)"


class SightingsPolicyRule(Rule):
    rule_id = "QA.SIGHTINGS.001"
    title = "Sightings policy (observables only; IR-scoped; valid targets)"
    default_severity = "WARN"

    def enabled(self, ctx: RuleContext) -> bool:
        return bool((ctx.config or {}).get("enforce_sightings_policy", True))

    def evaluate(self, ctx: RuleContext) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        id_to_obj: Dict[str, Dict[str, Any]] = {
            o.get("id"): o
            for o in (ctx.objects or [])
            if isinstance(o, dict) and o.get("id")
        }

        for r in (ctx.relationships or []):
            if not isinstance(r, dict):
                continue
            rtype = r.get("relationship_type") or r.get("relationshipType")
            if rtype != "stix-sighting-relationship" and rtype != "sighting":
                continue

            rid = r.get("id")
            from_obj = r.get("from") or {}
            to_obj = r.get("to") or {}

            from_id = (from_obj or {}).get("id") or r.get("fromId")
            to_id = (to_obj or {}).get("id") or r.get("toId")

            from_res = id_to_obj.get(from_id) or (from_obj if isinstance(from_obj, dict) else {})
            to_res = id_to_obj.get(to_id) or (to_obj if isinstance(to_obj, dict) else {})

            from_type = (from_res.get("entity_type") or from_res.get("entityType") or "").strip()
            to_type = (to_res.get("entity_type") or to_res.get("entityType") or "").strip()

            from_name = _display_name(from_res)
            to_name = _display_name(to_res)

            # Rule 1: sighting source must be an observable
            if from_type and from_type not in _OBSERVABLE_TYPES:
                findings.append(
                    self.finding(
                        "WARN",
                        f"Sighting source '{from_name}' (type: {from_type}) is not an observable. "
                        "Sightings must only be used for observable entities.",
                        object_refs=[rid] if rid else [],
                        evidence={
                            "relationship_id": rid,
                            "from_type": from_type,
                            "from_name": from_name,
                            "to_type": to_type,
                            "to_name": to_name,
                        },
                        recommendation=(
                            "Sightings must only be created for Observable entities (IP, domain, hash, etc.). "
                            "They must appear inside Incident Response containers only, not Report containers."
                        ),
                    )
                )

            # Rule 2: sighting target must be System, Individual, or Organization
            _VALID_SIGHTING_TARGETS = frozenset({"System", "Individual", "Organization"})
            if to_type and to_type not in _VALID_SIGHTING_TARGETS:
                findings.append(
                    self.finding(
                        "WARN",
                        f"Sighting target '{to_name}' (type: {to_type}) is not a valid sighting target. "
                        "Valid targets are: System, Individual, Organization.",
                        object_refs=[rid] if rid else [],
                        evidence={
                            "relationship_id": rid,
                            "from_type": from_type,
                            "from_name": from_name,
                            "to_type": to_type,
                            "to_name": to_name,
                        },
                        recommendation=(
                            "The target of a Sighting must be a System (endpoint/asset), "
                            "Individual (user/employee), or Organization (internal business unit)."
                        ),
                    )
                )

            # Rule 3: sightings must not appear in Report containers (advisory)
            # We can only assert this as a WARN since we're running inside a Report enrichment.
            findings.append(
                self.finding(
                    "WARN",
                    f"Sighting relationship found inside a Report container. "
                    "Sightings must only appear inside Incident Response containers.",
                    object_refs=[rid] if rid else [],
                    evidence={
                        "relationship_id": rid,
                        "from_type": from_type,
                        "from_name": from_name,
                        "to_type": to_type,
                        "to_name": to_name,
                    },
                    recommendation=(
                        "Move this sighting to an Incident Response container. "
                        "Report containers must not contain sightings per the ingestion policy."
                    ),
                )
            )

        return findings
