from __future__ import annotations

from typing import Any, Dict, List

from .base import Rule, RuleContext


def _display_name(o: Dict[str, Any]) -> str:
    for k in ("name", "value", "observable_value"):
        v = o.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return o.get("standard_id") or o.get("id") or "(unnamed)"


class ThreatActorPolicyRule(Rule):
    rule_id = "QA.THREATACTOR.001"
    title = "Threat actor policy (real-world only)"
    default_severity = "WARN"

    def enabled(self, ctx: RuleContext) -> bool:
        return bool((ctx.config or {}).get("threatactor_realworld_only", True))

    def evaluate(self, ctx: RuleContext) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for o in (ctx.objects or []):
            if not isinstance(o, dict):
                continue

            et = o.get("entity_type") or ""
            if et != "Threat-Actor" and et != "ThreatActor":
                continue

            oid = o.get("id")
            nm = _display_name(o)

            # Heuristic placeholders: treat unnamed / generic / fictional patterns as suspect.
            # This should be replaced later by your actual data model rules or a curated allowlist.
            suspect = False
            aliases = o.get("aliases") or []
            if isinstance(nm, str):
                lower = nm.lower()
                if any(x in lower for x in ("unknown", "unspecified", "fiction", "test", "sample")):
                    suspect = True

            if suspect:
                findings.append(
                    self.finding(
                        "WARN",
                        "Threat actor appears non-real-world or placeholder (policy violation).",
                        object_refs=[oid] if oid else [],
                        evidence={
                            "object": f"{et}:{nm} ({oid})",
                            "aliases": aliases if isinstance(aliases, list) else [],
                        },
                        recommendation="Threat actors should be real-world organizations in this implementation. Use Intrusion Set / Campaign where appropriate for clustered activity.",
                    )
                )

        return findings
