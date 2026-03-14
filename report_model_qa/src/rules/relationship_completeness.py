from __future__ import annotations

from typing import Any, Dict, List

from .base import Rule, RuleContext


def _display_name(o: Dict[str, Any]) -> str:
    for k in ("name", "value", "observable_value"):
        v = o.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return o.get("standard_id") or o.get("id") or "(unnamed)"


def _etype(o: Dict[str, Any]) -> str:
    return o.get("entity_type") or o.get("entityType") or "(unknown-type)"


class RelationshipCompletenessRule(Rule):
    rule_id = "QA.COMPLETENESS.001"
    title = "Relationship completeness (evidence/confidence/dates)"
    default_severity = "WARN"

    def enabled(self, ctx: RuleContext) -> bool:
        cfg = ctx.config or {}
        return bool(cfg.get("require_rel_evidence") or cfg.get("require_rel_confidence") or cfg.get("enforce_rel_dates"))

    def evaluate(self, ctx: RuleContext) -> List[Dict[str, Any]]:
        cfg = ctx.config or {}
        require_evidence = bool(cfg.get("require_rel_evidence", True))
        require_conf = bool(cfg.get("require_rel_confidence", True))
        min_conf = int(cfg.get("min_rel_confidence", 0) or 0)
        enforce_dates = bool(cfg.get("enforce_rel_dates", False))

        id_to_obj: Dict[str, Dict[str, Any]] = {
            o.get("id"): o for o in (ctx.objects or []) if isinstance(o, dict) and o.get("id")
        }

        findings: List[Dict[str, Any]] = []

        for r in (ctx.relationships or []):
            if not isinstance(r, dict):
                continue

            rid = r.get("id")
            rtype = r.get("relationship_type") or r.get("relationshipType") or "(unknown-relationship-type)"

            from_obj = r.get("from") or {}
            to_obj = r.get("to") or {}

            from_id = (from_obj or {}).get("id") or r.get("fromId")
            to_id = (to_obj or {}).get("id") or r.get("toId")

            from_res = id_to_obj.get(from_id) or (from_obj if isinstance(from_obj, dict) else {})
            to_res = id_to_obj.get(to_id) or (to_obj if isinstance(to_obj, dict) else {})

            from_disp = f"{_etype(from_res)}:{_display_name(from_res)} ({from_id})"
            to_disp = f"{_etype(to_res)}:{_display_name(to_res)} ({to_id})"

            desc = r.get("description") or r.get("x_opencti_description") or ""
            has_desc = isinstance(desc, str) and desc.strip() != ""

            conf = r.get("confidence")
            has_conf = isinstance(conf, int) and conf >= min_conf

            start = r.get("start_time") or r.get("startTime")
            stop = r.get("stop_time") or r.get("stopTime")
            has_dates = bool(start or stop)

            missing: List[str] = []
            if require_evidence and not has_desc:
                missing.append("description/evidence")
            if require_conf and not has_conf:
                missing.append("confidence")
            if enforce_dates and not has_dates:
                missing.append("dates")

            if not missing:
                continue

            findings.append(
                self.finding(
                    "WARN",
                    f"Relationship missing required fields: {', '.join(missing)}.",
                    object_refs=[rid] if rid else [],
                    evidence={
                        "relationship_id": rid,
                        "relationship_type": rtype,
                        "from": from_disp,
                        "to": to_disp,
                        "has_description": has_desc,
                        "confidence": conf,
                        "start_time": start,
                        "stop_time": stop,
                    },
                    recommendation="Populate relationship description with evidence from the source; set confidence if required; add dates if required by your model.",
                )
            )

        return findings
