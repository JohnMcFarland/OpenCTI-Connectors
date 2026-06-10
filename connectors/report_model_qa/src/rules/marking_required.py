from __future__ import annotations

from typing import Dict, List

from .base import Rule, RuleContext


class MarkingRequiredRule(Rule):
    rule_id = "QA.MARKING.001"
    title = "Report must have at least one marking definition"
    default_severity = "BLOCKER"

    def evaluate(self, ctx: RuleContext) -> List[Dict[str, object]]:
        report = ctx.report or {}
        report_id = report.get("id")

        # Your stack exposes objectMarking / objectMarkingIds on report.read()
        has_marking = False

        om = report.get("objectMarking")
        if isinstance(om, list) and len(om) > 0:
            has_marking = True

        om_ids = report.get("objectMarkingIds")
        if isinstance(om_ids, list) and len(om_ids) > 0:
            has_marking = True

        if has_marking:
            return []

        return [
            self.finding(
                "BLOCKER",
                "Report container has no marking definitions. Any marking is required.",
                object_refs=[report_id] if report_id else [],
                evidence={"checked_fields": ["objectMarking", "objectMarkingIds"]},
                recommendation="Assign at least one marking definition to the Report container (e.g., TLP:CLEAR).",
            )
        ]
