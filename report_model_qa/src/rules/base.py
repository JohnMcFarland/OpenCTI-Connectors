from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class RuleContext:
    # Raw report container
    report: Dict[str, Any]

    # Objects directly referenced by the report container (report-scope)
    objects: List[Dict[str, Any]]

    # Relationships discovered among those objects (best-effort)
    relationships: List[Dict[str, Any]]

    # Helper gives access to OpenCTI API + logging
    helper: Any

    # QA config snapshot (dict)
    config: Dict[str, Any]


class Rule:
    rule_id: str = "RULE_UNSET"
    title: str = "Unset Rule"
    default_severity: str = "INFO"

    def enabled(self, ctx: RuleContext) -> bool:
        return True

    def evaluate(self, ctx: RuleContext) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def finding(
        self,
        severity: str,
        message: str,
        object_refs: Optional[List[str]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        recommendation: str = "",
    ) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": severity,
            "message": message,
            "object_refs": object_refs or [],
            "evidence": evidence or {},
            "recommendation": recommendation,
        }
