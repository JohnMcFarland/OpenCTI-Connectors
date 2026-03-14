from __future__ import annotations

from typing import Any, Dict, List

from .base import Rule, RuleContext


def _display_name(o: Dict[str, Any]) -> str:
    for k in ("name", "value", "observable_value"):
        v = o.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return o.get("standard_id") or o.get("id") or "(unnamed)"


# Collection requirement label prefixes as used in the ingestion manual.
# Format: CR-NNNN (e.g. "CR-0026: State-Nexus China")
# Extend this tuple if additional CR taxonomies are introduced.
_CR_PREFIXES = ("CR-", "REQ-", "COLREQ-")


class LabelPolicyRule(Rule):
    rule_id = "QA.LABELS.001"
    title = "Labels must represent collection requirements only"
    default_severity = "WARN"

    def enabled(self, ctx: RuleContext) -> bool:
        return bool((ctx.config or {}).get("enforce_label_policy", True))

    def evaluate(self, ctx: RuleContext) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for o in (ctx.objects or []):
            if not isinstance(o, dict):
                continue
            oid = o.get("id")
            et = o.get("entity_type") or "(unknown-type)"
            nm = _display_name(o)

            labels = o.get("labels") or []
            if not isinstance(labels, list):
                continue

            bad = [
                lab for lab in labels
                if isinstance(lab, str) and not any(lab.startswith(p) for p in _CR_PREFIXES)
            ]

            if not bad:
                continue

            findings.append(
                self.finding(
                    "WARN",
                    f"Object '{nm}' ({et}) has labels that do not match collection requirement format: {bad}.",
                    object_refs=[oid] if oid else [],
                    evidence={
                        "object": f"{et}:{nm} ({oid})",
                        "non_cr_labels": bad,
                        "all_labels": labels,
                        "expected_prefix_format": "CR-NNNN (e.g. CR-0026: State-Nexus China)",
                    },
                    recommendation=(
                        "Labels are reserved for collection requirements. "
                        "Use the format CR-NNNN as defined in Step 5 of the ingestion manual. "
                        "Remove or relabel any non-CR labels."
                    ),
                )
            )

        return findings
