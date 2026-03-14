from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class DispositionInputs:
    report_title:        str
    report_stix_id:      str
    generated:           str
    verdict:             str
    severity_counts:     Dict[str, int]
    scope_entities:      int
    scope_relationships: int
    metrics:             Dict[str, int]
    total_rules_run:     int = 11   # total rule modules evaluated


# ---------------------------------------------------------------------------
# Verdict banners
# ---------------------------------------------------------------------------

_PASS_BANNER = """\
╔══════════════════════════════════════╗
║                                      ║
║   ✓  VERDICT: PASS                   ║
║                                      ║
╚══════════════════════════════════════╝"""

_FAIL_BANNER = """\
╔══════════════════════════════════════╗
║                                      ║
║   ✗  VERDICT: FAIL                   ║
║                                      ║
╚══════════════════════════════════════╝"""


def _verdict_banner(verdict: str) -> str:
    return _PASS_BANNER if verdict.upper() == "PASS" else _FAIL_BANNER


# ---------------------------------------------------------------------------
# Quality score calculation
# ---------------------------------------------------------------------------

# Deduction weights per severity level
_DEDUCTION = {"BLOCKER": 30, "ERROR": 20, "WARN": 7, "INFO": 0}


def _deduction_score(severity_counts: Dict[str, int]) -> int:
    """
    Deduction-based score (0–100).
    Starts at 100, loses points per finding by severity.
    Floored at 0.
    """
    total_deduction = sum(
        _DEDUCTION.get(sev.upper(), 0) * count
        for sev, count in severity_counts.items()
    )
    return max(0, 100 - total_deduction)


def _pass_rate_score(
    severity_counts: Dict[str, int],
    total_rules_run: int,
) -> int:
    """
    Pass-rate score (0–100).
    Proportion of rule modules that produced no BLOCKER/ERROR/WARN findings.
    A rule module 'passes' if it contributed zero findings above INFO level.
    Approximated as: rules_clean / total_rules_run * 100.
    """
    rules_with_issues = (
        severity_counts.get("BLOCKER", 0)
        + severity_counts.get("ERROR", 0)
        + severity_counts.get("WARN", 0)
    )
    # Each unique finding = one rule module with issues (cap at total_rules_run)
    rules_with_issues = min(rules_with_issues, total_rules_run)
    rules_clean = max(0, total_rules_run - rules_with_issues)
    return int((rules_clean / total_rules_run) * 100) if total_rules_run > 0 else 0


def _score_label(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Poor"
    return "Critical"


def _severity_line(c: Dict[str, int]) -> str:
    return "  ".join(
        f"{sev}: {c.get(sev, 0)}"
        for sev in ("BLOCKER", "ERROR", "WARN", "INFO")
    )


# ---------------------------------------------------------------------------
# Assessment text
# ---------------------------------------------------------------------------

def _dynamic_assessment(inp: DispositionInputs) -> str:
    verdict = inp.verdict.upper()
    c = inp.severity_counts
    m = inp.metrics

    gaps              = m.get("contextualization_gaps", 0)
    rel_missing_desc  = m.get("relationships_missing_description", 0)
    rel_missing_req   = m.get("relationships_missing_required", 0)
    rel_poor_desc     = m.get("relationships_poor_description", 0)
    rel_temporal      = m.get("relationships_temporal_violations", 0)
    orphaned_obs      = m.get("orphaned_observables", 0)
    prov_mismatch     = m.get("provenance_mismatches", 0)
    policy_viol       = m.get("policy_violations", 0)
    policy_not_eval   = m.get("policy_not_evaluable", 0)
    recon_gaps        = m.get("reconciliation_gaps", 0)
    recon_errors      = m.get("reconciliation_errors", 0)
    duplicates        = m.get("duplicate_entities", 0)
    is_naming         = m.get("intrusion_set_naming_violations", 0)

    if verdict == "PASS":
        advisory: List[str] = []
        if gaps or rel_missing_desc:
            advisory.append(
                "contextualization is incomplete (relationships lacking "
                "descriptions and/or isolated entities)"
            )
        if rel_missing_req or rel_poor_desc:
            advisory.append(
                "relationship completeness is degraded (missing required "
                "metadata or insufficient descriptions)"
            )
        if rel_temporal:
            advisory.append("relationship temporal coherence violations detected")
        if orphaned_obs:
            advisory.append(
                "observables are not linked to a named Identity via related-to"
            )
        if prov_mismatch:
            advisory.append(
                "relationship provenance is inconsistent with container "
                "author/markings"
            )
        if policy_viol:
            advisory.append(
                "relationship types violate the hard-coded relationship policy"
            )
        if policy_not_eval:
            advisory.append(
                "some policy checks were not evaluable due to missing endpoint typing"
            )
        if recon_gaps:
            advisory.append(
                f"{recon_gaps} entities/observables found in source document "
                "but absent from report scope"
            )
        if duplicates:
            advisory.append(
                f"{duplicates} duplicate entity name(s) detected in scope"
            )
        if is_naming:
            advisory.append(
                f"{is_naming} Intrusion Set(s) do not follow the required "
                "naming convention"
            )
        if advisory:
            return (
                "This report meets the minimum data-model requirements for "
                "continued use. However, quality deficiencies remain that "
                "SHOULD be corrected before the report is treated as a durable "
                "reference: " + "; ".join(advisory) + "."
            )
        return (
            "This report satisfies all minimum data-model requirements. "
            "No material deficiencies were detected."
        )

    # FAIL
    drivers: List[str] = []
    if c.get("BLOCKER", 0) > 0:
        drivers.append(
            "BLOCKER findings invalidate the container as a reliable "
            "graph representation"
        )
    if c.get("ERROR", 0) > 0:
        drivers.append(
            "ERROR findings violate required data-model fields or "
            "provenance requirements"
        )
    if recon_errors:
        drivers.append(
            f"{recon_errors} high-confidence named entities were found in "
            "the source document but are absent from report scope"
        )
    if policy_viol:
        drivers.append(
            "relationship legitimacy violations detected against the "
            "hard-coded policy"
        )
    return (
        "This report does not satisfy minimum data-model requirements for "
        "reliable use. "
        + (" ".join(drivers) if drivers else "Material deficiencies were detected.")
        + " Remediation is required before this report should be relied upon "
        "for analytic conclusions."
    )


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def render_disposition(inp: DispositionInputs) -> str:
    c     = inp.severity_counts
    total = sum(c.values())

    d_score   = _deduction_score(c)
    pr_score  = _pass_rate_score(c, inp.total_rules_run)
    d_label   = _score_label(d_score)
    pr_label  = _score_label(pr_score)

    assessment = _dynamic_assessment(inp)

    lines: List[str] = []

    # Verdict banner
    lines.append(_verdict_banner(inp.verdict))
    lines.append("")

    # Disposition header
    lines.append("────────────────────────────────────────")
    lines.append("REPORT MODEL QA DISPOSITION")
    lines.append("────────────────────────────────────────")
    lines.append("")
    lines.append(f"Report Title: {inp.report_title}")
    lines.append(f"Report ID:    {inp.report_stix_id}")
    lines.append(f"Generated:    {inp.generated}")
    lines.append("")

    # Quality scores
    lines.append("Quality Scores")
    lines.append(
        f"  • Compliance score:  {d_score:3d} / 100  ({d_label})"
        f"  — starts at 100, deducts {_DEDUCTION['BLOCKER']} per BLOCKER, "
        f"{_DEDUCTION['ERROR']} per ERROR, {_DEDUCTION['WARN']} per WARN"
    )
    lines.append(
        f"  • Rule pass rate:    {pr_score:3d} / 100  ({pr_label})"
        f"  — {inp.total_rules_run - min(c.get('BLOCKER',0)+c.get('ERROR',0)+c.get('WARN',0), inp.total_rules_run)}"
        f" of {inp.total_rules_run} rule modules clean"
    )
    lines.append("")

    # Scope overview
    lines.append("Scope Overview")
    lines.append(f"  • Entities evaluated:      {inp.scope_entities}")
    lines.append(f"  • Relationships evaluated:  {inp.scope_relationships}")
    lines.append(f"  • Findings: {total}  ({_severity_line(c)})")
    lines.append("")

    # Assessment
    lines.append("Assessment")
    lines.append(assessment)
    lines.append("")
    lines.append("────────────────────────────────────────")
    lines.append("")

    return "\n".join(lines)
