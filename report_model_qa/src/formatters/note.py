from __future__ import annotations

import json
from typing import Any, Dict, List

from formatters.tables import format_4col_table


def render_banner(title: str) -> str:
    lines = [
        "────────────────────────────────────────",
        title.upper(),
        "────────────────────────────────────────",
        "",
    ]
    return "\n".join(lines)


def render_section(f: Dict[str, Any], note_max_findings: int) -> str:
    section  = f.get("section") or "Findings"
    sev      = (f.get("severity") or "INFO").upper()
    code     = f.get("code") or "QA.UNKNOWN"
    title    = f.get("title") or ""
    norm     = f.get("norm") or ""
    rows     = f.get("rows") or []
    evidence = f.get("evidence")

    lines: List[str] = []

    if section in ("Document Extraction", "Reconciliation"):
        lines.append(render_banner(section).rstrip())
    else:
        lines.append(section.upper())
        lines.append("")

    lines.append(f"Finding:  {code}")
    lines.append(f"Severity: {sev}")
    if title:
        lines.append(f"Title:    {title}")
    if norm:
        lines.append(f"Standard: {norm}")
    lines.append("")

    if rows:
        if section in ("Document Extraction", "Reconciliation"):
            lines.append(format_4col_table(
                rows,
                max_rows=note_max_findings,
                headers=("Origin", "Signal", "Candidate", "Reason"),
            ))
        else:
            lines.append(format_4col_table(rows, max_rows=note_max_findings))
    else:
        lines.append("(No findings.)")
    lines.append("")

    if evidence is not None:
        lines.append("Evidence (machine)")
        try:
            lines.append(json.dumps(evidence))
        except Exception:
            lines.append(str(evidence))
        lines.append("")

    return "\n".join(lines)


_PCM_ORDER = [
    "Containment",
    "Contextualization",
    "Completeness",
    "Document Extraction",
    "Reconciliation",
    "Categorization",
    "Relationships",
    "Marking",
    "Sightings",
    "Threat Actor",
    "Labels",
]


def note_title(report_title: str, verdict: str) -> str:
    """
    Generate the OpenCTI note title. Verdict is included so it is
    visible in the notes list without opening the note.
    """
    v = verdict.upper()
    icon = "✓" if v == "PASS" else "✗"
    return f"QA [{icon} {v}]: {report_title}"


def compose_note(
    report: Dict[str, Any],
    verdict: str,
    findings: List[Dict[str, Any]],
    metrics: Dict[str, int],
    note_max_findings: int,
    disposition: str,
    config_snapshot: Dict[str, Any],
) -> str:
    from util.graph import safe_get

    order = {"BLOCKER": 0, "ERROR": 1, "WARN": 2, "INFO": 3}
    sorted_findings = sorted(
        findings,
        key=lambda x: order.get((x.get("severity") or "INFO").upper(), 9),
    )

    capped  = sorted_findings[:note_max_findings]
    omitted = len(sorted_findings) - len(capped)

    lines: List[str] = []
    lines.append(disposition)
    lines.append("TOP FINDINGS")
    lines.append("")

    for i, f in enumerate(capped, start=1):
        sev        = (f.get("severity") or "INFO").upper()
        code       = f.get("code") or "QA.UNKNOWN"
        title_line = f.get("title") or f.get("section") or ""
        lines.append(f"{i}. [{sev}] {code} — {title_line}")

    if omitted:
        lines.append(
            f"(+ {omitted} additional findings omitted — "
            "increase QA_NOTE_MAX_FINDINGS to see all)"
        )

    lines.append("")
    lines.append("FINDINGS")
    lines.append("")

    by_section: Dict[str, List[Dict[str, Any]]] = {}
    for f in capped:
        by_section.setdefault(f.get("section", "Findings"), []).append(f)

    for sec in _PCM_ORDER:
        for f in by_section.get(sec, []):
            lines.append(render_section(f, note_max_findings))

    for sec, fs in by_section.items():
        if sec not in _PCM_ORDER:
            for f in fs:
                lines.append(render_section(f, note_max_findings))

    lines.append("CONFIGURATION SNAPSHOT")
    try:
        lines.append(json.dumps(config_snapshot))
    except Exception:
        lines.append(str(config_snapshot))
    lines.append("")

    return "\n".join(lines).strip() + "\n"
