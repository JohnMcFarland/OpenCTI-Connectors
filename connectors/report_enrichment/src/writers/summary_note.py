from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from qa.note_gql import create_note_gql


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _section(title: str, lines: List[str]) -> str:
    if not lines:
        return f"## {title}\n\nNone.\n"
    return f"## {title}\n\n" + "\n".join(f"- {l}" for l in lines) + "\n"


def compose_summary(
    report_title: str, dry_run: bool, config_snapshot: Dict[str, Any],
    entities_created: List[Dict[str, Any]], entities_linked: List[Dict[str, Any]],
    entities_skipped: List[Dict[str, Any]], relationships: List[Dict[str, Any]],
    rels_skipped: List[Dict[str, Any]], assessment_notes: int,
    temporal_hints: int, elapsed_seconds: float,
) -> str:
    mode_label = "DRY RUN (preview only — nothing was written to the graph)" if dry_run else "LIVE"

    type_counts: Dict[str, int] = {}
    for e in entities_created:
        t = e.get("entity_type") or "Unknown"
        type_counts[t] = type_counts.get(t, 0) + 1

    created_lines  = [f"{v}x {k}" for k, v in sorted(type_counts.items())]
    created_lines += [f"  {e.get('entity_type','?')}:{e.get('name','?')}" for e in entities_created[:30]]
    if len(entities_created) > 30:
        created_lines.append(f"  ... and {len(entities_created) - 30} more")

    linked_lines = [f"{e.get('entity_type','?')}:{e.get('name','?')}" for e in entities_linked[:40]]
    if len(entities_linked) > 40:
        linked_lines.append(f"... and {len(entities_linked) - 40} more")

    rel_lines = [
        f"{r.get('source','?')} -[{r.get('rel','?')}]-> {r.get('target','?')}  ({r.get('basis','')})"
        for r in relationships[:40]
    ]
    if len(relationships) > 40:
        rel_lines.append(f"... and {len(relationships) - 40} more")

    skip_lines = [
        f"{e.get('entity_type','?')}:{e.get('name','?')} — {e.get('reason','?')}"
        for e in entities_skipped[:20]
    ]
    rel_skip_lines = [
        f"{r.get('source','?')} -[{r.get('rel','?')}]-> {r.get('target','?')} — {r.get('reason','?')}"
        for r in rels_skipped[:20]
    ]

    sections = [
        f"# Enrichment Summary",
        f"\n**Mode:** {mode_label}  \n**Generated:** {_utc_now()}  \n**Elapsed:** {elapsed_seconds:.1f}s\n",
        "---\n",
        f"## Counts\n\n"
        f"- Entities created: {len(entities_created)}\n"
        f"- Entities linked (existing): {len(entities_linked)}\n"
        f"- Entities skipped: {len(entities_skipped)}\n"
        f"- Relationships created: {len(relationships)}\n"
        f"- Relationships skipped: {len(rels_skipped)}\n"
        f"- Assessment notes created: {assessment_notes}\n"
        f"- Temporal hints applied: {temporal_hints}\n",
        _section("Entities Created", created_lines),
        _section("Entities Linked (Existing, Added to Scope)", linked_lines),
        _section("Relationships Created", rel_lines),
        _section("Entities Skipped", skip_lines),
        _section("Relationships Skipped", rel_skip_lines),
        _section("Configuration", [f"{k}: {v}" for k, v in config_snapshot.items()]),
    ]
    return "\n".join(sections)


def write_summary_note(
    helper: Any, report_id: str, report_title: str, dry_run: bool,
    config_snapshot: Dict[str, Any], entities_created: List[Dict[str, Any]],
    entities_linked: List[Dict[str, Any]], entities_skipped: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]], rels_skipped: List[Dict[str, Any]],
    assessment_notes: int, temporal_hints: int, elapsed_seconds: float,
) -> None:
    body  = compose_summary(
        report_title=report_title, dry_run=dry_run, config_snapshot=config_snapshot,
        entities_created=entities_created, entities_linked=entities_linked,
        entities_skipped=entities_skipped, relationships=relationships,
        rels_skipped=rels_skipped, assessment_notes=assessment_notes,
        temporal_hints=temporal_hints, elapsed_seconds=elapsed_seconds,
    )
    mode  = "DRY RUN" if dry_run else "LIVE"
    create_note_gql(
        helper=helper,
        title=f"Enrichment Summary [{mode}] — {report_title}",
        content=body,
        objects=[report_id],
        note_types=["Enrichment"],
    )
