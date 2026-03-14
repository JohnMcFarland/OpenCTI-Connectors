from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


@dataclass(frozen=True)
class QAConfig:
    # Output behavior
    write_note: bool = True
    attach_json: bool = True
    note_max_findings: int = 50
    max_findings_per_rule: int = 200
    emit_verdict: bool = True
    fail_on_blockers: bool = True

    # Enforcement toggles (aligned to your operating rules)
    enforce_label_policy: bool = True
    enforce_sightings_policy: bool = True
    threatactor_realworld_only: bool = True
    require_rel_evidence: bool = True
    require_rel_confidence: bool = True
    min_rel_confidence: int = 0
    enforce_rel_dates: bool = False

    # Safety fuses
    max_total_findings: int = 2000
    fail_if_graph_incomplete: bool = True

    @staticmethod
    def from_env() -> "QAConfig":
        return QAConfig(
            write_note=_env_bool("QA_WRITE_NOTE", True),
            attach_json=_env_bool("QA_ATTACH_JSON", True),
            note_max_findings=_env_int("QA_NOTE_MAX_FINDINGS", 50),
            max_findings_per_rule=_env_int("QA_MAX_FINDINGS_PER_RULE", 200),
            emit_verdict=_env_bool("QA_EMIT_VERDICT", True),
            fail_on_blockers=_env_bool("QA_FAIL_ON_BLOCKERS", True),
            enforce_label_policy=_env_bool("QA_ENFORCE_LABEL_POLICY", True),
            enforce_sightings_policy=_env_bool("QA_ENFORCE_SIGHTINGS_POLICY", True),
            threatactor_realworld_only=_env_bool("QA_THREATACTOR_REALWORLD_ONLY", True),
            require_rel_evidence=_env_bool("QA_REQUIRE_REL_EVIDENCE", True),
            require_rel_confidence=_env_bool("QA_REQUIRE_REL_CONFIDENCE", True),
            min_rel_confidence=_env_int("QA_MIN_REL_CONFIDENCE", 0),
            enforce_rel_dates=_env_bool("QA_ENFORCE_REL_DATES", False),
            max_total_findings=_env_int("QA_MAX_TOTAL_FINDINGS", 2000),
            fail_if_graph_incomplete=_env_bool("QA_FAIL_IF_GRAPH_INCOMPLETE", True),
        )
