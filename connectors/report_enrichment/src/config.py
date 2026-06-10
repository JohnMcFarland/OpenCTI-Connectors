from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return float(v)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


@dataclass(frozen=True)
class EnrichmentConfig:
    """
    All enrichment behaviour flags. Every value is sourced from environment
    variables so the connector can be tuned without rebuilding the image.
    Sensitive values (tokens, URLs) are never stored here — they live in
    docker-compose.override.yml exclusively.
    """

    # When True: run full extraction pipeline but write only a preview Note.
    # Nothing is created or modified in the graph. Used for analyst trust-
    # building and diagnosing false positives before the first production run.
    dry_run: bool = False

    # Minimum smart-parse confidence score required before the connector will
    # create an entity from a contextual extraction. Deterministic tokens
    # (CVE IDs, ATT&CK T-codes, UNC cluster IDs) always pass regardless of
    # this threshold — they are unambiguous structured identifiers.
    smart_confidence_threshold: float = 0.85

    # Whether to create Observable-type entities (IPv4, Domain, File hash,
    # URL, ASN, etc.). Set False to limit creation to SDOs only.
    create_observables: bool = True

    # Whether to create SDO-type entities (Intrusion Set, Malware, Tool, etc.)
    create_sdo: bool = True

    # When True, infer relationships from entity co-occurrence within the same
    # paragraph. Paragraph-bounded co-occurrence is a substantially stronger
    # signal than document-wide co-occurrence.
    paragraph_cooccurrence: bool = True

    # When True, scan extracted text for assessment language patterns
    # ("X assesses with high confidence that Y") and create Assessment Notes.
    assessment_notes: bool = True

    # When True, extract date strings proximate to entity mentions and
    # propagate them as first_seen candidates to created entities / relationships.
    temporal_hints: bool = True

    # When True, run a victim-oriented extraction pass looking for cue phrases
    # ("targeted", "compromised", "breached") followed by organisation-like strings.
    victim_extraction: bool = True

    # When True, extract both the entity BEFORE and AFTER cue phrases to
    # produce typed relationship candidates (e.g. "X attributed to Y").
    cue_relations: bool = True

    # When True, draw resolves-to and belongs-to chains for co-extracted
    # domain/IP and IP/ASN pairs found in DNS-resolution sentence contexts.
    observable_chains: bool = True

    # When True, write a structured summary Note on the report listing what
    # was created, linked, skipped, and why.
    write_summary_note: bool = True

    @staticmethod
    def from_env() -> "EnrichmentConfig":
        return EnrichmentConfig(
            dry_run=_env_bool("ENRICHMENT_DRY_RUN", False),
            smart_confidence_threshold=_env_float("ENRICHMENT_SMART_CONFIDENCE_THRESHOLD", 0.85),
            create_observables=_env_bool("ENRICHMENT_CREATE_OBSERVABLES", True),
            create_sdo=_env_bool("ENRICHMENT_CREATE_SDO", True),
            paragraph_cooccurrence=_env_bool("ENRICHMENT_PARAGRAPH_COOCCURRENCE", True),
            assessment_notes=_env_bool("ENRICHMENT_ASSESSMENT_NOTES", True),
            temporal_hints=_env_bool("ENRICHMENT_TEMPORAL_HINTS", True),
            victim_extraction=_env_bool("ENRICHMENT_VICTIM_EXTRACTION", True),
            cue_relations=_env_bool("ENRICHMENT_CUE_RELATIONS", True),
            observable_chains=_env_bool("ENRICHMENT_OBSERVABLE_CHAINS", True),
            write_summary_note=_env_bool("ENRICHMENT_WRITE_SUMMARY_NOTE", True),
        )
