from __future__ import annotations
import re

import os
import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from pycti import OpenCTIConnectorHelper

from config import EnrichmentConfig
from extractors.assessment import extract_assessments
from extractors.temporal import extract_temporal_hints
from extractors.victim import extract_victims
from extractors.paragraph_cooccurrence import segment_paragraphs, infer_paragraph_relationships
from extractors.cue_phrase_relations import extract_cue_relations, extract_observable_chains
from extractors.preprocess import preprocess_for_extraction
from util.defang import defang_entity_name, defang_text_block
from writers.entity_creator import EntityCreator
from writers.relationship_creator import RelationshipCreator
from writers.summary_note import write_summary_note

from qa.graph import safe_get
from qa.entity_kb import EntityKB
from qa.note_gql import create_note_gql
from qa.pdf_suggestions import (
    _assemble_text,
    _select_supported_files,
    _suggest_from_text_deterministic,
    _kb_scan_rows,
    _smart_parse_rows,
)
from qa.reconciliation import qa_reconciliation

APP_NAME    = "Report Enrichment"
APP_VERSION = "1.0.0"

logger = logging.getLogger(__name__)

_OBSERVABLE_TYPES: Set[str] = {
    "IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "Email-Addr",
    "StixFile", "Autonomous-System", "Windows-Registry-Key",
    "Mutex", "User-Account", "Network-Traffic", "X509-Certificate",
    "Bank-Account", "Software",
}

_CREATABLE_SDO_TYPES: Set[str] = {
    "Intrusion-Set", "Threat-Actor", "Campaign", "Malware", "Tool",
    "Attack-Pattern", "Vulnerability", "Infrastructure", "Channel",
    "Organization", "Sector",
}

_MANAGED_TYPES: Set[str] = {"Course-Of-Action"}

_DETERMINISTIC_REASONS: Set[str] = {
    "UNC pattern found in extracted text.",
    "CVE identifier found in extracted text.",
    "ATT&CK technique ID found in extracted text.",
    "ATT&CK mitigation ID found in extracted text.",
    "CAPEC identifier found in extracted text.",
}

_LIKELIHOOD_FROM_CONFIDENCE = {
    range(90, 101): "Very High",
    range(75,  90): "High",
    range(40,  75): "Medium",
    range(10,  40): "Low",
    range(0,   10): "Very Low",
}


def _likelihood_label(confidence_int: int) -> Optional[str]:
    for r, label in _LIKELIHOOD_FROM_CONFIDENCE.items():
        if confidence_int in r:
            return label
    return None


class ReportEnrichmentConnector:
    """
    Enrichment connector: reads a Report container's attached document, extracts
    entities and relationships using the QA connector's extraction pipeline, and
    materialises them directly into the knowledge graph.
    Trigger: INTERNAL_ENRICHMENT on Report scope — fired manually by an analyst.
    """

    def __init__(self) -> None:
        self.cfg = EnrichmentConfig.from_env()
        self.helper = OpenCTIConnectorHelper({
            "opencti_url":                os.environ.get("OPENCTI_URL"),
            "opencti_token":              os.environ.get("OPENCTI_TOKEN"),
            "connector_id":               os.environ.get("CONNECTOR_ID"),
            "connector_type":             os.environ.get("CONNECTOR_TYPE", "INTERNAL_ENRICHMENT"),
            "connector_name":             os.environ.get("CONNECTOR_NAME", APP_NAME),
            "connector_scope":            os.environ.get("CONNECTOR_SCOPE", "Report"),
            "connector_confidence_level": int(os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", "50")),
            "connector_log_level":        os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
        })
        self._kb = EntityKB()
        logger.info("%s v%s started (dry_run=%s)", APP_NAME, APP_VERSION, self.cfg.dry_run)

    def _enrichment_handler(self, data: Dict[str, Any]) -> str:
        entity_id = safe_get(data, "entity_id", "entityId", "id")
        if not entity_id:
            return "No entity_id in message"
        return self._process_report(str(entity_id))

    def run(self) -> None:
        self.helper.listen(message_callback=self._enrichment_handler)

    def _process_report(self, report_stix_id: str) -> str:
        t_start = time.monotonic()
        self._kb.ensure_ready(self.helper)

        report = self.helper.api.report.read(id=report_stix_id, withFiles=True)
        if not report:
            logger.error("Report not found: %s", report_stix_id)
            return "Report not found"

        report_id     = safe_get(report, "id") or ""
        report_title  = safe_get(report, "name") or "(untitled report)"
        report_author = self._resolve_author_name(report)

        logger.info("Processing report: %s", report_title)

        # --- Extract text ---
        file_sets = _select_supported_files(report)
        extraction_attempts: List[str] = []
        extracted_text, pdf_meta = _assemble_text(self.helper, report, file_sets, extraction_attempts)
        # Strip HTML markup and rehydrate defanged indicators before any extractor runs.
        # All downstream extractors receive clean fanged text. Note output re-defangs
        # observable values via defang_entity_name() at write time.
        extracted_text = preprocess_for_extraction(extracted_text)

        if not extracted_text.strip():
            msg = (f"No text could be extracted from report attachments or content fields. "
                   f"Attempted: {', '.join(extraction_attempts) or 'none'}.")
            logger.warning(msg)
            if self.cfg.write_summary_note:
                create_note_gql(helper=self.helper,
                                title=f"Enrichment: No text extracted — {report_title}",
                                content=msg, objects=[report_id], note_types=["Enrichment"])
            return "No text extracted — nothing to enrich"

        # --- Extraction pipeline ---
        det_rows, _, _        = _suggest_from_text_deterministic(extracted_text)
        # Post-filter deterministic domain candidates: reject URL path fragments
        # (slug-like strings ending in .html/.htm/.php, or containing path separators)
        # that the domain regex matches when processing article-sourced documents.
        det_rows = [
            r for r in det_rows
            if not (
                isinstance(r, (tuple, list))
                and len(r) >= 3
                and str(r[2]).startswith('Domain-Name:')
                and self._is_url_slug(str(r[2]).partition(':')[2])
            )
            and not (
                isinstance(r, (tuple, list))
                and len(r) >= 3
                and str(r[2]).startswith('Url:')
                and self._is_news_url(str(r[2]).partition(':')[2])
            )
        ]
        kb_rows, kb_matches   = _kb_scan_rows(extracted_text, self._kb)
        smart_rows, _, smart_candidates = _smart_parse_rows(extracted_text, kb=self._kb)

        victim_candidates: List[Dict[str, Any]] = []
        if self.cfg.victim_extraction:
            victim_candidates = extract_victims(extracted_text)
            logger.info("Victim extraction: %d candidates", len(victim_candidates))

        cue_relations: List[Dict[str, Any]] = []
        if self.cfg.cue_relations:
            cue_relations = extract_cue_relations(extracted_text, report_author)
            logger.info("Cue-phrase relations: %d candidates", len(cue_relations))

        obs_chains: List[Dict[str, Any]] = []
        if self.cfg.observable_chains:
            obs_chains = extract_observable_chains(extracted_text)
            logger.info("Observable chains: %d candidates", len(obs_chains))

        para_relations: List[Dict[str, Any]] = []
        if self.cfg.paragraph_cooccurrence:
            paragraphs    = segment_paragraphs(extracted_text)
            all_candidates = self._build_candidate_list(smart_candidates, kb_matches, victim_candidates)
            para_relations = infer_paragraph_relationships(paragraphs, all_candidates)
            logger.info("Paragraph co-occurrence: %d relation candidates", len(para_relations))

        assessment_records: List[Dict[str, Any]] = []
        if self.cfg.assessment_notes:
            assessment_records = extract_assessments(extracted_text, report_author)
            logger.info("Assessment patterns: %d found", len(assessment_records))

        temporal_hints_list: List[Dict[str, Any]] = []
        if self.cfg.temporal_hints:
            all_candidates_t = self._build_candidate_list(smart_candidates, kb_matches, victim_candidates)
            temporal_hints_list = extract_temporal_hints(extracted_text, all_candidates_t)
            logger.info("Temporal hints: %d found", len(temporal_hints_list))

        # --- Reconciliation ---
        current_obj_ids = self._enumerate_report_object_ids(report)
        resolved_objects, relationship_ids, _ = self._resolve_scope(current_obj_ids)
        recon_finding = qa_reconciliation(resolved_objects, det_rows + smart_rows, kb_matches, smart_candidates)
        recon_gaps    = recon_finding.get("rows") or []
        logger.info("Reconciliation: %d gaps", len(recon_gaps))

        temporal_index = self._build_temporal_index(temporal_hints_list)

        # --- Dry run or live ---
        if self.cfg.dry_run:
            return self._write_dry_run_preview(
                report_id=report_id, report_title=report_title, kb_matches=kb_matches,
                recon_gaps=recon_gaps, smart_candidates=smart_candidates,
                victim_candidates=victim_candidates, cue_relations=cue_relations,
                obs_chains=obs_chains, para_relations=para_relations,
                assessment_records=assessment_records, temporal_hints=temporal_hints_list,
                elapsed=time.monotonic() - t_start,
            )

        entity_cr = EntityCreator(self.helper, report)
        rel_cr    = RelationshipCreator(
            helper=self.helper, report=report, markings=entity_cr.markings,
            created_by=entity_cr.created_by, report_id=report_id,
        )
        id_map: Dict[str, str] = {}

        # Phase A: Link KB-matched entities.
        # Attack-Pattern entities are gated to MITRE-confirmed entries only.
        # Generic KB entities typed as Attack-Pattern (e.g. "Cyber Espionage",
        # "Email Account") must not be linked — they are not ATT&CK techniques.
        # Only link if the KB entry carries a mitre_id field, or if the entity
        # name matches the T-code pattern, or if the KB explicitly flagged it
        # as a MITRE technique via its external_references.
        for match in kb_matches:
            eid   = match.get("entity_id","")
            etype = match.get("entity_type","")
            ename = match.get("name","")
            if not eid or not etype or not ename:
                continue
            if etype == "Attack-Pattern" and not self._is_mitre_attack_pattern(match):
                entity_cr.skipped.append({
                    "entity_type": etype, "name": ename,
                    "reason": "attack_pattern_not_mitre: no confirmed T-code in KB entry",
                })
                logger.info("Skipped non-MITRE Attack-Pattern KB match: %s", ename)
                continue
            entity_cr.link_existing(eid, etype, ename)
            id_map[f"{etype}:{ename.lower()}"] = eid

        # Phase B: Materialise reconciliation gaps
        self._materialise_gaps(recon_gaps, smart_candidates, entity_cr, id_map, temporal_index, report_author)

        # Phase C: Victim entities
        for victim in victim_candidates:
            if not victim.get("name"):
                continue
            conf_int = int(round(victim.get("confidence", 0.60) * 100))
            snippet  = victim.get("snippet") or ""
            desc = (f"Potential victim organisation identified via cue-phrase extraction. "
                    f"Cue: '{victim.get('cue_phrase', '')}'. Context: \"{snippet[:200]}\"")
            eid = entity_cr.ensure_sdo("Organization", victim["name"], description=desc,
                                       confidence=conf_int, basis="victim_extraction")
            if eid:
                id_map[f"Organization:{victim['name'].lower()}"] = eid

        # Phase D: Cue-phrase relationships
        for rel_cand in cue_relations:
            src_name, src_type = rel_cand["source_name"], rel_cand["source_type"]
            tgt_name, tgt_type = rel_cand["target_name"], rel_cand["target_type"]
            rel_type, confidence, evidence = rel_cand["rel_type"], rel_cand["confidence"], rel_cand["evidence"]
            is_vendor = rel_cand.get("vendor_suffix", False)

            src_id = self._ensure_entity_by_name(entity_cr, id_map, src_type, src_name, False, "cue_phrase_source")
            tgt_id = self._ensure_entity_by_name(entity_cr, id_map, tgt_type, tgt_name, is_vendor, "cue_phrase_target")
            if not src_id or not tgt_id:
                logger.warning("Phase D: skipping cue-phrase relationship %s -[%s]-> %s — src_id=%s tgt_id=%s",
                               src_name, rel_type, tgt_name, src_id, tgt_id)
                continue

            desc       = f"Cue-phrase extraction: '{evidence[:200]}'. Basis: {rel_cand.get('basis','')}."
            start_time = temporal_index.get(f"{src_type}:{src_name.lower()}")
            rel_cr.create_relationship(source_id=src_id, source_type=src_type, rel_type=rel_type,
                                       target_id=tgt_id, target_type=tgt_type, description=desc,
                                       confidence=confidence, start_time=start_time,
                                       basis=rel_cand.get("basis","cue_phrase"),
                                       source_name=src_name, target_name=tgt_name)

            if is_vendor:
                canonical_id = self._kb_lookup_id(tgt_name)
                if canonical_id and canonical_id != tgt_id:
                    vs_name = f"{tgt_name}({report_author})"
                    rel_cr.create_relationship(source_id=tgt_id, source_type=tgt_type,
                                               rel_type="related-to", target_id=canonical_id,
                                               target_type=tgt_type,
                                               description=f"{vs_name} is a vendor-specific designator as used by {report_author}.",
                                               confidence=0.90, basis="vendor_suffix_link",
                                               source_name=vs_name, target_name=tgt_name)

        # Phase E: Observable chains
        for chain in obs_chains:
            src_id = self._ensure_entity_by_name(entity_cr, id_map, chain["source_type"], chain["source_name"], False, "observable_chain")
            tgt_id = self._ensure_entity_by_name(entity_cr, id_map, chain["target_type"], chain["target_name"], False, "observable_chain")
            if not src_id or not tgt_id:
                continue
            rel_cr.create_relationship(source_id=src_id, source_type=chain["source_type"],
                                       rel_type=chain["rel_type"], target_id=tgt_id,
                                       target_type=chain["target_type"],
                                       description=f"Observable chain: {chain['evidence'][:200]}",
                                       confidence=chain["confidence"], basis=chain.get("basis","observable_chain"),
                                       source_name=chain["source_name"], target_name=chain["target_name"])

        # Phase F: Paragraph co-occurrence
        # Diagnostic: log id_map contents and all para_relation candidates
        logger.info("Phase F diagnostic — id_map entries (%d): %s",
                    len(id_map), list(id_map.keys()))
        logger.info("Phase F diagnostic — para_relations (%d): %s",
                    len(para_relations),
                    [(r['source_type'], r['source_name'], r['rel_type'],
                      r['target_type'], r['target_name']) for r in para_relations])
        for para_rel in para_relations:
            src_key = f"{para_rel['source_type']}:{para_rel['source_name'].lower()}"
            tgt_key = f"{para_rel['target_type']}:{para_rel['target_name'].lower()}"
            src_id = id_map.get(src_key)
            tgt_id = id_map.get(tgt_key)
            if not src_id:
                logger.warning("Phase F: src not in id_map — key=%s available_keys=%s",
                               src_key, [k for k in id_map if para_rel['source_type'].lower() in k])
            if not tgt_id:
                logger.warning("Phase F: tgt not in id_map — key=%s available_keys=%s",
                               tgt_key, [k for k in id_map if para_rel['target_type'].lower() in k])
            if not src_id or not tgt_id:
                # Fallback: attempt entity search rather than silently skipping.
                # MITRE gate: Attack-Pattern entities must not be created via the
                # fallback path — they bypassed the KB match gate meaning no T-code
                # was confirmed. Creating them here would produce non-MITRE stubs.
                if not src_id:
                    if para_rel["source_type"] == "Attack-Pattern":
                        logger.info("Phase F fallback: skipping Attack-Pattern source "
                                    "%s — no confirmed T-code", para_rel["source_name"])
                    else:
                        src_id = self._ensure_entity_by_name(
                            entity_cr, id_map, para_rel["source_type"],
                            para_rel["source_name"], False, "para_cooccurrence_fallback"
                        )
                if not tgt_id:
                    if para_rel["target_type"] == "Attack-Pattern":
                        logger.info("Phase F fallback: skipping Attack-Pattern target "
                                    "%s — no confirmed T-code", para_rel["target_name"])
                    else:
                        tgt_id = self._ensure_entity_by_name(
                            entity_cr, id_map, para_rel["target_type"],
                            para_rel["target_name"], False, "para_cooccurrence_fallback"
                        )
            if not src_id or not tgt_id:
                logger.warning("Phase F: skipping relationship %s -[%s]-> %s — could not resolve both entities",
                               para_rel["source_name"], para_rel["rel_type"], para_rel["target_name"])
                continue
            rel_cr.create_relationship(source_id=src_id, source_type=para_rel["source_type"],
                                       rel_type=para_rel["rel_type"], target_id=tgt_id,
                                       target_type=para_rel["target_type"],
                                       description=f"Paragraph co-occurrence: \"{para_rel['evidence'][:200]}\". Analyst validation recommended.",
                                       confidence=para_rel["confidence"], basis="paragraph_cooccurrence",
                                       source_name=para_rel["source_name"], target_name=para_rel["target_name"])

        # Phase G: Assessment Notes
        assessment_notes_created = 0
        for rec in assessment_records:
            try:
                likelihood = rec.get("likelihood") or _likelihood_label(rec.get("confidence", 50))
                content = (f"**Subject:** {rec['subject']}\n\n**Claim:** {rec['claim']}\n\n"
                           f"**Confidence:** {rec['confidence']}\n**Likelihood:** {likelihood or 'Not specified'}\n\n"
                           f"**Source sentence:** \"{rec['sentence']}\"\n\n"
                           f"*Auto-extracted by Report Enrichment connector. Verify against source document.*")
                create_note_gql(helper=self.helper,
                                title=f"Assessment: {rec['subject']} — {rec['claim'][:80]}",
                                content=content, objects=[report_id], note_types=["Assessment"])
                assessment_notes_created += 1
            except Exception as e:
                logger.warning("Failed to create assessment note: %s", e)

        # Phase H: Summary note
        elapsed = time.monotonic() - t_start
        config_snapshot = {
            "version": APP_VERSION, "dry_run": self.cfg.dry_run,
            "smart_confidence_threshold": self.cfg.smart_confidence_threshold,
            "create_observables": self.cfg.create_observables, "create_sdo": self.cfg.create_sdo,
            "paragraph_cooccurrence": self.cfg.paragraph_cooccurrence,
            "assessment_notes": self.cfg.assessment_notes, "temporal_hints": self.cfg.temporal_hints,
            "victim_extraction": self.cfg.victim_extraction, "cue_relations": self.cfg.cue_relations,
            "observable_chains": self.cfg.observable_chains, "kb_entries": self._kb.entry_count,
        }
        if self.cfg.write_summary_note:
            write_summary_note(helper=self.helper, report_id=report_id, report_title=report_title,
                               dry_run=False, config_snapshot=config_snapshot,
                               entities_created=entity_cr.created, entities_linked=entity_cr.linked,
                               entities_skipped=entity_cr.skipped, relationships=rel_cr.created,
                               rels_skipped=rel_cr.skipped, assessment_notes=assessment_notes_created,
                               temporal_hints=len(temporal_hints_list), elapsed_seconds=elapsed)

        summary = (f"Enrichment complete: created={len(entity_cr.created)} linked={len(entity_cr.linked)} "
                   f"relationships={len(rel_cr.created)} assessments={assessment_notes_created} elapsed={elapsed:.1f}s")
        logger.info(summary)
        return summary

    # --- Materialisation helpers ---

    # Known news and media domains — their hostnames and article URLs are
    # source citations, not adversary infrastructure. Suppressed from the
    # domain/URL observable candidate list.
    _NEWS_DOMAINS: frozenset = frozenset({
        "securityaffairs.com", "tecmundo.com.br", "bleepingcomputer.com",
        "therecord.media", "darkreading.com", "cyberscoop.com",
        "wired.com", "arstechnica.com", "reuters.com", "apnews.com",
        "bbc.com", "bbc.co.uk", "cnn.com", "thehackernews.com",
        "threatpost.com", "zdnet.com", "securityweek.com",
        "krebsonsecurity.com", "bankinfosecurity.com", "govinfosecurity.com",
        "databreaches.net", "hackread.com", "infosecurity-magazine.com",
    })

    # TLD-only patterns: fragments like "com.br", "co.uk" that the domain
    # regex matches when parsing compound ccTLDs split from full hostnames.
    _TLD_ONLY_RE = re.compile(
        r"^(?:com|net|org|edu|gov|mil|co|ac|ne|or)\.[a-z]{2,3}$",
        re.IGNORECASE,
    )

    @staticmethod
    def _is_mitre_attack_pattern(kb_match: dict) -> bool:
        """
        Return True only if a KB-matched Attack-Pattern entity has a confirmed
        MITRE ATT&CK external reference. Gates the KB match phase to prevent
        generic entities typed as Attack-Pattern (e.g. "Cyber Espionage",
        "Email Account") from being linked as if they were ATT&CK techniques.

        Checks:
          1. KB entry carries a mitre_id field (populated if EntityKB stores it)
          2. Entity name matches the T#### or T####.### pattern
          3. KB entry has an x_mitre_id in its external_references field
        """
        import re as _re
        _TCODE_RE = _re.compile(r"T\d{4}(?:\.\d{3})?")

        name = (kb_match.get("name") or "").strip()
        if _TCODE_RE.search(name):
            return True
        mitre_id = kb_match.get("mitre_id") or kb_match.get("x_mitre_id") or ""
        if mitre_id and _TCODE_RE.search(str(mitre_id)):
            return True
        ext_refs = kb_match.get("external_references") or []
        for ref in ext_refs:
            if isinstance(ref, dict):
                ext_id = ref.get("external_id") or ""
                if _TCODE_RE.search(str(ext_id)):
                    return True
        return False

    @staticmethod
    def _is_news_url(url: str) -> bool:
        """
        Return True if a URL candidate is a news article citation rather than
        adversary infrastructure. Matches against the known news domain list.
        Source citation URLs appear in documents as references and should not
        be ingested as threat observables.
        """
        if not url:
            return False
        url_lower = url.lower()
        # Strip scheme for domain matching
        for scheme in ("https://", "http://", "hxxps://", "hxxp://"):
            if url_lower.startswith(scheme):
                url_lower = url_lower[len(scheme):]
                break
        # Strip www. prefix
        if url_lower.startswith("www."):
            url_lower = url_lower[4:]
        # Match against news domains
        for nd in ReportEnrichmentConnector._NEWS_DOMAINS:
            if url_lower == nd or url_lower.startswith(nd + "/") or url_lower.startswith(nd + ":"):
                return True
        return False

    @staticmethod
    def _is_url_slug(name: str) -> bool:
        """
        Return True if a candidate domain name should be suppressed as a
        non-adversary domain. Catches:
          - URL path fragments ending in web file extensions
          - Values containing path separators
          - Hyphen-dense article slugs
          - TLD-only fragments (com.br, co.uk) split from compound ccTLDs
          - Right-hand labels too long to be valid TLDs (> 6 chars)
          - Known news / media domains whose URLs are source citations
        """
        import re as _re
        if not name:
            return False
        # Web file extensions and binary file extensions.
        # Binary extensions (.dll, .exe, .apk, etc.) appear in malware reports
        # as filenames and are matched by the domain regex because their extension
        # looks like a TLD. Reject them as domain observables — they belong as
        # StixFile entries, not Domain-Name entries.
        if _re.search(
            r"\.(html?|php|aspx?|jsp|cfm|cgi|shtml|"
            r"dll|exe|apk|rar|zip|sys|bat|ps1|sh|jar|deb|rpm|msi|cab|pkg|"
            r"dmg|iso|img|vhd|vmdk|bin|dat|tmp|log|ini|cfg|conf|"
            r"pdf|doc|docx|xls|xlsx|ppt|pptx|txt|csv|json|xml|yaml|yml)$",
            name, _re.IGNORECASE
        ):
            return True
        # Path separators
        if "/" in name:
            return True
        # Hyphen-dense slugs
        left_label = name.split(".")[0]
        if left_label.count("-") > 4:
            return True
        if len(left_label) > 30 and "-" in left_label:
            return True
        # TLD-only fragments (com.br, co.uk, etc.)
        if ReportEnrichmentConnector._TLD_ONLY_RE.match(name):
            return True
        # Right-hand label too long to be a real TLD — catches "www.tecmundo"
        # where "tecmundo" is parsed as the TLD by the domain regex.
        parts = name.split(".")
        if len(parts) >= 2 and len(parts[-1]) > 6:
            return True
        # Known news / media domains
        name_lower = name.lower()
        for nd in ReportEnrichmentConnector._NEWS_DOMAINS:
            if name_lower == nd or name_lower.endswith("." + nd):
                return True
        return False

    def _materialise_gaps(self, recon_gaps, smart_candidates, entity_cr, id_map, temporal_index, report_author):
        sp_confidence: Dict[str, float] = {
            (c.get("name") or "").lower(): c.get("confidence", 0.0) for c in (smart_candidates or [])
        }
        for row in recon_gaps:
            if not isinstance(row, (tuple, list)) or len(row) < 3:
                continue
            signal, candidate, reason = (row[1] if len(row)>1 else ""), (row[2] if len(row)>2 else ""), (row[3] if len(row)>3 else "")
            if signal != "missing-from-scope" or ":" not in str(candidate):
                continue
            entity_type, _, name = str(candidate).partition(":")
            entity_type, name = entity_type.strip(), name.strip()
            if not entity_type or not name or entity_type in _MANAGED_TYPES:
                continue

            is_deterministic = any(tag in str(reason) for tag in _DETERMINISTIC_REASONS)
            sp_conf = sp_confidence.get(name.lower(), 0.0)

            if entity_type in _OBSERVABLE_TYPES:
                if not self.cfg.create_observables:
                    entity_cr.skipped.append({"entity_type": entity_type, "name": name, "reason": "create_observables=false"})
                    continue
            elif entity_type in _CREATABLE_SDO_TYPES:
                if not self.cfg.create_sdo:
                    entity_cr.skipped.append({"entity_type": entity_type, "name": name, "reason": "create_sdo=false"})
                    continue
                # Attack Patterns must have an explicit MITRE T-code in the
                # extraction reason. KB matches and smart-parse candidates for
                # Attack Patterns are suppressed — only deterministic T-code
                # extraction (e.g. "T1566.001 found in text") is accepted.
                if entity_type == "Attack-Pattern":
                    has_tcode = any(
                        marker in str(reason)
                        for marker in ("ATT&CK technique ID", "ATT&CK mitigation ID", "CAPEC identifier")
                    )
                    if not has_tcode:
                        entity_cr.skipped.append({"entity_type": entity_type, "name": name,
                                                  "reason": "attack_pattern_not_mitre: no T-code in extraction reason"})
                        continue
                if not is_deterministic and sp_conf > 0 and sp_conf < self.cfg.smart_confidence_threshold:
                    entity_cr.skipped.append({"entity_type": entity_type, "name": name,
                                              "reason": f"smart_parse_confidence={sp_conf:.2f} below threshold={self.cfg.smart_confidence_threshold}"})
                    continue
            else:
                entity_cr.skipped.append({"entity_type": entity_type, "name": name, "reason": "entity_type_not_creatable"})
                continue

            conf_int   = 75 if is_deterministic else (int(round(sp_conf * 100)) if sp_conf > 0 else 50)
            first_seen = temporal_index.get(f"{entity_type}:{name.lower()}")
            extra      = {"first_seen": first_seen} if first_seen else {}
            desc = (f"Auto-created by Report Enrichment connector. "
                    f"Extraction basis: {'deterministic' if is_deterministic else 'contextual'}. "
                    f"Source: {report_author}. Reason: {str(reason)[:200]}")

            if entity_type in _OBSERVABLE_TYPES:
                eid = entity_cr.ensure_observable(entity_type=entity_type, value=name,
                                                  description=desc, basis="reconciliation_gap")
            else:
                eid = entity_cr.ensure_sdo(entity_type=entity_type, name=name, description=desc,
                                           confidence=conf_int, extra_fields=extra, basis="reconciliation_gap")
            if eid:
                id_map[f"{entity_type}:{name.lower()}"] = eid

    def _ensure_entity_by_name(self, entity_cr, id_map, entity_type, name, apply_vendor_suffix, basis) -> Optional[str]:
        lookup_name = f"{name}({entity_cr.author_name})" if apply_vendor_suffix else name
        cache_key   = f"{entity_type}:{lookup_name.lower()}"
        if cache_key in id_map:
            return id_map[cache_key]
        if entity_type in _OBSERVABLE_TYPES:
            eid = entity_cr.ensure_observable(entity_type=entity_type, value=lookup_name, basis=basis)
        else:
            eid = entity_cr.ensure_sdo(entity_type=entity_type, name=name, basis=basis,
                                       apply_vendor_suffix=apply_vendor_suffix)
        if eid:
            id_map[cache_key] = eid
        return eid

    def _kb_lookup_id(self, name: str) -> Optional[str]:
        entries = self._kb.lookup(name)
        return entries[0].entity_id if entries else None

    def _build_candidate_list(self, smart_candidates, kb_matches, victim_candidates) -> List[Dict[str, Any]]:
        out = []
        for c in smart_candidates:
            out.append({"name": c.get("name"), "entity_type": c.get("entity_type")})
        for m in kb_matches:
            out.append({"name": m.get("name"), "entity_type": m.get("entity_type")})
        for v in victim_candidates:
            out.append({"name": v.get("name"), "entity_type": "Organization"})
        return [c for c in out if c.get("name")]

    def _build_temporal_index(self, temporal_hints: List[Dict[str, Any]]) -> Dict[str, str]:
        index: Dict[str, str] = {}
        precision_rank = {"month": 3, "quarter": 2, "year": 1}
        for hint in temporal_hints:
            key      = f"{hint.get('entity_type','')}:{(hint.get('entity_name') or '').lower()}"
            existing = index.get(key)
            if not existing:
                index[key] = hint["iso_date"]
            else:
                new_rank = precision_rank.get(hint.get("precision", "year"), 1)
                old_rank = 3 if len(existing) >= 17 else (2 if len(existing) >= 10 else 1)
                if new_rank > old_rank:
                    index[key] = hint["iso_date"]
        return index

    # --- Dry-run preview ---

    def _write_dry_run_preview(self, report_id, report_title, kb_matches, recon_gaps,
                                smart_candidates, victim_candidates, cue_relations, obs_chains,
                                para_relations, assessment_records, temporal_hints, elapsed) -> str:
        lines = [
            f"# Enrichment DRY RUN Preview — {report_title}",
            f"\n**Mode:** DRY RUN  \n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  \n**Elapsed:** {elapsed:.1f}s\n",
            "---\n",
            f"## KB-matched existing entities ({len(kb_matches)} would be linked)",
        ]
        for m in kb_matches[:30]:
            display_name = defang_entity_name(m.get('name',''), m.get('entity_type',''))
            lines.append(f"- {m.get('entity_type')}:{display_name} (id={m.get('entity_id','')})")
        if len(kb_matches) > 30:
            lines.append(f"  ... and {len(kb_matches) - 30} more")

        gaps_to_show = [r for r in recon_gaps if isinstance(r,(tuple,list)) and len(r)>=3 and r[1]=="missing-from-scope"]
        lines.append(f"\n## Reconciliation gaps ({len(gaps_to_show)} entities would be created or searched)")
        for row in gaps_to_show[:40]:
            lines.append(f"- {row[2]} | {str(row[3])[:120]}")
        if len(gaps_to_show) > 40:
            lines.append(f"  ... and {len(gaps_to_show) - 40} more")

        lines.append(f"\n## Victim candidates ({len(victim_candidates)} would be checked/created)")
        for v in victim_candidates[:20]:
            lines.append(f"- Organization:{v.get('name')} (conf={v.get('confidence',0):.2f})")

        lines.append(f"\n## Cue-phrase relationships ({len(cue_relations)} would be drawn)")
        for r in cue_relations[:30]:
            vs = " [vendor-suffix]" if r.get("vendor_suffix") else ""
            lines.append(f"- {r['source_type']}:{r['source_name']} -[{r['rel_type']}]-> {r['target_type']}:{r['target_name']}{vs} (conf={r['confidence']:.2f})")

        lines.append(f"\n## Observable chains ({len(obs_chains)} would be drawn)")
        for c in obs_chains[:20]:
            lines.append(f"- {c['source_type']}:{c['source_name']} -[{c['rel_type']}]-> {c['target_type']}:{c['target_name']}")

        lines.append(f"\n## Paragraph co-occurrence relationships ({len(para_relations)} would be drawn)")
        for r in para_relations[:20]:
            lines.append(f"- {r['source_type']}:{r['source_name']} -[{r['rel_type']}]-> {r['target_type']}:{r['target_name']} (conf={r['confidence']:.2f})")

        lines.append(f"\n## Assessment notes ({len(assessment_records)} would be created)")
        for a in assessment_records[:10]:
            lines.append(f"- {a.get('subject','?')}: \"{a.get('claim','')[:100]}\" (conf={a.get('confidence',50)})")

        lines.append(f"\n## Temporal hints ({len(temporal_hints)} found)")
        for h in temporal_hints[:10]:
            lines.append(f"- {h.get('entity_type')}:{h.get('entity_name')} → {h.get('iso_date')} ({h.get('precision')})")

        body = "\n".join(lines)
        create_note_gql(helper=self.helper, title=f"Enrichment DRY RUN Preview — {report_title}",
                        content=body, objects=[report_id], note_types=["Enrichment"])
        return f"Dry-run preview written ({len(gaps_to_show)} gaps, {len(cue_relations)} cue relations)"

    # --- Graph reading helpers ---

    def _enumerate_report_object_ids(self, report: Dict[str, Any]) -> List[str]:
        ids = safe_get(report, "objectsIds") or []
        if ids:
            return list(ids)
        objs = safe_get(report, "objects") or []
        out: List[str] = []
        for o in objs:
            if isinstance(o, dict) and o.get("id"):
                out.append(o["id"])
            elif isinstance(o, str):
                out.append(o)
        return out

    def _resolve_scope(self, obj_ids: List[str]) -> Tuple[Dict[str,Dict[str,Any]], List[str], List[str]]:
        resolved: Dict[str, Dict[str, Any]] = {}
        relationship_ids: List[str] = []
        unreadable: List[str] = []
        for oid in obj_ids:
            try:
                rel = self.helper.api.stix_core_relationship.read(id=oid)
                if rel and safe_get(rel, "relationship_type", "relationshipType"):
                    relationship_ids.append(oid)
                    continue
            except Exception:
                pass
            try:
                obj = (self.helper.api.stix_core_object.read(id=oid)
                       or self.helper.api.stix_domain_object.read(id=oid)
                       or self.helper.api.stix_cyber_observable.read(id=oid))
                if obj:
                    resolved[oid] = obj
                    continue
            except Exception:
                pass
            unreadable.append(oid)
        return resolved, relationship_ids, unreadable

    def _resolve_author_name(self, report: Dict[str, Any]) -> str:
        cb = report.get("createdBy")
        if isinstance(cb, dict):
            return (cb.get("name") or cb.get("id") or "Unknown").strip()
        name = (safe_get(report, "name") or "").split(":")[0].strip()
        return name or "Unknown"


if __name__ == "__main__":
    ReportEnrichmentConnector().run()
