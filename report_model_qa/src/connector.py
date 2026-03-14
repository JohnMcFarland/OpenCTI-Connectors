from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pycti import OpenCTIConnectorHelper

from config import QAConfig
from formatters.note import compose_note, note_title
from formatters.summary import DispositionInputs, render_disposition
from rules.base import RuleContext
from rules.categorization import qa_relationship_provenance
from rules.completeness import qa_relationship_fields, qa_report_fields
from rules.containment import qa_containment
from rules.contextualization import qa_contextualization
from rules.entity_naming import qa_duplicate_entities, qa_intrusion_set_naming
from rules.label_policy import LabelPolicyRule
from rules.marking_required import MarkingRequiredRule
from rules.reconciliation import qa_reconciliation
from rules.relationships import qa_relationship_policy
from rules.pdf_suggestions import qa_document_suggestions
from rules.sightings_policy import SightingsPolicyRule
from rules.threat_actor_policy import ThreatActorPolicyRule
from util.entity_kb import EntityKB
from util.note_gql import create_note_gql
from util.graph import safe_get

APP_NAME    = "Report Model QA (Non-Destructive)"
APP_VERSION = "0.9.3"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    c = {"BLOCKER": 0, "ERROR": 0, "WARN": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if sev not in c:
            sev = "INFO"
        c[sev] += 1
    return c


def verdict_from(findings: List[Dict[str, Any]], fail_on_blockers: bool) -> str:
    if fail_on_blockers:
        for f in findings:
            if (f.get("severity") or "").upper() == "BLOCKER":
                return "FAIL"
    for f in findings:
        if (f.get("severity") or "").upper() == "ERROR":
            return "FAIL"
    return "PASS"


def _finding_from_rule_result(rule_finding: Dict[str, Any], section: str) -> Dict[str, Any]:
    rows = rule_finding.get("rows") or []
    if not rows:
        msg      = rule_finding.get("message") or ""
        obj_refs = rule_finding.get("object_refs") or []
        rec      = rule_finding.get("recommendation") or ""
        reason   = msg
        if rec:
            reason += f" | Recommendation: {rec}"
        for ref in obj_refs[:5]:
            rows.append((str(ref), "finding", "", reason))
        if not rows:
            rows.append(("", "finding", "", reason))
    return {
        "section":  section,
        "severity": rule_finding.get("severity") or "INFO",
        "code":     rule_finding.get("rule_id") or "QA.UNKNOWN",
        "title":    rule_finding.get("title") or "",
        "norm":     rule_finding.get("recommendation") or "",
        "rows":     rows,
        "evidence": rule_finding.get("evidence") or {},
        "metrics":  rule_finding.get("metrics") or {},
    }


class ReportModelQAConnector:
    def __init__(self) -> None:
        self.cfg = QAConfig.from_env()

        self.helper = OpenCTIConnectorHelper(
            {
                "opencti_url":              os.environ.get("OPENCTI_URL"),
                "opencti_token":            os.environ.get("OPENCTI_TOKEN"),
                "connector_id":             os.environ.get("CONNECTOR_ID"),
                "connector_type":           os.environ.get("CONNECTOR_TYPE", "INTERNAL_ENRICHMENT"),
                "connector_name":           os.environ.get("CONNECTOR_NAME", APP_NAME),
                "connector_scope":          os.environ.get("CONNECTOR_SCOPE", "Report"),
                "connector_confidence_level": int(os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", "0")),
                "connector_log_level":      os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
            }
        )

        self._marking_rule      = MarkingRequiredRule()
        self._sightings_rule    = SightingsPolicyRule()
        self._threat_actor_rule = ThreatActorPolicyRule()
        self._label_rule        = LabelPolicyRule()
        self._kb                = EntityKB()

        self.helper.log_info(f"Starting {APP_NAME} v{APP_VERSION}")
        self.helper.log_info(f"Config: {self.cfg}")

    # -------- reads --------

    def _read_any_object(self, object_id: str) -> Optional[Dict[str, Any]]:
        for fn in (
            lambda: self.helper.api.stix_core_object.read(id=object_id),
            lambda: self.helper.api.stix_domain_object.read(id=object_id),
            lambda: self.helper.api.stix_cyber_observable.read(id=object_id),
        ):
            try:
                obj = fn()
                if obj:
                    return obj
            except Exception:
                continue
        return None

    def _read_relationship(self, rel_id: str) -> Optional[Dict[str, Any]]:
        try:
            return self.helper.api.stix_core_relationship.read(id=rel_id)
        except Exception:
            return None

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

    def _resolve_scope(
        self, obj_ids: List[str]
    ) -> tuple[Dict[str, Dict[str, Any]], List[str], List[str]]:
        resolved: Dict[str, Dict[str, Any]] = {}
        relationship_ids: List[str] = []
        unreadable: List[str] = []
        for oid in obj_ids:
            rel = self._read_relationship(oid)
            if rel and safe_get(rel, "relationship_type", "relationshipType"):
                relationship_ids.append(oid)
                continue
            obj = self._read_any_object(oid)
            if obj:
                resolved[oid] = obj
                continue
            unreadable.append(oid)
        return resolved, relationship_ids, unreadable

    def _build_rule_context(
        self,
        report: Dict[str, Any],
        resolved_objects: Dict[str, Dict[str, Any]],
        relationship_ids: List[str],
    ) -> RuleContext:
        relationships: List[Dict[str, Any]] = []
        for rid in relationship_ids:
            rel = self._read_relationship(rid)
            if rel:
                relationships.append(rel)
        return RuleContext(
            report=report,
            objects=list(resolved_objects.values()),
            relationships=relationships,
            helper=self.helper,
            config={
                "enforce_label_policy":      self.cfg.enforce_label_policy,
                "enforce_sightings_policy":  self.cfg.enforce_sightings_policy,
                "threatactor_realworld_only":self.cfg.threatactor_realworld_only,
                "require_rel_evidence":      self.cfg.require_rel_evidence,
                "require_rel_confidence":    self.cfg.require_rel_confidence,
                "min_rel_confidence":        self.cfg.min_rel_confidence,
                "enforce_rel_dates":         self.cfg.enforce_rel_dates,
            },
        )

    # -------- note --------

    def _write_note(
        self, report_internal_id: str, report_title: str,
        verdict: str, content: str,
    ) -> None:
        if not self.cfg.write_note:
            return
        body = (content or "").strip()
        if not body:
            body = f"QA: {report_title}\nGenerated: {utc_now_iso()}\n\n(No content generated.)\n"
        # Verdict is embedded in the note title — visible in the notes list
        title = note_title(report_title, verdict)
        create_note_gql(
            helper=self.helper,
            title=title,
            content=body,
            objects=[report_internal_id],
            note_types=["QA"],
        )

    # -------- main --------

    def _process_report(self, report_stix_id: str) -> str:
        self._kb.ensure_ready(self.helper)

        report = self.helper.api.report.read(id=report_stix_id, withFiles=True)
        if not report:
            self.helper.log_error("Report not found", {"id": report_stix_id})
            return "Report not found"

        report_internal_id = safe_get(report, "id")
        report_title       = safe_get(report, "name") or "(untitled report)"
        if not report_internal_id:
            self.helper.log_error("Report missing internal id", {"stix_id": report_stix_id})
            return "Report missing internal id"

        obj_ids = self._enumerate_report_object_ids(report)
        resolved_objects, relationship_ids, unreadable_ids = self._resolve_scope(obj_ids)

        findings: List[Dict[str, Any]] = []
        metrics: Dict[str, int] = {
            "scope_entities":                    len(resolved_objects),
            "scope_relationships":               len(relationship_ids),
            "contextualization_gaps":            0,
            "relationships_missing_description": 0,
            "orphaned_observables":              0,
            "relationships_missing_required":    0,
            "relationships_poor_description":    0,
            "relationships_temporal_violations": 0,
            "duplicate_entities":                0,
            "intrusion_set_naming_violations":   0,
            "provenance_mismatches":             0,
            "policy_violations":                 0,
            "policy_not_evaluable":              0,
            "doc_suggestions_objects":           0,
            "doc_suggestions_relationships":     0,
            "reconciliation_gaps":               0,
            "reconciliation_errors":              0,
        }

        # Containment
        f = qa_containment(str(report_internal_id), obj_ids, unreadable_ids)
        if f:
            findings.append(f)

        # Contextualization
        f = qa_contextualization(
            str(report_internal_id), resolved_objects, relationship_ids,
            read_relationship_fn=self._read_relationship,
            read_any_object_fn=self._read_any_object,
        )
        if f:
            findings.append(f)
            m = f.get("metrics") or {}
            metrics["contextualization_gaps"]            += int(m.get("contextualization_gaps", 0))
            metrics["relationships_missing_description"] += int(m.get("relationships_missing_description", 0))
            metrics["orphaned_observables"]              += int(m.get("orphaned_observables", 0))

        # Completeness
        f = qa_report_fields(report)
        if f:
            findings.append(f)

        f = qa_relationship_fields(
            resolved_objects, relationship_ids,
            read_relationship_fn=self._read_relationship,
            read_any_object_fn=self._read_any_object,
        )
        if f:
            findings.append(f)
            m = f.get("metrics") or {}
            metrics["relationships_missing_required"]    += int(m.get("relationships_missing_required", 0))
            metrics["relationships_poor_description"]    += int(m.get("relationships_poor_description", 0))
            metrics["relationships_temporal_violations"] += int(m.get("relationships_temporal_violations", 0))

        # Duplicate entity detection
        f = qa_duplicate_entities(resolved_objects)
        if f:
            findings.append(f)
            metrics["duplicate_entities"] += int((f.get("metrics") or {}).get("duplicate_entities", 0))

        # Intrusion Set naming convention
        f = qa_intrusion_set_naming(report, resolved_objects)
        if f:
            findings.append(f)
            metrics["intrusion_set_naming_violations"] += int(
                (f.get("metrics") or {}).get("intrusion_set_naming_violations", 0)
            )

        # Document Extraction — KB passed for smart-parse reclassification
        doc_finding, suggestion_rows, kb_matches, smart_candidates = qa_document_suggestions(
            self.helper, report, kb=self._kb
        )
        if doc_finding:
            findings.append(doc_finding)
            m = doc_finding.get("metrics") or {}
            metrics["doc_suggestions_objects"]       += int(m.get("doc_suggestions_objects", 0))
            metrics["doc_suggestions_relationships"] += int(m.get("doc_suggestions_relationships", 0))

        # Reconciliation — smart_candidates carry confidence for severity scoring
        f = qa_reconciliation(
            resolved_objects, suggestion_rows, kb_matches, smart_candidates
        )
        if f:
            findings.append(f)
            metrics["reconciliation_gaps"] += int((f.get("metrics") or {}).get("reconciliation_gaps", 0))
            metrics["reconciliation_errors"] += int((f.get("metrics") or {}).get("reconciliation_errors", 0))

        # Categorization
        f = qa_relationship_provenance(
            report, resolved_objects, relationship_ids,
            read_relationship_fn=self._read_relationship,
            read_any_object_fn=self._read_any_object,
        )
        if f:
            findings.append(f)
            metrics["provenance_mismatches"] += int((f.get("metrics") or {}).get("provenance_mismatches", 0))

        # Relationship policy
        f = qa_relationship_policy(
            resolved_objects, relationship_ids,
            read_relationship_fn=self._read_relationship,
            read_any_object_fn=self._read_any_object,
        )
        if f:
            findings.append(f)
            m = f.get("metrics") or {}
            metrics["policy_violations"]    += int(m.get("policy_violations", 0))
            metrics["policy_not_evaluable"] += int(m.get("policy_not_evaluable", 0))

        # Class-based rules
        rule_ctx = self._build_rule_context(report, resolved_objects, relationship_ids)

        if self._marking_rule.enabled(rule_ctx):
            for rf in self._marking_rule.evaluate(rule_ctx):
                findings.append(_finding_from_rule_result(rf, "Marking"))

        if self._sightings_rule.enabled(rule_ctx):
            for rf in self._sightings_rule.evaluate(rule_ctx):
                findings.append(_finding_from_rule_result(rf, "Sightings"))

        if self._threat_actor_rule.enabled(rule_ctx):
            for rf in self._threat_actor_rule.evaluate(rule_ctx):
                findings.append(_finding_from_rule_result(rf, "Threat Actor"))

        if self._label_rule.enabled(rule_ctx):
            for rf in self._label_rule.evaluate(rule_ctx):
                findings.append(_finding_from_rule_result(rf, "Labels"))

        verdict = verdict_from(findings, fail_on_blockers=self.cfg.fail_on_blockers)
        counts  = severity_counts(findings)

        disposition = render_disposition(
            DispositionInputs(
                report_title=str(report_title),
                report_stix_id=str(
                    safe_get(report, "standard_id")
                    or safe_get(report, "standardId")
                    or report_stix_id
                ),
                generated=utc_now_iso(),
                verdict=verdict,
                severity_counts=counts,
                scope_entities=metrics.get("scope_entities", 0),
                scope_relationships=metrics.get("scope_relationships", 0),
                metrics=metrics,
                total_rules_run=11,
            )
        )

        config_snapshot = {
            "version":                    APP_VERSION,
            "write_note":                 self.cfg.write_note,
            "fail_on_blockers":           self.cfg.fail_on_blockers,
            "note_max_findings":          self.cfg.note_max_findings,
            "enforce_label_policy":       self.cfg.enforce_label_policy,
            "enforce_sightings_policy":   self.cfg.enforce_sightings_policy,
            "threatactor_realworld_only": self.cfg.threatactor_realworld_only,
            "require_rel_evidence":       self.cfg.require_rel_evidence,
            "require_rel_confidence":     self.cfg.require_rel_confidence,
            "enforce_rel_dates":          self.cfg.enforce_rel_dates,
            "kb_ttl_hours":               self._kb._ttl_hours,
            "kb_entries":                 self._kb.entry_count,
            "kb_built_at":                self._kb.built_at.isoformat() if self._kb.built_at else None,
        }

        note_body = compose_note(
            report=report,
            verdict=verdict,
            findings=findings,
            metrics=metrics,
            note_max_findings=self.cfg.note_max_findings,
            disposition=disposition,
            config_snapshot=config_snapshot,
        )

        self._write_note(str(report_internal_id), str(report_title), verdict, note_body)

        self.helper.log_info(
            f"QA complete: {verdict} | "
            f"entities={metrics['scope_entities']} "
            f"rels={metrics['scope_relationships']} "
            f"recon_gaps={metrics['reconciliation_gaps']} "
            f"duplicates={metrics['duplicate_entities']} "
            f"kb_entries={self._kb.entry_count}"
        )
        return f"QA complete: {verdict}"

    def _enrichment_handler(self, data: Dict[str, Any]) -> str:
        entity_id = safe_get(data, "entity_id", "entityId", "id")
        if not entity_id:
            return "No entity id in message"
        return self._process_report(str(entity_id))

    def run(self) -> None:
        self.helper.listen(message_callback=self._enrichment_handler)


if __name__ == "__main__":
    ReportModelQAConnector().run()
