from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from qa.relationship_policy import is_allowed

logger = logging.getLogger(__name__)


def _clamp_confidence(conf: float) -> int:
    return max(0, min(100, int(round(conf * 100))))


class RelationshipCreator:
    """
    Policy-gated, idempotent relationship creation with marking/createdBy inheritance.
    Three gates: data model policy, run-local dedup, graph existence check.
    """

    def __init__(self, helper: Any, report: Dict[str, Any],
                 markings: List[str], created_by: Optional[str], report_id: str) -> None:
        self.helper     = helper
        self.report     = report
        self.markings   = markings
        self.created_by = created_by
        self.report_id  = report_id
        self.created:   List[Dict[str, Any]] = []
        self.skipped:   List[Dict[str, Any]] = []
        self._seen:     set = set()

    def create_relationship(
        self,
        source_id: str, source_type: str,
        rel_type: str,
        target_id: str, target_type: str,
        description: str,
        confidence: float,
        start_time: Optional[str] = None,
        stop_time:  Optional[str] = None,
        basis:       str = "",
        source_name: str = "",
        target_name: str = "",
    ) -> Optional[str]:
        if not source_id or not target_id:
            self._skip(source_name, rel_type, target_name, "missing_entity_id")
            return None

        decision = is_allowed(source_type, rel_type, target_type)
        if not decision.allowed:
            self._skip(source_name, rel_type, target_name, f"policy_denied: {decision.reason}")
            return None

        sig = f"{source_id}|{rel_type.lower()}|{target_id}"
        if sig in self._seen:
            self._skip(source_name, rel_type, target_name, "already_created_this_run")
            return None
        self._seen.add(sig)

        if self._relationship_exists(source_id, rel_type, target_id):
            self._skip(source_name, rel_type, target_name, "already_in_graph")
            return None

        return self._do_create(source_id, rel_type, target_id, description, confidence,
                               start_time, stop_time, basis, source_name, target_name)

    def _relationship_exists(self, from_id: str, rel_type: str, to_id: str) -> bool:
        try:
            query = """
            query RelExists($fromId: String!, $toId: String!, $relType: String!) {
              stixCoreRelationships(
                filters: [
                  {key: "fromId",            values: [$fromId]},
                  {key: "toId",              values: [$toId]},
                  {key: "relationship_type", values: [$relType]}
                ]
                first: 1
              ) { edges { node { id } } }
            }
            """
            res = self.helper.api.query(query, {"fromId": from_id, "toId": to_id, "relType": rel_type})
            edges = (((res or {}).get("data") or {}).get("stixCoreRelationships", {}).get("edges") or [])
            return len(edges) > 0
        except Exception as e:
            logger.debug("Relationship existence check failed: %s", e)
            return False

    def _do_create(self, source_id, rel_type, target_id, description, confidence,
                   start_time, stop_time, basis, source_name, target_name) -> Optional[str]:
        kwargs: Dict[str, Any] = {
            "fromId": source_id, "toId": target_id,
            "relationship_type": rel_type,
            "description": description or f"Auto-inferred via {basis or 'text extraction'}.",
            "confidence": _clamp_confidence(confidence),
        }
        if self.created_by:
            kwargs["createdBy"] = self.created_by
        if self.markings:
            kwargs["objectMarking"] = self.markings
        # Only pass temporal fields when they carry a real value. Passing None
        # causes pycti to set epoch-zero (1970-01-01) for start_time and
        # max-epoch (year 5138) for stop_time, producing QA temporal violations
        # on every relationship created without source-document date evidence.
        if start_time and start_time.strip():
            kwargs["start_time"] = start_time
        if stop_time and stop_time.strip():
            kwargs["stop_time"] = stop_time

        try:
            result = self.helper.api.stix_core_relationship.create(**kwargs)
            if not isinstance(result, dict) or not result.get("id"):
                self._skip(source_name, rel_type, target_name, "no_id_returned")
                return None

            rel_id = result["id"]
            if self.report_id:
                try:
                    self.helper.api.report.add_stix_object_or_stix_relationship(
                        id=self.report_id, stixObjectOrStixRelationshipId=rel_id,
                    )
                except Exception as e:
                    logger.warning("Failed to scope relationship to report: %s", e)

            self.created.append({
                "source": source_name or source_id, "rel": rel_type,
                "target": target_name or target_id, "id": rel_id, "basis": basis,
            })
            logger.info("Created relationship: %s -[%s]-> %s (basis=%s)",
                        source_name, rel_type, target_name, basis)
            return rel_id

        except Exception as e:
            logger.warning("Failed to create relationship %s -[%s]-> %s: %s",
                           source_name, rel_type, target_name, e)
            self._skip(source_name, rel_type, target_name, f"api_error: {e}")
            return None

    def _skip(self, source: str, rel: str, target: str, reason: str) -> None:
        self.skipped.append({"source": source, "rel": rel, "target": target, "reason": reason})
