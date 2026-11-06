"""Runs one cycle: promote and reconcile, label, then export."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .config import Settings
from .grouping import flush_groupings, grouping_day
from .labels import LabelPolicy, ObservableContext, build_labels
from .lifecycle import CycleResult, LifecycleManager
from .markings import is_blocked
from .opencti_client import OpenCTIClient
from .records import (
    STATUS_ACTIVE,
    STATUS_DECAYING,
    STATUS_REVOKED,
    STATUS_WOULD_CREATE,
    ExportRecord,
)
from .sinks import ExportError, Sink
from .store import StateStore


class IndicatorExportConnector:
    def __init__(
        self,
        helper: Any,
        settings: Settings,
        client: OpenCTIClient,
        store: StateStore,
        sink: Sink,
    ) -> None:
        self.helper = helper
        self.settings = settings
        self.client = client
        self.store = store
        self.sink = sink
        self.logger = helper.connector_logger
        self.lifecycle = LifecycleManager(client, store, settings, self.logger)
        self.policy = LabelPolicy(
            blocked_markings=settings.blocked_markings,
            max_labels=settings.max_labels,
            excluded_entity_types=settings.excluded_entity_types,
        )

    def run(self) -> None:
        self.logger.info(
            f"Starting. dry_run={self.settings.dry_run} "
            f"target={self.settings.target.mode}"
        )
        self.helper.schedule_iso(
            message_callback=self.process,
            duration_period=self.settings.connector_duration_period,
        )

    def process(self) -> None:
        now = datetime.now(timezone.utc)
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, f"Indicator export @ {now.isoformat()}"
        )
        message = "Cycle complete."
        in_error = False
        try:
            message, in_error = self._run_cycle()
            state = self.helper.get_state() or {}
            state["last_run"] = now.isoformat()
            self.helper.set_state(state)
        except Exception as exc:  # noqa: BLE001 - the work item must always close
            message = f"Cycle failed: {exc}"
            in_error = True
            self.logger.error(message)
        finally:
            self.helper.api.work.to_processed(work_id, message, in_error=in_error)

    def _run_cycle(self) -> Tuple[str, bool]:
        self._check_blocked_markings_exist()
        result = self.lifecycle.run_cycle()
        author_id = self.client.resolve_author()
        indicators = self.client.owned_indicators(author_id)
        records, blocked = self._build_records(indicators, result)

        # Export problems do not undo lifecycle work. They only flag the cycle,
        # and the next cycle tries again.
        export_failed = False
        try:
            summary, delivered = self.sink.deliver(records, self.settings.dry_run)
        except ExportError as exc:
            export_failed = True
            delivered = exc.delivered
            summary = f"Export failed: {exc}"
            self.logger.error(summary)

        grouped = 0
        if not self.settings.dry_run:
            grouped = self._update_groupings(author_id, delivered, result)

        stats = ", ".join(f"{key}={value}" for key, value in result.stats.items())
        message = f"{summary}. Blocked by marking: {blocked}. Grouped: {grouped}. {stats}"
        self.logger.info(message)
        return message, export_failed or result.stats["errors"] > 0

    def _check_blocked_markings_exist(self) -> None:
        """A blocked term that matches nothing is probably a typo, and would
        silently block nothing."""
        blocked = self.settings.blocked_markings
        if not any(
            is_blocked([marking], blocked)
            for marking in self.client.marking_definitions()
        ):
            self.logger.warning(
                f"No marking definition matches EXPORT_BLOCKED_MARKINGS: {sorted(blocked)}"
            )

    def _update_groupings(
        self, author_id: str, delivered: Sequence[ExportRecord], result: CycleResult
    ) -> int:
        today = grouping_day(datetime.now(timezone.utc))
        self.store.queue_grouping(
            today, [record.opencti_id for record in delivered if record.opencti_id]
        )
        added, errors = flush_groupings(
            self.client,
            self.store,
            self.logger,
            author_id,
            self.client.default_marking()["id"],
            today,
        )
        result.stats["errors"] += errors
        return added

    def _build_records(
        self, indicators: List[Dict[str, Any]], result: CycleResult
    ) -> Tuple[List[ExportRecord], int]:
        records: List[ExportRecord] = []
        blocked = 0
        for indicator in indicators + result.previews:
            if is_blocked(
                indicator.get("objectMarking") or [], self.settings.blocked_markings
            ):
                blocked += 1
                continue
            try:
                observable = self._observable_for(indicator, result)
                context = self._context_for(observable, result)
            except Exception as exc:  # noqa: BLE001
                # Withheld rather than sent with incomplete labels.
                result.stats["errors"] += 1
                self.logger.error(f"Skipped {indicator.get('standard_id')}: {exc}")
                continue
            records.append(self._to_record(indicator, observable, context, result))
        return records, blocked

    def _observable_for(
        self, indicator: Dict[str, Any], result: CycleResult
    ) -> Optional[Dict[str, Any]]:
        if "observable" in indicator:
            return indicator["observable"]
        known = result.observables.get(indicator["id"])
        return known or self.client.based_on_observable(indicator["id"])

    def _context_for(
        self, observable: Optional[Dict[str, Any]], result: CycleResult
    ) -> ObservableContext:
        if not observable:
            return ObservableContext()
        return self.lifecycle.context_for(observable["id"], result)

    def _status(self, indicator: Dict[str, Any], result: CycleResult) -> str:
        if indicator.get("id") is None:
            return STATUS_WOULD_CREATE
        if indicator.get("revoked"):
            return STATUS_REVOKED
        if indicator["id"] in result.decaying:
            return STATUS_DECAYING
        if self.store.get_decay(indicator["id"]):
            return STATUS_DECAYING
        return STATUS_ACTIVE

    def _to_record(
        self,
        indicator: Dict[str, Any],
        observable: Optional[Dict[str, Any]],
        context: ObservableContext,
        result: CycleResult,
    ) -> ExportRecord:
        observable = observable or {}
        inherited = [
            label.get("value", "")
            for source in (indicator, observable)
            for label in source.get("objectLabel") or []
        ]
        labels = build_labels(context, inherited, self.policy)
        markings = indicator.get("objectMarking") or []
        return ExportRecord(
            stix_id=indicator["standard_id"],
            name=indicator.get("name") or "",
            pattern=indicator.get("pattern") or "",
            pattern_type=indicator.get("pattern_type") or "stix",
            observable_type=observable.get("entity_type")
            or indicator.get("x_opencti_main_observable_type")
            or "",
            observable_value=observable.get("observable_value") or "",
            indicator_types=tuple(indicator.get("indicator_types") or ()),
            confidence=indicator.get("confidence"),
            score=indicator.get("x_opencti_score"),
            markings=tuple(m.get("definition") or "" for m in markings),
            marking_refs=tuple(m["standard_id"] for m in markings if m.get("standard_id")),
            status=self._status(indicator, result),
            created=indicator.get("created") or "",
            valid_from=indicator.get("valid_from") or "",
            valid_until=indicator.get("valid_until"),
            revoked=bool(indicator.get("revoked")),
            labels=labels.labels,
            labels_dropped=labels.dropped,
            opencti_id=indicator.get("id"),
        )
