"""Orchestration: scheduled poll → normalize → build STIX → send.

EXTERNAL_IMPORT. Uses helper scheduling + work lifecycle + state (no hand-rolled
while/sleep loop). One Incident Response container per attack episode (decision A).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from .akamai_client import AkamaiClient
from .config import Settings
from .models import cap_seen_ids
from .prolexic import ProlexicPoller
from .siem import SiemPoller
from .stix_builder import AkamaiStixBuilder


class AkamaiDdosConnector:
    def __init__(self, helper, settings: Settings) -> None:
        self.helper = helper
        self.settings = settings
        self.client = AkamaiClient(settings, helper.connector_logger)
        self.prolexic = ProlexicPoller(self.client, settings, helper.connector_logger)
        self.siem = SiemPoller(self.client, settings, helper.connector_logger)
        self.builder = AkamaiStixBuilder(helper, settings)

    # -- scheduling --------------------------------------------------------

    def run(self) -> None:
        self.builder.prepare()  # resolve default marking once
        self.helper.schedule_iso(
            message_callback=self.process,
            duration_period=self.settings.connector_duration_period,
        )

    def process(self) -> None:
        now = datetime.now(timezone.utc)
        state = self.helper.get_state() or {}
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, f"Akamai DDoS run @ {now.isoformat()}"
        )
        try:
            if self.settings.akamai_prolexic_enabled:
                self._run_prolexic(state, now, work_id)
            if self.settings.akamai_siem_enabled:
                self._run_siem(state, now, work_id)
            self.helper.set_state(state)
        except Exception as exc:  # noqa: BLE001 - log + let the scheduler retry next period
            self.helper.connector_logger.error("Run failed", {"error": str(exc)})
            raise
        finally:
            self.helper.api.work.to_processed(work_id, "Akamai DDoS run complete")

    # -- paths -------------------------------------------------------------

    def _run_prolexic(self, state: dict, now: datetime, work_id: str) -> None:
        pstate = state.setdefault("prolexic", {})
        seen_list = list(pstate.get("seen_attack_ids", []))
        seen = set(seen_list)  # membership test only; ordering carried by seen_list
        start = self._window_start(pstate.get("last_end"), now)
        events = self.prolexic.fetch(start, now, seen)
        self.helper.connector_logger.info("Prolexic attacks", {"count": len(events)})
        new_ids: list[str] = []
        for event in events:
            self._emit(event, work_id)
            new_ids.append(event.attack_id)
        pstate["last_end"] = now.isoformat()
        # F-05: insertion-ordered cap; evict the OLDEST 5000+, not an arbitrary subset.
        pstate["seen_attack_ids"] = cap_seen_ids(seen_list, new_ids, 5000)

    def _run_siem(self, state: dict, now: datetime, work_id: str) -> None:
        sstate = state.setdefault("siem", {})
        for config_id in self.settings.siem_config_id_list:
            # Per-config state: {"offset": <token>, "last_end": <iso>}. F-06: when the
            # offset is present it drives incremental fetch; when it is absent (genuine
            # first run OR a lost/invalidated offset) resume from last_end, falling back
            # to initial_lookback_days only when there is no recorded boundary.
            cstate = sstate.setdefault(config_id, {})
            offset = cstate.get("offset")
            from_ts = None
            if not offset:
                from_ts = int(self._window_start(cstate.get("last_end"), now).timestamp())
            events, next_offset = self.siem.fetch(config_id, offset, from_ts, None)
            self.helper.connector_logger.info(
                "SIEM episodes", {"config_id": config_id, "count": len(events)}
            )
            for event in events:
                self._emit(event, work_id)
            cstate["offset"] = next_offset
            cstate["last_end"] = now.isoformat()

    # -- emit --------------------------------------------------------------

    def _emit(self, event, work_id: str) -> None:
        # One bundle per attack episode keeps all object_refs resolvable together.
        objects = self.builder.build(event)
        if not objects:
            return
        # F-04: object_refs above the platform bundle threshold can be truncated
        # silently, producing an incomplete container with no error signal. Chunked
        # container emission is NOT yet implemented; until it is, surface the count so
        # a silent partial write becomes visible. Must be closed before SIEM at scale.
        count = len(objects)
        if count > self.settings.akamai_max_bundle_objects:
            self.helper.connector_logger.warning(
                "Bundle object count exceeds threshold; OpenCTI may silently truncate "
                "object_refs (F-04: chunked emission not yet implemented)",
                {
                    "attack_id": event.attack_id,
                    "object_count": count,
                    "threshold": self.settings.akamai_max_bundle_objects,
                },
            )
        bundle = json.dumps({
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        })
        self.helper.send_stix2_bundle(bundle, work_id=work_id)

    # -- helpers -----------------------------------------------------------

    def _window_start(self, last_end: str | None, now: datetime) -> datetime:
        if last_end:
            return datetime.fromisoformat(last_end)
        return now - timedelta(days=self.settings.akamai_initial_lookback_days)
