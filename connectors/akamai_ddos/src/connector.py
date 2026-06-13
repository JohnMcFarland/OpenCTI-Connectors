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
            self.helper.connector_id, f"Akamai DDoS run @ {now.isoformat()}"
        )
        try:
            if self.settings.akamai_prolexic_enabled:
                self._run_prolexic(state, now, work_id)
            if self.settings.akamai_siem_enabled:
                self._run_siem(state, now, work_id)
            self.helper.set_state(state)
        except Exception as exc:  # noqa: BLE001 — log + let the scheduler retry next period
            self.helper.connector_logger.error("Run failed", {"error": str(exc)})
            raise
        finally:
            self.helper.api.work.to_processed(work_id, "Akamai DDoS run complete")

    # -- paths -------------------------------------------------------------

    def _run_prolexic(self, state: dict, now: datetime, work_id: str) -> None:
        pstate = state.setdefault("prolexic", {})
        seen = set(pstate.get("seen_attack_ids", []))
        start = self._window_start(pstate.get("last_end"), now)
        events = self.prolexic.fetch(start, now, seen)
        self.helper.connector_logger.info("Prolexic attacks", {"count": len(events)})
        for event in events:
            self._emit(event, work_id)
            seen.add(event.attack_id)
        pstate["last_end"] = now.isoformat()
        pstate["seen_attack_ids"] = list(seen)[-5000:]  # cap retained ids

    def _run_siem(self, state: dict, now: datetime, work_id: str) -> None:
        sstate = state.setdefault("siem", {})
        from_ts = int(self._window_start(None, now).timestamp())
        for config_id in self.settings.siem_config_id_list:
            offset = sstate.get(config_id)
            events, next_offset = self.siem.fetch(
                config_id, offset, None if offset else from_ts, None
            )
            self.helper.connector_logger.info(
                "SIEM episodes", {"config_id": config_id, "count": len(events)}
            )
            for event in events:
                self._emit(event, work_id)
            sstate[config_id] = next_offset

    # -- emit --------------------------------------------------------------

    def _emit(self, event, work_id: str) -> None:
        # One bundle per attack episode keeps all object_refs resolvable together.
        objects = self.builder.build(event)
        if not objects:
            return
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
