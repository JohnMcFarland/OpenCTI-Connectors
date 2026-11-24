"""Orchestration: scheduled run -> UDM streams -> events -> STIX -> send.

EXTERNAL_IMPORT. Uses helper scheduling + work lifecycle + platform state (no
hand-rolled while/sleep loop). State:

    {"flows": StreamCursor, "security": StreamCursor, "admin": StreamCursor,
     "systems": {<mac>: <pinned System name>},
     "firmware": {<device mac>: <version last sent>},
     "wan_ips": [<every WAN address seen, newest last>]}

Each stream reads from (cursor - overlap), or the initial lookback on its first run,
skips records already imported unchanged, and imports the rest oldest first in
bundles of UDM_EVENTS_PER_BUNDLE. The cursor is saved after every bundle, so a run
that fails part-way resumes where it stopped instead of starting over. A stream that
fails keeps its cursor and does not stop the other stream.

v0.4.2 replaced: no first-run guess from container names, no full re-scan of every
page (paging stops at the cursor), no 8-hour re-import, no count inflation.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from collections import Counter  # UDM-DRYRUN-V1
from itertools import groupby

from .config import Settings
from .models import (StreamCursor, UdmEvent, parse_admin, parse_flow, parse_security,
                     security_blocked)
from .network import NetworkContext
from .opencti_lookup import OpenCTILookup
from .stix_builder import UdmStixBuilder, container_day
from .udm_client import UdmClient, UdmError

_SEEN_CAP = 50000
_MAX_CLOCK_SKEW_MS = 3_600_000  # records dated further ahead than this are bad data
_WAN_HISTORY_CAP = 50


class UdmConnector:
    def __init__(self, helper, settings: Settings) -> None:
        self.helper = helper
        self.settings = settings
        self.log = helper.connector_logger
        self.client = UdmClient(settings, helper.connector_logger)
        self.lookup = OpenCTILookup(helper)
        self.builder = UdmStixBuilder(helper, settings, self.lookup)
        self._truncated: str | None = None
        self._devices: list[dict] = []
        # UDM-DRYRUN-V1: no state is saved in a dry run, so the next live run
        # reads the same window again.
        if settings.udm_dry_run:
            self.helper.set_state = lambda _state: None
            self.log.warning("UDM_DRY_RUN=true: bundles are built and counted; "
                             "nothing is sent and state is not saved")

    # -- scheduling --------------------------------------------------------

    def run(self) -> None:
        self.client.check()  # fail fast on bad host / key / TLS
        self.builder.prepare()
        self.helper.schedule_iso(
            message_callback=self.process,
            duration_period=self.settings.connector_duration_period,
        )

    def process(self) -> None:
        state = self.helper.get_state() or {}
        self.lookup.begin_run()
        now_ms = int(time.time() * 1000)
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"UDM run @ {datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc).isoformat()}")
        failed: list[str] = []
        try:
            net = self._network(state)
        except Exception as exc:  # noqa: BLE001 - without context nothing is safe to import
            self.log.error("Could not read UDM network context; run skipped",
                           {"error": str(exc)})
            self.helper.api.work.to_processed(work_id, f"UDM run skipped: {exc}", in_error=True)
            return
        streams = []
        if self.settings.udm_flows_enabled:
            streams.append(("flows", self._fetch_flows))
        if self.settings.udm_security_enabled:
            streams.append(("security", self._fetch_security))
        if self.settings.udm_admin_enabled:
            streams.append(("admin", self._fetch_admin))
        for stream, fetch in streams:
            cursor = StreamCursor.load(state.get(stream))
            try:
                sent = self._run_stream(stream, fetch, cursor, net, now_ms, state, work_id)
                self.log.info("Stream complete", {"stream": stream, "events": sent,
                                                  "cursor_ms": cursor.cursor_ms})
            except Exception as exc:  # noqa: BLE001 - isolate streams, resume next run
                failed.append(stream)
                self.log.error("Stream failed; resumes from its cursor next run",
                               {"stream": stream, "error": str(exc)})
            finally:
                cursor.prune(self._overlap_ms, _SEEN_CAP)
                state[stream] = cursor.dump()
                state["systems"] = net.dump_pins()
                self.helper.set_state(state)
        if self.settings.udm_inventory_enabled:
            try:
                self._inventory(state, net, now_ms, work_id)
            except Exception as exc:  # noqa: BLE001 - retried next run (state not updated)
                failed.append("inventory")
                self.log.error("Inventory failed", {"error": str(exc)})
        msg = "UDM run complete" + (f"; failed: {', '.join(failed)}" if failed else "")
        self.helper.api.work.to_processed(work_id, msg, in_error=bool(failed))

    @property
    def _overlap_ms(self) -> int:
        return self.settings.udm_overlap_minutes * 60_000

    # -- context -----------------------------------------------------------

    def _network(self, state: dict) -> NetworkContext:
        history = list(state.get("wan_ips") or [])
        try:
            self._devices = self.client.devices()
            current = self.client.wan_ips(self._devices)
        except UdmError as exc:
            self.log.warning("Device / WAN address lookup failed", {"error": str(exc)})
            self._devices, current = [], []
        forwards: list[dict] = []
        if self.settings.udm_port_forwards_enabled:
            try:
                forwards = self.client.port_forwards()
            except UdmError as exc:  # only loses the "forwarded service" annotation
                self.log.warning("Port-forward lookup failed", {"error": str(exc)})
        for ip in current + self.settings.wan_ip_list:
            if ip in history:
                history.remove(ip)
            history.append(ip)
        if not history:
            # Fail closed: without our WAN address, inbound flows would import our own
            # public IP as an external observable (and a candidate Indicator).
            raise UdmError("no WAN address from stat/device and UDM_WAN_IPS is empty")
        state["wan_ips"] = history[-_WAN_HISTORY_CAP:]
        return NetworkContext(
            wan_ips=state["wan_ips"],
            internal_networks=self.settings.internal_networks,
            clients=self.client.known_clients(),
            pinned=state.get("systems"),
            gateway_name=self.settings.udm_gateway_name,
            devices=self._devices,
            forwards=forwards,
        )

    def _inventory(self, state: dict, net: NetworkContext, now_ms: int, work_id: str) -> None:
        """Send device firmware only when it differs from what was last sent."""
        sent = dict(state.get("firmware") or {})
        changed = [d for d in self._devices
                   if d.get("mac") and d.get("version")
                   and sent.get(d["mac"].lower()) != str(d["version"])]
        if not changed:
            return
        day = _iso(now_ms)[:10]
        objects = self.builder.build_inventory(day, changed, net)
        if objects:
            self._send(objects, work_id)
        for d in changed:
            sent[d["mac"].lower()] = str(d["version"])
        state["firmware"] = sent
        state["systems"] = net.dump_pins()
        self.helper.set_state(state)
        self.log.info("Inventory sent", {"devices": len(changed)})

    # -- streams -------------------------------------------------------------

    def _fetch_flows(self, since_ms: int, now_ms: int) -> list[UdmEvent]:
        result = self.client.blocked_flows(since_ms)
        self.log.info("traffic-flows read", {"pages": result.pages, "stopped": result.stopped,
                                             "records": len(result.records)})
        events = [e for e in map(parse_flow, result.records) if e]
        if result.stopped == "max-pages":
            # Only the newest pages were read. Import them, then fail the stream so the
            # gap is visible in the work log rather than a warning nobody reads.
            oldest = min((e.last_ms for e in events), default=now_ms)
            self._truncated = (
                f"UDM_MAX_PAGES reached: flows from {_iso(since_ms)} to {_iso(oldest)} "
                "were not read; raise UDM_MAX_PAGES or shorten UDM_INITIAL_LOOKBACK_DAYS")
        return events

    def _fetch_security(self, since_ms: int, now_ms: int) -> list[UdmEvent]:
        result = self.client.security_events(since_ms, now_ms)
        rows = result.records
        if self.settings.udm_security_skip_blocked:
            rows = [r for r in rows if not security_blocked(r)]
        self.log.info("system-log read", {"pages": result.pages,
                                           "entries": len(result.records), "kept": len(rows)})
        if result.stopped == "max-pages":
            self._truncated = (f"UDM_MAX_PAGES reached reading the security log from "
                               f"{_iso(since_ms)}; older entries were not read")
        return [e for e in map(parse_security, rows) if e and e.last_ms >= since_ms]

    def _fetch_admin(self, since_ms: int, now_ms: int) -> list[UdmEvent]:
        result = self.client.audit_events(since_ms, now_ms)
        self.log.info("system-log (audit) read", {"pages": result.pages,
                                                   "entries": len(result.records)})
        if result.stopped == "max-pages":
            self._truncated = (f"UDM_MAX_PAGES reached reading the audit log from "
                               f"{_iso(since_ms)}; older entries were not read")
        return [e for e in map(parse_admin, result.records) if e and e.last_ms >= since_ms]

    def _run_stream(self, stream: str, fetch, cursor: StreamCursor, net: NetworkContext,
                    now_ms: int, state: dict, work_id: str) -> int:
        initial_ms = self.settings.udm_initial_lookback_days * 86_400_000
        # Never read from the future, even if a bad record once moved the cursor there.
        since = min(cursor.since_ms(now_ms, self._overlap_ms, initial_ms), now_ms)
        self._truncated = None
        latest: dict[str, UdmEvent] = {}
        future = 0
        for e in fetch(since, now_ms):  # a page can repeat a record: keep its newest copy
            if e.last_ms > now_ms + _MAX_CLOCK_SKEW_MS:
                future += 1  # would drag the cursor ahead and stall the stream
                continue
            if e.key not in latest or e.last_ms > latest[e.key].last_ms:
                latest[e.key] = e
        if future:
            self.log.warning("Skipped records dated in the future (check the UDM clock)",
                             {"stream": stream, "records": future})
        events = sorted((e for e in latest.values() if cursor.is_new(e)),
                        key=lambda e: (e.last_ms, e.key))
        sent = 0
        size = self.settings.udm_events_per_bundle
        for i in range(0, len(events), size):
            chunk = events[i:i + size]
            for day, day_events in groupby(sorted(chunk, key=container_day), key=container_day):
                objects = self.builder.build(stream, day, list(day_events), net)
                if objects:
                    self._send(objects, work_id)
            for e in chunk:
                cursor.mark(e)
            sent += len(chunk)
            # Persist progress after each bundle so a crash resumes here.
            state[stream] = cursor.dump()
            state["systems"] = net.dump_pins()
            self.helper.set_state(state)
        if self._truncated:
            raise UdmError(self._truncated)
        return sent

    def _send(self, objects: list[dict], work_id: str) -> None:
        # UDM-DRYRUN-V1: log what would have been sent, then stop.
        if self.settings.udm_dry_run:
            types = Counter(o.get("type") for o in objects)
            containers = sorted({o.get("name", "") for o in objects
                                 if o.get("type") == "case-incident"})
            self.log.info("DRY RUN: bundle not sent",
                          {"objects": len(objects), "types": dict(types),
                           "containers": containers})
            return
        bundle = json.dumps({
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        })
        self.helper.send_stix2_bundle(bundle, work_id=work_id, update=True)


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
