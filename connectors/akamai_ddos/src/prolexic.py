"""Prolexic Analytics poller — network-layer (L3/L4) DDoS attack reports.

Endpoints (base path /prolexic-analytics/v2):
  GET /attack-reports/contract/{contract}/start/{start}/end/{end}   list in window
  GET /attack-report/contract/{contract}/attack-id/{attackId}       single detail

Confirmed payload shape (see tests/fixtures/attack-reports-get.json):
  { "status": bool, "currentContract": str, "data": [ {
      "attackId": int, "destinationPort": str|null, "ticketId": int, "eventId": int,
      "eventStartTime"/"eventEndTime"/"startTime"/"endTime": epoch-seconds-UTC,
      "eventTypes": [str],                       # vectors, e.g. "SYN Flood"
      "peaks": [ {"location": str, "peakId": int, "bandwidth": bps-int, "pps": int} ],
      "destinations": [ {"netmask": int, "ip": str} ]   # the TARGET/victim assets
  } ] }

IMPORTANT: Prolexic attack reports carry NO attacker source IPs — `ip`/`destinations`
are the *target*. Source top-talkers exist only in /events (eventInfo.topSourceIPs),
under a different, non-correlatable id namespace, and are typically spoofed for L3/L4.
So AttackEvent.source_ips is left empty here unless /events enrichment is enabled.

State: {"last_end": iso, "seen_attack_ids": [...]}. First run backfills
settings.akamai_initial_lookback_days, then incremental.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .akamai_client import AkamaiClient
from .config import Settings
from .models import AttackEvent

_BASE = "/prolexic-analytics/v2"


class ProlexicPoller:
    def __init__(self, client: AkamaiClient, settings: Settings, logger) -> None:
        self.client = client
        self.settings = settings
        self.logger = logger
        self.contract = settings.akamai_prolexic_contract

    def fetch(self, start: datetime, end: datetime, seen: set[str]) -> list[AttackEvent]:
        path = (
            f"{_BASE}/attack-reports/contract/{self.contract}"
            f"/start/{int(start.timestamp())}/end/{int(end.timestamp())}"
        )
        payload = self.client.get_json(path)
        if not payload.get("status", True):
            self.logger.warning("Prolexic non-OK status", {"msg": payload.get("statusMsg")})

        events: list[AttackEvent] = []
        for raw in payload.get("data", []):
            attack_id = str(raw.get("attackId") or raw.get("eventId") or "")
            if not attack_id or attack_id in seen:
                continue
            try:
                events.append(self._normalize(raw, attack_id))
            except Exception as exc:  # noqa: BLE001 — skip a malformed row, keep the run
                self.logger.warning("Skipping unparseable Prolexic attack",
                                    {"attack_id": attack_id, "error": str(exc)})
        return events

    # -- normalization -----------------------------------------------------

    def _normalize(self, raw: dict, attack_id: str) -> AttackEvent:
        start = raw.get("eventStartTime") or raw.get("startTime")
        end = raw.get("eventEndTime") or raw.get("endTime")

        # vectors: list endpoint -> eventTypes[]; single endpoint -> attackTypeName
        vectors = list(raw.get("eventTypes") or [])
        if not vectors and raw.get("attackTypeName"):
            vectors = [raw["attackTypeName"]]

        # peaks: list endpoint -> peaks[]; single endpoint -> eventBw/eventPps
        peaks = raw.get("peaks") or []
        bws = [p.get("bandwidth") for p in peaks if isinstance(p.get("bandwidth"), int)]
        ppss = [p.get("pps") for p in peaks if isinstance(p.get("pps"), int)]
        if not bws and isinstance(raw.get("eventBw"), int):
            bws = [raw["eventBw"]]
        if not ppss and isinstance(raw.get("eventPps"), int):
            ppss = [raw["eventPps"]]
        scrub_centers = sorted({p["location"] for p in peaks if p.get("location")})
        if not scrub_centers and raw.get("location"):
            scrub_centers = [raw["location"]]

        # targets: list endpoint -> destinations[]; single endpoint -> ip + netmask
        dests = raw.get("destinations") or []
        target_ips = [self._cidr(d.get("ip"), d.get("netmask")) for d in dests if d.get("ip")]
        if not target_ips and raw.get("ip"):
            target_ips = [self._cidr(raw["ip"], raw.get("netmask"))]

        dest_ports: list[int] = []
        if raw.get("destinationPort"):
            try:
                dest_ports = [int(raw["destinationPort"])]
            except (TypeError, ValueError):
                pass

        return AttackEvent(
            source_system="prolexic",
            attack_id=attack_id,
            start_time=self._epoch(start),
            end_time=self._epoch(end),
            is_ddos=True,  # Prolexic only reports DDoS
            vectors=vectors,
            dest_ports=dest_ports,
            target_ips=target_ips,
            peak_bps=max(bws) if bws else None,
            peak_pps=max(ppss) if ppss else None,
            ticket_id=str(raw["ticketId"]) if raw.get("ticketId") else None,
            mitigation=("Scrubbed at: " + ", ".join(scrub_centers)) if scrub_centers else None,
            source_ips=[],  # see module docstring; optionally enriched from /events
            raw=raw,
        )

    @staticmethod
    def _epoch(value) -> datetime:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)

    @staticmethod
    def _cidr(ip: str, netmask) -> str:
        return f"{ip}/{netmask}" if netmask not in (None, "") else ip
