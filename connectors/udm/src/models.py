"""Normalized UDM events, and the parsers that build them from raw UniFi records.

Stdlib only, so the parsing and cursor logic tests run without pycti installed.

Two raw sources feed one shape:

  * v2 traffic-flows (action=blocked): firewall, IPS-signature and other blocks.
  * v2 system-log/all, SECURITY category: IPS threat events and honeypot hits.
    (Legacy stat/ips/event returns 404 on current Network versions.)

The `key` of an event is its native UniFi id, prefixed by stream, and is what keeps
re-reads idempotent: the same record always builds the same STIX ids.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass
class Endpoint:
    ip: str = ""
    port: int | None = None
    mac: str = ""
    host: str = ""  # hostname or client name the gateway attached to this side
    country: str = ""  # ISO 3166-1 alpha-2, as UniFi reports it
    zone: str = ""  # UniFi firewall zone (Internal / External / ...)
    network: str = ""  # UniFi network (VLAN) name


@dataclass
class UdmEvent:
    stream: str  # "flows" | "security" | "admin"
    native_id: str
    first: datetime
    last: datetime
    src: Endpoint
    dst: Endpoint
    label: str  # kind: SIGNATURE, REGION_BLOCKING, THREAT_BLOCKED, HONEYPOT_HIT_DETECTED, ...
    action: str = ""  # "blocked" / "alert" (detected, not blocked)
    protocol: str = ""
    direction: str = ""
    severity: str | None = None
    count: int = 1
    policy_name: str = ""
    policy_type: str = ""
    category: str = ""
    signature: str = ""
    signature_id: str = ""
    signature_class: str = ""
    affected_product: str = ""
    risk_text: str = ""
    message: str = ""
    ips_list: str = ""  # IPS rule set that matched, e.g. ciarmy / dshield / emerging-scan
    service: str = ""  # UniFi's service name for the destination port (SSH, HTTPS, ...)
    admin: str = ""  # admin account (admin stream)
    platform: str = ""  # how the admin connected (admin stream)
    cves: list[str] = field(default_factory=list)
    bytes_total: int | None = None
    packets_total: int | None = None

    @property
    def key(self) -> str:
        return f"{self.stream}:{self.native_id}"

    @property
    def last_ms(self) -> int:
        return to_ms(self.last)


# -- time helpers -----------------------------------------------------------


def to_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def from_epoch(value) -> datetime | None:
    """UniFi mixes epoch seconds and milliseconds; anything below 1e11 is seconds."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    if v < 1e11:
        v *= 1000
    try:
        return datetime.fromtimestamp(v / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):  # e.g. microseconds read as ms
        return None


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str(value) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _cves(*values: str) -> list[str]:
    out: list[str] = []
    for value in values:
        for part in (value or "").replace(";", ",").replace(" ", ",").split(","):
            part = part.strip().upper()
            if part.startswith("CVE-") and part not in out:
                out.append(part)
    return out


def _severity(value) -> str | None:
    v = _str(value).lower()
    return v if v in _SEVERITIES else None


# -- traffic-flows ------------------------------------------------------------


def _flow_endpoint(raw: dict | None) -> Endpoint:
    raw = raw or {}
    return Endpoint(
        ip=_str(raw.get("ip")),
        port=_int(raw.get("port")),
        mac=_str(raw.get("mac")).lower(),
        host=_str(raw.get("host_name") or raw.get("client_name") or raw.get("device_name")),
        country=_str(raw.get("region")).upper(),
        zone=_str(raw.get("zone_name")),
        network=_str(raw.get("network_name")),
    )


def parse_flow(raw: dict) -> UdmEvent | None:
    """One blocked traffic-flow record, or None if it lacks an id or a time."""
    native_id = _str(raw.get("id") or raw.get("_id"))
    first = from_epoch(raw.get("flow_start_time") or raw.get("time"))
    last = from_epoch(raw.get("time") or raw.get("flow_start_time"))
    if not native_id or not first or not last:
        return None
    if last < first:
        first, last = last, first
    policy = (raw.get("policies") or [{}])[0] or {}
    ips = raw.get("ips") or {}
    td = raw.get("traffic_data") or {}
    internal_type = _str(policy.get("internal_type")).upper()
    return UdmEvent(
        stream="flows",
        native_id=native_id,
        first=first,
        last=last,
        src=_flow_endpoint(raw.get("source")),
        dst=_flow_endpoint(raw.get("destination")),
        label=internal_type or "BLOCK",
        action="blocked",
        protocol=_str(raw.get("protocol")).upper(),
        direction=_str(raw.get("direction")).lower(),
        severity=_severity(raw.get("risk")),
        count=max(1, _int(raw.get("count")) or 1),
        policy_name=_str(policy.get("name")),
        policy_type=_str(policy.get("type")),
        category=_str(policy.get("ips_category")),
        ips_list=_str(ips.get("category_name")),
        service=_str(raw.get("service")) if _str(raw.get("service")) != "OTHER" else "",
        signature=_str(ips.get("signature")),
        signature_id=_str(ips.get("signature_id")),
        signature_class=_str(ips.get("signature_class")),
        affected_product=_str(ips.get("affected_product")),
        risk_text=_str(ips.get("alarm_category_potential_risk")),
        cves=_cves(_str(ips.get("relevant_cve"))),
        bytes_total=_int(td.get("bytes_total")),
        packets_total=_int(td.get("packets_total")),
    )


# -- security log (v2 system-log, SECURITY category) -------------------------------

_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_PLACEHOLDER = re.compile(r"\{([A-Z_]+)\}")


def security_blocked(raw: dict) -> bool:
    return _str(raw.get("event") or raw.get("key")).upper().startswith("THREAT_BLOCKED")


def _sec_side(params: dict, ip_key: str, client_key: str) -> Endpoint:
    ipp = params.get(ip_key) or {}
    cl = params.get(client_key) or {}
    mac = _str(cl.get("id")).lower()
    return Endpoint(ip=_str(ipp.get("id")),
                    mac=mac if _MAC.match(mac) else "",
                    host=_str(cl.get("name") or cl.get("hostname")))


def _fill(template: str, params: dict) -> str:
    """message_raw with its {PLACEHOLDER}s replaced by the parameters' display names."""
    def name(m):
        v = params.get(m.group(1)) or {}
        return _str(v.get("name") or v.get("id")) or m.group(0)
    return _PLACEHOLDER.sub(name, template or "")


def parse_security(raw: dict) -> UdmEvent | None:
    """One SECURITY entry of the v2 system log (IPS threat, honeypot hit, ...), or None
    if it lacks an id or a time. *_IP parameters carry an address in `id`; *_CLIENT /
    CLIENT parameters carry the client's MAC in `id` and its display name in `name`."""
    native_id = _str(raw.get("id"))
    when = from_epoch(raw.get("timestamp"))
    if not native_id or not when:
        return None
    params = raw.get("parameters") or {}
    src = _sec_side(params, "SRC_IP", "SRC_CLIENT")
    dst = _sec_side(params, "DST_IP", "DST_CLIENT")
    if not src.ip and not src.mac and params.get("CLIENT"):  # honeypot: the client that hit it
        src = _sec_side(params, "", "CLIENT")
    message = _fill(_str(raw.get("message_raw")), params)
    return UdmEvent(
        stream="security",
        native_id=native_id,
        first=when,
        last=when,
        src=src,
        dst=dst,
        label=_str(raw.get("event") or raw.get("key")).upper() or "SECURITY",
        action="blocked" if security_blocked(raw) else "alert",
        severity=_severity(raw.get("severity")),
        category=_str(raw.get("subcategory")),
        signature=_str(raw.get("key")),
        message=message,
        cves=_cves(*message.split()),
    )


# -- admin access (v2 system-log, AUDIT category) --------------------------------


def parse_admin(raw: dict) -> UdmEvent | None:
    """One ADMIN_ACCESS entry of the system log, or None if it is another AUDIT key or
    lacks an id or a time. Parameters: ADMIN (account), IP (source address),
    PLATFORM (how the admin connected)."""
    if _str(raw.get("key")) != "ADMIN_ACCESS":
        return None
    native_id = _str(raw.get("id"))
    when = from_epoch(raw.get("timestamp"))
    if not native_id or not when:
        return None
    params = raw.get("parameters") or {}
    admin = _str((params.get("ADMIN") or {}).get("name"))
    platform = _str((params.get("PLATFORM") or {}).get("name"))
    return UdmEvent(
        stream="admin",
        native_id=native_id,
        first=when,
        last=when,
        src=Endpoint(ip=_str((params.get("IP") or {}).get("id"))),
        dst=Endpoint(),
        label="ADMIN_ACCESS",
        action="login",
        message=_fill(_str(raw.get("message_raw")), params),
        admin=admin,
        platform=platform,
    )


# -- cursor state -----------------------------------------------------------------


@dataclass
class StreamCursor:
    """Per-stream progress, persisted in connector state as
    {"cursor_ms": <int|None>, "seen": {<event key>: <last_ms>}}.

    `cursor_ms` is the newest event time imported (the UDM's clock, not ours).
    Each run re-reads `overlap` before it, to catch records written late or
    extended after they were read, and `seen` skips the ones already imported
    unchanged. A record that comes back with a newer last-time is re-imported,
    and its deterministic ids update the same objects in place.
    """

    cursor_ms: int | None = None
    seen: dict[str, int] = field(default_factory=dict)

    @classmethod
    def load(cls, raw: dict | None) -> "StreamCursor":
        raw = raw or {}
        cursor = raw.get("cursor_ms")
        seen = raw.get("seen") or {}
        return cls(int(cursor) if cursor is not None else None,
                   {str(k): int(v) for k, v in seen.items()})

    def dump(self) -> dict:
        return {"cursor_ms": self.cursor_ms, "seen": dict(self.seen)}

    def since_ms(self, now_ms: int, overlap_ms: int, initial_ms: int) -> int:
        if self.cursor_ms is None:
            return now_ms - initial_ms
        return self.cursor_ms - overlap_ms

    def is_new(self, event: UdmEvent) -> bool:
        prior = self.seen.get(event.key)
        return prior is None or event.last_ms > prior

    def mark(self, event: UdmEvent) -> None:
        self.seen[event.key] = max(event.last_ms, self.seen.get(event.key, 0))
        self.cursor_ms = max(self.cursor_ms or 0, event.last_ms)

    def prune(self, overlap_ms: int, cap: int) -> None:
        """Keep only keys the next run's overlap can re-read, newest `cap` of them."""
        if self.cursor_ms is None:
            self.seen.clear()
            return
        floor = self.cursor_ms - overlap_ms
        kept = sorted(((k, v) for k, v in self.seen.items() if v >= floor),
                      key=lambda kv: kv[1])
        self.seen = dict(kept[-cap:])
