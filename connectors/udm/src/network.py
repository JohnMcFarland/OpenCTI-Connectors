"""Which side of an event is ours, and the stable System name for each internal host.

Stdlib only. Rebuilt every run from the UDM's client list and WAN addresses.

System names are what OpenCTI dedups Systems on, so they must not drift. v0.4.2
named a host by whatever hostname was visible that run, so a host that was offline
(or renamed) became a second System. Here a MAC's name is chosen once and pinned in
connector state; later hostname changes do not mint a new System.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import Endpoint

_PIN_CAP = 5000
_GATEWAY_TYPES = {"udm", "ugw", "uxg", "udr", "ucg"}


def _ports(spec) -> set[int]:
    """UniFi port spec: "443", "80,443" or "8000-8010"."""
    out: set[int] = set()
    for part in str(spec or "").split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.strip().isdigit() and hi.strip().isdigit():
                a, b = int(lo), int(hi)
                if 0 < a <= b < 65536 and b - a <= 1024:
                    out.update(range(a, b + 1))
        elif part.isdigit() and 0 < int(part) < 65536:
            out.add(int(part))
    return out


@dataclass
class Forward:
    """An enabled port-forward rule: WAN `ports` -> `target_ip`:`target_ports`."""

    name: str
    ports: set[int]
    protocols: set[str]
    target_ip: str
    target_ports: set[int]

    @classmethod
    def parse(cls, rule: dict) -> "Forward | None":
        if not rule.get("enabled", True):
            return None
        ports = _ports(rule.get("dst_port"))
        target = str(rule.get("fwd") or "").strip()
        if not ports or not target:
            return None
        proto = str(rule.get("proto") or "tcp_udp").lower()
        protocols = {"TCP", "UDP"} if proto in ("tcp_udp", "both", "") else {proto.upper()}
        return cls(name=str(rule.get("name") or "unnamed").strip(), ports=ports,
                   protocols=protocols, target_ip=target,
                   target_ports=_ports(rule.get("fwd_port")) or ports)


def _norm(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


class NetworkContext:
    def __init__(self, wan_ips: list[str], internal_networks: list, clients: list[dict],
                 pinned: dict[str, str] | None, gateway_name: str,
                 devices: list[dict] | None = None,
                 forwards: list[dict] | None = None) -> None:
        self.wan_ips = {_norm(ip) for ip in wan_ips}
        self.internal_networks = internal_networks
        self.gateway_name = gateway_name
        self.pinned: dict[str, str] = dict(pinned or {})
        self.clients: dict[str, dict] = {}
        self.ip_to_mac: dict[str, str] = {}
        self.forwards = [f for f in map(Forward.parse, forwards or []) if f]
        # UniFi devices (switches, APs) are named Systems too, under their UniFi name;
        # the gateway's own MAC is the gateway System, so it never gets a second name.
        for d in devices or []:
            mac = (d.get("mac") or "").lower()
            if not mac:
                continue
            if d.get("type") in _GATEWAY_TYPES or d.get("wan1"):
                self.pinned[mac] = gateway_name
            clients = [*clients, {"mac": mac, "name": d.get("name") or d.get("model"),
                                  "ip": d.get("ip"), "device_model": d.get("model")}]
        for c in clients:
            mac = (c.get("mac") or "").lower()
            if not mac:
                continue
            self.clients[mac] = c
            for key in ("ip", "last_ip", "fixed_ip"):
                ip = c.get(key)
                if ip:
                    self.ip_to_mac.setdefault(ip, mac)

    # -- classification ------------------------------------------------------

    def classify(self, ip: str) -> str:
        """"wan" (the gateway's own public address), "internal", "external", or "" when
        there is no usable address."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        if str(addr) in self.wan_ips:
            return "wan"
        if addr.is_multicast or addr.is_unspecified or str(addr) == "255.255.255.255":
            return ""  # not a host: no System, no observable
        if any(addr in net for net in self.internal_networks):
            return "internal"
        # Private, CGNAT, loopback, link-local, multicast, ... are never imported as
        # observables: OpenCTI could promote them to Indicators and block our own hosts.
        return "external" if addr.is_global else "internal"

    # -- systems ---------------------------------------------------------------

    def system_name(self, ep: Endpoint) -> str:
        """Stable name of the internal host behind `ep`."""
        mac = ep.mac or self.ip_to_mac.get(ep.ip, "")
        if mac:
            if mac not in self.pinned:
                name = self._client_name(mac, ep)
                if name in self.pinned.values():  # e.g. two "iPhone"s: keep them apart
                    name = f"{name} ({mac})"
                self.pinned[mac] = name
            return self.pinned[mac]
        # No MAC from the record or the client list: name it by what the record says,
        # unless that name already belongs to a known client (a different host).
        if ep.host and ep.host not in self.pinned.values():
            return ep.host
        return f"{ep.host} ({ep.ip})" if ep.host else f"Host {ep.ip}"

    def system_description(self, name: str, ep: Endpoint) -> str:
        if name == self.gateway_name:
            return "UniFi Dream Machine Pro gateway (WAN interface)."
        mac = ep.mac or self.ip_to_mac.get(ep.ip, "")
        if not mac:
            return "Internal host seen in UniFi Dream Machine telemetry (MAC unknown)."
        c = self.clients.get(mac) or {}
        if c.get("device_model"):
            return f"UniFi network device, model {c['device_model']}, MAC {mac}."
        oui = c.get("oui") or "unknown vendor"
        return f"Internal network client, MAC {mac} ({oui})."

    def system_for_ip(self, ip: str) -> str:
        """System name of an internal address (for port-forward targets)."""
        return self.system_name(Endpoint(ip=ip))

    def forward_for(self, dst: Endpoint, protocol: str, kind: str) -> Forward | None:
        """The port-forward rule this destination hit: the WAN side of a rule, or (after
        the gateway translated it) the rule's internal target."""
        if dst.port is None:
            return None
        for f in self.forwards:
            if protocol and protocol.upper() not in f.protocols:
                continue
            if kind == "wan" and dst.port in f.ports:
                return f
            if dst.ip == f.target_ip and dst.port in f.target_ports:
                return f
        return None

    def _client_name(self, mac: str, ep: Endpoint) -> str:
        c = self.clients.get(mac) or {}
        # `name` is the alias set in the UniFi UI, steadier than the DHCP hostname.
        return (c.get("name") or c.get("hostname") or ep.host or f"Client {mac}").strip()

    def dump_pins(self) -> dict[str, str]:
        if len(self.pinned) > _PIN_CAP:
            # Oldest pins first in insertion order; drop those beyond the cap.
            self.pinned = dict(list(self.pinned.items())[-_PIN_CAP:])
        return dict(self.pinned)
