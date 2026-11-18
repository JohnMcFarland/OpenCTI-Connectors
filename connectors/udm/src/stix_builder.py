"""Build STIX bundles (lists of dict objects) from normalized UDM events.

Encodes the repo data model (Data_Model_Acceptable_Relationships.csv + CTI Ingestion
Manual) in code. The UDM is an INTERNAL source ("what we saw"), so:

  * Container = Incident Response (case-incident), one per stream per UTC day.
    Sightings are ONLY emitted inside it.
  * NO Incident objects (user decision, 2026-11-18: ~900/day was too noisy). Each UDM
    event with an external address becomes a Sighting of that address on the System
    it involved, carrying the event details; events with no external address are
    not imported.
  * NO Indicators, NO Labels, NO observable descriptions.
  * Network-Traffic carries a SINGLE port only (house rule).
  * Only external (globally routable, not our WAN) IPs become observables. Internal
    hosts are Systems, never IP observables, so OpenCTI cannot promote our own
    addresses to Indicators.
  * Every observable is related-to >= 1 named Identity (the System it was seen on).
  * Countries and Vulnerabilities are looked up, never created. A signature's CVE
    links the external IP to the existing Vulnerability (related-to).
  * Relationship verbs come from ALLOWED_EDGES; anything else is `related-to` with a
    description (manual §3.4k escape hatch).
  * Every id is deterministic and independent of mutable fields (last seen, count),
    so re-reading a record updates the same objects instead of creating new ones.
    This, plus shipping bundles instead of per-object API calls, is what removes
    v0.4.2's Elasticsearch load (a search before every write) and its duplicates.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import stix2
from pycti import (
    CaseIncident,
    Identity,
    StixCoreRelationship,
    StixSightingRelationship,
)

from .config import Settings
from .models import UdmEvent
from .network import NetworkContext
from .opencti_lookup import OpenCTILookup

# OASIS STIX SCO namespace; same single-port Network-Traffic key as akamai_ddos and
# splunk, so a port dedups across connectors.
_SCO_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# Precise verbs from Data_Model_Acceptable_Relationships.csv this connector emits.
# Every other edge (ipv6->country, ip->system, ip->network-traffic, ip->vulnerability,
# network-traffic->system, system->organization) has no listed verb: `related-to`.
ALLOWED_EDGES: set[tuple[str, str, str]] = {
    ("ipv4-addr", "located-at", "country"),
}

CONTAINER_TITLES = {"flows": "UDM Blocked Flows", "security": "UDM Security Events",
                    "admin": "UDM Admin Access", "inventory": "UDM Inventory"}
_SOURCES = {"flows": "UniFi traffic-flows", "security": "UniFi system log (Security)",
            "admin": "UniFi system log (Admin access)"}
_CONTAINER_WHAT = {"flows": "blocked traffic flows", "security": "security log events",
                   "admin": "admin logins from external addresses",
                   "inventory": "device firmware inventory"}
# IPS rule sets that mean "this address is on a known-bad list", not just "this
# traffic matched a pattern".
_REPUTATION_LISTS = {"ciarmy": "CINS Army bad-reputation list",
                     "dshield": "DShield top-attackers list",
                     "compromised": "known-compromised hosts list"}


def container_day(event: UdmEvent) -> str:
    return event.first.astimezone(timezone.utc).strftime("%Y-%m-%d")


class UdmStixBuilder:
    def __init__(self, helper, settings: Settings, lookup: OpenCTILookup) -> None:
        self.log = helper.connector_logger
        self.settings = settings
        self.lookup = lookup
        self.confidence = settings.udm_confidence
        self.author_id = Identity.generate_id(settings.udm_author_name, "organization")
        self.org_id = Identity.generate_id(settings.udm_organization_name, "organization")
        self.marking_id: str | None = None

    def prepare(self) -> None:
        """Resolve the marking once. Fail closed: unmarked internal telemetry is worse
        than not ingesting it."""
        self.marking_id = self.lookup.marking(self.settings.udm_tlp)
        if not self.marking_id:
            raise RuntimeError(
                f"Configured TLP marking could not be resolved ({self.settings.udm_tlp}); "
                "refusing to start. Verify the marking exists in OpenCTI.")

    # -- public ------------------------------------------------------------

    def build(self, stream: str, day: str, events: list[UdmEvent],
              net: NetworkContext) -> list[dict]:
        """One bundle: the day's container plus everything `events` reference. Several
        bundles may carry the same container; OpenCTI merges their object_refs."""
        if not self.marking_id:
            raise RuntimeError("prepare() must resolve the marking before build()")
        objects: dict[str, dict] = {}
        refs: dict[str, None] = {}

        def add(obj: dict, member: bool = True) -> str:
            objects.setdefault(obj["id"], obj)
            if member:
                refs[obj["id"]] = None
            return obj["id"]

        def ref(object_id: str) -> None:  # exists in OpenCTI, not shipped
            refs[object_id] = None

        add(self._identity(self.settings.udm_author_name, "organization"), member=False)
        add(self._identity(self.settings.udm_organization_name, "organization"))
        static = len(refs)
        for event in events:
            self._event(event, net, add, ref)
        if len(refs) == static:  # no event in this batch had an external address
            return []
        day_start = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        add(self._container(stream, day, day_start, list(refs)), member=False)
        return list(objects.values())

    # -- one event -----------------------------------------------------------

    def _event(self, e: UdmEvent, net: NetworkContext, add, ref) -> None:
        """Sightings only (user decision: no Incident objects). An event with no external
        address (internal-to-internal or internal-to-gateway blocks, honeypot hits) has
        nothing to sight and is not imported at all."""
        externals, internals = [], []
        for ep in (e.src, e.dst):
            kind = net.classify(ep.ip)
            if not ep.ip and ep.mac:  # a known client named by MAC, no address given
                kind = "internal"
            if kind == "external":
                externals.append(ep)
            elif kind in ("wan", "internal"):
                internals.append((kind, ep))
        if not externals:
            return

        systems = []
        for kind, ep in internals:
            name = net.gateway_name if kind == "wan" else net.system_name(ep)
            systems.append(self._system(add, net, name, ep))
        if not systems:  # e.g. transit traffic: seen at the gateway
            systems.append(self._system(add, net, net.gateway_name, e.dst))

        port = e.dst.port if e.dst.port and 0 < e.dst.port < 65536 else None
        nt_id = None
        extra: list[str] = []
        if port:
            nt_id = add(self._network_traffic(port))
            for sys_id, sys_name in systems:
                add(self._rel(nt_id, "network-traffic", "related-to", sys_id, "system",
                              f"Destination port {port} of blocked traffic involving "
                              f"{sys_name}, seen by the UniFi Dream Machine."))
            fwd = net.forward_for(e.dst, e.protocol, net.classify(e.dst.ip))
            if fwd:
                # Attack surface: this port is open to the internet through a forward.
                tgt_name = net.system_for_ip(fwd.target_ip)
                tgt_id, _ = self._system(add, net, tgt_name, _Ep(fwd.target_ip))
                add(self._rel(nt_id, "network-traffic", "related-to", tgt_id, "system",
                              f"Exposed to the internet by UniFi port forward '{fwd.name}' "
                              f"({'/'.join(sorted(fwd.protocols))}) to {tgt_name}."))
                extra.append(f"Port forward: '{fwd.name}' to {tgt_name} "
                             "(this traffic targeted a forwarded service)")

        what = _what(e)
        details = describe(e, extra)
        for ep in externals:
            ip_type = "ipv6-addr" if ":" in ep.ip else "ipv4-addr"
            ip_id = add(self._ip(ep.ip))
            role = "source" if ep is e.src else "destination"
            country_id = self.lookup.country(ep.country) if ep.country else None
            if country_id:
                ref(country_id)
                # Only the IPv4 row is listed; IPv6 takes the escape hatch.
                verb = "located-at" if ip_type == "ipv4-addr" else "related-to"
                add(self._rel(ip_id, ip_type, verb, country_id, "country",
                              f"UniFi geolocated this address to {ep.country}."))
            if nt_id:
                # Protocol is text on this edge only (no protocol object, house rule).
                # One edge per IP/port pair: a later event on the same pair with another
                # protocol rewrites this text.
                add(self._rel(ip_id, ip_type, "related-to", nt_id, "network-traffic",
                              f"Address seen by the UniFi Dream Machine in blocked traffic "
                              f"to port {port}."
                              + (f" Protocol: {e.protocol}." if e.protocol else "")))
            for cve in e.cves:
                vuln_id = self.lookup.vulnerability(cve)
                if vuln_id:
                    ref(vuln_id)
                    sig = f"'{e.signature}'" if e.signature else "an IPS signature"
                    # The CVE is signature metadata: it says what the rule detects, not
                    # that the target was vulnerable or that exploitation succeeded.
                    add(self._rel(ip_id, ip_type, "related-to", vuln_id, "vulnerability",
                                  f"UniFi IPS signature {sig}, which UniFi associates with "
                                  f"{cve}, fired on {e.action or 'blocked'} traffic where this "
                                  f"address was the {role}."))
            for sys_id, sys_name in systems:
                add(self._rel(ip_id, ip_type, "related-to", sys_id, "system",
                              f"Address seen by the UniFi Dream Machine in traffic "
                              f"involving {sys_name}."))
                add(self._sighting(ip_id, sys_id, e,
                                   f"External {role} of {what}.\n\n{details}"))

    # -- inventory -----------------------------------------------------------

    def build_inventory(self, day: str, devices: list[dict], net: NetworkContext) -> list[dict]:
        """Firmware of each UniFi device: Software related-to the device's System, in a
        "UDM Inventory" container for the day the version was first seen."""
        if not self.marking_id:
            raise RuntimeError("prepare() must resolve the marking before build()")
        objects: dict[str, dict] = {}
        refs: dict[str, None] = {}

        def add(obj: dict, member: bool = True) -> str:
            objects.setdefault(obj["id"], obj)
            if member:
                refs[obj["id"]] = None
            return obj["id"]

        add(self._identity(self.settings.udm_author_name, "organization"), member=False)
        add(self._identity(self.settings.udm_organization_name, "organization"))
        for d in devices:
            mac, version = (d.get("mac") or "").lower(), d.get("version")
            if not mac or not version:
                continue
            model = d.get("model") or "device"
            name = net.system_name(_Ep("", mac))
            sys_id, _ = self._system(add, net, name, _Ep(d.get("ip") or "", mac))
            sw_id = add(self._base(json.loads(stix2.Software(
                name=f"UniFi {model} firmware", version=str(version),
                vendor="Ubiquiti").serialize())))
            add(self._rel(sw_id, "software", "related-to", sys_id, "system",
                          f"Firmware {version} reported running on {name} by the UniFi "
                          f"controller (first seen {day})."))
        if len(refs) <= 1:
            return []
        day_start = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        add(self._container("inventory", day, day_start, list(refs)), member=False)
        return list(objects.values())

    def _system(self, add, net: NetworkContext, name: str, ep) -> tuple[str, str]:
        sys_id = Identity.generate_id(name, "system")
        add(self._identity(name, "system", net.system_description(name, ep)))
        add(self._rel(sys_id, "system", "related-to", self.org_id, "organization",
                      f"Network asset of {self.settings.udm_organization_name}."))
        return sys_id, name

    # -- object builders ---------------------------------------------------

    def _base(self, obj: dict, *, created_by: bool = True) -> dict:
        obj["spec_version"] = "2.1"
        obj["object_marking_refs"] = [self.marking_id]
        if created_by:
            obj["created_by_ref"] = self.author_id
        return obj

    def _identity(self, name: str, cls: str, description: str = "") -> dict:
        obj_id = Identity.generate_id(name, cls)
        obj = {"type": "identity", "id": obj_id, "name": name, "identity_class": cls}
        if description:
            obj["description"] = description
        return self._base(obj, created_by=obj_id != self.author_id)

    def _ip(self, value: str) -> dict:
        cls = stix2.IPv6Address if ":" in value else stix2.IPv4Address
        return self._base(json.loads(cls(value=value).serialize()))

    def _network_traffic(self, port: int) -> dict:
        # SINGLE PORT ONLY: no protocol, refs, or byte counts by house rule.
        return self._base({
            "type": "network-traffic",
            "id": f"network-traffic--{uuid.uuid5(_SCO_NS, f'dst_port={port}')}",
            "dst_port": port,
        })

    def _sighting(self, ip_id: str, sys_id: str, e: UdmEvent, description: str) -> dict:
        # Id keyed on the event, not its last-seen or count: a record re-read with later
        # activity updates this Sighting instead of adding another (v0.4.2 re-added the
        # count of every overlapping record on every run).
        return self._base({
            "type": "sighting",
            # Keyed on the UniFi record alone (pycti only hashes these values): live
            # records have no flow_start_time, so "first" is `time`, which moves when the
            # UDM extends a flow. Two events in the same second stay two Sightings.
            "id": StixSightingRelationship.generate_id(ip_id, [sys_id], e.key),
            "sighting_of_ref": ip_id,
            "where_sighted_refs": [sys_id],
            "description": description,
            "first_seen": e.first.isoformat(),
            "last_seen": max(e.last, e.first + timedelta(seconds=1)).isoformat(),
            "count": e.count,
            "confidence": self.confidence,
            "x_opencti_negative": False,
        })

    def _container(self, stream: str, day: str, day_start: datetime, refs: list[str]) -> dict:
        name = f"{CONTAINER_TITLES[stream]} — {day}"
        what = _CONTAINER_WHAT[stream]
        return self._base({
            "type": "case-incident",
            "id": CaseIncident.generate_id(name, day_start.isoformat()),
            "name": name,
            # Stable text: the container is re-sent by every bundle of the day.
            "description": (f"UniFi Dream Machine {what} for {day} (UTC). "
                            + ("Firmware versions as Software related to each device's "
                               "System." if stream == "inventory" else
                               "Each event is a Sighting of the external address on the "
                               "internal System or gateway it involved.")),
            "created": day_start.isoformat(),
            "object_refs": refs,
        })

    def _rel(self, src_id, src_log, rel_type, tgt_id, tgt_log, description,
             start: str | None = None, stop: str | None = None) -> dict:
        if rel_type != "related-to" and (src_log, rel_type, tgt_log) not in ALLOWED_EDGES:
            raise ValueError(f"Edge not on the data-model allow-list: "
                             f"{src_log},{rel_type},{tgt_log}")
        rel = {
            "type": "relationship",
            # Timeless id: dates move as a record is extended, the edge does not.
            "id": StixCoreRelationship.generate_id(rel_type, src_id, tgt_id),
            "relationship_type": rel_type,
            "source_ref": src_id,
            "target_ref": tgt_id,
            "description": description,
            "confidence": self.confidence,
        }
        if start and stop:
            rel["start_time"], rel["stop_time"] = start, stop
        return self._base(rel)


# -- text helpers ---------------------------------------------------------------


class _Ep:
    """Minimal endpoint for System naming outside an event."""

    def __init__(self, ip: str, mac: str = "") -> None:
        self.ip, self.mac, self.host, self.port = ip, mac, "", None


def _what(e: UdmEvent) -> str:
    if e.stream == "admin":
        who = f" by admin '{e.admin}'" if e.admin else ""
        via = f" via {e.platform}" if e.platform else ""
        return f"a login to UniFi Network{who}{via}"
    if e.stream == "security":
        return f"a UniFi security event ({e.label.lower().replace('_', ' ')})"
    label = e.label.lower().replace("_", " ")
    policy = f" by policy '{e.policy_name}'" if e.policy_name else ""
    return f"a blocked {label} flow{policy}"


def _ep(ep) -> str:
    s = f"{ep.ip or '?'}:{ep.port if ep.port is not None else '?'}"
    if ep.host:
        s += f" ({ep.host})"
    if ep.country:
        s += f" [{ep.country}]"
    where = ", ".join(x for x in (f"zone {ep.zone}" if ep.zone else "",
                                  f"network {ep.network}" if ep.network else "") if x)
    if where:
        s += f" {{{where}}}"
    return s


def describe(e: UdmEvent, extra: list[str] | None = None) -> str:
    lines = [f"{_SOURCES[e.stream]}: {_what(e)}.", ""]
    if e.message:
        lines[1:1] = [e.message, ""]

    def row(label: str, value) -> None:
        if value not in (None, "", []):
            lines.append(f"{label}: {value}")

    row("Action", e.action)
    row("Severity", e.severity)
    row("Policy", e.policy_name)
    row("Policy type", e.policy_type)
    row("Category", e.category)
    if e.ips_list:
        rep_list = _REPUTATION_LISTS.get(e.ips_list.lower())
        row("IPS rule set", f"{e.ips_list} (address is on the {rep_list})" if rep_list
            else e.ips_list)
    row("Service", e.service)
    row("Admin", e.admin)
    row("Platform", e.platform)
    row("Signature", e.signature)
    row("Signature ID", e.signature_id)
    row("Signature class", e.signature_class)
    row("Affected product", e.affected_product)
    row("CVE", ", ".join(e.cves))
    row("Risk", e.risk_text)
    row("Protocol", e.protocol)
    row("Direction", e.direction)
    row("Source", _ep(e.src))
    if e.dst.ip or e.dst.port is not None:
        row("Destination", _ep(e.dst))
    for line in extra or []:
        lines.append(line)
    row("Count", e.count if e.count > 1 else None)
    if e.bytes_total is not None:
        row("Traffic", f"{e.bytes_total:,} bytes / {e.packets_total or 0:,} packets")
    row("First seen", e.first.isoformat())
    row("Last seen", e.last.isoformat() if e.last != e.first else None)
    row("UniFi record", f"{e.label} {e.native_id}")
    return "\n".join(lines)
