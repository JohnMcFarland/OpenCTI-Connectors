"""The 2026-11-18 additions, shaped on what a live UDM Pro returned (read-only probe):
network/zone, IPS rule-set and service text; admin logins from external addresses;
port-forward matching; device firmware inventory."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src.models import Endpoint, parse_admin, parse_flow
from src.network import Forward, NetworkContext, _ports

pytest.importorskip("pycti")

from src import connector as mod  # noqa: E402
from src.opencti_lookup import OpenCTILookup  # noqa: E402
from src.stix_builder import UdmStixBuilder, container_day  # noqa: E402
from src.udm_client import UdmClient  # noqa: E402

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
WAN = "198.51.100.1"
T0 = 1_760_000_000_000
NAS_MAC = "aa:bb:cc:00:00:01"
UDM_MAC = "f4:e2:c6:00:00:01"
SW_MAC = "f4:e2:c6:00:00:02"
DEVICES = [
    {"type": "udm", "model": "UDMPRO", "name": "Dream Machine", "mac": UDM_MAC,
     "version": "4.1.13.12345", "wan1": {"ip": WAN}, "ip": "192.168.0.1"},
    {"type": "usw", "model": "USL24PB", "name": "Core Switch", "mac": SW_MAC,
     "version": "7.1.26.15869", "uplink": {"ip": "192.168.0.20"}, "ip": "192.168.0.20"},
]
FORWARDS = [{"_id": "x", "name": "Plex", "enabled": True, "proto": "tcp_udp",
             "dst_port": "32400", "fwd": "192.168.1.5", "fwd_port": "32400"},
            {"name": "Off", "enabled": False, "proto": "tcp", "dst_port": "22",
             "fwd": "192.168.1.6"}]


def live_flow(fid="f1", **over):
    """Shaped like the live records: no flow_start_time, zone/network/service set."""
    raw = {"id": fid, "time": T0, "count": 1, "protocol": "TCP", "direction": "incoming",
           "risk": "medium", "service": "SSH", "action": "blocked",
           "source": {"ip": "45.33.32.9", "port": 50000, "region": "DE",
                      "zone_name": "External"},
           "destination": {"ip": WAN, "port": 22, "zone_name": "Gateway"},
           "policies": [{"name": "Block", "internal_type": "SIGNATURE", "type": "IPS"}],
           "ips": {"signature": "ET CINS Active Threat Intelligence Poor Reputation IP",
                   "category_name": "ciarmy", "relevant_cve": "", "description": "",
                   "signature_class": "", "enhanced_detection": False}}
    raw.update(over)
    return parse_flow(raw)


def admin_entry(ip, eid="a1", ts=T0):
    return {"id": eid, "timestamp": ts, "category": "AUDIT", "key": "ADMIN_ACCESS",
            "message_raw": "{ADMIN} accessed UniFi Network using the {PLATFORM}. "
                           "Source IP: {IP}",
            "parameters": {"ADMIN": {"id": "u1", "name": "alice"},
                           "IP": {"id": ip, "name": ip},
                           "PLATFORM": {"id": "web", "name": "web"}}}


def net(**kw):
    args = dict(wan_ips=[WAN], internal_networks=[], pinned=None, gateway_name="UDM-WAN",
                clients=[{"mac": NAS_MAC, "hostname": "nas", "ip": "192.168.1.5"}],
                devices=DEVICES, forwards=FORWARDS)
    args.update(kw)
    return NetworkContext(**args)


@pytest.fixture
def builder(settings):
    helper = MagicMock()
    helper.api.marking_definition.read.return_value = {"standard_id": MARKING}
    helper.api.location.read.return_value = None
    helper.api.vulnerability.read.return_value = None
    b = UdmStixBuilder(helper, settings, OpenCTILookup(helper))
    b.prepare()
    return b


def by_type(objs):
    out: dict[str, list] = {}
    for o in objs:
        out.setdefault(o["type"], []).append(o)
    return out


# -- parsing ------------------------------------------------------------------------


def test_flow_text_fields():
    e = live_flow()
    assert e.ips_list == "ciarmy" and e.service == "SSH" and e.cves == []
    assert e.src.zone == "External" and e.dst.zone == "Gateway"
    assert live_flow(service="OTHER").service == ""  # UniFi's catch-all is noise


def test_parse_admin():
    e = parse_admin(admin_entry("45.33.32.200"))
    assert e.stream == "admin" and e.src.ip == "45.33.32.200" and e.admin == "alice"
    assert e.message == "alice accessed UniFi Network using the web. Source IP: 45.33.32.200"
    assert parse_admin({**admin_entry("1.1.1.1"), "key": "MADE_CHANGES_ONE_SETTING_OBJECT"}) is None


# -- network context ---------------------------------------------------------------


def test_port_specs_and_forward_parsing():
    assert _ports("443") == {443} and _ports("80, 443") == {80, 443}
    assert _ports("8000-8002") == {8000, 8001, 8002} and _ports("x") == set()
    f = Forward.parse(FORWARDS[0])
    assert f.protocols == {"TCP", "UDP"} and f.ports == {32400} and f.target_ip == "192.168.1.5"
    assert Forward.parse(FORWARDS[1]) is None  # disabled


def test_forward_matching_on_wan_and_after_translation():
    n = net()
    assert n.forward_for(Endpoint(ip=WAN, port=32400), "TCP", "wan").name == "Plex"
    assert n.forward_for(Endpoint(ip="192.168.1.5", port=32400), "UDP", "internal").name == "Plex"
    assert n.forward_for(Endpoint(ip=WAN, port=22), "TCP", "wan") is None  # rule disabled
    assert n.forward_for(Endpoint(ip=WAN, port=32400), "ICMP", "wan") is None


def test_unifi_devices_are_named_systems_and_gateway_mac_is_the_gateway():
    n = net()
    assert n.system_name(Endpoint(mac=UDM_MAC)) == "UDM-WAN"
    assert n.system_name(Endpoint(ip="192.168.0.20")) == "Core Switch"
    assert "USL24PB" in n.system_description("Core Switch", Endpoint(mac=SW_MAC))


# -- graph ------------------------------------------------------------------------


def test_sighting_text_carries_zone_rule_set_and_service(builder):
    e = live_flow()
    t = by_type(builder.build("flows", container_day(e), [e], net()))
    (sig,) = t["sighting"]
    d = sig["description"]
    assert "IPS rule set: ciarmy (address is on the CINS Army bad-reputation list)" in d
    assert "Service: SSH" in d and "{zone External}" in d


def test_hit_on_a_forwarded_port_marks_the_exposure(builder):
    e = live_flow(destination={"ip": WAN, "port": 32400}, service="")
    objs = builder.build("flows", container_day(e), [e], net())
    t = by_type(objs)
    (sig,) = t["sighting"]
    assert "Port forward: 'Plex' to nas" in sig["description"]
    nas = next(o for o in t["identity"] if o.get("name") == "nas")
    nt = t["network-traffic"][0]
    exposure = [o for o in t["relationship"]
                if o["source_ref"] == nt["id"] and o["target_ref"] == nas["id"]]
    assert exposure and "port forward 'Plex'" in exposure[0]["description"]
    assert sig["where_sighted_refs"] != [nas["id"]]  # still sighted where it was blocked


def test_admin_login_from_outside_is_sighted_on_the_gateway(builder):
    e = parse_admin(admin_entry("45.33.32.200"))
    t = by_type(builder.build("admin", container_day(e), [e], net()))
    assert t["case-incident"][0]["name"].startswith("UDM Admin Access")
    (sig,) = t["sighting"]
    gw = next(o for o in t["identity"] if o.get("name") == "UDM-WAN")
    assert sig["where_sighted_refs"] == [gw["id"]]
    assert "login to UniFi Network by admin 'alice' via web" in sig["description"]
    assert "network-traffic" not in t and "Destination:" not in sig["description"]
    inside = parse_admin(admin_entry("192.168.1.50", "a2"))
    assert builder.build("admin", container_day(inside), [inside], net()) == []


def test_inventory_bundle(builder):
    objs = builder.build_inventory("2026-11-18", DEVICES, net())
    t = by_type(objs)
    assert t["case-incident"][0]["name"] == "UDM Inventory — 2026-11-18"
    sw = {o["name"]: o for o in t["software"]}
    assert sw["UniFi UDMPRO firmware"]["version"] == "4.1.13.12345"
    assert sw["UniFi USL24PB firmware"]["vendor"] == "Ubiquiti"
    names = {o["id"]: o["name"] for o in t["identity"]}
    links = {(names.get(r["target_ref"]), r["source_ref"]) for r in t["relationship"]
             if r["source_ref"].startswith("software--")}
    assert {n for n, _ in links} == {"UDM-WAN", "Core Switch"}
    assert set(t["case-incident"][0]["object_refs"]) >= {o["id"] for o in t["software"]}


# -- connector runs ------------------------------------------------------------------


class Resp:
    def __init__(self, body, status=200):
        self.body, self.status_code, self.text = body, status, str(body)

    def json(self):
        return self.body


class FakeUdm:
    def __init__(self):
        self.headers: dict = {}
        self.devices = json.loads(json.dumps(DEVICES))
        self.audit = [admin_entry("45.33.32.200", "a1", T0 - 5000),
                      admin_entry("192.168.1.50", "a2", T0 - 4000)]

    def request(self, method, url, json=None, verify=None, timeout=None):
        if url.endswith("system-log/all"):
            cat = json["categories"][0]
            rows = [a for a in self.audit if a["category"] == cat
                    and json["timestampFrom"] <= a["timestamp"] <= json["timestampTo"]]
            return Resp({"data": rows if json["pageNumber"] == 0 else [],
                         "total_page_count": 1})
        if url.endswith("/traffic-flows"):
            return Resp({"data": [], "has_next": False})
        if url.endswith("stat/device"):
            return Resp({"meta": {"rc": "ok"}, "data": self.devices})
        if url.endswith("rest/portforward"):
            return Resp({"meta": {"rc": "ok"}, "data": FORWARDS})
        return Resp({"meta": {"rc": "ok"}, "data": []})


class FakeHelper:
    def __init__(self):
        self.state = None
        self.connector_logger = MagicMock()
        self.api = MagicMock()
        self.api.marking_definition.read.return_value = {"standard_id": MARKING}
        self.api.location.read.return_value = None
        self.connect_id = "c"
        self.sent: list[dict] = []

    def get_state(self):
        return self.state

    def set_state(self, s):
        self.state = json.loads(json.dumps(s))

    def send_stix2_bundle(self, bundle, **kw):
        self.sent.append(json.loads(bundle))


@pytest.fixture
def rig(settings, monkeypatch):
    helper, udm = FakeHelper(), FakeUdm()
    c = mod.UdmConnector.__new__(mod.UdmConnector)
    c.helper, c.settings, c.log = helper, settings, helper.connector_logger
    c._truncated, c._devices = None, []
    c.client = UdmClient(settings, helper.connector_logger, session=udm)
    c.lookup = OpenCTILookup(helper)
    c.builder = UdmStixBuilder(helper, settings, c.lookup)
    c.builder.prepare()
    monkeypatch.setattr(mod.time, "time", lambda: T0 / 1000)
    return c, helper, udm


def containers(helper):
    return [o["name"].split(" — ")[0] for b in helper.sent for o in b["objects"]
            if o["type"] == "case-incident"]


def test_run_sends_admin_and_inventory_once_then_only_changes(rig):
    c, helper, udm = rig
    c.process()
    assert sorted(containers(helper)) == ["UDM Admin Access", "UDM Inventory"]
    admin_sightings = [o for b in helper.sent for o in b["objects"] if o["type"] == "sighting"]
    assert len(admin_sightings) == 1  # the internal login was dropped
    assert helper.state["firmware"] == {UDM_MAC: "4.1.13.12345", SW_MAC: "7.1.26.15869"}
    assert helper.state["systems"][UDM_MAC] == "UDM-WAN"

    helper.sent.clear()
    c.process()
    assert helper.sent == []  # nothing new, firmware unchanged

    udm.devices[1]["version"] = "7.2.0.16000"
    c.process()
    (bundle,) = helper.sent
    sw = [o for o in bundle["objects"] if o["type"] == "software"]
    assert [s["version"] for s in sw] == ["7.2.0.16000"]  # only the changed device


def test_toggles_turn_the_additions_off(rig, monkeypatch):
    c, helper, udm = rig
    for k in ("udm_admin_enabled", "udm_inventory_enabled", "udm_port_forwards_enabled"):
        monkeypatch.setattr(c.settings, k, False)
    c.process()
    assert helper.sent == []
