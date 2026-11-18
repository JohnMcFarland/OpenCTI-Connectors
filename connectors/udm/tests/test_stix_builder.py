"""Graph shape: Sightings only (no Incident objects), allow-listed edges, no internal/WAN
observables, deterministic ids that survive a record being extended, and conformance
through pycti's own splitter."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

pytest.importorskip("pycti")

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter  # noqa: E402

from src.models import parse_flow, parse_security  # noqa: E402
from src.network import NetworkContext  # noqa: E402
from src.opencti_lookup import OpenCTILookup  # noqa: E402
from src.stix_builder import ALLOWED_EDGES, UdmStixBuilder, container_day  # noqa: E402

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
GERMANY = "location--b8d0549f-de06-5ebd-a6e9-d31a581dba5d"
LOG4J = "vulnerability--c7cab88d-d7e1-5b33-8e9c-2c5a0e4a8a0b"
WAN = "198.51.100.1"
T0 = 1_760_000_000_000


def flow(fid="f1", last=T0, count=1, **over):
    raw = {"id": fid, "flow_start_time": T0, "time": last, "count": count,
           "protocol": "tcp", "risk": "medium",
           "source": {"ip": "45.33.32.9", "port": 50000, "region": "DE"},
           "destination": {"ip": WAN, "port": 22},
           "policies": [{"name": "Block SSH", "internal_type": "FIREWALL"}]}
    raw.update(over)
    return parse_flow(raw)


@pytest.fixture
def builder(settings):
    helper = MagicMock()
    helper.api.marking_definition.read.return_value = {"standard_id": MARKING}
    helper.api.location.read.side_effect = lambda filters: (
        {"standard_id": GERMANY} if filters["filters"][1]["values"] in (["DE"], ["US"]) else None)
    helper.api.vulnerability.read.side_effect = lambda filters: (
        {"standard_id": LOG4J} if filters["filters"][0]["values"] == ["CVE-2021-44228"] else None)
    b = UdmStixBuilder(helper, settings, OpenCTILookup(helper))
    b.prepare()
    return b, helper


def net(**kw):
    args = dict(wan_ips=[WAN], internal_networks=[], pinned=None, gateway_name="UDM-WAN",
                clients=[{"mac": "aa:bb:cc:00:00:01", "hostname": "nas", "ip": "192.168.1.5"}])
    args.update(kw)
    return NetworkContext(**args)


def build(b, events, n=None):
    e = events[0]
    return b.build(e.stream, container_day(e), events, n or net())


def by_type(objs):
    out: dict[str, list] = {}
    for o in objs:
        out.setdefault(o["type"], []).append(o)
    return out


def test_inbound_flow_to_wan(builder):
    b, _ = builder
    objs = build(b, [flow()])
    t = by_type(objs)
    assert [o["value"] for o in t["ipv4-addr"]] == ["45.33.32.9"]  # never the WAN IP
    assert t["network-traffic"][0] == {**t["network-traffic"][0], "dst_port": 22}
    assert set(t["network-traffic"][0]) == {"type", "id", "dst_port", "spec_version",
                                           "object_marking_refs", "created_by_ref"}
    assert "incident" not in t
    (sig,) = t["sighting"]
    assert "FIREWALL f1" in sig["description"] and "Severity: medium" in sig["description"]
    assert sig["description"].startswith("External source of a blocked firewall flow")
    systems = {o["name"]: o["id"] for o in t["identity"] if o["identity_class"] == "system"}
    assert sig["where_sighted_refs"] == [systems["UDM-WAN"]]
    rels = {(o["relationship_type"], o["source_ref"], o["target_ref"]) for o in t["relationship"]}
    ip_id = t["ipv4-addr"][0]["id"]
    assert ("located-at", ip_id, GERMANY) in rels
    nt_id = t["network-traffic"][0]["id"]
    assert ("related-to", ip_id, nt_id) in rels  # IP -> port
    ip_port = next(o for o in t["relationship"]
                   if o["source_ref"] == ip_id and o["target_ref"] == nt_id)
    port_sys = next(o for o in t["relationship"]
                    if o["source_ref"] == nt_id and o["target_ref"] == systems["UDM-WAN"])
    assert "Protocol: TCP." in ip_port["description"]  # protocol only as text, here
    assert "TCP" not in port_sys["description"]
    assert ("related-to", nt_id, systems["UDM-WAN"]) in rels  # port -> System
    assert ("related-to", ip_id, systems["UDM-WAN"]) in rels  # identity floor
    assert not [o for o in t["relationship"] if "start_time" in o]  # structural, undated
    (case,) = t["case-incident"]
    assert case["name"] == "UDM Blocked Flows — 2025-10-09"
    members = set(case["object_refs"])
    assert {o["id"] for o in objs if o["type"] != "case-incident"} - members == {b.author_id}
    assert GERMANY in members
    for o in objs:
        assert "x_opencti_description" not in o and "labels" not in o
        assert o["object_marking_refs"] == [MARKING]
    assert "indicator" not in t


def test_outbound_flow_sights_external_on_internal_host(builder):
    b, _ = builder
    e = flow(source={"ip": "192.168.1.5", "port": 40000, "mac": "aa:bb:cc:00:00:01"},
             destination={"ip": "2001:db8::1", "port": 443})  # documentation range: not global
    objs = build(b, [e])
    t = by_type(objs)
    assert "ipv4-addr" not in t and "ipv6-addr" not in t and "sighting" not in t
    e2 = flow(source={"ip": "192.168.1.5", "mac": "aa:bb:cc:00:00:01"},
              destination={"ip": "2606:4700::1111", "port": 443, "region": "US"})
    t = by_type(build(b, [e2]))
    (sig,) = t["sighting"]
    nas = [o for o in t["identity"] if o.get("name") == "nas"][0]
    assert sig["where_sighted_refs"] == [nas["id"]] and t["ipv6-addr"][0]["value"] == "2606:4700::1111"
    assert all(o["relationship_type"] == "related-to" for o in t["relationship"])  # v6 -> country too
    assert "aa:bb:cc:00:00:01" in nas["description"]


def test_events_without_an_external_ip_are_not_imported(builder):
    b, _ = builder
    internal = flow(source={"ip": "192.168.1.5"}, destination={"ip": "192.168.1.6", "port": 445})
    assert build(b, [internal]) == []  # no container shipped for nothing
    objs = build(b, [internal, flow("f9")])
    assert len([o for o in objs if o["type"] == "sighting"]) == 1
    assert "Host 192.168.1.6" not in {o.get("name") for o in objs}


def test_ids_stable_when_record_is_extended(builder):
    b, _ = builder
    # As live: no flow_start_time, so the start moves with `time` when extended.
    a = {o["id"]: o for o in build(b, [flow(last=T0, count=1, flow_start_time=None)])}
    c = {o["id"]: o for o in build(b, [flow(last=T0 + 60_000, count=9, flow_start_time=None)])}
    assert set(a) == set(c)
    sig = next(o for o in c.values() if o["type"] == "sighting")
    assert sig["count"] == 9 and sig["last_seen"].startswith("2025-10-09T08:54")


def test_signature_cve_links_the_ip_to_an_existing_vulnerability(builder):
    b, helper = builder
    e = flow(policies=[{"internal_type": "SIGNATURE", "ips_category": "Exploit"}],
             ips={"signature": "ET EXPLOIT Log4j", "relevant_cve": "CVE-2021-44228, CVE-1999-0001"})
    objs = build(b, [e])
    t = by_type(objs)
    ip_id = t["ipv4-addr"][0]["id"]
    (rel,) = [o for o in t["relationship"] if o["target_ref"] == LOG4J]
    assert rel["source_ref"] == ip_id and rel["relationship_type"] == "related-to"
    assert "ET EXPLOIT Log4j" in rel["description"] and "source" in rel["description"]
    assert LOG4J in t["case-incident"][0]["object_refs"]  # existing entity, referenced
    assert "vulnerability" not in t and "incident" not in t  # never created
    (sig,) = t["sighting"]
    assert "CVE: CVE-2021-44228, CVE-1999-0001" in sig["description"]  # both kept as text
    build(b, [e])
    assert helper.api.vulnerability.read.call_count == 2  # one lookup per CVE, cached


def test_honeypot_hit_is_not_imported(builder):
    b, _ = builder
    e = parse_security({"id": "e5b1c0de-0000-4000-8000-000000000002", "timestamp": T0,
                        "category": "SECURITY", "event": "HONEYPOT_HIT_DETECTED",
                        "key": "HONEYPOT_HIT_DETECTED_KNOWN_CLIENT",
                        "message_raw": "Honeypot triggered by {CLIENT}.",
                        "parameters": {"CLIENT": {"id": "aa:bb:cc:00:00:01", "name": "nas"}}})
    assert build(b, [e]) == []  # no external address (user decision: drop)


def test_security_threat_with_external_ip_is_sighted(builder):
    b, _ = builder
    e = parse_security({"id": "t1", "timestamp": T0, "category": "SECURITY",
                        "event": "THREAT_DETECTED", "key": "THREAT_DETECTED_V3",
                        "severity": "HIGH",
                        "message_raw": "Intrusion attempt from {SRC_IP} to {DST_IP}.",
                        "parameters": {"SRC_IP": {"id": "45.33.32.77"},
                                       "DST_IP": {"id": "192.168.1.5"}}})
    t = by_type(build(b, [e]))
    assert t["case-incident"][0]["name"].startswith("UDM Security Events")
    (sig,) = t["sighting"]
    assert "Intrusion attempt from 45.33.32.77 to 192.168.1.5." in sig["description"]
    assert "network-traffic" not in t  # the log carries no port


def test_every_edge_is_related_to_or_allow_listed(builder):
    b, _ = builder
    for o in build(b, [flow(), flow("f2", source={"ip": "8.8.8.8", "region": "US"})]):
        if o["type"] == "relationship" and o["relationship_type"] != "related-to":
            assert o["relationship_type"] == "located-at"
    assert all(edge[1] == "located-at" for edge in ALLOWED_EDGES)
    with pytest.raises(ValueError):
        b._rel("a", "ipv4-addr", "targets", "b", "system", "x")


def test_bundle_splits_cleanly_with_pycti(builder):
    b, _ = builder
    objs = build(b, [flow(), flow("f2", source={"ip": "8.8.4.4"}), flow("f3")])
    bundle = {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000",
              "objects": objs}
    _, incompatible, pieces = OpenCTIStix2Splitter().split_bundle_with_expectations(
        json.dumps(bundle))
    split_ids = {o["id"] for piece in pieces for o in json.loads(piece)["objects"]}
    assert incompatible == [] and split_ids >= {o["id"] for o in objs}


def test_two_events_in_the_same_second_are_two_sightings(builder):
    b, _ = builder
    objs = build(b, [flow("s1"), flow("s2")])
    assert len([o for o in objs if o["type"] == "sighting"]) == 2
