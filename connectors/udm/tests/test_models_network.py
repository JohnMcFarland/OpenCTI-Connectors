"""Record parsing, cursor bookkeeping, and internal/external classification."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from src.models import (Endpoint, StreamCursor, from_epoch, parse_flow, parse_security,
                        security_blocked)
from src.network import NetworkContext

T0 = 1_760_000_000_000  # ms


def flow(fid="f1", start=T0, last=None, **over):
    raw = {
        "id": fid, "flow_start_time": start, "time": last or start, "count": 3,
        "protocol": "tcp", "direction": "incoming", "risk": "High",
        "source": {"ip": "203.0.113.9", "port": 51515, "region": "de"},
        "destination": {"ip": "198.51.100.1", "port": 22},
        "policies": [{"name": "Block SSH", "type": "FIREWALL", "internal_type": "firewall"}],
        "ips": {}, "traffic_data": {"bytes_total": 120, "packets_total": 2},
    }
    raw.update(over)
    return raw


def test_parse_flow_fields():
    e = parse_flow(flow(last=T0 + 5000))
    assert e.key == "flows:f1" and e.label == "FIREWALL" and e.severity == "high"
    assert e.src == Endpoint("203.0.113.9", 51515, "", "", "DE")
    assert e.dst.port == 22 and e.count == 3 and e.protocol == "TCP"
    assert e.last_ms == T0 + 5000 and e.first < e.last


def test_parse_flow_rejects_missing_id_or_time_and_reads_seconds():
    assert parse_flow(flow(fid="")) is None
    assert parse_flow(flow(start=None, time=None)) is None
    assert from_epoch(1_760_000_000) == from_epoch(1_760_000_000_000)


def test_parse_flow_signature_cves():
    e = parse_flow(flow(policies=[{"internal_type": "SIGNATURE", "ips_category": "Scan"}],
                        ips={"signature": "ET SCAN", "relevant_cve": "cve-2021-44228; CVE-2021-45046"}))
    assert e.label == "SIGNATURE" and e.cves == ["CVE-2021-44228", "CVE-2021-45046"]


def test_parse_security_threat_and_honeypot():
    T = T0
    blocked = {"id": "e5b1c0de-0000-4000-8000-000000000001", "timestamp": T, "category": "SECURITY",
          "subcategory": "SECURITY_INTRUSION_PREVENTION", "key": "THREAT_BLOCKED_V3",
          "event": "THREAT_BLOCKED", "severity": "HIGH",
          "message_raw": "A network intrusion attempt from {SRC_IP} to {DST_IP} has been detected and blocked.",
          "parameters": {"SRC_IP": {"id": "45.33.32.51", "name": "45.33.32.51"},
                         "DST_IP": {"id": "192.168.1.5", "name": "192.168.1.5"}}}
    e = parse_security(blocked)
    assert security_blocked(blocked) and e.action == "blocked" and e.severity == "high"
    assert e.stream == "security" and e.label == "THREAT_BLOCKED"
    assert e.src.ip == "45.33.32.51" and e.dst.ip == "192.168.1.5"
    assert e.message == ("A network intrusion attempt from 45.33.32.51 to 192.168.1.5 "
                         "has been detected and blocked.")
    honey = {"id": "e5b1c0de-0000-4000-8000-000000000002", "timestamp": T, "category": "SECURITY",
          "subcategory": "SECURITY_HONEYPOT", "key": "HONEYPOT_HIT_DETECTED_KNOWN_CLIENT",
          "event": "HONEYPOT_HIT_DETECTED", "severity": "MEDIUM",
          "message_raw": "Honeypot triggered by {CLIENT}.",
          "parameters": {"CLIENT": {"id": "aa:bb:cc:00:00:01", "name": "nas", "hostname": "nas"},
                         "MAC": {"id": "aa:bb:cc:00:00:01", "name": "aa:bb:cc:00:00:01"}}}
    h = parse_security(honey)
    assert not security_blocked(honey) and h.action == "alert"
    assert h.label == "HONEYPOT_HIT_DETECTED"
    assert h.src == Endpoint(mac="aa:bb:cc:00:00:01", host="nas")
    assert h.message == "Honeypot triggered by nas."
    assert parse_security({**honey, "id": ""}) is None


def test_flow_host_falls_back_to_unifi_device_name():
    e = parse_flow(flow(destination={"ip": "192.168.1.2", "port": 443,
                                      "device_name": "Core Switch"}))
    assert e.dst.host == "Core Switch"


def test_cursor_skips_unchanged_reimports_extended_and_prunes():
    c = StreamCursor()
    assert c.since_ms(T0, 60_000, 86_400_000) == T0 - 86_400_000
    e1 = parse_flow(flow("a", last=T0))
    assert c.is_new(e1)
    c.mark(e1)
    assert not c.is_new(parse_flow(flow("a", last=T0)))
    assert c.is_new(parse_flow(flow("a", last=T0 + 1)))  # extended record
    assert c.since_ms(T0 + 10**9, 60_000, 0) == T0 - 60_000
    c.mark(parse_flow(flow("b", start=T0 + 120_000)))
    c.prune(60_000, 10)
    assert list(c.seen) == ["flows:b"]  # "a" is older than cursor - overlap
    assert StreamCursor.load(c.dump()) == c


def test_cursor_never_moves_backwards():
    c = StreamCursor()
    c.mark(parse_flow(flow("late", start=T0 + 50)))
    c.mark(parse_flow(flow("old", start=T0)))
    assert c.cursor_ms == T0 + 50


def _net(**kw):
    args = dict(wan_ips=["198.51.100.1"], internal_networks=[], clients=[], pinned=None,
                gateway_name="UDM-WAN")
    args.update(kw)
    return NetworkContext(**args)


def test_classify():
    net = _net(internal_networks=[ipaddress.ip_network("192.0.2.0/24")])
    assert net.classify("198.51.100.1") == "wan"
    assert net.classify("8.8.8.8") == "external"
    assert net.classify("2001:4860:4860::8888") == "external"
    for ip in ("192.168.1.5", "10.1.1.1", "100.64.0.1", "fe80::1", "192.0.2.7"):
        assert net.classify(ip) == "internal", ip
    for ip in ("", "nope", "224.0.0.251", "ff02::1", "0.0.0.0", "255.255.255.255"):
        assert net.classify(ip) == "", ip  # not a host


def test_system_names_pinned_per_mac():
    clients = [{"mac": "AA:BB:CC:00:00:01", "hostname": "nas", "ip": "192.168.1.5",
                "oui": "Synology"}]
    net = _net(clients=clients)
    by_ip = net.system_name(Endpoint(ip="192.168.1.5"))
    assert by_ip == "nas"
    pins = net.dump_pins()
    # Next run: the host was renamed and is offline; the pinned name holds.
    net2 = _net(clients=[{"mac": "aa:bb:cc:00:00:01", "hostname": "nas-renamed"}], pinned=pins)
    assert net2.system_name(Endpoint(ip="192.168.1.99", mac="aa:bb:cc:00:00:01")) == "nas"
    assert "Synology" in net.system_description("nas", Endpoint(ip="192.168.1.5"))
    # Unknown host without MAC falls back to the record's name, then the IP.
    assert net.system_name(Endpoint(ip="192.168.1.77", host="printer")) == "printer"
    assert net.system_name(Endpoint(ip="192.168.1.78")) == "Host 192.168.1.78"


def test_alias_preferred_over_hostname():
    net = _net(clients=[{"mac": "aa:00:00:00:00:02", "name": "Office TV", "hostname": "lgwebos"}])
    assert net.system_name(Endpoint(mac="aa:00:00:00:00:02")) == "Office TV"


def test_parse_flow_tolerates_nulls():
    e = parse_flow({"id": 7, "time": T0, "source": None, "destination": None,
                    "policies": None, "ips": None})
    assert e and e.src.ip == "" and e.label == "BLOCK"
    assert e.first == datetime.fromtimestamp(T0 / 1000, tz=timezone.utc)


def test_same_hostname_on_two_macs_stays_two_systems():
    net = _net(clients=[{"mac": "aa:00:00:00:00:01", "hostname": "iPhone"},
                        {"mac": "aa:00:00:00:00:02", "hostname": "iPhone"}])
    a = net.system_name(Endpoint(mac="aa:00:00:00:00:01"))
    b = net.system_name(Endpoint(mac="aa:00:00:00:00:02"))
    assert a == "iPhone" and b == "iPhone (aa:00:00:00:00:02)"


def test_out_of_range_timestamp_is_rejected_not_raised():
    assert from_epoch(1.76e15 * 1000) is None
    assert parse_flow(flow(start=1.76e18, time=1.76e18)) is None


def test_macless_hostname_does_not_merge_into_a_known_client():
    net = _net(clients=[{"mac": "aa:00:00:00:00:01", "hostname": "nas", "ip": "192.168.1.5"}])
    assert net.system_name(Endpoint(ip="192.168.1.5")) == "nas"
    assert net.system_name(Endpoint(ip="192.168.1.80", host="nas")) == "nas (192.168.1.80)"
