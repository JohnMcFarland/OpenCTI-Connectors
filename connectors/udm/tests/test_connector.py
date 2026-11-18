"""Run/state semantics against a simulated UDM over many runs with a moving clock:
new, extended and late records; failures mid-run; WAN fail-closed; stream isolation.

The real UdmClient pages through a fake HTTP session, so the early stop is exercised
against the same data the cursor relies on."""

from __future__ import annotations

import json
import random
from datetime import timedelta
from collections import Counter
from unittest.mock import MagicMock

import pytest

pytest.importorskip("pycti")

from src import connector as mod  # noqa: E402
from src.opencti_lookup import OpenCTILookup  # noqa: E402
from src.stix_builder import UdmStixBuilder  # noqa: E402
from src.udm_client import UdmClient  # noqa: E402

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
HOUR = 3_600_000
START = 1_760_000_000_000
WAN = "198.51.100.1"


class Resp:
    def __init__(self, body, status=200):
        self.body, self.status_code, self.text = body, status, str(body)

    def json(self):
        return self.body


class FakeUdm:
    """Holds flow records and security-log entries and answers the UniFi endpoints."""

    def __init__(self):
        self.flows: dict[str, dict] = {}
        self.alerts: list[dict] = []
        self.wan = [WAN]
        self.fail_security = False
        self.headers: dict = {}
        self.flow_requests = 0

    def request(self, method, url, json=None, verify=None, timeout=None):
        if url.endswith("/traffic-flows"):
            self.flow_requests += 1
            ordered = sorted(self.flows.values(), key=lambda r: -r["time"])
            size, n = json["pageSize"], json["pageNumber"]
            page = ordered[n * size:(n + 1) * size]
            return Resp({"data": [dict(r) for r in page],
                         "has_next": (n + 1) * size < len(ordered)})
        if url.endswith("system-log/all"):
            if self.fail_security:
                return Resp("<html>404</html>", 404)
            rows = [a for a in self.alerts
                    if json["timestampFrom"] <= a["timestamp"] <= json["timestampTo"]]
            size, n = json["pageSize"], json["pageNumber"]
            return Resp({"data": rows[n * size:(n + 1) * size],
                         "total_page_count": -(-len(rows) // size)})
        if url.endswith("stat/device"):
            return Resp({"meta": {"rc": "ok"}, "data": [{"type": "udm", "wan1": {"ip": ip}} for ip in self.wan]})
        if url.endswith("rest/user"):
            return Resp({"meta": {"rc": "ok"}, "data": [
                {"mac": "aa:bb:cc:00:00:01", "hostname": "nas", "ip": "192.168.1.5"}]})
        return Resp({"meta": {"rc": "ok"}, "data": []})

    def add_flow(self, fid, t, src="45.33.32.1", count=1):
        # Like the live UDM: no flow_start_time, only `time` (which moves when extended).
        self.flows[fid] = {"id": fid, "time": t, "count": count,
                           "protocol": "tcp",
                           "source": {"ip": src, "port": 40000, "region": "US"},
                           "destination": {"ip": WAN, "port": 22},
                           "policies": [{"name": "Block", "internal_type": "FIREWALL"}]}


class FakeHelper:
    def __init__(self):
        self.state = None
        self.connector_logger = MagicMock()
        self.api = MagicMock()
        self.api.marking_definition.read.return_value = {"standard_id": MARKING}
        self.api.location.read.return_value = None
        self.connect_id = "c"
        self.sent: list[dict] = []
        self.fail_after: int | None = None  # raise on the Nth send from now

    def get_state(self):
        return self.state

    def set_state(self, s):
        self.state = json.loads(json.dumps(s))  # platform state is JSON

    def send_stix2_bundle(self, bundle, **kw):
        if self.fail_after is not None:
            if self.fail_after == 0:
                self.fail_after = None
                raise RuntimeError("worker queue unavailable")
            self.fail_after -= 1
        self.sent.append(json.loads(bundle))


@pytest.fixture
def rig(settings, monkeypatch):
    monkeypatch.setattr(settings, "udm_page_size", 20)
    monkeypatch.setattr(settings, "udm_events_per_bundle", 7)
    monkeypatch.setattr(settings, "udm_initial_lookback_days", 1)
    helper, udm = FakeHelper(), FakeUdm()
    c = mod.UdmConnector.__new__(mod.UdmConnector)
    c.helper, c.settings, c.log = helper, settings, helper.connector_logger
    c.client = UdmClient(settings, helper.connector_logger, session=udm)
    c.lookup = OpenCTILookup(helper)
    c.builder = UdmStixBuilder(helper, settings, c.lookup)
    c.builder.prepare()
    clock = {"now": START}
    monkeypatch.setattr(mod.time, "time", lambda: clock["now"] / 1000)
    return c, helper, udm, clock


def incidents(helper):
    """(UniFi record id, last_seen) of every Sighting sent, in order. One Sighting per
    event here (one external IP, one System), named as the old Incidents were."""
    out = []
    for b in helper.sent:
        for o in b["objects"]:
            if o["type"] == "sighting":
                rec = next(line for line in o["description"].splitlines()
                           if line.startswith("UniFi record: ")).split()[-1]
                prefix = "SEC" if "system log" in o["description"] else "FLOW"
                out.append((f"UDM-{prefix}-{rec}", o["last_seen"]))
    return out


def test_many_runs_import_every_version_once(rig):
    c, helper, udm, clock = rig
    rng = random.Random(7)
    # A pre-existing backlog: inside and outside the 1-day initial lookback.
    for i in range(30):
        udm.add_flow(f"old{i}", START - 2 * 86_400_000 + i * HOUR // 2)
    for i in range(40):
        udm.add_flow(f"bk{i}", START - 20 * HOUR + i * 1000)
    failures = 0
    seq = 0
    for run in range(48):
        clock["now"] += HOUR
        now = clock["now"]
        for _ in range(rng.randint(0, 25)):
            seq += 1
            udm.add_flow(f"n{seq}", now - rng.randint(0, HOUR - 1))
        # A late record written behind the cursor, but inside the overlap.
        seq += 1
        udm.add_flow(f"late{seq}", now - HOUR - 10 * 60_000)
        # Extend an existing record: later activity, higher count.
        fid = rng.choice(list(udm.flows))
        if not fid.startswith("old"):
            r = udm.flows[fid]
            r["time"] = now - 1000
            r["count"] += 5
        if run % 9 == 4:
            helper.fail_after = rng.randint(0, 2)
            failures += 1
        c.process()

    sent = incidents(helper)
    # Every in-window record arrived, in its final version.
    final = {}
    for name, last in sent:
        final[name] = max(final.get(name, ""), last)
    expected = {f"UDM-FLOW-{fid}" for fid in udm.flows if not fid.startswith("old")}
    assert set(final) == expected  # nothing outside the initial lookback
    from src.models import parse_flow
    for fid, raw in udm.flows.items():
        if fid.startswith("old"):
            continue
        e = parse_flow(raw)
        assert final[f"UDM-FLOW-{fid}"] == (e.last + timedelta(seconds=1)).isoformat()
    # An unchanged version is re-sent only by a bundle retried after a failure.
    dupes = sum(n - 1 for n in Counter(sent).values() if n > 1)
    assert dupes <= failures * c.settings.udm_events_per_bundle
    # The early stop works: far fewer page reads than full scans of 4+ pages per run.
    pages_full = (len(udm.flows) // 20 + 1) * 48
    assert udm.flow_requests < pages_full / 2
    state = helper.state
    assert state["flows"]["cursor_ms"] <= clock["now"]
    assert state["systems"] == {} and state["wan_ips"] == [WAN]
    # Every bundle carries its container, and every member resolves in the bundle or
    # is an existing-entity reference.
    for b in helper.sent:
        ids = {o["id"] for o in b["objects"]}
        (case,) = [o for o in b["objects"] if o["type"] == "case-incident"]
        assert set(case["object_refs"]) <= ids


def test_failed_send_keeps_cursor_and_resumes(rig):
    c, helper, udm, clock = rig
    for i in range(20):
        udm.add_flow(f"a{i}", START - HOUR + i * 1000)
    clock["now"] += 60_000
    helper.fail_after = 1  # first bundle ok, second raises
    c.process()
    first = helper.state["flows"]["cursor_ms"]
    assert first is not None and len(incidents(helper)) == 7
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True
    c.process()
    names = [n for n, _ in incidents(helper)]
    assert sorted(set(names)) == sorted(f"UDM-FLOW-a{i}" for i in range(20))
    assert len(names) == 20  # resumed after the 7 already sent, no re-send


def test_no_wan_address_fails_closed(rig, monkeypatch):
    c, helper, udm, clock = rig
    udm.wan = []
    udm.add_flow("x", START - 1000)
    c.process()
    assert helper.sent == []
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_old_wan_address_stays_out_of_the_graph(rig):
    c, helper, udm, clock = rig
    c.process()  # learns WAN
    udm.wan = ["198.51.100.77"]  # ISP changed our address
    udm.add_flow("y", START - 1000, src="45.33.32.9")
    udm.flows["y"]["source"]["ip"] = WAN  # e.g. a hairpin record naming the old address
    clock["now"] += HOUR
    c.process()
    values = {o.get("value") for b in helper.sent for o in b["objects"]}
    assert WAN not in values and helper.state["wan_ips"] == [WAN, "198.51.100.77"]


def test_security_failure_does_not_stop_flows(rig):
    c, helper, udm, clock = rig
    udm.fail_security = True
    udm.add_flow("z", START - 1000)
    c.process()
    assert [n for n, _ in incidents(helper)] == ["UDM-FLOW-z"]
    assert helper.state["security"]["cursor_ms"] is None
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_security_events_without_an_external_ip_are_not_imported(rig):
    c, helper, udm, clock = rig
    T = START - 5000
    udm.alerts = [{"id": "e5b1c0de-0000-4000-8000-000000000001", "timestamp": T, "category": "SECURITY",
          "subcategory": "SECURITY_INTRUSION_PREVENTION", "key": "THREAT_BLOCKED_V3",
          "event": "THREAT_BLOCKED", "severity": "HIGH",
          "message_raw": "A network intrusion attempt from {SRC_IP} to {DST_IP} has been detected and blocked.",
          "parameters": {"SRC_IP": {"id": "45.33.32.51", "name": "45.33.32.51"},
                         "DST_IP": {"id": "192.168.1.5", "name": "192.168.1.5"}}}, {"id": "e5b1c0de-0000-4000-8000-000000000002", "timestamp": T, "category": "SECURITY",
          "subcategory": "SECURITY_HONEYPOT", "key": "HONEYPOT_HIT_DETECTED_KNOWN_CLIENT",
          "event": "HONEYPOT_HIT_DETECTED", "severity": "MEDIUM",
          "message_raw": "Honeypot triggered by {CLIENT}.",
          "parameters": {"CLIENT": {"id": "aa:bb:cc:00:00:01", "name": "nas", "hostname": "nas"},
                         "MAC": {"id": "aa:bb:cc:00:00:01", "name": "aa:bb:cc:00:00:01"}}}]
    c.process()
    assert incidents(helper) == []  # blocked threat skipped, honeypot is internal-only
    assert helper.state["security"]["cursor_ms"] == T  # still marked as processed
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is False


def test_future_dated_record_does_not_stall_the_stream(rig):
    c, helper, udm, clock = rig
    udm.add_flow("future", START + 50 * 365 * 86_400_000)
    udm.add_flow("ok1", START - 1000)
    c.process()
    assert helper.state["flows"]["cursor_ms"] == START - 1000
    clock["now"] += HOUR
    udm.add_flow("ok2", clock["now"] - 1000)
    c.process()
    assert [n for n, _ in incidents(helper)] == ["UDM-FLOW-ok1", "UDM-FLOW-ok2"]


def test_page_cap_imports_what_it_read_and_reports_the_gap(rig, monkeypatch):
    c, helper, udm, clock = rig
    monkeypatch.setattr(c.settings, "udm_max_pages", 2)
    for i in range(100):
        udm.add_flow(f"m{i}", START - 10 * HOUR + i * 60_000)
    c.process()
    assert len(incidents(helper)) == 40  # 2 pages of 20
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True
    errors = [str(call) for call in helper.connector_logger.error.call_args_list]
    assert any("UDM_MAX_PAGES reached" in e for e in errors)
