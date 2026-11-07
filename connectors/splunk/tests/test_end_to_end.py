"""One run through the real connector, cases, builder and lookup, with only Splunk and
the OpenCTI API faked, then through pycti's own bundle splitter. Pins the exact fields
each object carries, which the mocked unit tests cannot."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

pytest.importorskip("pycti")

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter  # noqa: E402

from src import connector as mod  # noqa: E402
from src.config import Settings  # noqa: E402
from src.opencti_lookup import OpenCTILookup  # noqa: E402
from src.searches import SearchDef  # noqa: E402
from src.splunk_client import JobResult  # noqa: E402
from src.stix_builder import SplunkStixBuilder  # noqa: E402

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
T1059 = "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
ROWS = [
    {"_time": "2026-10-27T10:00:00.000+00:00", "event_id": "n1", "rule": "Beacon",
     "urgency": "high", "dest": "web01", "src": "203.0.113.5", "dest_port": "443",
     "user": "alice", "mitre": "T1059"},
    {"_time": "2026-10-27T11:00:00.000+00:00", "event_id": "n1", "rule": "Beacon",
     "urgency": "critical", "dest": "web02", "src": "203.0.113.6", "dest_port": "443",
     "user": "alice", "mitre": "T1059"},
]


@pytest.fixture
def run(monkeypatch):
    for k, v in {"OPENCTI_URL": "http://x", "OPENCTI_TOKEN": "t", "CONNECTOR_ID": "c",
                 "SPLUNK_BASE_URL": "https://s:8089", "SPLUNK_ORGANIZATION_NAME": "Acme",
                 "SPLUNK_CONFIDENCE": "80"}.items():
        monkeypatch.setenv(k, v)
    settings = Settings()
    search = SearchDef(name="ES", spl="search `notable`", app="ES", group_by=["event_id"],
                       title="{rule} ({event_id})", incident_type="alert",
                       severity_field="urgency", system_fields=["dest"],
                       observables={"src": "ip", "dest_port": "port", "user": "user-account"},
                       attack_pattern_fields=["mitre"])
    helper = MagicMock()
    helper.get_state.return_value = None
    helper.connect_id = "connector-id"
    helper.api.work.initiate_work.return_value = "work-1"
    helper.api.marking_definition.read.return_value = {"standard_id": MARKING}
    helper.api.attack_pattern.read.return_value = {"standard_id": T1059}

    c = mod.SplunkConnector.__new__(mod.SplunkConnector)
    c.helper, c.settings = helper, settings
    c.known_names, c.searches = {search.name}, [search]
    c.client = MagicMock()
    c.client.run_search.return_value = JobResult(ROWS)
    c.lookup = OpenCTILookup(helper)
    c.builder = SplunkStixBuilder(helper, settings, c.lookup)
    c.builder.prepare()
    c.process()
    return helper, search, c


def _objects(helper):
    (call,) = helper.send_stix2_bundle.call_args_list
    return call, json.loads(call.args[0])


def test_send_call_and_run_bookkeeping(run):
    helper, _, _ = run
    call, bundle = _objects(helper)
    assert call.kwargs == {"work_id": "work-1", "update": True}
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.args[0] == "work-1"
    assert helper.set_state.called


def test_splunk_is_asked_for_the_right_job(run):
    _, search, c = run
    (call,) = c.client.run_search.call_args_list
    spl, app, earliest, latest, time_mode, max_results, fields = call.args
    assert (spl, app, time_mode, max_results) == ("search `notable`", "ES", "index", 10000)
    assert latest - earliest == 86400  # the default first-run window
    assert set(fields) == {"_time", "event_id", "rule", "urgency", "dest", "src", "dest_port",
                           "user", "mitre"}


def test_every_object_field(run):
    helper, _, _ = run
    _, bundle = _objects(helper)
    by: dict[str, list[dict]] = {}
    for o in bundle["objects"]:
        by.setdefault(o["type"], []).append(o)

    (incident,) = by["incident"]
    assert incident["name"] == "Beacon (n1)"
    assert incident["incident_type"] == "alert"
    assert incident["severity"] == "critical"
    assert incident["source"] == "Splunk: ES"
    assert incident["confidence"] == 80
    assert incident["first_seen"] == incident["created"] == "2026-10-27T10:00:00+00:00"
    assert incident["last_seen"] == "2026-10-27T11:00:00+00:00"

    (case,) = by["case-incident"]
    assert case["name"] == incident["name"] and case["created"] == incident["created"]
    assert case["severity"] == "critical"
    assert "Import details:" in case["description"] and "Results: 2" in case["description"]

    author = next(o for o in by["identity"] if o["name"] == "Splunk"
                  and o["identity_class"] == "organization")
    for o in bundle["objects"]:
        assert o["spec_version"] == "2.1"
        assert o["object_marking_refs"] == [MARKING]
        if o is not author:
            assert o["created_by_ref"] == author["id"]

    (note,) = by["note"]
    assert note["object_refs"] == [incident["id"]]
    assert note["abstract"] == "Splunk provenance: ES"
    assert "search `notable`" in note["content"]
    assert note["created"] == incident["created"]

    systems = {o["id"]: o["name"] for o in by["identity"] if o["identity_class"] == "system"}
    assert set(systems.values()) == {"Splunk", "web01", "web02"}
    orgs = {o["name"] for o in by["identity"] if o["identity_class"] == "organization"}
    assert orgs == {"Splunk", "Acme"}

    observed = {o["id"]: o.get("value") or o.get("account_login") or str(o.get("dst_port"))
                for t in ("ipv4-addr", "user-account", "network-traffic") for o in by[t]}
    pairs = {(observed[s["sighting_of_ref"]], systems[s["where_sighted_refs"][0]]): s
             for s in by["sighting"]}
    assert set(pairs) == {("203.0.113.5", "web01"), ("203.0.113.6", "web02"),
                          ("alice", "web01"), ("alice", "web02"),
                          ("443", "web01"), ("443", "web02")}
    for s in by["sighting"]:
        assert s["confidence"] == 80 and s["count"] == 1 and s["x_opencti_negative"] is False
        assert s["description"].startswith("Observed by Splunk search 'ES'")
    assert pairs[("alice", "web02")]["first_seen"] == "2026-10-27T11:00:00+00:00"

    for r in by["relationship"]:
        assert r["confidence"] == 80 and r["description"]
    assert {r["relationship_type"] for r in by["relationship"]} == {"uses", "related-to"}
    (uses,) = [r for r in by["relationship"] if r["relationship_type"] == "uses"]
    assert (uses["source_ref"], uses["target_ref"]) == (incident["id"], T1059)
    assert T1059 in case["object_refs"]


def test_pycti_splitter_keeps_every_object(run):
    helper, _, _ = run
    call, bundle = _objects(helper)
    _, _, pieces = OpenCTIStix2Splitter().split_bundle_with_expectations(call.args[0])
    split_ids = {o["id"] for piece in pieces for o in json.loads(piece)["objects"]}
    assert split_ids >= {o["id"] for o in bundle["objects"]}


def test_lookup_outage_fails_the_search_instead_of_losing_the_link(run):
    helper, search, c = run
    helper.send_stix2_bundle.reset_mock()
    helper.api.attack_pattern.read.side_effect = ConnectionError("down")
    c.lookup = c.builder.lookup = OpenCTILookup(helper)  # no cached hits
    helper.get_state.return_value = {"searches": {search.name: {"cursor": "1000"}}}
    c.process()
    helper.send_stix2_bundle.assert_not_called()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True
    assert helper.set_state.call_args.args[0]["searches"][search.name]["cursor"] == "1000"
