"""STIX output conformance: IR container, sightings, single-port NT, no Indicators/Labels."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

pytest.importorskip("pycti")

from pycti import StixSightingRelationship  # noqa: E402

from src.cases import build_cases  # noqa: E402
from src.config import Settings  # noqa: E402
from src.searches import SearchDef  # noqa: E402
from src.stix_builder import SplunkStixBuilder  # noqa: E402

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
T1059 = "attack-pattern--00000000-0000-4000-8000-000000001059"
OBS = {"src": "ip", "dest_port": "port", "h": "file-hash", "user": "user-account",
       "url": "url", "dom": "domain-name", "mail": "email-addr", "mac": "mac-addr"}


@pytest.fixture
def settings(monkeypatch):
    for k, v in {"OPENCTI_URL": "http://x", "OPENCTI_TOKEN": "t", "CONNECTOR_ID": "c",
                 "SPLUNK_BASE_URL": "https://s:8089", "SPLUNK_ORGANIZATION_NAME": "Acme",
                 "SPLUNK_MAX_OBJECTS_PER_CASE": "2000"}.items():
        monkeypatch.setenv(k, v)
    return Settings()


def _builder(settings):
    lookup = MagicMock()
    lookup.marking.return_value = MARKING
    lookup.attack_pattern.side_effect = lambda tid: T1059 if tid == "T1059" else None
    return SplunkStixBuilder(MagicMock(), settings, lookup)


@pytest.fixture
def builder(settings):
    b = _builder(settings)
    b.prepare()
    return b


def _case(systems=("dest",), severity=None, rows=None, **row_extra):
    search = SearchDef(name="S", spl="search x", group_by=["event_id"],
                       system_fields=list(systems), severity_field="urg",
                       observables=OBS, attack_pattern_fields=["mitre"])
    row = {"_time": "1761552000", "event_id": "e1", "dest": "web01", "src": "1.1.1.1",
           "dest_port": "443", "h": "d41d8cd98f00b204e9800998ecf8427e",
           "mitre": "T1059 T9999", "user": "alice", **row_extra}
    if severity:
        row["urg"] = severity
    return search, build_cases(search, rows or [row], datetime.now(timezone.utc))[0]


def _by_type(objs):
    out: dict[str, list[dict]] = {}
    for o in objs:
        out.setdefault(o["type"], []).append(o)
    return out


def test_bundle_shape(builder):
    search, case = _case()
    objs = builder.build(search, case)
    t = _by_type(objs)

    assert len({o["id"] for o in objs}) == len(objs)  # no duplicate objects
    assert "indicator" not in t
    assert all("labels" not in o for o in objs)
    assert all(o.get("object_marking_refs") == [MARKING] for o in objs)

    container = t["case-incident"][0]
    assert objs[-1] is container
    member_ids = set(container["object_refs"])
    author = next(o for o in t["identity"] if o["name"] == "Splunk"
                  and o["identity_class"] == "organization")
    assert "created_by_ref" not in author
    assert author["id"] not in member_ids
    # Everything else (plus the looked-up Attack Pattern) is in the container.
    assert member_ids == {o["id"] for o in objs if o is not container and o is not author} | {T1059}

    # Single-port Network-Traffic only.
    (nt,) = t["network-traffic"]
    assert set(nt) - {"type", "id", "spec_version", "object_marking_refs", "created_by_ref",
                      "x_opencti_description"} == {"dst_port"}
    assert nt["dst_port"] == 443

    # Sightings target the asset System, never the sensor, when an asset is known,
    # and use the list form pycti expects for where_sighted_refs in their ids.
    web01 = next(o["id"] for o in t["identity"] if o["name"] == "web01")
    for s in t["sighting"]:
        assert s["where_sighted_refs"] == [web01]
        assert s["first_seen"] == s["last_seen"]  # exact source time, single row
        assert s["description"].startswith("Observed by Splunk search 'S'")
        assert s["id"] == StixSightingRelationship.generate_id(
            s["sighting_of_ref"], [web01], s["first_seen"], s["last_seen"])
    assert len(t["sighting"]) == 4  # ip, port, file, user

    # Only the listed precise verb; everything else is related-to with a description.
    assert {r["relationship_type"] for r in t["relationship"]} == {"uses", "related-to"}
    assert all(r["description"] and r["confidence"] for r in t["relationship"])
    uses = [r for r in t["relationship"] if r["relationship_type"] == "uses"]
    assert [r["target_ref"] for r in uses] == [T1059]

    # Every observable has a related-to edge to an Identity (System).
    identity_ids = {o["id"] for o in t["identity"]}
    for kind in ("ipv4-addr", "network-traffic", "file", "user-account"):
        oid = t[kind][0]["id"]
        assert any(r["source_ref"] == oid and r["target_ref"] in identity_ids
                   for r in t["relationship"])

    # Ownership edges are timeless (one per asset); activity edges carry the case
    # window, with stop strictly after start (STIX 2.1) even for a single row.
    org = next(o["id"] for o in t["identity"] if o["name"] == "Acme")
    for r in t["relationship"]:
        if r["target_ref"] == org:
            assert "start_time" not in r
        else:
            assert r["stop_time"] > r["start_time"]

    # Unresolved technique is reported (in the container), not minted.
    assert "T9999" in container["description"]
    assert "attack-pattern" not in t
    assert "severity" not in t["incident"][0]


def test_every_observable_kind_builds(builder):
    search, case = _case(url="https://x.test/a", dom="x.test", mail="a@x.test",
                         mac="aa:bb:cc:dd:ee:ff", src="2001:db8::1")
    t = _by_type(builder.build(search, case))
    assert t["ipv6-addr"][0]["value"] == "2001:db8::1"
    assert t["url"][0]["value"] == "https://x.test/a"
    assert t["domain-name"][0]["value"] == "x.test"
    assert t["email-addr"][0]["value"] == "a@x.test"
    assert t["mac-addr"][0]["value"] == "aa:bb:cc:dd:ee:ff"
    assert t["user-account"][0]["account_login"] == "alice"
    assert t["file"][0]["hashes"] == {"MD5": "d41d8cd98f00b204e9800998ecf8427e"}
    for kind in ("ipv6-addr", "url", "domain-name", "email-addr", "mac-addr"):
        assert "x_opencti_description" in t[kind][0]


@pytest.mark.parametrize("value, algo", [("a" * 40, "SHA-1"), ("b" * 64, "SHA-256")])
def test_file_hash_algorithms(builder, value, algo):
    search, case = _case(h=value)
    assert _by_type(builder.build(search, case))["file"][0]["hashes"] == {algo: value}


def test_note_is_stable_as_case_grows(builder):
    s1, small = _case()
    s2, big = _case(rows=[
        {"_time": "1761552000", "event_id": "e1", "dest": "web01", "src": "1.1.1.1"},
        {"_time": "1761559000", "event_id": "e1", "dest": "web01", "src": "2.2.2.2",
         "h": "nothex"}])
    n1 = _by_type(builder.build(s1, small))["note"][0]
    t2 = _by_type(builder.build(s2, big))
    assert n1["id"] == t2["note"][0]["id"]  # same group + first_seen -> same Note
    assert "SPL:" in n1["content"] and "Results" not in n1["content"]
    details = t2["case-incident"][0]["description"]
    assert "Results: 2" in details and "h x1" in details


def test_ownership_edge_identical_across_cases(builder):
    s1, c1 = _case(_time="1761552000")
    s2, c2 = _case(_time="1761600000", event_id="e2")
    org_edges = lambda objs: {o["id"] for o in objs  # noqa: E731
                              if o["type"] == "relationship" and "start_time" not in o}
    assert org_edges(builder.build(s1, c1)) == org_edges(builder.build(s2, c2))


def test_severity_on_incident_and_container(builder):
    search, case = _case(severity="Critical")
    t = _by_type(builder.build(search, case))
    assert t["incident"][0]["severity"] == "critical"
    assert t["case-incident"][0]["severity"] == "critical"


def test_sensor_system_is_sighting_target_without_asset(builder):
    search, case = _case(systems=())
    t = _by_type(builder.build(search, case))
    sensor = next(o["id"] for o in t["identity"] if o["identity_class"] == "system")
    assert {s["where_sighted_refs"][0] for s in t["sighting"]} == {sensor}


def test_asset_named_like_sensor_is_not_duplicated(builder):
    search, case = _case(dest="Splunk")
    objs = builder.build(search, case)
    assert len({o["id"] for o in objs}) == len(objs)
    assert sum(o["type"] == "identity" and o["identity_class"] == "system" for o in objs) == 1


def test_ids_are_deterministic(builder):
    search, case = _case()
    ids = lambda objs: sorted(o["id"] for o in objs)  # noqa: E731
    assert ids(builder.build(search, case)) == ids(builder.build(search, case))


def test_object_cap_keeps_most_seen_and_reports_it(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": "web01", "src": "9.9.9.9"},
            {"_time": "1761552000", "event_id": "e", "dest": "web01", "src": "9.9.9.9"},
            {"_time": "1761552000", "event_id": "e", "dest": "web01", "src": "1.1.1.1",
             "user": "alice"}]
    search, case = _case(rows=rows)
    builder.max_objects = 14
    objs = builder.build(search, case)
    assert len(objs) <= 14
    t = _by_type(objs)
    assert [o["value"] for o in t["ipv4-addr"]] == ["9.9.9.9"]  # most-seen kept
    assert "2 observable(s)" in t["case-incident"][0]["description"]


def test_object_cap_counts_systems(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": f"host{i}", "src": "1.1.1.1"}
            for i in range(100)]
    search, case = _case(rows=rows)
    builder.max_objects = 50
    objs = builder.build(search, case)
    assert len(objs) <= 50
    assert "system(s)" in _by_type(objs)["case-incident"][0]["description"]


def test_object_cap_counts_technique_links(builder):
    search, case = _case(mitre="T1059", src="-", dest_port="-", h="-", user="-")
    builder.max_objects = 7  # 4 static + Incident, 2 reserved: no room for the edge
    t = _by_type(builder.build(search, case))
    assert not any(r["relationship_type"] == "uses" for r in t["relationship"])
    assert "1 technique link(s)" in t["case-incident"][0]["description"]


def test_cap_dropping_every_asset_never_falls_back_to_sensor(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": f"host{i}", "src": "1.1.1.1"}
            for i in range(3)]
    search, case = _case(rows=rows)
    builder.max_objects = 7  # 4 static + Incident, 2 reserved: no room for any System
    t = _by_type(builder.build(search, case))
    assert "sighting" not in t and "ipv4-addr" not in t
    details = t["case-incident"][0]["description"]
    assert "3 system(s)" in details and "1 observable(s)" in details


def test_cap_dropping_one_asset_keeps_the_values_seen_elsewhere(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": f"host{i}", "src": f"1.1.1.{i}"}
            for i in range(2)]
    search, case = _case(rows=rows)
    builder.max_objects = 12  # 4 static + Incident, 2 reserved, room for one observable set
    t = _by_type(builder.build(search, case))
    assert len(t["sighting"]) == 1
    assert t["sighting"][0]["where_sighted_refs"][0] != builder.sensor_id  # never misattributed
    details = t["case-incident"][0]["description"]
    assert "1 observable(s)" in details and "1 system(s)" in details


def test_port_observable_reserves_its_extra_edge_under_the_cap(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": "Splunk", "dest_port": "443"}]
    search, case = _case(rows=rows)
    builder.max_objects = 10  # 5 used, 2 reserved: room 3, but a port needs 1 + 1 + 2 = 4
    t = _by_type(builder.build(search, case))
    assert "network-traffic" not in t
    builder.max_objects = 11
    t = _by_type(builder.build(search, case))
    assert len(t["network-traffic"]) == 1


def test_many_assets_cannot_crowd_out_observables(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": f"host{i:03}", "src": "1.1.1.1"}
            for i in range(100)]
    rows += [{"_time": "1761552000", "event_id": "e", "dest": "host042", "src": "1.1.1.1"}]
    search, case = _case(rows=rows)
    builder.max_objects = 50
    objs = builder.build(search, case)
    t = _by_type(objs)
    assert len(objs) <= 50
    assert len(t["ipv4-addr"]) == 1 and len(t["sighting"]) >= 5
    top = max(t["sighting"], key=lambda s: s["count"])
    assert top["count"] == 2  # the most-seen pairing is kept first
    assert "sighting(s)" in t["case-incident"][0]["description"]


def test_assets_with_no_observables_still_join_the_case(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": "host1"}]
    search, case = _case(rows=rows)
    t = _by_type(builder.build(search, case))
    assert "host1" in {o["name"] for o in t["identity"]}
    assert "sighting" not in t


def test_build_before_prepare_fails_closed(settings):
    search, case = _case()
    with pytest.raises(RuntimeError, match="prepare"):
        _builder(settings).build(search, case)


def test_unresolved_marking_fails_closed(builder):
    builder.lookup.marking.return_value = None
    with pytest.raises(RuntimeError, match="refusing to start"):
        builder.prepare()


def test_off_allow_list_verb_is_refused(builder):
    with pytest.raises(ValueError, match="allow-list"):
        builder._rel("a", "system", "belongs-to", "b", "organization", "x")


def test_sightings_only_on_assets_that_saw_the_value(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": "host1", "src": "1.1.1.1"},
            {"_time": "1761552600", "event_id": "e", "dest": "host2", "src": "2.2.2.2"},
            {"_time": "1761553200", "event_id": "e", "dest": "host1", "src": "1.1.1.1"}]
    search, case = _case(rows=rows)
    t = _by_type(builder.build(search, case))
    names = {o["id"]: o["name"] for o in t["identity"]}
    values = {o["id"]: o["value"] for o in t["ipv4-addr"]}
    got = {(values[s["sighting_of_ref"]], names[s["where_sighted_refs"][0]]): s
           for s in t["sighting"]}
    assert set(got) == {("1.1.1.1", "host1"), ("2.2.2.2", "host2")}  # no cross-product
    assert got[("1.1.1.1", "host1")]["count"] == 2
    assert got[("2.2.2.2", "host2")]["count"] == 1
    # Each Sighting and related-to edge carries that pairing's own times.
    assert got[("1.1.1.1", "host1")]["first_seen"] < got[("2.2.2.2", "host2")]["first_seen"]
    assert got[("2.2.2.2", "host2")]["first_seen"] == got[("2.2.2.2", "host2")]["last_seen"]
    edges = {(values[r["source_ref"]], names[r["target_ref"]]) for r in t["relationship"]
             if r["source_ref"] in values}
    assert edges == set(got)


def test_row_without_asset_is_sighted_on_the_sensor_alongside_real_assets(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": "host1", "src": "1.1.1.1"},
            {"_time": "1761552000", "event_id": "e", "dest": "-", "src": "2.2.2.2"}]
    search, case = _case(rows=rows)
    t = _by_type(builder.build(search, case))
    names = {o["id"]: o["name"] for o in t["identity"]}
    values = {o["id"]: o["value"] for o in t["ipv4-addr"]}
    assert {(values[s["sighting_of_ref"]], names[s["where_sighted_refs"][0]])
            for s in t["sighting"]} == {("1.1.1.1", "host1"), ("2.2.2.2", "Splunk")}


def test_untimed_sighting_uses_case_times(builder):
    rows = [{"event_id": "e", "dest": "host1", "src": "1.1.1.1"}]
    search, case = _case(rows=rows)
    (s,) = _by_type(builder.build(search, case))["sighting"]
    assert s["first_seen"] == case.first_seen.isoformat()


def test_equally_seen_assets_are_chosen_the_same_way_every_time(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": d, "src": "1.1.1.1"}
            for d in ("zulu", "alpha")]
    search, case = _case(rows=rows)
    builder.max_objects = 12  # 5 used, 2 reserved: room for the observable and one System
    t = _by_type(builder.build(search, case))
    (s,) = t["sighting"]
    names = {o["id"]: o["name"] for o in t["identity"]}
    assert names[s["where_sighted_refs"][0]] == "alpha"
    assert "1 sighting(s)" in t["case-incident"][0]["description"]


def test_a_wholly_dropped_observable_is_not_also_counted_as_sightings(builder):
    rows = [{"_time": "1761552000", "event_id": "e", "dest": "host1", "src": "1.1.1.1"}]
    search, case = _case(rows=rows)
    builder.max_objects = 7  # no room for anything after the Incident
    details = _by_type(builder.build(search, case))["case-incident"][0]["description"]
    assert "1 observable(s)" in details and "sighting(s)" not in details
