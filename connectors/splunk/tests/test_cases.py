"""Row grouping into Cases (stdlib only)."""

from __future__ import annotations

from datetime import datetime, timezone

from src.cases import RollingCases, build_cases, parse_time, render, values
from src.searches import SearchDef

FALLBACK = datetime(2026, 10, 27, tzinfo=timezone.utc)


def _search(**kw) -> SearchDef:
    base = dict(name="S", spl="search x", group_by=["event_id"],
                title="{rule} on {dest} ({group})", system_fields=["dest"],
                observables={"src": "ip", "dest_port": "port", "hash": "file-hash"},
                attack_pattern_fields=["mitre"], severity_field="urgency")
    base.update(kw)
    return SearchDef(**base)


def test_parse_time_epoch_and_iso():
    assert parse_time("1761552000") == datetime(2025, 10, 27, 8, 0, tzinfo=timezone.utc)
    assert parse_time("2026-10-27T10:00:00.000-04:00") == datetime(
        2026, 10, 27, 14, 0, tzinfo=timezone.utc)
    assert parse_time("2026-10-27T10:00:00") == datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
    assert parse_time("garbage") is None
    assert parse_time("nan") is None


def test_values_and_render():
    row = {"a": ["x", None, "", "y"], "b": "", "c": 5}
    assert values(row, "a") == ["x", "y"]
    assert values(row, "b") == [] and values(row, "missing") == []
    assert values(row, "c") == ["5"]
    assert render(" {a}-{group}-{missing} ", row, {"group": "g"}) == "x-g-"


def test_build_cases_groups_and_counts():
    rows = [
        {"_time": "1761552000", "event_id": "e1", "rule": "R", "dest": "web01",
         "src": ["1.1.1.1", "2.2.2.2"], "dest_port": "443", "hash": "zzz",
         "mitre": "T1059.001, T1071", "urgency": "medium"},
        {"_time": "1761552600", "event_id": "e1", "rule": "R", "dest": "web02",
         "src": "1.1.1.1", "dest_port": "443", "urgency": "High"},
        {"_time": "1761552000", "event_id": "e2", "rule": "R2", "dest": "db01", "src": "3.3.3.3"},
    ]
    cases = {c.key: c for c in build_cases(_search(), rows, FALLBACK)}
    assert set(cases) == {"e1", "e2"}
    c = cases["e1"]
    assert c.title == "R on web01 (e1)"
    assert c.row_count == 2
    assert c.systems == ["web01", "web02"]
    assert c.severity == "high"  # highest across the group's rows
    assert cases["e2"].severity is None
    assert c.techniques == ["T1059.001", "T1071"]
    assert c.rejected == {"hash": 1}
    assert (c.last_seen - c.first_seen).total_seconds() == 600
    # Most-seen first.
    assert [(o.kind, o.value, o.count) for o in c.observables] == [
        ("ipv4-addr", "1.1.1.1", 2), ("network-traffic", "443", 2), ("ipv4-addr", "2.2.2.2", 1)]
    assert "returned 2 result(s)" in c.description


def test_title_does_not_depend_on_row_order():
    rows = [{"_time": "1761552600", "event_id": "e", "rule": "late", "dest": "b"},
            {"_time": "1761552000", "event_id": "e", "rule": "early", "dest": "a"}]
    fwd = build_cases(_search(), rows, FALLBACK)[0]
    rev = build_cases(_search(), rows[::-1], FALLBACK)[0]
    assert fwd.title == rev.title == "early on a (e)"  # earliest row wins
    # Same time: ties broken by content, still order-independent.
    tie = [{**r, "_time": "1761552000"} for r in rows]
    assert build_cases(_search(), tie, FALLBACK)[0].title == \
        build_cases(_search(), tie[::-1], FALLBACK)[0].title


def test_description_template():
    s = _search(description="{rule}: {count} rows from {first_seen}")
    c = build_cases(s, [{"event_id": "e", "rule": "R", "_time": "1761552000"}], FALLBACK)[0]
    assert c.description == "R: 1 rows from 2025-10-27T08:00:00+00:00"


def test_rows_missing_group_columns_are_not_merged():
    s = _search(group_by=["event_id"])
    cases = build_cases(s, [{"src": "1.1.1.1"}, {"src": "2.2.2.2"}, {"event_id": "e"}], FALLBACK)
    assert len(cases) == 3


def test_ungrouped_key_ignores_unreferenced_columns():
    s = _search(group_by=[])
    a = build_cases(s, [{"src": "1.1.1.1", "_serial": "0", "_bkt": "a"}], FALLBACK)[0]
    b = build_cases(s, [{"src": "1.1.1.1", "_serial": "7", "_bkt": "b"}], FALLBACK)[0]
    assert a.key == b.key
    assert a.first_seen == FALLBACK  # no _time -> fallback
    blank = build_cases(_search(title="{missing}"), [{"x": "1"}], FALLBACK)[0]
    assert blank.title == "S: " + blank.key  # empty rendered title falls back


def test_fingerprint_changes_with_content():
    s = _search()
    row = {"event_id": "e", "src": "1.1.1.1", "_time": "1761552000", "urgency": "low"}
    one = build_cases(s, [row], FALLBACK)[0]
    same = build_cases(s, [dict(row)], FALLBACK)[0]
    variants = [
        build_cases(s, [{**row, "src": ["1.1.1.1", "2.2.2.2"]}], FALLBACK)[0],
        build_cases(s, [{**row, "urgency": "critical"}], FALLBACK)[0],
        build_cases(s, [{**row, "hash": "bad"}], FALLBACK)[0],
    ]
    assert one.fingerprint() == same.fingerprint()
    assert len({one.fingerprint(), *(v.fingerprint() for v in variants)}) == 4


def test_placeholder_assets_are_not_systems():
    rows = [{"event_id": "e", "dest": v} for v in ("unknown", "-", "N/A", " ", "web01")]
    assert build_cases(_search(), rows, FALLBACK)[0].systems == ["web01"]


def _one(rows, **kw):
    return build_cases(_search(**kw), rows, FALLBACK)[0]


def test_anchor_pins_identity_even_when_earlier_rows_join():
    c = _one([{"event_id": "e", "_time": "1761552600"}])
    created = datetime(2025, 10, 27, 9, 0, tzinfo=timezone.utc)  # after this row
    c.anchor("first title", created)
    assert (c.title, c.created) == ("first title", created)  # identity pinned
    assert c.first_seen == datetime(2025, 10, 27, 8, 10, tzinfo=timezone.utc)  # true time
    earlier = datetime(2025, 10, 1, tzinfo=timezone.utc)
    c.anchor("first title", earlier)
    assert c.created == earlier and c.first_seen == earlier


def test_untimed_case_uses_fallback_and_ignores_it_in_fingerprint():
    a = build_cases(_search(), [{"event_id": "e", "src": "1.1.1.1"}], FALLBACK)[0]
    b = build_cases(_search(), [{"event_id": "e", "src": "1.1.1.1"}],
                    datetime(2030, 1, 1, tzinfo=timezone.utc))[0]
    assert not a.timed and a.first_seen == a.created == FALLBACK
    b.anchor(a.title, a.created)
    assert b.first_seen == b.last_seen == FALLBACK  # pinned to first-sent fallback
    assert a.fingerprint() == b.fingerprint()


def test_sightings_follow_the_rows_not_the_whole_group():
    s = _search(group_by=["user"], observables={"src": "ip", "user": "user-account"},
                title="{user}")
    rows = [{"_time": "1761552000", "user": "alice", "dest": "host1", "src": "1.1.1.1"},
            {"_time": "1761552600", "user": "alice", "dest": "host2", "src": "2.2.2.2"},
            {"_time": "1761553200", "user": "alice", "dest": "host1", "src": "1.1.1.1"}]
    c = build_cases(s, rows, FALLBACK)[0]
    by = {o.value: o for o in c.observables}
    assert set(by["1.1.1.1"].sightings) == {"host1"}  # never on host2
    assert set(by["2.2.2.2"].sightings) == {"host2"}  # never on host1
    assert by["1.1.1.1"].sightings["host1"].count == 2
    assert {k: v.count for k, v in by["alice"].sightings.items()} == {"host1": 2, "host2": 1}
    host1 = by["1.1.1.1"].sightings["host1"]
    assert (host1.last - host1.first).total_seconds() == 1200  # its own times, not the case's


def test_row_without_asset_is_sighted_by_the_sensor():
    rows = [{"event_id": "e", "dest": "host1", "src": "1.1.1.1"},
            {"event_id": "e", "dest": "unknown", "src": "2.2.2.2"}]
    by = {o.value: o for o in build_cases(_search(), rows, FALLBACK)[0].observables}
    assert set(by["1.1.1.1"].sightings) == {"host1"}
    assert set(by["2.2.2.2"].sightings) == {None}


def test_multivalue_asset_row_sights_each_asset_it_names():
    rows = [{"event_id": "e", "dest": ["a", "b"], "src": "1.1.1.1"}]
    ob = build_cases(_search(), rows, FALLBACK)[0].observables[0]
    assert set(ob.sightings) == {"a", "b"} and ob.count == 1


def test_fingerprint_changes_when_a_value_moves_to_another_asset():
    row = {"event_id": "e", "dest": "a", "src": "1.1.1.1", "_time": "1761552000"}
    moved = {**row, "dest": "b"}
    s = _search(system_fields=["dest"], title="t ({group})")
    one = build_cases(s, [row], FALLBACK)[0]
    two = build_cases(s, [moved], FALLBACK)[0]
    two.systems = one.systems  # isolate the per-observable part
    assert one.fingerprint() != two.fingerprint()


def test_placeholders_are_skipped_not_counted_as_invalid():
    rows = [{"event_id": "e", "src": ["unknown", "-", "N/A", "not-an-ip"]}]
    c = build_cases(_search(), rows, FALLBACK)[0]
    assert c.observables == [] and c.rejected == {"src": 1}  # only the genuinely bad value


def test_title_keeps_groups_with_multivalue_columns_apart():
    s = _search(group_by=["src"], title="{rule} {src}")
    rows = [{"_time": "1761552000", "src": ["a", "b"], "rule": "R"},
            {"_time": "1761552000", "src": ["a", "c"], "rule": "R"}]
    assert sorted(c.title for c in build_cases(s, rows, FALLBACK)) == ["R a,b", "R a,c"]


def test_title_of_row_missing_group_columns_uses_its_key():
    s = _search(group_by=["event_id"], title="{rule} ({event_id})")
    rows = [{"_time": "1761552000", "rule": "R", "src": "1.1.1.1"},
            {"_time": "1761552000", "rule": "R", "src": "2.2.2.2"}]
    assert len({c.title for c in build_cases(s, rows, FALLBACK)}) == 2


def _rc(stored=None, cap=10, run_at=1000, horizon=500):
    return RollingCases(stored or {}, cap, run_at, horizon)


def _send(rc, case, linked=()):
    """What the connector does: returns whether the case went out."""
    if not rc.needs_send(case, linked):
        return False
    rc.mark_sent(case)
    return True


def test_rolling_cases_pin_identity_and_skip_unchanged():
    title = "{rule} ({group})"
    first = _one([{"event_id": "e", "_time": "1761552600", "rule": "R1"}], title=title)
    rc = _rc()
    assert _send(rc, first)
    stored = rc.commit()

    # Next run: an earlier row with a different rule joins the group.
    both = [{"event_id": "e", "_time": "1761552000", "rule": "R0"},
            {"event_id": "e", "_time": "1761552600", "rule": "R1"}]
    grown = _one(both, title=title)
    rc = _rc(stored)
    assert _send(rc, grown)  # content changed
    assert (grown.title, grown.created) == (first.title, first.created)  # same case id
    assert not _send(_rc(rc.commit()), _one(both, title=title))  # unchanged: skipped


def test_rolling_pin_survives_an_empty_run_and_expires_after_a_window():
    case = _one([{"event_id": "e", "_time": "1761552600"}])
    rc = _rc(run_at=1000, horizon=500)
    _send(rc, case)
    stored = rc.commit()
    assert list(_rc(stored, run_at=1100, horizon=600).commit()) == ["e"]  # empty run keeps it
    assert list(_rc(stored, run_at=1000, horizon=1000).commit()) == ["e"]  # boundary
    assert _rc(stored, run_at=2000, horizon=1001).commit() == {}  # whole window passed


def test_group_returning_after_an_empty_run_keeps_its_case():
    title = "{rule} ({group})"
    first = _one([{"event_id": "e", "_time": "1761552000", "rule": "old"},
                  {"event_id": "e", "_time": "1761552600", "rule": "new"}], title=title)
    rc = _rc()
    _send(rc, first)
    stored = _rc(rc.commit(), run_at=1100, horizon=600).commit()  # a run with no results
    back = _one([{"event_id": "e", "_time": "1761552600", "rule": "new"}], title=title)
    _rc(stored, run_at=1200, horizon=700).needs_send(back)
    assert (back.title, back.created) == (first.title, first.created)


def test_only_cases_confirmed_sent_are_remembered():
    a, b = _one([{"event_id": "a"}]), _one([{"event_id": "b"}])
    rc = _rc()
    assert _send(rc, a)
    assert rc.needs_send(b)  # the send of b then fails: no mark_sent
    assert list(rc.commit()) == ["a"]


def test_failed_resend_keeps_the_previous_entry():
    row = {"event_id": "e", "_time": "1761552600", "src": "1.1.1.1"}
    rc = _rc()
    _send(rc, _one([row]))
    stored = rc.commit()
    changed = _one([{**row, "src": "2.2.2.2"}])
    rc = _rc(stored)
    assert rc.needs_send(changed)  # not confirmed sent
    assert rc.commit() == stored  # so it is retried, still pinned


def test_rolling_cap_never_evicts_a_group_still_being_returned():
    rc = _rc(cap=2)
    for k in ("a", "b", "c", "d"):
        _send(rc, _one([{"event_id": k, "_time": "1761552000"}]))
    assert set(rc.commit()) == {"a", "b", "c", "d"}


def test_rolling_cap_evicts_missing_groups_longest_gone_first():
    stored = {"gone-long": ["t", "2025-01-01T00:00:00+00:00", "f", 700],
              "gone-new": ["t", "2025-01-01T00:00:00+00:00", "f", 800],
              "gone-mid": ["t", "2025-06-01T00:00:00+00:00", "f", 750]}
    rc = _rc(stored, cap=3, run_at=1000, horizon=500)
    _send(rc, _one([{"event_id": "live", "_time": "1761552000"}]))
    assert set(rc.commit()) == {"live", "gone-new", "gone-mid"}


def test_rolling_cap_keeps_every_missing_group_when_there_is_room():
    stored = {k: ["t", "2025-01-01T00:00:00+00:00", "f", 800] for k in "abc"}
    assert set(_rc(stored, cap=5, run_at=1000, horizon=500).commit()) == {"a", "b", "c"}


def test_rolling_cap_prefers_groups_still_being_returned():
    gone = _rc(run_at=900)
    _send(gone, _one([{"event_id": "gone", "_time": "1761559000"}]))
    rc = _rc(gone.commit(), cap=1, run_at=1000)
    _send(rc, _one([{"event_id": "live", "_time": "1761551000"}]))
    assert list(rc.commit()) == ["live"]


def test_rolling_case_is_resent_when_a_technique_becomes_linkable():
    row = {"event_id": "e", "_time": "1761552000", "mitre": "T1059"}
    rc = _rc()
    assert _send(rc, _one([row]), [])
    stored = rc.commit()
    assert not _rc(stored).needs_send(_one([row]), [])  # still missing
    assert _rc(stored).needs_send(_one([row]), ["T1059"])  # now in OpenCTI


def test_fingerprint_ignores_row_order():
    rows = [{"event_id": "e", "dest": "a", "src": "1.1.1.1", "_time": "1761552000"},
            {"event_id": "e", "dest": "b", "src": "2.2.2.2", "_time": "1761552000"}]
    fwd = build_cases(_search(), rows, FALLBACK)[0]
    rev = build_cases(_search(), rows[::-1], FALLBACK)[0]
    assert fwd.fingerprint() == rev.fingerprint()


def test_assets_differing_only_in_case_are_one_asset():
    rows = [{"event_id": "e", "dest": "DC01", "src": "1.1.1.1", "_time": "1761552000"},
            {"event_id": "e", "dest": "dc01", "src": "1.1.1.1", "_time": "1761552000"}]
    c = build_cases(_search(), rows, FALLBACK)[0]
    assert c.systems == ["DC01"]
    assert {k: s.count for k, s in c.observables[0].sightings.items()} == {"dc01": 2}


def test_stats_style_search_with_builtin_named_columns():
    s = _search(time_field="first_seen", group_by=["search_name"], title="{search_name}")
    rows = [{"first_seen": "1761552000", "search_name": "A", "src": "1.1.1.1"},
            {"first_seen": "1761552600", "search_name": "A", "src": "2.2.2.2"}]
    fields = s.referenced_fields()
    projected = [{k: v for k, v in r.items() if k in fields} for r in rows]  # what `f=` returns
    (c,) = build_cases(s, projected, FALLBACK)
    assert c.timed and c.key == "A" and c.title == "A"
    assert c.first_seen == datetime(2025, 10, 27, 8, 0, tzinfo=timezone.utc)


def test_odd_time_values_are_untimed_or_read_as_dates():
    assert parse_time("20240101") == datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert parse_time("20241399") is None
    assert parse_time("9999-12-31T23:59:59-05:00") is None  # overflows on conversion to UTC
    assert build_cases(_search(), [{"event_id": "e", "_time": "9999-12-31T23:59:59-05:00"}],
                       FALLBACK)[0].first_seen == FALLBACK


def test_rolling_severity_never_drops_when_a_critical_row_ages_out():
    both = [{"event_id": "e", "_time": "1761552000", "urgency": "critical"},
            {"event_id": "e", "_time": "1761552600", "urgency": "low"}]
    rc = _rc()
    _send(rc, _one(both))
    later = _one([both[1]])  # only the low row is still in the window
    rc = _rc(rc.commit())
    rc.needs_send(later)
    assert later.severity == "critical"
    rc.mark_sent(later)
    assert rc.commit()["e"][4] == "critical"


def test_anchor_raises_severity_and_keeps_it_when_none_is_known():
    c = _one([{"event_id": "e", "_time": "1761552000", "urgency": "high"}])
    c.anchor(c.title, c.created, "low")
    assert c.severity == "high"
    c.anchor(c.title, c.created, "critical")
    assert c.severity == "critical"
    plain = _one([{"event_id": "e", "_time": "1761552000"}])
    plain.anchor(plain.title, plain.created, None)
    assert plain.severity is None


def test_commit_keeps_returned_groups_however_long_sending_has_failed():
    stored = {"live": ["t", "2025-01-01T00:00:00+00:00", "f", 100, None],
              "gone": ["t", "2025-01-01T00:00:00+00:00", "f", 100, None]}
    rc = _rc(stored, cap=1, run_at=9000, horizon=8000)  # both older than the window
    assert list(rc.commit(["live"])) == ["live"]  # never sent this run, still kept


def test_rolling_cap_breaks_ties_by_the_newest_case():
    older = ["t", "2025-01-01T00:00:00+00:00", "f", 800, None]
    newer = ["t", "2025-06-01T00:00:00+00:00", "f", 800, None]
    for stored in ({"older": older, "newer": newer}, {"newer": newer, "older": older}):
        assert list(_rc(stored, cap=1, run_at=1000, horizon=500).commit()) == ["newer"]


def test_a_value_in_two_columns_of_a_row_counts_once():
    s = _search(observables={"src": "ip", "src_ip": "ip"})
    (ob,) = build_cases(s, [{"event_id": "e", "dest": "a", "src": "1.1.1.1",
                             "src_ip": "1.1.1.1"}], FALLBACK)[0].observables
    assert ob.count == 1 and ob.sightings["a"].count == 1 and ob.fields == {"src", "src_ip"}


def test_time_templates_are_blank_for_untimed_rows():
    s = _search(description="seen {first_seen} to {last_seen}")
    assert build_cases(s, [{"event_id": "e"}], FALLBACK)[0].description == "seen  to"


def test_multivalue_time_uses_the_earliest():
    row = {"event_id": "e", "_time": ["1761552600", "1761552000"]}
    assert build_cases(_search(), [row], FALLBACK)[0].first_seen == datetime(
        2025, 10, 27, 8, 0, tzinfo=timezone.utc)
