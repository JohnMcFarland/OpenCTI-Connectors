"""Run/state semantics: per-search cursor, failure isolation, rolling-window identity
and dedup, window splitting when a job hits max_results, and the entrypoint."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

pytest.importorskip("pycti")

from src import connector as mod  # noqa: E402
from src import main as main_mod  # noqa: E402
from src.searches import SearchDef  # noqa: E402
from src.splunk_client import JobResult, SplunkJobTimeout  # noqa: E402

NOW = 1_000_000
LATEST = NOW - 300
INITIAL = LATEST - 86400


class FakeHelper:
    def __init__(self, state=None):
        self.state = state
        self.connector_logger = MagicMock()
        self.api = MagicMock()
        self.connect_id = "c"
        self.bundles: list[str] = []

    def get_state(self):
        return self.state

    def set_state(self, s):
        self.state = json.loads(json.dumps(s))  # platform state is JSON

    def send_stix2_bundle(self, bundle, **kw):
        self.bundles.append(bundle)


@pytest.fixture
def make(monkeypatch):
    monkeypatch.setattr(mod.time, "time", lambda: NOW)

    def _make(searches, handler, state=None):
        helper = FakeHelper(state)
        c = mod.SplunkConnector.__new__(mod.SplunkConnector)
        c.helper = helper
        c.settings = MagicMock(splunk_ingest_lag_seconds=300, splunk_initial_lookback="-24h")
        c.known_names = {s.name for s in searches}
        c.searches = [s for s in searches if s.enabled]
        c.lookup = MagicMock()
        c.builder = MagicMock()
        c.builder.build.side_effect = lambda search, case: [
            {"type": "case-incident", "name": case.title, "created": case.first_seen.isoformat()}]
        c.client = MagicMock()
        calls = []

        def run_search(spl, app, earliest, latest, time_mode, max_results, fields):
            calls.append((spl, earliest, latest))
            return handler(spl, earliest, latest, max_results)
        c.client.run_search.side_effect = run_search
        return c, helper, calls
    return _make


ROW = {"_time": "999000", "event_id": "e1"}


def _sent(helper):
    return [json.loads(b)["objects"][0] for b in helper.bundles]


def test_cursor_advances_and_failures_are_isolated(make):
    ok = SearchDef(name="ok", spl="search ok", group_by=["event_id"])
    bad = SearchDef(name="bad", spl="search bad")
    off = SearchDef(name="off", spl="search off", enabled=False)

    def handler(spl, *_):
        if spl == "search bad":
            raise RuntimeError("boom")
        return JobResult([ROW])

    c, helper, calls = make([ok, bad, off], handler,
                            state={"searches": {"gone": {"cursor": "1"}, "off": {"cursor": "5"},
                                                "ok": {"cases": {"stale": ["t", "x", "y"]}}}})
    c.process()
    assert calls == [("search ok", INITIAL, LATEST), ("search bad", INITIAL, LATEST)]
    st = helper.state["searches"]
    assert st["ok"] == {"cursor": str(LATEST)}  # cursor mode keeps no per-case state
    assert st["bad"]["cursor"] == str(INITIAL)  # kept at its start, not advanced
    assert "gone" not in st  # removed from the file
    assert st["off"] == {"cursor": "5"}  # disabled keeps its cursor
    assert len(helper.bundles) == 1
    c.lookup.begin_run.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True

    # Next run resumes from the cursor for ok; the window is empty, so no job.
    calls.clear()
    c.process()
    assert calls == [("search bad", INITIAL, LATEST)]


def test_rolling_window_skips_unchanged_and_resends_changed(make):
    rolling = SearchDef(name="r", spl="search r", group_by=["event_id"], lookback="-7d",
                        observables={"src": "ip"})
    rows = [{"_time": "999000", "event_id": "e1", "src": "1.1.1.1"}]
    c, helper, calls = make([rolling], lambda *_: JobResult(list(rows)))
    c.process()
    c.process()
    assert [call[1] for call in calls] == [LATEST - 7 * 86400] * 2
    assert len(helper.bundles) == 1  # unchanged -> not re-sent

    rows.append({"_time": "999100", "event_id": "e1", "src": "2.2.2.2"})
    c.process()
    assert len(helper.bundles) == 2  # changed -> re-sent
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is False
    title, created, _fp, last_returned, _sev = helper.state["searches"]["r"]["cases"]["e1"]
    assert created.startswith("1970-01-12") and last_returned == LATEST


def test_rolling_case_keeps_identity_when_oldest_row_ages_out(make):
    rolling = SearchDef(name="r", spl="search r", group_by=["event_id"], lookback="-7d",
                        title="{rule} ({event_id})")
    rows = [{"_time": "990000", "event_id": "e1", "rule": "first"},
            {"_time": "995000", "event_id": "e1", "rule": "second"}]
    c, helper, _ = make([rolling], lambda *_: JobResult(list(rows)))
    c.process()
    rows.pop(0)  # the oldest row leaves the rolling window
    c.process()
    first, second = _sent(helper)
    assert (first["name"], first["created"]) == (second["name"], second["created"])
    assert first["name"] == "first (e1)"


def test_cursor_never_moves_backwards(make):
    s = SearchDef(name="s", spl="search s")
    ahead = str(LATEST + 500)  # e.g. ingest lag was raised since the last run
    c, helper, calls = make([s], lambda *_: JobResult([ROW]),
                            state={"searches": {"s": {"cursor": ahead}}})
    c.process()
    assert calls == [] and helper.state["searches"]["s"]["cursor"] == ahead


def test_rolling_untimed_rows_are_not_resent(make, monkeypatch):
    rolling = SearchDef(name="r", spl="| stats count by src", group_by=["src"],
                        lookback="-1d")
    c, helper, _ = make([rolling], lambda *_: JobResult([{"src": "1.1.1.1", "count": "3"}]))
    c.process()
    monkeypatch.setattr(mod.time, "time", lambda: NOW + 900)  # next run, later clock
    c.process()
    assert len(helper.bundles) == 1


def test_truncated_window_is_split_until_it_fits(make):
    s = SearchDef(name="s", spl="search s", max_results=2)
    # 4 rows spread across the window; any sub-window holding >2 is truncated.
    times = [INITIAL + 10, INITIAL + 20, LATEST - 20, LATEST - 10]

    def handler(spl, lo, hi, cap):
        inside = [{"_time": str(t), "n": str(t)} for t in times if lo <= t < hi]
        if len(inside) > cap:
            return JobResult([], truncated=True)
        return JobResult(inside)

    c, helper, calls = make([s], handler)
    c.process()
    assert len(calls) == 3  # full window, then both halves
    assert len(helper.bundles) == 4  # every row imported, ungrouped -> one case each
    assert helper.state["searches"]["s"]["cursor"] == str(LATEST)


def test_window_that_never_fits_fails_without_advancing(make):
    s = SearchDef(name="s", spl="| inputlookup big", max_results=1)
    c, helper, calls = make([s], lambda *_: JobResult([], truncated=True))
    c.process()
    # Splits depth-first down to a 1-second window, then gives up; never past the budget.
    assert 1 < len(calls) <= mod._MAX_JOBS_PER_SEARCH
    assert helper.bundles == []
    assert helper.state["searches"]["s"]["cursor"] == str(INITIAL)
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_job_budget_is_enforced(make, monkeypatch):
    monkeypatch.setattr(mod, "_MAX_JOBS_PER_SEARCH", 3)
    s = SearchDef(name="s", spl="| inputlookup big", max_results=1)
    c, helper, calls = make([s], lambda *_: JobResult([], truncated=True))
    c.process()
    assert len(calls) == 3
    assert "3 jobs" in str(helper.connector_logger.error.call_args)


def test_one_second_window_over_cap_fails(make):
    s = SearchDef(name="s", spl="search s", max_results=1)
    c, helper, calls = make([s], lambda *_: JobResult([], truncated=True),
                            state={"searches": {"s": {"cursor": str(LATEST - 1)}}})
    c.process()
    assert len(calls) == 1
    assert helper.state["searches"]["s"]["cursor"] == str(LATEST - 1)


def test_run_checks_splunk_then_prepares_then_schedules(make):
    c, helper, _ = make([], lambda *_: JobResult([]))
    helper.schedule_iso = MagicMock()
    c.client.check.return_value = "9.3.1"
    c.run()
    c.builder.prepare.assert_called_once()
    helper.schedule_iso.assert_called_once()
    assert helper.schedule_iso.call_args.kwargs["message_callback"] == c.process


def test_main_validates_searches_before_registering(monkeypatch):
    settings = MagicMock(splunk_searches_file="s.yml", connector_id="cid",
                         connector_name="Splunk", connector_scope="incident",
                         connector_duration_period="PT15M", connector_log_level="info")
    monkeypatch.setattr(main_mod, "load_settings", lambda: settings)
    monkeypatch.setattr(main_mod, "load_searches", lambda path: ["search-def"])
    helper_cls = MagicMock()
    connector_cls = MagicMock()
    monkeypatch.setattr(main_mod, "OpenCTIConnectorHelper", helper_cls)
    monkeypatch.setattr(main_mod, "SplunkConnector", connector_cls)
    main_mod.main()
    conf = helper_cls.call_args.args[0]
    assert conf["connector"]["type"] == "EXTERNAL_IMPORT"
    assert conf["connector"]["id"] == "cid"
    connector_cls.assert_called_once_with(helper_cls.return_value, settings, ["search-def"])
    connector_cls.return_value.run.assert_called_once()

    def bad(path):
        raise ValueError("bad searches")
    monkeypatch.setattr(main_mod, "load_searches", bad)
    helper_cls.reset_mock()
    with pytest.raises(ValueError):
        main_mod.main()
    helper_cls.assert_not_called()  # never registers with a broken searches file


def _dense(times):
    def handler(spl, lo, hi, cap):
        inside = [{"_time": str(t), "n": str(t)} for t in times if lo <= t < hi]
        return JobResult([], truncated=True) if len(inside) > cap else JobResult(inside)
    return handler


def test_backlog_drains_over_runs_instead_of_stalling(make, monkeypatch):
    monkeypatch.setattr(mod, "_MAX_JOBS_PER_SEARCH", 6)
    s = SearchDef(name="s", spl="search s", max_results=1)
    times = list(range(INITIAL, LATEST, 8640))  # 10 evenly spread rows, 1 per job fits
    c, helper, _ = make([s], _dense(times))

    c.process()
    first_cursor = int(helper.state["searches"]["s"]["cursor"])
    assert INITIAL < first_cursor < LATEST  # progress, not a stall
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is False
    assert "partly imported" in str(helper.connector_logger.warning.call_args)
    sent = len(helper.bundles)
    assert 0 < sent < len(times)

    for _ in range(40):  # later runs resume from the boundary until the backlog is gone
        c.process()
    assert helper.state["searches"]["s"]["cursor"] == str(LATEST)
    imported = [json.loads(b)["objects"][0]["created"] for b in helper.bundles]
    assert len(imported) == len(set(imported)) == len(times)  # each row exactly once


def test_partial_window_never_skips_past_incomplete_rows(make, monkeypatch):
    monkeypatch.setattr(mod, "_MAX_JOBS_PER_SEARCH", 6)
    s = SearchDef(name="s", spl="search s", max_results=1)
    times = list(range(INITIAL, LATEST, 8640))
    c, helper, _ = make([s], _dense(times))
    c.process()
    cursor = int(helper.state["searches"]["s"]["cursor"])
    assert len(helper.bundles) == sum(t < cursor for t in times)  # everything before it


def test_rolling_search_over_budget_fails_rather_than_half_imports(make, monkeypatch):
    monkeypatch.setattr(mod, "_MAX_JOBS_PER_SEARCH", 6)
    s = SearchDef(name="s", spl="search s", max_results=1, lookback="-1d")
    c, helper, _ = make([s], _dense(list(range(INITIAL, LATEST, 8640))))
    c.process()
    assert helper.bundles == []
    assert "cases" not in helper.state["searches"]["s"]
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_rolling_case_resent_once_its_technique_loads(make):
    s = SearchDef(name="r", spl="search r", group_by=["event_id"], lookback="-1d",
                  attack_pattern_fields=["mitre"])
    row = {"_time": "999000", "event_id": "e1", "mitre": "T1059"}
    c, helper, _ = make([s], lambda *_: JobResult([row]))
    c.lookup.attack_pattern.return_value = None
    c.process()
    c.process()
    assert len(helper.bundles) == 1
    c.lookup.attack_pattern.return_value = "attack-pattern--1"
    c.process()
    assert len(helper.bundles) == 2


def test_init_wires_enabled_searches_and_remembers_disabled(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(mod, "SplunkClient", client)
    monkeypatch.setattr(mod, "SplunkStixBuilder", MagicMock())
    on = SearchDef(name="on", spl="search a")
    off = SearchDef(name="off", spl="search b", enabled=False)
    helper, settings = MagicMock(), MagicMock()
    c = mod.SplunkConnector(helper, settings, [on, off])
    assert c.searches == [on] and c.known_names == {"on", "off"}
    client.assert_called_once_with(settings, helper.connector_logger)


def test_rolling_failed_send_keeps_what_went_out_and_retries_the_rest(make):
    rolling = SearchDef(name="r", spl="search r", group_by=["event_id"], lookback="-1d")
    rows = [{"_time": "999000", "event_id": "e1"}, {"_time": "999000", "event_id": "e2"}]
    c, helper, _ = make([rolling], lambda *_: JobResult(rows))
    good = c.builder.build.side_effect

    def fail_on_e2(search, case):
        if case.key == "e2":
            raise RuntimeError("bundle rejected")
        return good(search, case)
    c.builder.build.side_effect = fail_on_e2
    c.process()
    st = helper.state["searches"]["r"]
    assert list(st["cases"]) == ["e1"] and "cursor" not in st
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True

    c.builder.build.side_effect = good
    c.process()
    assert len(helper.bundles) == 2  # e1 not sent twice
    assert set(helper.state["searches"]["r"]["cases"]) == {"e1", "e2"}


def test_rolling_empty_run_does_not_forget_cases(make):
    rolling = SearchDef(name="r", spl="search r", group_by=["event_id"], lookback="-1d")
    rows = [ROW]
    c, helper, _ = make([rolling], lambda *_: JobResult(list(rows)))
    c.process()
    rows.clear()
    c.process()
    assert list(helper.state["searches"]["r"]["cases"]) == ["e1"]


def test_rolling_forgets_a_group_a_whole_window_after_it_last_appeared(make, monkeypatch):
    rolling = SearchDef(name="r", spl="search r", group_by=["event_id"], lookback="-1d")
    rows = [ROW]
    c, helper, _ = make([rolling], lambda *_: JobResult(list(rows)))
    c.process()
    rows.clear()
    monkeypatch.setattr(mod.time, "time", lambda: NOW + 86401)
    c.process()
    assert helper.state["searches"]["r"]["cases"] == {}


def test_cursor_retry_keeps_the_id_of_untimed_cases(make, monkeypatch):
    s = SearchDef(name="s", spl="| stats count by src", group_by=["src"])
    rows = [{"src": "a", "count": "1"}, {"src": "b", "count": "2"}]
    c, helper, _ = make([s], lambda *_: JobResult(rows))
    good = c.builder.build.side_effect

    def fail_on_b(search, case):
        if case.key == "b":
            raise RuntimeError("bundle rejected")
        return good(search, case)
    c.builder.build.side_effect = fail_on_b
    c.process()
    assert helper.state["searches"]["s"]["cursor"] == str(INITIAL)

    c.builder.build.side_effect = good
    monkeypatch.setattr(mod.time, "time", lambda: NOW + 900)  # the retry runs later
    c.process()
    sent = _sent(helper)
    assert len(sent) == 3  # a; then a again and b
    a_first, a_retry = [o for o in sent if o["name"].endswith(": a")]
    assert a_first["created"] == a_retry["created"]  # same id, not a duplicate case


def _slow_until(span):
    """Jobs over a window wider than `span` seconds time out."""
    def handler(spl, lo, hi, cap):
        if hi - lo > span:
            raise SplunkJobTimeout("Job 1 exceeded 900s")
        return JobResult([{"_time": str(lo), "n": str(lo)}])
    return handler


def test_slow_window_is_split_instead_of_growing_forever(make):
    s = SearchDef(name="s", spl="search s")
    c, helper, calls = make([s], _slow_until(50000))
    c.process()
    assert len(calls) == 3  # one timeout, then both halves
    assert helper.state["searches"]["s"]["cursor"] == str(LATEST)
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is False


def test_timeouts_are_budgeted_and_partial_progress_is_kept(make):
    s = SearchDef(name="s", spl="search s")

    def handler(spl, lo, hi, cap):
        if lo >= INITIAL + 40000 or hi - lo > 30000:
            raise SplunkJobTimeout("Job 1 exceeded 900s")
        return JobResult([{"_time": str(lo), "n": str(lo)}])

    c, helper, calls = make([s], handler)
    c.process()
    cursor = int(helper.state["searches"]["s"]["cursor"])
    assert INITIAL < cursor < LATEST  # kept what finished, stopped at the budget
    assert sum(1 for _ in calls) <= mod._MAX_JOBS_PER_SEARCH
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is False


def test_endless_timeouts_fail_after_the_timeout_budget(make):
    s = SearchDef(name="s", spl="search s")
    c, helper, calls = make([s], _slow_until(0))
    c.process()
    assert len(calls) == mod._MAX_TIMEOUTS_PER_SEARCH  # never 32 full job timeouts
    assert helper.state["searches"]["s"]["cursor"] == str(INITIAL)
    assert "SPLUNK_JOB_TIMEOUT" in str(helper.connector_logger.error.call_args)


def test_slow_backlog_drains_instead_of_retrying_the_same_windows(make, monkeypatch):
    week = 7 * 86400
    s = SearchDef(name="s", spl="search s")
    calls_per_run = []
    state = {"searches": {"s": {"cursor": str(LATEST - week)}}}
    c, helper, calls = make([s], _slow_until(6 * 3600), state=state)  # only <= 6h finishes
    for _ in range(12):
        calls.clear()
        c.process()
        calls_per_run.append(len(calls))
        if helper.state["searches"]["s"]["cursor"] == str(LATEST):
            break
    assert helper.state["searches"]["s"]["cursor"] == str(LATEST)  # fully caught up
    assert max(calls_per_run) <= mod._MAX_JOBS_PER_SEARCH
    assert helper.connector_logger.error.call_count < 6


def test_each_failed_run_narrows_the_next_one(make):
    s = SearchDef(name="s", spl="search s")
    c, helper, calls = make([s], _slow_until(1000))
    c.process()
    first = calls[0][2] - calls[0][1]
    assert helper.state["searches"]["s"]["cursor"] == str(INITIAL)  # nothing finished
    calls.clear()
    c.process()
    assert calls[0][2] - calls[0][1] < first / 4  # starts past where the last run stopped


def test_truncation_is_learned_so_resumed_runs_do_not_rebisect(make):
    s = SearchDef(name="s", spl="search s", max_results=2)
    times = list(range(INITIAL, LATEST, 21600))  # 4 rows
    c, helper, calls = make([s], _dense(times))
    c.process()
    assert len(calls) == 3  # full window truncated, then both halves
    assert helper.state["searches"]["s"]["span"] == 43200  # the half that fit

    helper.state["searches"]["s"]["cursor"] = str(INITIAL)  # same backlog again
    calls.clear()
    c.process()
    assert len(calls) == 2  # straight to the size that fits, no truncated job


def test_span_grows_back_and_clears_when_healthy(make):
    s = SearchDef(name="s", spl="search s")
    state = {"searches": {"s": {"cursor": str(INITIAL), "span": 21600}}}
    c, helper, calls = make([s], lambda *_: JobResult([]), state=state)
    c.process()
    assert len(calls) == 4  # the window cut into the remembered size, oldest first
    assert [call[1] for call in calls] == sorted(call[1] for call in calls)
    assert calls[-1][2] == LATEST
    assert helper.state["searches"]["s"]["span"] == 43200  # doubled after a clean run

    helper.state["searches"]["s"].update(cursor=str(LATEST - 900), span=600)
    c.process()
    assert "span" not in helper.state["searches"]["s"]  # 2 x 600 covers the whole window


def test_windows_cover_the_range_exactly_once():
    parts = mod._windows(100, 355, 100)[::-1]  # the stack, oldest first
    assert parts == [(100, 200), (200, 300), (300, 355)]
    assert mod._windows(100, 355, None) == [(100, 355)]


def test_windows_never_build_more_parts_than_a_run_can_use():
    parts = mod._windows(0, 30 * 86400, 1)
    assert len(parts) == mod._MAX_JOBS_PER_SEARCH + 1
    assert parts[-1] == (0, 1) and parts[0][1] == 30 * 86400  # still covers everything


def test_job_error_keeps_the_parts_already_finished(make):
    s = SearchDef(name="s", spl="search s")
    state = {"searches": {"s": {"cursor": str(INITIAL), "span": 21600}}}

    def handler(spl, lo, hi, cap):
        if lo >= INITIAL + 2 * 21600:
            raise RuntimeError("HTTP 500")
        return JobResult([{"_time": str(lo), "n": str(lo)}])

    c, helper, calls = make([s], handler, state=state)
    c.process()
    assert len(helper.bundles) == 2
    assert helper.state["searches"]["s"]["cursor"] == str(INITIAL + 2 * 21600)
    assert helper.state["searches"]["s"]["span"] == 21600  # not grown by a failed run
    assert "HTTP 500" in str(helper.connector_logger.warning.call_args)

    c.process()  # now the first part fails: a real error, shown as one
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True
    assert helper.state["searches"]["s"]["cursor"] == str(INITIAL + 2 * 21600)
    assert len(helper.bundles) == 2


def test_job_error_in_a_rolling_search_fails_it(make):
    s = SearchDef(name="s", spl="search s", group_by=["n"], lookback="-1d")

    def handler(spl, lo, hi, cap):
        raise RuntimeError("HTTP 500")

    c, helper, _ = make([s], handler, state={"searches": {"s": {"span": 21600}}})
    c.process()
    assert helper.bundles == []
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


@pytest.mark.parametrize("span, failed, errored, expected", [
    (None, 1000, False, 500),  # half the smallest failure
    (800, 1000, False, 500),   # a failure overrides the old size
    (None, 1, False, 1),       # floor
    (None, 0, False, None),    # clean run, no hint: nothing to remember
    (100, 0, False, 200),      # every job worked: grow, even if the budget ran out
    (600, 0, False, None),     # grown past the window: forget
    (500, 0, False, None),     # exactly the window: forget
    (100, 0, True, 100),       # Splunk down: proves nothing, must not inflate it
])
def test_learn_span(span, failed, errored, expected):
    st = {"span": span} if span else {}
    mod._learn_span(st, span, failed, errored, 1000)
    assert st.get("span") == expected


class Clock:
    """Runs the connector on its 15-minute schedule, with the clock really moving."""

    def __init__(self, monkeypatch, start=NOW):
        self.now = start
        monkeypatch.setattr(mod.time, "time", lambda: self.now)

    def runs(self, c, n):
        for _ in range(n):
            c.process()
            self.now += 900


def _lag(helper, clock):
    return clock.now - 900 - 300 - int(helper.state["searches"]["s"]["cursor"])


def test_cursor_search_catches_up_after_splunk_hangs(make, monkeypatch):
    clock = Clock(monkeypatch)
    hung = [True]

    def handler(spl, lo, hi, cap):
        if hung[0]:
            raise SplunkJobTimeout("Job 1 exceeded 900s")
        return JobResult([])

    s = SearchDef(name="s", spl="search s")
    c, helper, _ = make([s], handler, state={"searches": {"s": {"cursor": str(LATEST - 900)}}})
    clock.runs(c, 3)
    assert helper.state["searches"]["s"]["span"] < 10  # the hang drove it right down
    hung[0] = False
    clock.runs(c, 20)
    assert _lag(helper, clock) == 0
    assert "span" not in helper.state["searches"]["s"]  # back to one job per run


def test_cursor_search_recovers_from_a_short_log_storm(make, monkeypatch):
    clock = Clock(monkeypatch)
    storm = range(LATEST + 1000, LATEST + 1020)  # 20 dense seconds

    def handler(spl, lo, hi, cap):
        hits = sum(1 for t in storm if lo <= t < hi) * 600
        if hits > cap:
            return JobResult([], truncated=True)
        return JobResult([{"_time": str(t), "n": f"{t}.{i}"} for t in storm if lo <= t < hi
                          for i in range(600)])

    s = SearchDef(name="s", spl="search s", group_by=["n"])
    c, helper, _ = make([s], handler, state={"searches": {"s": {"cursor": str(LATEST)}}})
    clock.runs(c, 25)
    assert _lag(helper, clock) == 0
    assert "span" not in helper.state["searches"]["s"]


def test_rolling_search_recovers_after_splunk_hangs(make, monkeypatch):
    clock = Clock(monkeypatch)
    hung = [True]

    def handler(spl, lo, hi, cap):
        if hung[0]:
            raise SplunkJobTimeout("Job 1 exceeded 900s")
        return JobResult([{"_time": str(lo), "event_id": str(lo)}] if lo == hi - 1 else [])

    s = SearchDef(name="s", spl="search s", group_by=["event_id"], lookback="-7d")
    c, helper, calls = make([s], handler)
    clock.runs(c, 5)
    assert helper.state["searches"]["s"]["span"] < 7 * 86400 / 32  # below what can finish
    hung[0] = False
    calls.clear()
    clock.runs(c, 1)
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is False
    assert len(calls) <= mod._MAX_JOBS_PER_SEARCH  # the floor keeps it inside one run


def test_outage_errors_leave_the_span_alone(make, monkeypatch):
    clock = Clock(monkeypatch)
    s = SearchDef(name="s", spl="search s")

    def handler(spl, lo, hi, cap):
        raise RuntimeError("connection refused")

    c, helper, _ = make([s], handler,
                        state={"searches": {"s": {"cursor": str(LATEST), "span": 3600}}})
    clock.runs(c, 6)
    assert helper.state["searches"]["s"]["span"] == 3600


def test_rolling_span_settles_instead_of_refailing_every_other_run(make, monkeypatch):
    clock = Clock(monkeypatch)

    def handler(spl, lo, hi, cap):
        if hi - lo > 129600:  # only jobs up to 1.5 days finish
            raise SplunkJobTimeout("Job 1 exceeded 900s")
        return JobResult([])

    s = SearchDef(name="s", spl="search s", group_by=["n"], lookback="-7d")
    c, helper, _ = make([s], handler)
    results = []
    for _ in range(64):
        clock.runs(c, 1)
        results.append(helper.api.work.to_processed.call_args.kwargs["in_error"])
    assert sum(results[8:]) <= 4  # one failed probe per 16 clean runs at most
    assert "span" in helper.state["searches"]["s"]  # it did not forget what works


def test_rolling_span_still_recovers_fully_once_splunk_is_fast(make, monkeypatch):
    clock = Clock(monkeypatch)
    s = SearchDef(name="s", spl="search s", group_by=["n"], lookback="-7d")
    state = {"searches": {"s": {"span": 18900}}}  # the floor, left behind by an outage
    c, helper, calls = make([s], lambda *_: JobResult([]), state=state)
    clock.runs(c, 16 * 6)
    assert "span" not in helper.state["searches"]["s"]
    calls.clear()
    clock.runs(c, 1)
    assert len(calls) == 1  # back to one job per run


def test_huge_live_rolling_search_keeps_every_pin_and_warns(make, monkeypatch):
    monkeypatch.setattr(mod, "_CASES_CAP", 2)
    s = SearchDef(name="s", spl="search s", group_by=["event_id"], lookback="-1d")
    rows = [{"_time": "999000", "event_id": f"e{i}"} for i in range(3)]
    c, helper, _ = make([s], lambda *_: JobResult(rows))
    c.process()
    c.process()
    assert len(helper.state["searches"]["s"]["cases"]) == 3
    assert len(helper.bundles) == 3  # the second run re-sent nothing
    assert "more groups than expected" in str(helper.connector_logger.warning.call_args)


def test_failure_restarts_the_rolling_probe_count():
    st = {"span": 100, "clean_runs": 5}
    mod._learn_span(st, 100, 300, False, 1000, rolling=True)
    assert st == {"span": 150}


def test_rolling_probe_waits_for_enough_clean_runs():
    st = {"span": 100}
    for _ in range(mod._ROLLING_PROBE_RUNS - 1):
        mod._learn_span(st, 100, 0, False, 10000, rolling=True)
    assert st["span"] == 100
    mod._learn_span(st, 100, 0, False, 10000, rolling=True)
    assert st == {"span": 200}


def test_two_second_window_is_still_split(make):
    s = SearchDef(name="s", spl="search s", max_results=1)
    t = LATEST - 2

    def handler(spl, lo, hi, cap):
        return JobResult([], truncated=True) if hi - lo == 2 else JobResult(
            [{"_time": str(lo), "n": str(lo)}])

    c, helper, calls = make([s], handler, state={"searches": {"s": {"cursor": str(t)}}})
    c.process()
    assert [(lo, hi) for _, lo, hi in calls] == [(t, t + 2), (t, t + 1), (t + 1, t + 2)]
    assert len(helper.bundles) == 2


def test_rolling_send_outage_longer_than_the_window_keeps_the_case(make, monkeypatch):
    clock = Clock(monkeypatch)
    s = SearchDef(name="s", spl="search s", group_by=["event_id"], lookback="-1h",
                  title="{rule} ({event_id})")
    rows = [{"_time": str(LATEST - 1800), "event_id": "e1", "rule": "first"}]
    c, helper, _ = make([s], lambda *_: JobResult(list(rows)))
    good = c.builder.build.side_effect
    clock.runs(c, 1)

    c.builder.build.side_effect = RuntimeError("OpenCTI down")
    rows[0] = {"_time": str(clock.now), "event_id": "e1", "rule": "second"}
    clock.runs(c, 10)  # 2.5 hours, far longer than the lookback

    c.builder.build.side_effect = good
    rows[0]["_time"] = str(clock.now - 600)
    clock.runs(c, 1)
    sent = _sent(helper)
    assert len(sent) == 2 and sent[0]["name"] == sent[1]["name"] == "first (e1)"
    assert sent[0]["created"] == sent[1]["created"]  # the same case, not a second one


def test_progress_is_handed_to_the_helper_after_each_search(make):
    first = SearchDef(name="a", spl="search a")
    second = SearchDef(name="b", spl="search b")
    seen = {}

    def handler(spl, *_):
        if spl == "search b":
            seen["a"] = holder[0].state["searches"]["a"]["cursor"]
        return JobResult([])

    c, helper, _ = make([first, second], handler)
    holder = [helper]
    c.process()
    assert seen["a"] == str(LATEST)  # recorded before the next search started
