"""Scheduler: global budgets, round-robin, renderer outage, failure isolation,
status file and stale-source warnings."""

import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from conftest import PDF, FakeGraph, make_feed, test_settings, wire_graph
from engine import timing
from engine.profile import build_profile
from engine.render import RendererUnavailable
from engine.scheduler import Budget, Scheduler
from engine.status import StatusStore, iso
from engine.worker import SourceWorker


class Clock:
    """A controllable clock; sleeping advances it."""

    def __init__(self):
        self.t = 1_800_000_000.0

    def now(self):
        return self.t

    def advance(self, seconds):
        if seconds and seconds > 0:
            self.t += seconds


@pytest.fixture
def clock():
    c = Clock()
    with patch.object(timing, "now", c.now), patch.object(timing, "sleep", c.advance):
        yield c


def _profile(slug, **over):
    entry = {"name": slug.upper(), "author_name": f"{slug} org",
             "feed_urls": [f"https://{slug}.example/feed"],
             "allowed_hosts": [f"{slug}.example"], "request_delay": 0,
             "max_age_days": 0, "poll_interval": 3600}
    entry.update(over)
    return build_profile(slug, entry)


def _link(slug, n):
    return f"https://{slug}.example/post-{n}/"


class Fleet:
    """Several synthetic sources under one Scheduler, sharing one fake graph."""

    def __init__(self, tmp_path, counts, settings=None, render=None, **profile_over):
        self.graph = FakeGraph()
        self.api = MagicMock()
        wire_graph(self.api, self.graph)
        self.api.identity.create.side_effect = lambda **kw: {"id": "org-" + kw["name"]}
        self.api.marking_definition.read.return_value = {"id": "tlp"}
        self.settings = settings or test_settings()
        self.workers = {}
        for slug, n in counts.items():
            p = _profile(slug, **profile_over.get(slug, {}))
            feed = make_feed([_link(slug, i) for i in range(1, n + 1)])
            session = MagicMock()
            session.get.side_effect = (lambda f: lambda url, **k: MagicMock(
                content=f, text="", status_code=200))(feed)
            self.workers[slug] = SourceWorker(p, self.settings, self.api, MagicMock(),
                                              session=session)
        self.log = MagicMock()
        self.status = StatusStore(str(tmp_path / "status.json"))
        self.render = MagicMock(side_effect=render, return_value=PDF)
        self._patch = patch("engine.render.render_live_pdf", self.render)
        self._patch.start()
        self.sched = Scheduler(dict(self.workers), self.settings, self.log, self.status, "cid")
        self.sched.start(self.api)

    def stop(self):
        self._patch.stop()

    def rendered(self):
        return [c.args[0] for c in self.render.call_args_list]

    def due_all(self):
        for w in self.sched.workers.values():
            w.next_due = 0


@pytest.fixture
def fleet(tmp_path, clock):
    made = []

    def make(counts, **kw):
        f = Fleet(tmp_path, counts, **kw)
        made.append(f)
        return f

    yield make
    for f in made:
        f.stop()


def _created(f):
    return f.api.report.create.call_count


# --------------------------------------------------------------------------- #
# Budgets
# --------------------------------------------------------------------------- #

def test_global_report_budget_holds_across_sources(fleet, clock):
    f = fleet({"a": 4, "b": 4, "c": 4}, settings=test_settings(reports_per_cycle=5))
    f.sched.tick()
    assert _created(f) == 5
    # Same window: the budget is spent; due sources write nothing more.
    f.due_all()
    f.sched.tick()
    assert _created(f) == 5
    f.api.work.initiate_work.reset_mock()
    # Next window: the rest are rediscovered (graph dedup) and written.
    clock.advance(1800)
    f.due_all()
    f.sched.tick()
    assert _created(f) == 10
    clock.advance(1800)
    f.due_all()
    f.sched.tick()
    assert _created(f) == 12


def test_budget_spent_items_wait_for_the_next_window(fleet, clock):
    f = fleet({"a": 3}, settings=test_settings(reports_per_cycle=1))
    f.sched.tick()
    w = f.sched.workers["a"]
    assert _created(f) == 1
    assert w.next_due == f.sched.budget.window_end      # sooner than poll_interval
    assert w.next_due < clock.now() + w.profile.poll_interval


def test_per_source_poll_cap(fleet, clock):
    f = fleet({"a": 5, "b": 1}, settings=test_settings(max_reports_per_source_poll=2))
    f.sched.tick()
    by_source = {"a": 0, "b": 0}
    for c in f.api.external_reference.create.call_args_list:
        by_source[c.kwargs["url"].split("//")[1].split(".")[0]] += 1
    assert by_source == {"a": 2, "b": 1}
    # The capped source comes back at the next window to continue.
    assert f.sched.workers["a"].next_due == f.sched.budget.window_end


def test_budget_window_rolls_aligned():
    b = Budget(2, 1800, 0)
    assert b.take() and b.take() and not b.take() and b.spent
    b.roll(1799)
    assert b.spent
    b.roll(1800 * 3 + 5)
    assert not b.spent and b.window_end == 1800 * 4
    b.give_back()
    assert b.used == 0


def test_render_concurrency_is_a_global_cap(fleet, clock):
    lock, state = threading.Lock(), {"now": 0, "max": 0, "per": {}}

    def slow(url, *a, **k):
        slug = url.split("//")[1].split(".")[0]
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
            state["per"][slug] = state["per"].get(slug, 0) + 1
            assert state["per"][slug] == 1, "two renders in flight for one source"
        time.sleep(0.02)
        with lock:
            state["now"] -= 1
            state["per"][slug] -= 1
        return PDF

    f = fleet({"a": 3, "b": 3, "c": 3, "d": 3}, settings=test_settings(render_concurrency=2),
              render=slow)
    f.sched.tick()
    assert _created(f) == 12
    assert state["max"] == 2


def test_round_robin_prevents_one_backlog_starving_others(fleet, clock):
    f = fleet({"a": 6, "b": 2, "c": 1}, settings=test_settings(render_concurrency=1))
    f.sched.tick()
    order = [u.split("//")[1].split(".")[0] for u in f.rendered()]
    assert order[:5] == ["a", "b", "c", "a", "b"]
    assert order.count("a") == 6 and len(order) == 9


def test_request_delay_spaces_one_sources_items(fleet, clock):
    f = fleet({"a": 3}, settings=test_settings(render_concurrency=2),
              a={"request_delay": 30})
    times = []
    f.render.side_effect = lambda *a, **k: (times.append(clock.now()), PDF)[1]
    f.sched.tick()
    assert len(times) == 3
    # The scheduler sleeps out the source's cooldown before its next item
    # (the fake clock moves only when the scheduler sleeps).
    assert [b - a for a, b in zip(times, times[1:])] == [30, 30]


# --------------------------------------------------------------------------- #
# Renderer outage: one shared signal
# --------------------------------------------------------------------------- #

def test_renderer_outage_pauses_all_rendering(fleet, clock):
    down = {"on": True}

    def render(url, *a, **k):
        if down["on"]:
            raise RendererUnavailable("HTTP 503: renderer down")
        return PDF

    f = fleet({"a": 2, "b": 2}, settings=test_settings(render_concurrency=1, render_retries=1),
              render=render)
    f.sched.tick()
    # The first item hit the outage; nothing else was even tried.
    assert f.render.call_count == 1
    assert _created(f) == 0
    assert f.sched.renderer_paused_until == clock.now() + f.settings.renderer_pause_seconds
    # The outage is not the items' fault.
    assert all(not w.transient_failures and not w.permanent_skips
               for w in f.sched.workers.values())
    # During the pause, polls discover and dedup but neither render nor open works.
    f.api.work.initiate_work.reset_mock()
    f.due_all()
    f.sched.tick()
    assert f.render.call_count == 1
    f.api.work.initiate_work.assert_not_called()
    # After the pause, everything is ingested.
    down["on"] = False
    clock.advance(f.settings.renderer_pause_seconds)
    f.due_all()
    f.sched.tick()
    assert _created(f) == 4


def test_outage_poll_is_retried_when_the_pause_ends(fleet, clock):
    f = fleet({"a": 1}, settings=test_settings(render_retries=1),
              render=RendererUnavailable("down"))
    f.sched.tick()
    assert f.sched.workers["a"].next_due == f.sched.renderer_paused_until
    closed = f.api.work.to_processed.call_args
    assert closed.kwargs["in_error"] is True


# --------------------------------------------------------------------------- #
# Failure isolation
# --------------------------------------------------------------------------- #

def test_failing_source_backs_off_without_stopping_the_rest(fleet, clock):
    f = fleet({"a": 2, "b": 2})
    a = f.sched.workers["a"]
    a.discover = MagicMock(side_effect=RuntimeError("parser exploded"))
    start = clock.now()
    f.sched.tick()
    assert _created(f) == 2                                   # b unaffected
    assert a.next_due == start + 2 * 3600                     # doubled
    assert "Traceback" in a.log.log_error.call_args.args[0]
    for expected in (4 * 3600, 6 * 3600, 6 * 3600):           # doubling, capped at 6h
        clock.t = a.next_due
        f.sched.tick()
        assert a.next_due == clock.now() + expected
    # Recovery resets the backoff.
    a.discover = MagicMock(return_value=[])
    clock.t = a.next_due
    f.sched.tick()
    assert a.crashes == 0 and a.next_due == clock.now() + 3600


def test_a_crash_in_one_items_write_is_contained(fleet, clock):
    f = fleet({"a": 2, "b": 1})
    real = f.api.report.create.side_effect
    calls = {"n": 0}

    def flaky(**kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("API 500")
        return real(**kw)

    f.api.report.create.side_effect = flaky
    f.sched.tick()
    assert len(f.graph.created()) == 2
    failed = [w for w in f.sched.workers.values() if w.transient_failures]
    assert len(failed) == 1


def test_due_sources_oldest_first(fleet, clock):
    f = fleet({"a": 0, "b": 0, "c": 0})
    ws = f.sched.workers
    ws["a"].next_due, ws["b"].next_due, ws["c"].next_due = 30, 10, clock.now() + 99
    assert [w.profile.slug for w in f.sched.due(clock.now())] == ["b", "a"]


# --------------------------------------------------------------------------- #
# Observability: works, summaries, status file, stale warning
# --------------------------------------------------------------------------- #

def test_works_named_per_source_and_summary_lines(fleet, clock):
    f = fleet({"a": 1, "b": 0})
    f.sched.tick()
    f.api.work.initiate_work.assert_called_once_with("cid", "A poll")
    line = f.sched.workers["a"].log.log_info.call_args_list[-1].args[0]
    for part in ("discovered 1", "in scope 1", "already ingested 0", "created 1",
                 "(0 without PDF)", "transient 0", "skipped permanently 0"):
        assert part in line
    cycle = f.log.log_info.call_args.args[0]
    assert cycle.startswith("Cycle: 2 sources polled, 1 Reports written")
    assert "render queue depth 0" in cycle


def test_status_file(fleet, clock, tmp_path):
    f = fleet({"a": 1, "b": 1})
    f.sched.workers["b"].session.get.side_effect = ConnectionError("down")
    f.sched.tick()
    data = json.loads((tmp_path / "status.json").read_text())
    a, b = data["sources"]["a"], data["sources"]["b"]
    assert a["state"] == "running" and a["last_outcome"] == "ok"
    assert a["last_report"] == iso(clock.now()) and a["consecutive_failures"] == 0
    assert a["next_due"] == iso(clock.now() + 3600)
    assert b["last_outcome"] == "feed-failed" and b["consecutive_failures"] == 1
    assert "last_report" not in b


def test_stale_source_warns_once_a_day(fleet, clock):
    f = fleet({"a": 0}, a={"stale_after_days": 7})
    w = f.sched.workers["a"]
    f.status.entry("a")["last_report"] = iso(clock.now() - 8 * 86400)
    f.sched.tick()
    stale = [c for c in w.log.log_warning.call_args_list if "No new Report" in str(c)]
    assert len(stale) == 1
    clock.advance(3600)
    f.due_all()
    f.sched.tick()
    assert len([c for c in w.log.log_warning.call_args_list if "No new Report" in str(c)]) == 1
    clock.advance(86400)
    f.due_all()
    f.sched.tick()
    assert len([c for c in w.log.log_warning.call_args_list if "No new Report" in str(c)]) == 2


def test_recent_report_is_not_stale(fleet, clock):
    f = fleet({"a": 0})
    f.status.entry("a")["last_report"] = iso(clock.now() - 86400)
    f.sched.tick()
    assert not any("No new Report" in str(c)
                   for c in f.sched.workers["a"].log.log_warning.call_args_list)


def test_source_that_cannot_resolve_its_marking_does_not_start(tmp_path, clock):
    api = MagicMock()
    api.marking_definition.read.side_effect = lambda filters: (
        None if filters["filters"][0]["values"] == ["TLP:RED"] else {"id": "m"})
    api.identity.create.return_value = {"id": "a"}
    ws = {s: SourceWorker(_profile(s, **({"tlp": "TLP:RED"} if s == "bad" else {})),
                          test_settings(), api, MagicMock(), session=MagicMock())
          for s in ("good", "bad")}
    status = StatusStore(str(tmp_path / "s.json"))
    sched = Scheduler(ws, test_settings(), MagicMock(), status)
    sched.start(api)
    assert set(sched.workers) == {"good"}
    assert status.sources["bad"]["state"] == "failed-start"
