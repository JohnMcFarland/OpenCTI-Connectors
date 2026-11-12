"""AGG_DRY_RUN=true writes nothing to OpenCTI (mocked client)."""

from unittest.mock import MagicMock, patch

from conftest import LIVE, PROFILES, FakeGraph, make_feed, test_settings, wire_graph
from engine import timing
from engine.scheduler import Scheduler
from engine.settings import EngineSettings
from engine.status import StatusStore
from engine.worker import SourceWorker

# The only client calls a dry run may make: reads.
READS = {"external_reference.list", "report.list", "marking_definition.read"}


def _links(slug, n):
    host = sorted(PROFILES[slug].allowed_hosts)[0]
    return [f"https://{host}/dry/article-{i}/" for i in range(1, n + 1)]


def test_dry_run_setting_from_environment():
    assert EngineSettings.from_env({"AGG_DRY_RUN": "true"}).dry_run is True
    assert EngineSettings.from_env({"AGG_DRY_RUN": "false"}).dry_run is False
    assert EngineSettings.from_env({}).dry_run is False


def test_dry_run_writes_nothing(tmp_path):
    graph = FakeGraph()
    api = MagicMock()
    wire_graph(api, graph)
    api.marking_definition.read.return_value = {"id": "m"}
    settings = test_settings(dry_run=True)
    workers, feeds = {}, {}
    for slug in LIVE:
        links = _links(slug, 3)
        graph.add_ingested(links[0])            # one already ingested by the old connector
        feeds[slug] = links
        session = MagicMock()
        session.get.side_effect = (lambda f: lambda url, **k: MagicMock(
            content=f, text="", status_code=200))(make_feed(links))
        workers[slug] = SourceWorker(PROFILES[slug], settings, api, MagicMock(), session=session)
    sched = Scheduler(dict(workers), settings, MagicMock(), StatusStore(str(tmp_path / "s.json")))
    with patch("engine.render.render_live_pdf") as render, \
         patch("engine.report.classify_report") as classify, \
         patch.object(timing, "sleep"):
        sched.start(api)
        sched.tick()
        for w in sched.workers.values():
            w.next_due = 0
        sched.tick()                           # second poll: nothing logged twice

    called = {name for name, _args, _kw in api.method_calls}
    assert called <= READS, f"dry run called {sorted(called - READS)}"
    render.assert_not_called()
    classify.assert_not_called()
    assert graph.created() == set()
    assert set(sched.workers) == set(LIVE)     # every live source ran

    # What would be created: the new URLs only, each logged once.
    for slug, w in workers.items():
        lines = [c.args[0] for c in w.log.log_info.call_args_list if "DRY-RUN" in c.args[0]]
        assert sorted(lines) == sorted(
            f"DRY-RUN would create Report for {u} (Story {i})"
            for i, u in enumerate(feeds[slug]) if i > 0)
