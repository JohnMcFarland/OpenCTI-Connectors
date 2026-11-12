"""main.py: startup wiring, invalid-entry isolation, the run loop's boundary."""

import importlib.util
from unittest.mock import MagicMock, patch

import pytest
import yaml

from conftest import ROOT, SOURCES
from engine import timing
from engine.settings import EngineSettings


def _main_module():
    spec = importlib.util.spec_from_file_location("waypoint_main", ROOT / "main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_startup_logs_mode_and_marker(monkeypatch, tmp_path):
    main = _main_module()
    monkeypatch.setenv("AGG_SOURCES_FILE", str(SOURCES))
    monkeypatch.setenv("AGG_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
    helper = MagicMock()
    helper.api.marking_definition.read.return_value = {"id": "m"}
    helper.api.identity.create.return_value = {"id": "a"}
    with patch.object(main, "OpenCTIConnectorHelper", return_value=helper), \
         patch.object(main.Scheduler, "run_forever", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            main.main()
    logged = " ".join(str(c) for c in helper.log_info.call_args_list)
    assert "standalone mode" in logged
    assert "WAYPOINT-V1 started: 8 sources running" in logged
    helper.log_error.assert_not_called()


def test_invalid_entry_disables_only_that_source(tmp_path):
    main = _main_module()
    good = {"name": "Good", "author_name": "Good Org", "feed_urls": ["https://g.example/feed"],
            "allowed_hosts": ["g.example"]}
    path = tmp_path / "sources.yml"
    path.write_text(yaml.safe_dump({
        "good": good,
        "broken": dict(good, discovery="carrier-pigeon"),
        "off": dict(good, enabled=False),
    }), encoding="utf-8")
    helper = MagicMock()
    settings = EngineSettings(sources_file=str(path), status_file=str(tmp_path / "s.json"))
    workers, status = main.build(helper, settings)
    assert set(workers) == {"good"}
    assert status.sources["broken"]["state"] == "invalid"
    assert status.sources["broken"]["reason"].startswith("discovery:")
    assert status.sources["off"]["state"] == "disabled"
    assert "broken" in helper.log_error.call_args.args[0]


def test_run_loop_survives_a_failing_tick():
    from engine.scheduler import Scheduler
    sched = Scheduler({}, EngineSettings(), MagicMock(), MagicMock())
    calls = {"n": 0}

    def tick():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        raise KeyboardInterrupt

    sched.tick = tick
    with patch.object(timing, "sleep"), pytest.raises(KeyboardInterrupt):
        sched.run_forever()
    assert "boom" in sched.log.log_error.call_args.args[0]
