"""Unit tests for the shared Crucible classify_report helper."""

from unittest.mock import MagicMock, patch

import pytest
import requests

import classify_report as cr


@pytest.fixture
def collector(monkeypatch):
    """Point the helper at a fake Collector URL."""
    monkeypatch.setenv("CRUCIBLE_COLLECTOR_URL", "http://collector:8004/")
    monkeypatch.delenv("CRUCIBLE_CLASSIFY_TIMEOUT", raising=False)


def _resp(ok=True, status=200, payload=None):
    r = MagicMock(ok=ok, status_code=status)
    r.json.return_value = payload if payload is not None else {}
    return r


def test_unset_url_makes_no_call(monkeypatch):
    monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
    with patch.object(cr.requests, "post") as post:
        assert cr.classify_report("t", default_types=["open-source-reporting"]) == [
            "open-source-reporting"]
    post.assert_not_called()


def test_success_returns_type_and_ignores_collection_requirements(collector):
    payload = {"report_type": "threat-analysis", "collection_requirements": ["CR08"]}
    with patch.object(cr.requests, "post", return_value=_resp(payload=payload)) as post:
        out = cr.classify_report("Title", "desc", "full body", "Src", "https://x/a",
                                 ["open-source-reporting"])
    assert out == ["threat-analysis"]
    url = post.call_args.args[0]
    body = post.call_args.kwargs["json"]
    assert url == "http://collector:8004/classify"
    assert body == {"title": "Title", "description": "desc", "content": "full body",
                    "source": "Src", "source_url": "https://x/a"}
    assert post.call_args.kwargs["timeout"] == cr.DEFAULT_TIMEOUT


@pytest.mark.parametrize("raises,resp,fragment", [
    (requests.Timeout("slow"), None, "Timeout: slow"),
    (requests.ConnectionError("down"), None, "ConnectionError: down"),
    (None, _resp(ok=False, status=503), "HTTP 503"),
    (None, _resp(payload={"collection_requirements": []}), "no report_type"),
    (None, _resp(payload={"report_type": "  "}), "no report_type"),
])
def test_failures_fall_back_and_log(collector, raises, resp, fragment):
    logged = []
    with patch.object(cr.requests, "post", side_effect=raises, return_value=resp):
        out = cr.classify_report("My Title", source="BleepingComputer",
                                 default_types=["open-source-reporting"],
                                 logger=logged.append)
    assert out == ["open-source-reporting"]
    assert len(logged) == 1
    assert "BleepingComputer" in logged[0] and "My Title" in logged[0]
    assert fragment in logged[0]


def test_failure_without_logger_stays_silent(collector):
    with patch.object(cr.requests, "post", side_effect=requests.Timeout("slow")):
        assert cr.classify_report("t", default_types=["x"]) == ["x"]


def test_legacy_default_unchanged_for_existing_callers(collector):
    with patch.object(cr.requests, "post", side_effect=requests.Timeout("slow")):
        assert cr.classify_report("t") == ["threat-report"]


@pytest.mark.parametrize("raw,expected", [
    ("180", 180.0), ("2.5", 2.5), ("", cr.DEFAULT_TIMEOUT),
    ("abc", cr.DEFAULT_TIMEOUT), ("0", cr.DEFAULT_TIMEOUT), ("-5", cr.DEFAULT_TIMEOUT),
])
def test_timeout_env(collector, monkeypatch, raw, expected):
    monkeypatch.setenv("CRUCIBLE_CLASSIFY_TIMEOUT", raw)
    with patch.object(cr.requests, "post", return_value=_resp(payload={"report_type": "a"})) as post:
        cr.classify_report("t")
    assert post.call_args.kwargs["timeout"] == expected
