"""Splunk REST flow: create job -> poll -> page results -> cancel (HTTP mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src import splunk_client as mod


def _resp(status=200, body=None, content=b"x"):
    r = MagicMock(status_code=status, content=content)
    r.json.return_value = body or {}
    if not content:  # like requests: an empty body is not valid JSON
        r.json.side_effect = ValueError("no JSON")
    r.request.method = "GET"
    r.url = "https://s:8089/x?y"
    return r


def _done(count):
    return _resp(body={"entry": [{"content": {"dispatchState": "DONE", "isDone": True,
                                              "resultCount": count}}]})


def _settings(**kw):
    base = dict(splunk_base_url="https://s:8089/", splunk_owner="nobody",
                splunk_results_api="v2", splunk_request_timeout=5, splunk_job_timeout=60,
                splunk_page_size=2, splunk_index_time_skew_seconds=50,
                splunk_token="tok", splunk_username="", splunk_password="", verify=True)
    base.update(kw)
    return MagicMock(**base)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    c = mod.SplunkClient(_settings(), MagicMock())
    c.session = MagicMock()
    return c


def test_index_mode_job_paged_projected_and_cancelled(client):
    client.session.post.side_effect = [_resp(201, {"sid": "123"}), _resp()]
    client.session.get.side_effect = [
        _resp(body={"entry": [{"content": {"dispatchState": "RUNNING"}}]}),
        _done(3),
        _resp(body={"results": [{"a": 1}, {"a": 2}]}),
        _resp(body={"results": [{"a": 3}]}),
    ]
    res = client.run_search("search x", "search", 100, 200, "index", 10, ["a", "_time"])
    assert res.rows == [{"a": 1}, {"a": 2}, {"a": 3}] and not res.truncated

    create = client.session.post.call_args_list[0]
    assert create.args[0] == "https://s:8089/servicesNS/nobody/search/search/jobs"
    data = create.kwargs["data"]
    assert (data["index_earliest"], data["index_latest"]) == ("100", "200")
    # _time bounded by the skew, never unbounded (would scan every bucket).
    assert (data["earliest_time"], data["latest_time"]) == ("50", "250")
    assert data["max_count"] == "11"  # one past the cap, above Splunk's 10k default

    pages = client.session.get.call_args_list[2:]
    assert pages[0].args[0] == "https://s:8089/services/search/v2/jobs/123/results"
    assert [p.kwargs["params"]["offset"] for p in pages] == [0, 2]
    assert [p.kwargs["params"]["count"] for p in pages] == [2, 1]  # no wasted empty page
    assert pages[0].kwargs["params"]["f"] == ["a", "_time"]

    cancel = client.session.post.call_args_list[1]
    assert cancel.args[0].endswith("/services/search/jobs/123/control")
    assert cancel.kwargs["data"]["action"] == "cancel"


def test_event_mode_bounds_time_only(client):
    client.session.post.side_effect = [_resp(201, {"sid": "1"}), _resp()]
    client.session.get.side_effect = [_done(0)]
    res = client.run_search("search x", "app", 100, 200, "event", 10)
    data = client.session.post.call_args_list[0].kwargs["data"]
    assert "index_earliest" not in data
    assert (data["earliest_time"], data["latest_time"]) == ("100", "200")
    assert res.rows == [] and client.session.get.call_count == 1  # no results fetch


def test_over_cap_reports_truncation_without_downloading(client):
    client.session.post.side_effect = [_resp(201, {"sid": "1"}), _resp()]
    client.session.get.side_effect = [_done(3)]
    res = client.run_search("search x", "app", 1, 2, "event", 2)
    assert res.truncated and res.rows == []
    assert client.session.get.call_count == 1  # status only, no results pages
    assert client.session.post.call_args_list[1].args[0].endswith("/jobs/1/control")


def test_exactly_cap_is_not_truncated(client):
    client.session.post.side_effect = [_resp(201, {"sid": "1"}), _resp()]
    client.session.get.side_effect = [_done(2), _resp(body={"results": [{"a": 1}, {"a": 2}]})]
    res = client.run_search("search x", "app", 1, 2, "event", 2)
    assert not res.truncated and len(res.rows) == 2


def test_fewer_rows_than_result_count_fails(client):
    # e.g. limits.conf maxresultrows below max_results: never silently drop the rest.
    client.session.post.side_effect = [_resp(201, {"sid": "1"}), _resp()]
    client.session.get.side_effect = [_done(4), _resp(body={"results": [{"a": 1}, {"a": 2}]}),
                                      _resp(body={"results": []})]
    with pytest.raises(mod.SplunkSearchError, match="returned 2 of 4"):
        client.run_search("search x", "app", 1, 2, "event", 10)
    assert client.session.post.call_args_list[1].args[0].endswith("/jobs/1/control")


def test_v1_results_path():
    c = mod.SplunkClient(_settings(splunk_results_api="v1"), MagicMock())
    assert c.results_path == "search/jobs"


def test_failed_job_raises_and_still_cancels(client):
    client.session.post.side_effect = [_resp(201, {"sid": "9"}), _resp()]
    client.session.get.return_value = _resp(body={"entry": [{"content": {
        "dispatchState": "FAILED", "messages": [{"type": "FATAL", "text": "bad SPL"}]}}]})
    with pytest.raises(mod.SplunkSearchError, match="bad SPL"):
        client.run_search("search x", "search", 1, 2, "event", 10)
    assert client.session.post.call_args_list[1].args[0].endswith("/jobs/9/control")


def test_done_but_failed_raises(client):
    client.session.post.side_effect = [_resp(201, {"sid": "9"}), _resp()]
    client.session.get.return_value = _resp(body={"entry": [{"content": {
        "dispatchState": "DONE", "isDone": True, "isFailed": True}}]})
    with pytest.raises(mod.SplunkSearchError, match="no detail"):
        client.run_search("search x", "search", 1, 2, "event", 10)


@pytest.mark.parametrize("content, msg", [
    ({"isDone": True, "isFinalized": True, "resultCount": 5}, "incomplete"),
    ({"isDone": True, "resultCount": 5, "messages": [
        {"type": "WARN", "text": "Search results might be incomplete: peer down"}]}, "peer down"),
    ({"isZombie": True}, "failed"),
])
def test_partial_or_dead_jobs_are_not_accepted(client, content, msg):
    client.session.post.side_effect = [_resp(201, {"sid": "9"}), _resp()]
    client.session.get.return_value = _resp(body={"entry": [{"content": content}]})
    with pytest.raises(mod.SplunkSearchError, match=msg):
        client.run_search("search x", "search", 1, 2, "event", 10)
    assert client.session.get.call_count == 1  # no rows fetched from a partial job
    assert client.session.post.call_args_list[1].args[0].endswith("/jobs/9/control")


def test_benign_messages_do_not_fail_a_job(client):
    client.session.post.side_effect = [_resp(201, {"sid": "9"}), _resp()]
    client.session.get.return_value = _resp(body={"entry": [{"content": {
        "isDone": True, "resultCount": 0,
        "messages": [{"type": "INFO", "text": "Your timerange was substituted"}]}}]})
    assert client.run_search("search x", "search", 1, 2, "event", 10).rows == []


def test_job_timeout(client, monkeypatch):
    client.job_timeout = 5
    ticks = iter([0, 3, 10])
    monkeypatch.setattr(mod.time, "monotonic", lambda: next(ticks))
    client.session.post.side_effect = [_resp(201, {"sid": "7"}), _resp()]
    client.session.get.return_value = _resp(body={"entry": [{"content": {
        "dispatchState": "RUNNING"}}]})
    with pytest.raises(mod.SplunkSearchError, match="exceeded 5s"):
        client.run_search("search x", "search", 1, 2, "event", 10)
    assert client.session.post.call_args_list[1].args[0].endswith("/jobs/7/control")


def test_cancel_failure_does_not_mask_result(client):
    client.session.post.side_effect = [_resp(201, {"sid": "1"}), RuntimeError("down")]
    client.session.get.side_effect = [_done(0)]
    assert client.run_search("search x", "app", 1, 2, "event", 10).rows == []


def test_http_error_surfaces_splunk_message(client):
    client.session.post.return_value = _resp(400, {"messages": [{"text": "Unknown search command"}]})
    with pytest.raises(mod.SplunkSearchError, match="Unknown search command"):
        client.run_search("search x", "search", 1, 2, "event", 10)


def test_http_error_non_json_body(client):
    r = _resp(502)
    r.json.side_effect = ValueError
    r.text = "Bad Gateway"
    client.session.get.return_value = r
    with pytest.raises(mod.SplunkSearchError, match="Bad Gateway"):
        client.check()


def test_check_returns_version(client):
    client.session.get.return_value = _resp(body={"entry": [{"content": {"version": "9.3.1"}}]})
    assert client.check() == "9.3.1"


def test_auth_modes():
    tok = mod.SplunkClient(_settings(), MagicMock())
    assert tok.session.headers["Authorization"] == "Bearer tok" and tok.session.auth is None
    basic = mod.SplunkClient(_settings(splunk_token="", splunk_username="u",
                                       splunk_password="p"), MagicMock())
    assert basic.session.auth == ("u", "p") and "Authorization" not in basic.session.headers
    with pytest.raises(ValueError, match="SPLUNK_TOKEN"):
        mod.SplunkClient(_settings(splunk_token="", splunk_username=""), MagicMock())


def test_post_is_never_retried():
    c = mod.SplunkClient(_settings(), MagicMock())
    retry = c.session.get_adapter("https://s").max_retries
    assert retry.allowed_methods == frozenset({"GET"})


def test_unverified_tls_warns_once():
    log = MagicMock()
    c = mod.SplunkClient(_settings(verify=False), log)
    assert c.session.verify is False
    log.warning.assert_called_once()


def test_every_request_asks_for_json_with_a_timeout(client):
    client.session.post.side_effect = [_resp(201, {"sid": "1"}), _resp()]
    client.session.get.side_effect = [_done(1), _resp(body={"results": [{"a": 1}]})]
    client.run_search("search x", "app", 1, 2, "event", 10)
    for call in client.session.get.call_args_list:
        assert call.kwargs["params"]["output_mode"] == "json"
        assert call.kwargs["timeout"] == 5
    for call in client.session.post.call_args_list:
        assert call.kwargs["data"]["output_mode"] == "json"
        assert call.kwargs["timeout"] == 5
    assert client.session.post.call_args_list[0].kwargs["data"]["exec_mode"] == "normal"


def test_gets_retry_throttling_and_gateway_errors():
    c = mod.SplunkClient(_settings(), MagicMock())
    retry = c.session.get_adapter("https://s").max_retries
    assert set(retry.status_forcelist) == {429, 502, 503, 504} and retry.total == 3
    assert c.session.get_adapter("http://s").max_retries is not None


def test_job_timeout_is_a_distinct_error(client, monkeypatch):
    client.job_timeout = 1
    ticks = iter([0, 5])
    monkeypatch.setattr(mod.time, "monotonic", lambda: next(ticks))
    client.session.post.side_effect = [_resp(201, {"sid": "7"}), _resp()]
    client.session.get.return_value = _resp(body={"entry": [{"content": {}}]})
    with pytest.raises(mod.SplunkJobTimeout):
        client.run_search("search x", "search", 1, 2, "event", 10)


def test_204_on_a_status_poll_means_not_ready(client):
    client.session.post.side_effect = [_resp(201, {"sid": "1"}), _resp()]
    client.session.get.side_effect = [_resp(204, content=b""), _resp(body={}), _done(0)]
    assert client.run_search("search x", "app", 1, 2, "event", 10).rows == []
    assert client.session.get.call_count == 3
