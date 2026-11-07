from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import requests

import client as client_module
from client import MIN_EXPORT_LINES, S3_HOST, SilentPushAPIError, SilentPushClient

SIGNED_URL = f"https://{S3_HOST}/iofa/all_iofas_ips.txt?Signature=secret"
LINES = [f"10.0.{i // 250}.{i % 250}" for i in range(MIN_EXPORT_LINES)]


def response(status=200, json_body=None, content=b"", headers=None):
    fake = MagicMock(status_code=status, content=content, text="body")
    fake.headers = headers or {}
    fake.json.return_value = json_body
    return fake


def export_body(lines=LINES, **kwargs):
    return response(content="\n".join(lines).encode(), **kwargs)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(client_module.time, "sleep", lambda _: None)


@pytest.fixture
def client():
    instance = SilentPushClient("the-key")
    instance._session = MagicMock()
    return instance


@pytest.fixture
def s3_get(monkeypatch):
    fake = MagicMock(return_value=export_body())
    monkeypatch.setattr(client_module.requests, "get", fake)
    return fake


def test_export_follows_the_redirect_without_sending_the_key(client, s3_get):
    client._session.get.return_value = response(302, headers={"Location": SIGNED_URL})

    assert client.download_export("all_iofas_ips.txt") == LINES

    assert client._session.get.call_args.kwargs["allow_redirects"] is False
    args, kwargs = s3_get.call_args
    assert args == (SIGNED_URL,)
    assert "headers" not in kwargs


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/file",
        f"http://{S3_HOST}/file",
        f"https://{S3_HOST}.evil.example/file",
        "",
    ],
)
def test_export_refuses_any_other_redirect(client, s3_get, location):
    client._session.get.return_value = response(302, headers={"Location": location})
    with pytest.raises(SilentPushAPIError):
        client.download_export("all_iofas_ips.txt")
    s3_get.assert_not_called()


def test_truncated_download_is_an_error(client, s3_get):
    client._session.get.return_value = response(302, headers={"Location": SIGNED_URL})
    s3_get.return_value = export_body(headers={"Content-Length": "99999999"})
    with pytest.raises(SilentPushAPIError, match="truncated"):
        client.download_export("all_iofas_ips.txt")


def test_tiny_export_is_an_error(client, s3_get):
    client._session.get.return_value = response(302, headers={"Location": SIGNED_URL})
    s3_get.return_value = export_body(LINES[:5])
    with pytest.raises(SilentPushAPIError, match="only 5 lines"):
        client.download_export("all_iofas_ips.txt")


def test_connection_error_never_quotes_the_signed_url(client, s3_get):
    client._session.get.return_value = response(302, headers={"Location": SIGNED_URL})
    s3_get.side_effect = requests.ConnectionError(SIGNED_URL)
    with pytest.raises(SilentPushAPIError) as caught:
        client.download_export("all_iofas_ips.txt")
    assert "Signature" not in str(caught.value)


def test_transient_status_is_retried_and_permanent_is_not(client):
    client._session.get.side_effect = [
        response(503),
        response(429, headers={"Retry-After": "1"}),
        response(json_body={"metadata": {"pages": 1}, "data": [{"uuid": "a"}]}),
    ]
    assert client.list_feeds() == [{"uuid": "a"}]

    client._session.get.side_effect = [response(403)]
    with pytest.raises(SilentPushAPIError, match="403"):
        client.list_feeds()


def test_list_feeds_walks_every_page(client):
    client._session.get.side_effect = [
        response(json_body={"metadata": {"pages": 2}, "data": [{"uuid": "a"}]}),
        response(json_body={"metadata": {"pages": 2}, "data": [{"uuid": "b"}]}),
    ]
    assert [feed["uuid"] for feed in client.list_feeds()] == ["a", "b"]
    calls = client._session.get.call_args_list
    assert [call.kwargs["params"]["page"] for call in calls] == [1, 2]


def test_list_feeds_rejects_an_unknown_shape(client):
    client._session.get.return_value = response(json_body={"oops": 1})
    with pytest.raises(SilentPushAPIError):
        client.list_feeds()


def test_enrich_reads_both_response_shapes(client):
    client._session.post.return_value = response(json_body={"response": [{"a": 1}]})
    assert client.enrich("domain", ["a.com"]) == [{"a": 1}]
    assert client._session.post.call_args.kwargs["json"] == {"domains": ["a.com"]}

    client._session.post.return_value = response(
        json_body={"response": {"ip2asn": [{"ip": "1.1.1.1"}]}}
    )
    assert client.enrich("ipv4", ["1.1.1.1"]) == [{"ip": "1.1.1.1"}]
    assert client._session.post.call_args.kwargs["json"] == {"ipv4s": ["1.1.1.1"]}


def test_enrich_retries_an_empty_answer_then_gives_up(client):
    empty = response(json_body={"response": {}})
    client._session.post.side_effect = [
        empty,
        response(json_body={"response": [{"a": 1}]}),
    ]
    assert client.enrich("domain", ["a.com"]) == [{"a": 1}]

    client._session.post.reset_mock()
    client._session.post.side_effect = None
    client._session.post.return_value = empty
    assert client.enrich("domain", ["a.com"]) == []
    assert client._session.post.call_count == client_module.EMPTY_ENRICH_ATTEMPTS


def test_enrich_refuses_a_batch_the_api_would_silently_truncate(client):
    with pytest.raises(ValueError):
        client.enrich("domain", ["a.com"] * 101)



def scan_page(stamps):
    rows = [{"u": stamp, "first_seen_on": stamp} for stamp in stamps]
    return response(json_body={"response": {"data": rows}, "error": None})


CUTOFF = datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)


def test_feed_scan_pages_newest_first_and_stops_past_the_cutoff(client, monkeypatch):
    monkeypatch.setattr(client_module, "FEED_SCAN_PAGE_SIZE", 2)
    client._session.post.side_effect = [
        scan_page(["2026-11-07T12:00:00", "2026-11-07T11:00:00"]),
        scan_page(["2026-11-07T10:30:00", "2026-11-07T09:59:59"]),
        AssertionError("paged past the cutoff"),
    ]
    rows = client.feed_scan_since("q", CUTOFF)
    assert [row["u"] for row in rows] == [
        "2026-11-07T12:00:00",
        "2026-11-07T11:00:00",
        "2026-11-07T10:30:00",
    ]
    bodies = [call.kwargs["json"] for call in client._session.post.call_args_list]
    # `skip` is ignored by the API; only `page` moves the window.
    assert [body["page"] for body in bodies] == [1, 2]
    assert all("skip" not in body for body in bodies)
    assert all(body["sorting"] == ["first_seen_on/desc"] for body in bodies)


def test_feed_scan_stops_on_a_short_page(client, monkeypatch):
    monkeypatch.setattr(client_module, "FEED_SCAN_PAGE_SIZE", 2)
    client._session.post.side_effect = [scan_page(["2026-11-07T12:00:00"])]
    assert len(client.feed_scan_since("q", CUTOFF)) == 1


def test_a_row_exactly_at_the_cutoff_is_kept(client):
    client._session.post.side_effect = [scan_page(["2026-11-07T10:00:00"])]
    assert len(client.feed_scan_since("q", CUTOFF)) == 1


def test_feed_scan_refuses_rows_that_are_not_newest_first(client, monkeypatch):
    """Stopping early would otherwise drop newer rows further down."""
    monkeypatch.setattr(client_module, "FEED_SCAN_PAGE_SIZE", 2)
    client._session.post.side_effect = [
        scan_page(["2026-11-07T11:00:00", "2026-11-07T12:00:00"]),
    ]
    with pytest.raises(SilentPushAPIError, match="newest first"):
        client.feed_scan_since("q", CUTOFF)


def test_feed_scan_refuses_a_row_without_a_date(client):
    client._session.post.return_value = response(
        json_body={"response": {"data": [{"u": 1}]}, "error": None}
    )
    with pytest.raises(SilentPushAPIError, match="first_seen_on"):
        client.feed_scan_since("q", CUTOFF)


def test_feed_scan_error_payload_is_an_error(client):
    client._session.post.return_value = response(
        json_body={"error": "AttributeError", "message": "bad field"}
    )
    with pytest.raises(SilentPushAPIError):
        client.feed_scan_since("q", CUTOFF)


def test_feed_scan_stops_at_the_page_cap(client, monkeypatch):
    monkeypatch.setattr(client_module, "FEED_SCAN_PAGE_SIZE", 1)
    monkeypatch.setattr(client_module, "FEED_SCAN_MAX_PAGES", 3)
    client._session.post.side_effect = [
        scan_page([f"2026-11-07T12:0{i}:00"[:19]]) for i in (5, 4, 3, 2)
    ]
    with pytest.raises(SilentPushAPIError, match="past 3 pages"):
        client.feed_scan_since("q", CUTOFF)
