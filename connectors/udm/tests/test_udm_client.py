"""UDM client paging: stop at the window when pages are newest-first, never trust the
early stop otherwise, raise on errors, and page the security log."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.udm_client import UdmClient, UdmError


class Resp:
    def __init__(self, body, status=200):
        self.body, self.status_code, self.text = body, status, str(body)

    def json(self):
        return self.body


class FakeSession:
    def __init__(self, handler):
        self.handler, self.headers, self.calls = handler, {}, []

    def request(self, method, url, json=None, verify=None, timeout=None):
        self.calls.append((method, url, json))
        return self.handler(method, url, json)


def client(settings, handler):
    s = FakeSession(handler)
    return UdmClient(settings, MagicMock(), session=s), s


def pages_handler(pages):
    def h(method, url, payload):
        n = payload["pageNumber"]
        data = pages[n] if n < len(pages) else []
        return Resp({"data": data, "has_next": n + 1 < len(pages)})
    return h


B = 1_760_000_000_000


def rec(i, t):
    return {"id": str(i), "time": B + t}


def test_api_key_header_and_tls_setting(settings):
    c, s = client(settings, lambda *a: Resp({"meta": {"rc": "ok"}, "data": []}))
    assert s.headers["X-API-Key"] == "k" and c.verify is False
    c.check()
    assert s.calls[0][1] == "https://192.168.1.1/proxy/network/api/s/default/stat/sysinfo"


def test_stops_at_first_page_older_than_window(settings):
    pages = [[rec(1, 900), rec(2, 800)], [rec(3, 700), rec(4, 400)], [rec(5, 300)], [rec(6, 1)]]
    c, s = client(settings, pages_handler(pages))
    out = c.blocked_flows(since_ms=B + 500)
    assert [r["id"] for r in out.records] == ["1", "2", "3"]
    assert out.stopped == "older-than-window" and len(s.calls) == 3
    assert s.calls[0][2]["action"] == ["blocked"] and s.calls[0][2]["pageNumber"] == 0


def test_unordered_pages_are_read_to_the_end(settings):
    pages = [[rec(1, 100), rec(2, 900)], [rec(3, 50)], [rec(4, 950)]]
    c, s = client(settings, pages_handler(pages))
    out = c.blocked_flows(since_ms=B + 500)
    assert sorted(r["id"] for r in out.records) == ["2", "4"] and out.stopped == "end"


def test_max_pages_cap(settings, monkeypatch):
    monkeypatch.setattr(settings, "udm_max_pages", 2)
    pages = [[rec(i, 1000 - i)] for i in range(5)]
    c, _ = client(settings, pages_handler(pages))
    out = c.blocked_flows(since_ms=B)
    assert out.stopped == "max-pages" and len(out.records) == 2


@pytest.mark.parametrize("resp", [Resp({}, 500), Resp({"nodata": 1}), Resp("x")])
def test_errors_raise_instead_of_ending_the_walk(settings, resp):
    c, _ = client(settings, lambda *a: resp)
    with pytest.raises(UdmError):
        c.blocked_flows(since_ms=0)


def test_legacy_rc_error_raises(settings):
    c, _ = client(settings, lambda *a: Resp({"meta": {"rc": "error", "msg": "api.err.NoSiteContext"}}))
    with pytest.raises(UdmError):
        c.known_clients()


def test_security_log_pages_with_server_side_filter(settings, monkeypatch):
    monkeypatch.setattr(settings, "udm_page_size", 2)
    entries = [{"id": str(i), "timestamp": 1000 - i, "category": "SECURITY"} for i in range(5)]

    def h(method, url, payload):
        assert url.endswith("/v2/api/site/default/system-log/all")
        assert payload["categories"] == ["SECURITY"] and payload["timestampFrom"] == 10
        n, size = payload["pageNumber"], payload["pageSize"]
        return Resp({"data": entries[n * size:(n + 1) * size],
                     "total_page_count": 3, "total_element_count": 5})

    c, s = client(settings, h)
    out = c.security_events(10, 2000)
    assert [e["id"] for e in out.records] == ["0", "1", "2", "3", "4"]
    assert out.stopped == "end" and len(s.calls) == 3


def test_known_clients_merges_offline_and_live(settings):
    def h(method, url, payload):
        if url.endswith("rest/user"):
            return Resp({"data": [{"mac": "AA:01", "name": "nas"}, {"mac": "aa:02", "hostname": "old"}]})
        return Resp({"data": [{"mac": "aa:01", "ip": "192.168.1.5"}]})

    c, _ = client(settings, h)
    got = {x["mac"].lower(): x for x in c.known_clients()}
    assert got["aa:01"]["name"] == "nas" and got["aa:01"]["ip"] == "192.168.1.5"
    assert "aa:02" in got


def test_wan_ips_come_from_the_gateway_only(settings):
    # As seen live: switches report their own LAN address as uplink.ip.
    c, _ = client(settings, lambda *a: Resp({"data": [
        {"type": "usw", "uplink": {"ip": "192.168.0.20"}},
        {"type": "udm", "wan1": {"ip": "198.51.100.1"}, "uplink": {"ip": "198.51.100.1"}},
        {"type": "uap"}]}))
    assert c.wan_ips() == ["198.51.100.1"]


def test_settings_parse_false_string(monkeypatch, settings):
    from src.config import Settings

    monkeypatch.setenv("UDM_VERIFY_SSL", "false")
    assert Settings().verify is False
    monkeypatch.setenv("UDM_CA_BUNDLE", "/ca.pem")
    assert Settings().verify == "/ca.pem"
    monkeypatch.setenv("UDM_INTERNAL_SUBNETS", "not-a-net")
    with pytest.raises(Exception):
        Settings()


def test_order_is_checked_across_pages(settings):
    # Each page is descending, but page 2 is newer than page 1: not newest-first.
    pages = [[rec(1, 600), rec(2, 550)], [rec(3, 900), rec(4, 100)], [rec(5, 50)], [rec(6, 990)]]
    c, s = client(settings, pages_handler(pages))
    out = c.blocked_flows(since_ms=B + 500)
    assert sorted(r["id"] for r in out.records) == ["1", "2", "3", "6"]
    assert out.stopped == "end" and len(s.calls) == 4
