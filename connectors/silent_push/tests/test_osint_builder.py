from datetime import datetime, timezone

import pytest

from stix_builder import (
    SilentPushStixBuilder,
    classify_url,
    osint_value,
    parse_seen_time,
    unflatten,
)

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"


def test_unflatten_rebuilds_nesting_and_keeps_plain_keys():
    row = unflatten(
        {
            "ip": "1.2.3.4",
            "ip_location.country_code": "DE",
            "ip_location.country_name": "Germany",
            "benign_info.known_benign": True,
        }
    )
    assert row["ip"] == "1.2.3.4"
    assert row["ip_location"] == {"country_code": "DE", "country_name": "Germany"}
    assert row["benign_info"]["known_benign"] is True


def test_unflatten_tolerates_a_leaf_and_a_branch_sharing_a_name():
    row = unflatten({"a": 1, "a.b": 2})
    assert row["a"] == {"b": 2}
    row = unflatten({"a.b": 2, "a": 1})
    assert row["a"] == {"b": 2}


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://x.example/a?b=c", ("url", "https://x.example/a?b=c")),
        ("http://203.0.113.5:8080/x", ("url", "http://203.0.113.5:8080/x")),
        ("ftp://x.example/a", None),
        ("https://", None),
        ("https://x.example/a b", None),
        ("https://[::1", None),
        ("https://x.example/" + "a" * 3000, None),
    ],
)
def test_classify_url(raw, expected):
    assert classify_url(raw) == expected


@pytest.mark.parametrize(
    "row,expected",
    [
        ({"indicator": "1.2.3.4", "type": "ip"}, ("ipv4-addr", "1.2.3.4")),
        ({"indicator": "2001:db8::1", "type": "ip"}, ("ipv6-addr", "2001:db8::1")),
        ({"indicator": "Evil.Example.", "type": "domain"}, ("domain-name", "evil.example")),
        ({"indicator": "evil.example", "type": "ip"}, None),
        ({"indicator": "1.2.3.4", "type": "domain"}, None),
        ({"indicator": None, "type": "ip"}, None),
    ],
)
def test_osint_value(row, expected):
    assert osint_value(row) == expected


def test_parse_seen_time_reads_naive_feed_scan_timestamps_as_utc():
    assert parse_seen_time("2026-11-07T01:47:47") == datetime(
        2026, 11, 7, 1, 47, 47, tzinfo=timezone.utc
    )
    assert parse_seen_time("garbage") is None
    assert parse_seen_time(None) is None


def test_url_observable_has_no_asn_or_country():
    builder = SilentPushStixBuilder(MARKING, 70)
    objects = builder.build_osint_indicator(
        "url",
        "https://bad.example/x",
        [{"feed": "TweetFeed URLs", "vendor": "Daniel López", "asn": 1}],
    )
    assert [obj.type for obj in objects] == ["url", "relationship"]


def test_osint_report_name_and_description():
    builder = SilentPushStixBuilder(MARKING, 70)
    slot = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)
    ref = "ipv4-addr--ff1b2a3c-4d5e-5f60-8a7b-1c2d3e4f5a6b"
    report = builder.build_report(slot, [ref], "OSINT")
    assert report.name == "Silent Push OSINT — 2026-11-07 12:00 UTC"
    assert "open-source" in report.description
    iofa = builder.build_report(slot, [ref], "IOFA")
    assert iofa.id != report.id
