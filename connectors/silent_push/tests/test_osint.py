"""The OSINT stream, run through the same multi-run harness as IOFA.

The harness clock starts at 2026-11-07 00:05 UTC and each run moves it on 12h.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from client import SilentPushAPIError
from test_connector import FakeClient, harness  # noqa: F401  (fixture)

VALUE_TYPES = ("domain-name", "ipv4-addr", "ipv6-addr", "url")
START = datetime(2026, 11, 7, 0, 5, tzinfo=timezone.utc)


def osint_reports(harness):
    return {name for name in harness.reports() if name.startswith("Silent Push OSINT")}


def find(harness, value):
    return [
        obj
        for bundle in harness.bundles
        for obj in bundle
        if obj["type"] in VALUE_TYPES and obj["value"] == value
    ]


# --- the time window ------------------------------------------------------


def test_first_run_takes_the_last_24_hours_only(harness):
    harness.osint("198.18.0.1", minutes_ago=5)
    harness.osint("198.18.0.2", minutes_ago=23 * 60)
    harness.osint("198.18.0.3", minutes_ago=25 * 60)
    harness.run()

    assert harness.stream_values("OSINT") == {"198.18.0.1", "198.18.0.2"}
    assert harness.client.scan_cutoffs == [START - timedelta(hours=24)]
    assert osint_reports(harness) == {"Silent Push OSINT - 2026-11-07 00:00 UTC"}


def test_later_runs_take_what_is_new_since_the_last_run(harness):
    harness.osint("198.18.0.1")
    harness.run()
    harness.osint("198.18.0.2", minutes_ago=60)  # added between the runs
    harness.run()

    # Previous run's start, less the one-hour overlap.
    assert harness.client.scan_cutoffs[1] == START - timedelta(hours=1)
    assert harness.stream_values("OSINT") == {"198.18.0.1", "198.18.0.2"}
    assert osint_reports(harness) == {
        "Silent Push OSINT - 2026-11-07 00:00 UTC",
        "Silent Push OSINT - 2026-11-07 12:00 UTC",
    }


def test_the_overlap_never_ingests_a_value_twice(harness):
    harness.osint("198.18.0.1", minutes_ago=1)
    harness.run()  # cursor 00:05; next cutoff 23:05 the day before
    harness.run()
    assert len(find(harness, "198.18.0.1")) == 1
    assert len(osint_reports(harness)) == 1


def test_a_value_re_added_to_its_feed_is_not_new(harness):
    """AlienVault re-adds most of its list each day with a fresh timestamp."""
    harness.osint("198.18.0.1")
    harness.run()
    harness.osint("198.18.0.1", minutes_ago=30)
    harness.run()
    assert len(find(harness, "198.18.0.1")) == 1


def test_failed_send_keeps_the_cursor_and_loses_nothing(harness):
    harness.osint("198.18.0.1")
    harness.send_failures = 1  # IOFA's first run is a baseline, so this hits OSINT
    harness.run()
    assert len(harness.failed_runs()) == 1
    assert not harness.connector.osint_cursor.read()

    harness.run()
    assert harness.client.scan_cutoffs[1] == START + timedelta(hours=12) - timedelta(hours=24)
    assert harness.stream_values("OSINT") == {"198.18.0.1"}


def test_feed_scan_failure_keeps_the_cursor(harness):
    harness.osint("198.18.0.1")
    harness.run()
    harness.client.feed_scan_since = MagicMock(side_effect=SilentPushAPIError("down"))
    harness.run()
    assert harness.connector.osint_cursor.read() == START


def test_an_empty_window_keeps_the_cursor_without_failing(harness):
    harness.osint("198.18.0.1", minutes_ago=90)  # outside the next run's overlap
    harness.run()
    harness.run()  # nothing new
    assert not harness.failed_runs()
    assert harness.connector.osint_cursor.read() == START
    harness.osint("198.18.0.2", minutes_ago=60 * 13)  # landed late, before run 2
    harness.run()
    assert "198.18.0.2" in harness.stream_values("OSINT")


def test_query_window_in_days_covers_a_long_outage(harness):
    harness.osint("198.18.0.1")
    harness.run()
    harness.now += timedelta(days=3)  # connector down for three days
    harness.osint("198.18.0.9", minutes_ago=60 * 24 * 2)
    harness.run()
    assert harness.client.scan_queries[0].endswith('first_seen_on >= "now-1d"')
    assert harness.client.scan_queries[1].endswith('first_seen_on >= "now-4d"')
    assert "198.18.0.9" in harness.stream_values("OSINT")


# --- what is built --------------------------------------------------------


def test_osint_and_iofa_get_separate_reports_and_work_items(harness):
    harness.run()  # IOFA baseline
    harness.client.domains.append("new.example")
    harness.osint("198.18.0.3")
    harness.run()

    assert harness.reports() == {
        "Silent Push IOFA - 2026-11-07 12:00 UTC",
        "Silent Push OSINT - 2026-11-07 12:00 UTC",
    }
    assert harness.stream_values("IOFA") == {"new.example"}
    assert harness.stream_values("OSINT") == {"198.18.0.3"}
    names = [
        call.args[1]
        for call in harness.connector.helper.api.work.initiate_work.call_args_list
    ]
    assert names[-2:] == [
        "Silent Push IOFA 2026-11-07 12:00 UTC",
        "Silent Push OSINT 2026-11-07 12:00 UTC",
    ]


def test_observable_carries_feed_vendor_score_asn_and_country(harness):
    harness.osint("198.18.0.3", sp_risk_score=64)
    harness.run()
    objects = harness.bundles[0]
    ip = find(harness, "198.18.0.3")[0]
    assert ip["x_opencti_score"] == 64
    assert "CINS Army List IP (CINS)" in ip["x_opencti_description"]
    assert ip["x_opencti_create_indicator"] is False
    assert any(obj["type"] == "autonomous-system" for obj in objects)
    assert any(obj["type"] == "location" for obj in objects)
    assert not any(
        obj["type"] in ("intrusion-set", "malware", "tool", "indicator", "note")
        for obj in objects
    )


def test_urls_domains_and_ipv6_are_ingested(harness):
    harness.osint(
        "https://bad.example/login", kind="url", feed="TweetFeed URLs", vendor="Daniel L\u00f3pez"
    )
    harness.osint(
        "evil.example", kind="domain", feed="TweetFeed Domains", vendor="Daniel L\u00f3pez"
    )
    harness.osint("2001:db8::1")
    harness.run()
    assert harness.stream_values("OSINT") == {
        "https://bad.example/login",
        "evil.example",
        "2001:db8::1",
    }


def test_value_in_two_feeds_is_one_observable_from_the_earliest_listing(harness):
    harness.osint("198.18.0.9", minutes_ago=10, sp_risk_score=10)
    harness.osint(
        "198.18.0.9",
        minutes_ago=600,
        feed="Green Snow",
        vendor="Green Snow",
        sp_risk_score=80,
    )
    harness.run()
    ips = find(harness, "198.18.0.9")
    assert len(ips) == 1
    assert ips[0]["x_opencti_score"] == 80
    assert "Green Snow (Green Snow)" in ips[0]["x_opencti_description"]
    assert "CINS Army List IP (CINS)" in ips[0]["x_opencti_description"]
    author_edge = next(
        obj
        for obj in harness.bundles[0]
        if obj["type"] == "relationship"
        and obj["source_ref"] == ips[0]["id"]
        and obj["target_ref"].startswith("identity--")
    )
    assert author_edge["start_time"].startswith("2026-11-06T14:05:00")


def test_duplicate_feeds_are_excluded_but_shared_values_still_land(harness):
    harness.osint("https://phish.example/a", kind="url", feed="OpenPhish", vendor="OpenPhish")
    harness.osint("198.18.0.7", feed="ThreatFox Recent IPs", vendor="abuse.ch")
    harness.osint("198.18.0.7")
    harness.osint("av.example", kind="domain", feed="AlienVault Domain", vendor="AlienVault")
    harness.osint("198.18.0.8", feed="AlienVault IP", vendor="AlienVault")
    harness.run()
    assert harness.stream_values("OSINT") == {"198.18.0.7"}
    assert "ThreatFox" not in find(harness, "198.18.0.7")[0]["x_opencti_description"]
    assert "https://phish.example/a" not in harness.connector.osint_store.load()


def test_rows_from_other_categories_are_ignored(harness):
    harness.osint("198.18.0.8", feed_category="default")
    harness.run()
    assert harness.bundles == []


def test_query_selects_global_open_source_vendors_only(harness):
    harness.run()
    query = harness.client.scan_queries[0]
    assert '"CINS"' in query and '"Daniel L\u00f3pez"' in query
    assert 'feed_scope = ["GLOBAL"]' in query
    assert '"AlienVault"' not in query  # its only feed is excluded
    assert '"OpenPhish"' not in query
    assert "Snowflake" not in query  # an org feed's vendor
    assert "Silent Push" not in query  # an IOFA feed's vendor


def test_benign_and_sinkholed_values_are_handled_but_not_ingested(harness):
    harness.osint("198.18.0.4", **{"benign_info.known_benign": True})
    harness.osint("198.18.0.5", **{"ip_flags.is_sinkhole": True})
    harness.osint("198.18.0.6")
    harness.run()
    assert harness.stream_values("OSINT") == {"198.18.0.6"}
    assert {"198.18.0.4", "198.18.0.5"} <= harness.connector.osint_store.load()


def test_unusable_rows_are_skipped_without_failing(harness):
    harness.osint("not a value")
    harness.osint("ftp://x.example/a", kind="url")
    harness.osint("10.0.0.1", kind="domain")
    harness.osint("198.18.0.6")
    harness.run()
    assert harness.stream_values("OSINT") == {"198.18.0.6"}
    assert not harness.failed_runs()


# --- the two streams together ---------------------------------------------


def test_one_stream_failing_does_not_stop_the_other(harness):
    harness.run()
    harness.client.domains.append("new.example")
    harness.client.feed_scan_since = MagicMock(side_effect=SilentPushAPIError("down"))
    harness.run()
    assert harness.stream_values("IOFA") == {"new.example"}
    assert len(harness.failed_runs()) == 1

    harness.client.feed_scan_since = FakeClient.feed_scan_since.__get__(harness.client)
    harness.osint("198.18.0.3")
    harness.client.download_export = MagicMock(side_effect=SilentPushAPIError("down"))
    harness.run()
    assert "198.18.0.3" in harness.stream_values("OSINT")
    assert len(harness.failed_runs()) == 2


def test_disabled_stream_never_runs(harness):
    harness.connector.osint_enabled = False
    harness.osint("198.18.0.1")
    harness.run()
    assert harness.client.scan_queries == []

    harness.connector.osint_enabled = True
    harness.connector.iofa_enabled = False
    harness.client.download_export = MagicMock(side_effect=AssertionError("IOFA ran"))
    harness.run()
    assert harness.stream_values("OSINT") == {"198.18.0.1"}
    assert not harness.failed_runs()


def test_catalogue_is_fetched_once_per_run_and_shared(harness):
    calls = []
    original = harness.client.list_feeds
    harness.client.list_feeds = lambda: calls.append(1) or original()
    harness.run()
    harness.client.domains.append("new.example")
    harness.run()
    assert len(calls) == 2  # IOFA's run 2 reuses the copy OSINT needs too


def test_week_of_runs_with_rotating_lists(harness):
    """Two runs a day: every addition lands exactly once, re-adds never again."""
    expected = set()
    for step in range(14):
        for i in range(3):
            harness.osint(f"203.0.{step}.{i}", minutes_ago=30 + i)
            expected.add(f"203.0.{step}.{i}")
        if step:
            harness.osint(f"203.0.{step - 1}.0", minutes_ago=20)  # re-added
        if step == 4:
            harness.send_failures = 1
        harness.run()
    assert harness.stream_values("OSINT") == expected
    values = [
        obj["value"]
        for bundle in harness.bundles
        for obj in bundle
        if obj["type"] == "ipv4-addr"
    ]
    assert len(values) == len(set(values))
    assert len(osint_reports(harness)) == 13  # 14 slots minus the failed one


def test_a_vendor_with_some_feeds_kept_stays_in_the_query(harness):
    harness.connector.osint_exclude = {"TweetFeed URLs"}
    harness.client.feeds.append(
        {"uuid": "td", "name": "TweetFeed Domains", "category": "open_source", "vendor": "Daniel L\u00f3pez"}
    )
    harness.run()
    assert '"Daniel L\u00f3pez"' in harness.client.scan_queries[0]


def test_excluding_every_open_source_feed_fails_loudly(harness):
    harness.connector.osint_exclude = {
        feed["name"] for feed in harness.client.feeds if feed.get("category") == "open_source"
    }
    harness.run()
    assert harness.client.scan_queries == []
    assert len(harness.failed_runs()) == 1
