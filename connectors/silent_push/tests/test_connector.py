import json
import random
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

import connector as connector_module
from client import DOMAIN_EXPORT, IP_EXPORT, SilentPushAPIError
from connector import (
    SilentPushConnector,
    plan_batches,
    seconds_until_next_slot,
    slot_start,
)
from seen_store import Cursor, SeenStore
from stix_builder import SilentPushStixBuilder, parse_seen_time

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
TWELVE_HOURS = 12 * 3600
START = datetime(2026, 11, 7, 0, 5, tzinfo=timezone.utc)
FEEDS = [
    {"uuid": "fin7", "name": "Threat Actor - FIN7 Domains", "category": "iofa"},
    {"uuid": "bp", "name": "Bulletproof Hosting IPs", "category": "iofa"},
    {"uuid": "org", "name": "Aladdin Snowflake 1", "category": "default", "vendor": "Snowflake"},
    {"uuid": "iv", "name": "Keitaro C2 IPs", "category": "iofa", "vendor": "Silent Push"},
    {"uuid": "av", "name": "AlienVault IP", "category": "open_source", "vendor": "AlienVault"},
    {"uuid": "ci", "name": "CINS Army List IP", "category": "open_source", "vendor": "CINS"},
    {"uuid": "op", "name": "OpenPhish", "category": "open_source", "vendor": "OpenPhish"},
    {"uuid": "tf", "name": "TweetFeed URLs", "category": "open_source", "vendor": "Daniel L\u00f3pez"},
]


def osint_row(indicator, kind="ip", feed="CINS Army List IP", vendor="CINS", **extra):
    """A Feed Scan row as the API sends it: nested fields flattened to dots."""
    row = {
        "indicator": indicator,
        "type": kind,
        "feed": feed,
        "vendor": vendor,
        "feed_category": "open_source",
        "first_seen_on": "2026-11-07T01:47:47",
        "last_seen_on": "2026-11-07T11:56:56",
        "sp_risk_score": 22,
        "benign_info.known_benign": False,
        "ip_flags.is_sinkhole": False,
    }
    if kind == "ip":
        row.update({"asn": 64500, "asname": "AS", "ip_location.country_code": "DE"})
    row.update(extra)
    return row


class FakeClient:
    """The API as the connector sees it, with a moving export."""

    def __init__(self):
        self.domains = ["base-0.example", "base-1.example"]
        self.ips = ["192.0.2.1"]
        self.enrich_calls = []
        self.empty_values = set()  # any batch holding one of these answers []
        self.missing_values = set()  # answered, but with no row for these
        self.osint_rows = []  # whatever Feed Scan holds, any age
        self.scan_queries = []
        self.scan_cutoffs = []
        self.feeds = list(FEEDS)

    def download_export(self, name):
        return {DOMAIN_EXPORT: self.domains, IP_EXPORT: self.ips}[name]

    def list_feeds(self):
        return self.feeds

    def feed_scan_since(self, query, cutoff):
        """Like the real call: rows added at or after cutoff, newest first."""
        self.scan_queries.append(query)
        self.scan_cutoffs.append(cutoff)
        fresh = [
            dict(row)
            for row in self.osint_rows
            if parse_seen_time(row["first_seen_on"]) >= cutoff
        ]
        return sorted(fresh, key=lambda row: row["first_seen_on"], reverse=True)

    def enrich(self, kind, values):
        self.enrich_calls.append((kind, list(values)))
        if self.empty_values & set(values):
            return []
        rows = []
        for value in values:
            if value in self.missing_values:
                continue
            feed = "fin7" if kind == "domain" else "bp"
            base = {
                "sp_risk_score": 100,
                "listing_score_feeds_explain": [
                    {"feed_uuid": feed, "listed_first": 20261101}
                ],
            }
            if kind == "domain":
                rows.append({**base, "domaininfo": {"domain": value}})
            else:
                rows.append({**base, "ip": value, "asn": 64500, "asname": "AS"})
        return rows or [{"ip": "0.0.0.0", "domaininfo": {"domain": "other.example"}}]


class Harness:
    def __init__(self, tmp_path, monkeypatch):
        self.now = START
        harness = self

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return harness.now

        monkeypatch.setattr(connector_module, "datetime", Clock)
        self.client = FakeClient()
        self.bundles = []
        self.send_failures = 0

        instance = SilentPushConnector.__new__(SilentPushConnector)
        instance.helper = MagicMock()
        instance.helper.send_stix2_bundle.side_effect = self._send
        instance.interval_seconds = TWELVE_HOURS
        instance.enrich_budget = 60
        instance.client = self.client
        instance.store = SeenStore(str(tmp_path), "seen_iofa.txt")
        instance.osint_store = SeenStore(str(tmp_path), "seen_osint.txt")
        instance.osint_cursor = Cursor(str(tmp_path), "osint_last_run.txt")
        instance.osint_initial_lookback = timedelta(hours=24)
        instance.iofa_enabled = True
        instance.osint_enabled = True
        instance.osint_exclude = {
            name.strip()
            for name in connector_module.DEFAULT_OSINT_EXCLUDE.split(",")
        }
        instance._catalogue = None
        instance.builder = SilentPushStixBuilder(MARKING, 70)
        self.connector = instance

    def _send(self, bundle, update, work_id):
        if self.send_failures:
            self.send_failures -= 1
            raise RuntimeError("queue down")
        self.bundles.append(json.loads(bundle)["objects"])

    def osint(self, indicator, minutes_ago=5, **extra):
        """Add a Feed Scan row first seen `minutes_ago` before the harness clock."""
        added = self.now - timedelta(minutes=minutes_ago)
        row = osint_row(
            indicator,
            first_seen_on=added.strftime("%Y-%m-%dT%H:%M:%S"),
            **extra,
        )
        self.client.osint_rows.append(row)
        return row

    def run(self):
        self.connector.run_once()
        self.now += timedelta(hours=12)

    def values(self):
        return {
            obj["value"]
            for bundle in self.bundles
            for obj in bundle
            if obj["type"] in ("domain-name", "ipv4-addr", "ipv6-addr", "url")
        }

    def stream_values(self, stream):
        """Values carried by bundles whose Report belongs to `stream`."""
        found = set()
        for bundle in self.bundles:
            names = [obj["name"] for obj in bundle if obj["type"] == "report"]
            if names and names[0].startswith(f"Silent Push {stream} "):
                found |= {
                    obj["value"]
                    for obj in bundle
                    if obj["type"] in ("domain-name", "ipv4-addr", "ipv6-addr", "url")
                }
        return found

    def reports(self):
        return {
            obj["name"]
            for bundle in self.bundles
            for obj in bundle
            if obj["type"] == "report"
        }

    def failed_runs(self):
        calls = self.connector.helper.api.work.to_processed.call_args_list
        return [call for call in calls if call.kwargs.get("in_error")]


@pytest.fixture
def harness(tmp_path, monkeypatch):
    return Harness(tmp_path, monkeypatch)


def test_slot_start_and_next_slot():
    now = datetime(2026, 11, 7, 13, 30, tzinfo=timezone.utc)
    assert slot_start(now, TWELVE_HOURS) == datetime(2026, 11, 7, 12, tzinfo=timezone.utc)
    assert seconds_until_next_slot(now, TWELVE_HOURS) == 10.5 * 3600


def test_plan_batches_alternates_respects_caps_and_budget():
    domains = [f"d{i}.example" for i in range(250)]
    ips = [f"10.0.0.{i}" for i in range(250)]

    planned = plan_batches(domains, ips, 60)
    kinds = [kind for kind, _ in planned]
    assert kinds == ["domain", "ipv4", "domain", "ipv4", "domain"]
    sizes = sorted(len(batch) for kind, batch in planned if kind == "domain")
    assert sizes == [50, 100, 100]
    sizes = sorted(len(batch) for kind, batch in planned if kind == "ipv4")
    assert sizes == [50, 200]
    assert len(plan_batches(domains, ips, 2)) == 2
    assert plan_batches(["a.example"], [], 60) == [("domain", ["a.example"])]


def test_first_run_is_a_baseline_and_ingests_nothing(harness):
    harness.run()
    assert harness.bundles == []
    assert harness.client.enrich_calls == []
    assert harness.connector.store.load() == {
        "base-0.example",
        "base-1.example",
        "192.0.2.1",
    }


def test_failed_baseline_download_leaves_no_state(harness):
    harness.client.download_export = MagicMock(side_effect=SilentPushAPIError("nope"))
    harness.run()
    assert not harness.connector.store.exists()
    assert len(harness.failed_runs()) == 1


def test_only_additions_are_enriched_and_ingested(harness):
    harness.run()
    harness.client.domains.append("new.example")
    harness.client.ips.append("192.0.2.2")
    harness.run()

    assert harness.values() == {"new.example", "192.0.2.2"}
    assert sorted(kind for kind, _ in harness.client.enrich_calls) == ["domain", "ipv4"]
    assert harness.reports() == {"Silent Push IOFA - 2026-11-07 12:00 UTC"}
    objects = harness.bundles[0]
    assert any(obj["type"] == "intrusion-set" for obj in objects)
    report = next(obj for obj in objects if obj["type"] == "report")
    assert set(report["object_refs"]) <= {obj["id"] for obj in objects}


def test_a_run_with_no_additions_makes_no_report_and_no_calls(harness):
    harness.run()
    harness.run()
    assert harness.bundles == []
    assert harness.client.enrich_calls == []
    assert not harness.failed_runs()


def test_a_value_that_leaves_and_returns_is_not_new(harness):
    harness.run()
    harness.client.domains.remove("base-0.example")
    harness.run()
    harness.client.domains.append("base-0.example")
    harness.run()
    assert harness.client.enrich_calls == []


def test_failed_send_loses_nothing(harness):
    harness.run()
    harness.client.domains.append("new.example")
    harness.send_failures = 1
    harness.run()
    assert len(harness.failed_runs()) == 1
    assert "new.example" not in harness.connector.store.load()

    harness.run()
    assert "new.example" in harness.values()
    assert "new.example" in harness.connector.store.load()


def test_enrichment_exception_loses_nothing(harness):
    harness.run()
    harness.client.domains.append("new.example")
    original = harness.client.enrich
    harness.client.enrich = MagicMock(side_effect=SilentPushAPIError("HTTP 403"))
    harness.run()
    assert len(harness.failed_runs()) == 1

    harness.client.enrich = original
    harness.run()
    assert "new.example" in harness.values()


def test_budget_carries_the_rest_over_without_loss(harness):
    harness.connector.enrich_budget = 2
    harness.run()
    added = [f"new-{i}.example" for i in range(450)]
    harness.client.domains += added

    harness.run()
    assert len(harness.client.enrich_calls) == 2
    assert len(harness.values()) == 200
    harness.run()
    harness.run()
    assert harness.values() == set(added)
    assert len(harness.client.enrich_calls) == 5


def test_quota_stays_capped_when_a_huge_delta_appears(harness):
    harness.run()
    harness.client.domains += [f"flood-{i}.example" for i in range(20000)]
    harness.run()
    assert len(harness.client.enrich_calls) == 60


def test_value_the_api_never_answers_does_not_wedge_the_connector(harness):
    """Its batch-mates get through because later additions reshuffle them."""
    random.seed(1)
    harness.run()
    harness.client.domains.append("poison.example")
    harness.client.empty_values = {"poison.example"}

    early = []
    for step in range(20):
        added = [f"ok-{step}-{i}.example" for i in range(300)]
        harness.client.domains += added
        if step < 10:
            early += added
        harness.run()

    assert set(early) <= harness.values()
    assert "poison.example" not in harness.values()
    assert not harness.failed_runs()


def test_repeated_empty_answers_stop_the_run_early(harness):
    harness.run()
    values = [f"new-{i}.example" for i in range(1000)]
    harness.client.domains += values
    harness.client.empty_values = set(values)
    harness.run()
    assert len(harness.client.enrich_calls) == connector_module.MAX_EMPTY_BATCHES
    assert harness.bundles == []


def test_a_partly_answered_batch_ingests_the_gap_bare_and_finishes(harness):
    harness.run()
    harness.client.domains += ["answered.example", "gap.example"]
    harness.client.missing_values = {"gap.example"}
    harness.run()
    assert harness.values() == {"answered.example", "gap.example"}

    calls = len(harness.client.enrich_calls)
    harness.run()
    assert len(harness.client.enrich_calls) == calls


def test_rows_that_match_nothing_fail_loudly_and_mark_nothing(harness):
    harness.run()
    harness.client.domains.append("new.example")
    harness.client.missing_values = {"new.example"}
    harness.run()
    assert len(harness.failed_runs()) == 1
    assert "new.example" not in harness.connector.store.load()


def test_empty_catalogue_fails_rather_than_losing_attribution(harness):
    harness.run()
    harness.client.domains.append("new.example")
    harness.client.feeds = []
    harness.run()
    assert len(harness.failed_runs()) == 2  # IOFA and OSINT both refuse
    assert harness.client.enrich_calls == []


def test_org_feeds_are_never_used(harness):
    assert set(harness.connector._iofa_feeds()) == {"fin7", "bp", "iv"}


def test_benign_and_unusable_values_are_handled_once_and_never_ingested(harness):
    harness.run()
    harness.client.domains += ["bad value", "benign.example"]
    original = harness.client.enrich

    def enrich(kind, values):
        rows = original(kind, values)
        for row in rows:
            if row.get("domaininfo", {}).get("domain") == "benign.example":
                row["ns_reputation"] = {"is_sinkholed": True}
        return rows

    harness.client.enrich = enrich
    harness.run()
    assert harness.values() == set()
    assert {"bad value", "benign.example"} <= harness.connector.store.load()


def test_week_of_runs_with_a_moving_clock_and_churn(harness):
    """Two runs a day: every addition lands, and each slot gets its Report."""
    harness.run()
    expected = set()
    for step in range(14):
        added = [f"run-{step}-{i}.example" for i in range(3)]
        harness.client.domains += added
        harness.client.ips.append(f"198.51.100.{step + 1}")
        harness.client.domains.pop(0)  # churn at the old end of the file
        expected |= set(added) | {f"198.51.100.{step + 1}"}
        if step == 5:
            harness.send_failures = 1
        harness.run()

    assert harness.values() == expected
    assert len(harness.failed_runs()) == 1
    assert len(harness.reports()) == 13  # 14 slots minus the one that failed
    assert "Silent Push IOFA - 2026-11-08 00:00 UTC" in harness.reports()


def test_seen_store_survives_a_partial_line_from_a_crash(tmp_path):
    store = SeenStore(str(tmp_path))
    store.write_baseline(["a.example"])
    with open(store.path, "a", encoding="utf-8") as handle:
        handle.write("half-writ")
    store.append(["b.example"])
    assert {"a.example", "b.example"} <= store.load()
