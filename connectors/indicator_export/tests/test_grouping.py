from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from src.connector import IndicatorExportConnector
from src.grouping import flush_groupings, grouping_day, grouping_name
from src.sinks import CsvSink, Delivery, ExportError
from src.store import StateStore

from .fakes import SENSITIVE, FakeClient, FakeLogger, FakeStateHelper, ap_link, ipv4, settings


def utc(*parts):
    return datetime(*parts, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "moment, day",
    [
        (utc(2026, 11, 7, 4, 59), "2026-11-06"),  # 23:59 EST
        (utc(2026, 11, 7, 5, 0), "2026-11-07"),  # 00:00 EST
        (utc(2026, 7, 2, 3, 59), "2026-07-01"),  # 23:59 EDT
        (utc(2026, 7, 2, 4, 0), "2026-07-02"),  # 00:00 EDT
    ],
)
def test_day_changes_at_eastern_midnight_all_year(moment, day):
    assert grouping_day(moment) == day


def test_name():
    assert grouping_name("2026-11-06") == "Indicator Export 2026-11-06"


@pytest.fixture
def store(tmp_path):
    state = StateStore(FakeStateHelper())
    yield state


def flush(client, store, today="2026-11-06"):
    return flush_groupings(client, store, FakeLogger(), "author", "m-strict", today)


def test_same_day_lands_in_one_grouping(store):
    client = FakeClient()
    store.queue_grouping("2026-11-06", ["a", "b"])
    assert flush(client, store) == (2, 0)
    assert client.groupings == {"Indicator Export 2026-11-06": ["a", "b"]}


def test_an_indicator_is_added_once_a_day(store):
    client = FakeClient()
    store.queue_grouping("2026-11-06", ["a"])
    flush(client, store)
    store.queue_grouping("2026-11-06", ["a"])
    assert flush(client, store) == (0, 0)
    assert client.groupings["Indicator Export 2026-11-06"] == ["a"]


def test_a_new_day_adds_it_again_to_the_new_grouping(store):
    client = FakeClient()
    store.queue_grouping("2026-11-06", ["a"])
    flush(client, store)
    store.queue_grouping("2026-11-07", ["a"])
    flush(client, store, today="2026-11-07")
    assert client.groupings["Indicator Export 2026-11-07"] == ["a"]


def test_failed_add_is_retried_into_its_original_day(store):
    client = FakeClient()
    store.queue_grouping("2026-11-06", ["a"])
    client.fail_grouping_adds = True
    assert flush(client, store) == (0, 1)

    client.fail_grouping_adds = False
    assert flush(client, store, today="2026-11-07") == (1, 0)
    assert client.groupings["Indicator Export 2026-11-06"] == ["a"]


def test_finished_days_are_forgotten_but_today_is_kept(store):
    client = FakeClient()
    store.queue_grouping("2026-11-05", ["old"])
    store.queue_grouping("2026-11-06", ["new"])
    flush(client, store)
    store.queue_grouping("2026-11-06", ["new"])
    assert store.pending_grouping() == []


def build(tmp_path, client, sink=None, state_helper=None, **overrides):
    helper = MagicMock()
    helper.connector_logger = FakeLogger()
    helper.get_state.return_value = {}
    config = settings(EXPORT_DATA_DIR=str(tmp_path), **overrides)
    state = StateStore(state_helper or FakeStateHelper())
    connector = IndicatorExportConnector(
        helper, config, client, state, sink or CsvSink(str(tmp_path), 5)
    )
    return connector, helper, state


def today_name():
    return grouping_name(grouping_day(datetime.now(timezone.utc)))


def test_created_and_exported_indicator_is_in_todays_grouping_once(tmp_path):
    client = FakeClient()
    client.qualifying = [ap_link(ipv4())]
    connector, _, state = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()
    connector.process()
    assert client.groupings[today_name()] == list(client.indicators)


def test_exported_indicator_created_on_another_day_joins_todays_grouping(tmp_path):
    client = FakeClient()
    observable = ipv4()
    client.qualifying = [ap_link(observable)]
    connector, _, state = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()
    indicator_id = next(iter(client.indicators))
    client.based_on[indicator_id] = observable
    state.prune_grouped("9999-12-31")
    client.groupings.clear()

    connector.process()
    assert client.groupings[today_name()] == [indicator_id]


def test_sensitive_indicator_is_grouped_but_not_exported(tmp_path):
    client = FakeClient()
    client.qualifying = [ap_link(ipv4(markings=[SENSITIVE]))]
    connector, _, state = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()
    assert client.groupings[today_name()] == list(client.indicators)


def test_dry_run_creates_no_grouping(tmp_path):
    client = FakeClient(dry_run=True, author=None)
    client.qualifying = [ap_link(ipv4())]
    connector, _, state = build(tmp_path, client)
    connector.process()
    assert client.groupings == {}


def test_dry_run_leaves_groupings_alone_when_indicators_already_exist(tmp_path):
    client = FakeClient()
    observable = ipv4()
    client.qualifying = [ap_link(observable)]
    shared = FakeStateHelper()
    live, _, live_state = build(tmp_path, client, state_helper=shared, INDICATOR_DRY_RUN="false")
    live.process()
    client.based_on[next(iter(client.indicators))] = observable
    live_state.prune_grouped("9999-12-31")
    live_state.save()
    client.groupings.clear()
    client.dry_run = True

    dry, _, dry_state = build(tmp_path, client, state_helper=shared)
    dry.process()
    assert client.groupings == {}
    assert dry_state.pending_grouping() == []


def test_grouping_failure_does_not_stop_the_export_and_flags_the_cycle(tmp_path):
    client = FakeClient()
    client.qualifying = [ap_link(ipv4())]
    client.fail_grouping_adds = True
    connector, helper, state = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True
    assert state.pending_grouping()


def test_batches_delivered_before_a_failure_are_still_grouped(tmp_path):
    class PartialSink:
        def deliver(self, records, dry_run):
            raise ExportError("second batch failed", delivered=tuple(records))

    client = FakeClient()
    observable = ipv4()
    client.qualifying = [ap_link(observable)]
    connector, _, state = build(tmp_path, client, sink=PartialSink(), INDICATOR_DRY_RUN="false")
    connector.process()
    indicator_id = next(iter(client.indicators))
    client.based_on[indicator_id] = observable
    state.prune_grouped("9999-12-31")
    client.groupings.clear()
    connector.process()
    assert client.groupings[today_name()] == [indicator_id]


def test_nothing_delivered_adds_nothing_new(tmp_path):
    class QuietSink:
        def deliver(self, records, dry_run):
            return Delivery("nothing changed", ())

    client = FakeClient()
    observable = ipv4()
    client.qualifying = [ap_link(observable)]
    connector, _, state = build(tmp_path, client, sink=QuietSink(), INDICATOR_DRY_RUN="false")
    connector.process()
    client.based_on[next(iter(client.indicators))] = observable
    state.prune_grouped("9999-12-31")
    client.groupings.clear()
    connector.process()
    assert client.groupings == {}
