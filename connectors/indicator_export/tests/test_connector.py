"""Whole-cycle tests, plus the real client against a fake pycti API."""

import csv
import glob
from unittest.mock import MagicMock

import pytest

from src.connector import IndicatorExportConnector
from src.opencti_client import OpenCTIClient
from src.sinks import CsvSink, ExportError
from src.store import StateStore

from .fakes import FakeClient, FakeLogger, RED, ap_link, entity, ipv4, related, settings


def build(tmp_path, client, sink=None, **overrides):
    helper = MagicMock()
    helper.connector_logger = FakeLogger()
    helper.get_state.return_value = {}
    config = settings(EXPORT_DATA_DIR=str(tmp_path), **overrides)
    store = StateStore(str(tmp_path))
    sink = sink or CsvSink(str(tmp_path), 5)
    return IndicatorExportConnector(helper, config, client, store, sink), helper


def rows(tmp_path):
    path = sorted(glob.glob(str(tmp_path / "*.csv")))[-1]
    with open(path, newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def graph(client, observable=None):
    observable = observable or ipv4()
    client.qualifying = [ap_link(observable)]
    client.relationships[observable["id"]] = [
        related(observable["id"], entity("Intrusion-Set", "APT29")),
        related(observable["id"], entity("System", "HOST-01")),
        related(observable["id"], entity("Malware", "Hidden", markings=[RED])),
    ]
    return observable


def test_dry_run_csv_shows_what_would_be_created(tmp_path):
    client = FakeClient(dry_run=True, author=None)
    graph(client)
    connector, helper = build(tmp_path, client)
    connector.process()

    row = rows(tmp_path)[0]
    assert row["status"] == "would_create"
    assert row["labels"] == "intrusion-set:APT29"
    assert row["labels_dropped"] == "excluded_type=1;marking=1"
    assert row["confidence"] == "85"
    assert client.indicators == {}
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is False


def test_labels_are_never_written_to_opencti(tmp_path):
    client = FakeClient()
    graph(client)
    connector, _ = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()

    assert rows(tmp_path)[0]["labels"] == "intrusion-set:APT29"
    indicator = next(iter(client.indicators.values()))
    assert indicator["objectLabel"] == []


def test_live_cycle_exports_the_created_indicator(tmp_path):
    client = FakeClient()
    graph(client)
    connector, _ = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()

    row = rows(tmp_path)[0]
    assert row["status"] == "active"
    assert row["observable_value"] == "1.2.3.4"
    assert row["valid_until"]


def test_indicator_above_ceiling_is_withheld(tmp_path):
    client = FakeClient()
    graph(client, ipv4(markings=[RED]))
    connector, helper = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()

    assert rows(tmp_path) == []
    assert "Blocked by marking: 1" in helper.api.work.to_processed.call_args.args[1]


def test_revoked_and_decaying_status_reach_the_export(tmp_path):
    client = FakeClient()
    observable = graph(client)
    connector, _ = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()
    indicator_id = next(iter(client.indicators))
    client.based_on[indicator_id] = observable

    client.qualifying = [ap_link(ipv4("obs-2", "5.6.7.8"))]
    connector.process()
    by_value = {row["observable_value"]: row for row in rows(tmp_path)}
    assert by_value["1.2.3.4"]["status"] == "decaying"

    client.indicators[indicator_id]["revoked"] = True
    connector.process()
    by_value = {row["observable_value"]: row for row in rows(tmp_path)}
    assert by_value["1.2.3.4"]["status"] == "revoked"


def test_removing_a_relationship_removes_the_label(tmp_path):
    client = FakeClient()
    observable = graph(client)
    connector, _ = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()
    client.based_on[next(iter(client.indicators))] = observable

    client.relationships[observable["id"]] = []
    connector.process()
    assert rows(tmp_path)[0]["labels"] == ""


def test_label_lookup_failure_withholds_rather_than_sends_partial(tmp_path):
    client = FakeClient()
    observable = graph(client)
    connector, helper = build(tmp_path, client, INDICATOR_DRY_RUN="false")
    connector.process()
    client.based_on[next(iter(client.indicators))] = observable

    client.fail_relationships_for = {observable["id"]}
    connector.process()
    assert rows(tmp_path) == []
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_export_failure_keeps_lifecycle_work_and_flags_the_cycle(tmp_path):
    class BrokenSink:
        def deliver(self, records, dry_run):
            raise ExportError("destination down")

    client = FakeClient()
    graph(client)
    connector, helper = build(tmp_path, client, sink=BrokenSink(), INDICATOR_DRY_RUN="false")
    connector.process()

    assert len(client.indicators) == 1
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_unexpected_failure_still_closes_the_work_item(tmp_path):
    client = FakeClient()
    client.qualifying_relationships = MagicMock(side_effect=RuntimeError("api down"))
    connector, helper = build(tmp_path, client)
    connector.process()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def real_client(dry_run):
    helper = MagicMock()
    helper.connector_logger = FakeLogger()
    return OpenCTIClient(helper, "Indicator Export", dry_run), helper.api


def test_dry_run_client_makes_no_write_calls():
    client, api = real_client(dry_run=True)
    assert client.create_indicator(name="x", pattern="[y]") is None
    client.create_relationship("a", "b", "based-on", 15, "author", [])
    client.delete_relationship("r")
    client.add_marking("i", "m")
    client.update_assessment("i", 85, ["malicious-activity"])
    client.set_valid_until("i", "2026-01-01T00:00:00Z")
    client.revoke("i")

    api.indicator.create.assert_not_called()
    api.indicator.update_field.assert_not_called()
    api.stix_core_relationship.create.assert_not_called()
    api.stix_core_relationship.delete.assert_not_called()
    api.stix_domain_object.add_marking_definition.assert_not_called()


def test_dry_run_author_lookup_does_not_create():
    client, api = real_client(dry_run=True)
    api.identity.read.return_value = None
    assert client.resolve_author() is None
    api.identity.create.assert_not_called()


def test_live_client_sends_list_shaped_edits():
    client, api = real_client(dry_run=False)
    client.revoke("i")
    api.indicator.update_field.assert_called_with(
        id="i", input=[{"key": "revoked", "value": [True]}]
    )
    client.set_valid_until("i", None)
    api.indicator.update_field.assert_called_with(
        id="i", input=[{"key": "valid_until", "value": []}]
    )


def test_every_list_call_pages_through_all_results():
    client, api = real_client(dry_run=False)
    api.stix_core_relationship.list.return_value = []
    api.indicator.list.return_value = []
    client.qualifying_relationships()
    client.observable_relationships("o")
    client.based_on_observable("i")
    client.indicates_edges("i")
    client.owned_indicators("a")
    for call in api.stix_core_relationship.list.call_args_list:
        assert call.kwargs["getAll"] is True
    assert api.indicator.list.call_args.kwargs["getAll"] is True


def test_owned_query_does_not_filter_out_revoked():
    client, api = real_client(dry_run=False)
    api.indicator.list.return_value = []
    client.owned_indicators("a")
    keys = [f["key"] for f in api.indicator.list.call_args.kwargs["filters"]["filters"]]
    assert keys == ["createdBy"]


def test_missing_default_marking_fails_closed():
    client, api = real_client(dry_run=False)
    api.marking_definition.list.return_value = [{"definition": "TLP:CLEAR"}]
    with pytest.raises(RuntimeError):
        client.default_marking()


def test_graphql_selections_are_balanced():
    from src import opencti_client as module

    for name in (
        "_QUALIFYING_ATTRIBUTES",
        "_RELATED_ATTRIBUTES",
        "_BASED_ON_ATTRIBUTES",
        "_INDICATES_ATTRIBUTES",
        "INDICATOR_ATTRIBUTES",
    ):
        text = getattr(module, name)
        assert text.count("{") == text.count("}"), name
        assert "%s" not in text, name
