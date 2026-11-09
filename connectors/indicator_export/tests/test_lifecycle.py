from datetime import datetime, timedelta, timezone

import pytest
from pycti import Indicator

from src.lifecycle import LifecycleManager
from src.store import DecayEntry, StateStore

from .fakes import (
    AMBER_STRICT,
    CLEAR,
    RED,
    FakeClient,
    FakeLogger,
    FakeStateHelper,
    ap_link,
    entity,
    ipv4,
    related,
    settings,
)

NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


@pytest.fixture
def store(tmp_path):
    state = StateStore(FakeStateHelper())
    yield state


def manager(client, store, clock=lambda: NOW, **overrides):
    return LifecycleManager(client, store, settings(**overrides), FakeLogger(), clock)


def promoted(store, observable=None, client=None):
    """Create an Indicator through a real cycle and return the client."""
    client = client or FakeClient()
    observable = observable or ipv4()
    client.qualifying = [ap_link(observable)]
    manager(client, store).run_cycle()
    indicator_id = next(iter(client.indicators))
    client.based_on[indicator_id] = observable
    client.writes.clear()
    return client, indicator_id


def test_promotion_creates_indicator_and_both_edges(store):
    client = FakeClient()
    observable = ipv4()
    client.qualifying = [ap_link(observable)]
    result = manager(client, store).run_cycle()

    assert result.stats["promoted"] == 1
    indicator = next(iter(client.indicators.values()))
    assert indicator["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert indicator["valid_from"] == NOW.isoformat()
    kinds = {write[2] for write in client.writes if write[0] == "relationship"}
    assert kinds == {"based-on", "indicates"}


def test_no_attack_pattern_means_no_indicator(store):
    client = FakeClient()
    client.relationships["obs-1"] = [related("obs-1", entity("Intrusion-Set", "APT29"))]
    result = manager(client, store).run_cycle()
    assert result.stats["promoted"] == 0
    assert client.indicators == {}


ADVERSARY = ("Intrusion-Set", "APT29")
VICTIM = ("Organization", "Victim Corp")


@pytest.mark.parametrize(
    "entities, score, indicator_type",
    [
        ([], 50, "anomalous-activity"),
        ([("Tool", "PsExec")], 50, "anomalous-activity"),
        ([("Malware", "Emotet")], 75, "malicious-activity"),
        ([ADVERSARY], 75, "malicious-activity"),
        ([("Threat-Actor-Group", "SVR")], 75, "malicious-activity"),
        ([("Threat-Actor-Individual", "A Person")], 75, "malicious-activity"),
        ([VICTIM], 75, "malicious-activity"),
        ([ADVERSARY, VICTIM], 100, "malicious-activity"),
        ([("Malware", "Emotet"), VICTIM], 100, "malicious-activity"),
        ([("Threat-Actor-Individual", "A Person"), VICTIM], 100, "malicious-activity"),
    ],
)
def test_diamond_scoring(store, entities, score, indicator_type):
    client = FakeClient()
    client.qualifying = [ap_link(ipv4())]
    client.relationships["obs-1"] = [related("obs-1", entity(*e)) for e in entities]
    manager(client, store).run_cycle()
    indicator = next(iter(client.indicators.values()))
    assert indicator["x_opencti_score"] == score
    assert indicator["confidence"] == score
    assert indicator["indicator_types"] == [indicator_type]


def test_score_rises_as_the_diamond_fills_in(store):
    client, indicator_id = promoted(store)
    assert client.indicators[indicator_id]["x_opencti_score"] == 50

    client.relationships["obs-1"] = [related("obs-1", entity(*ADVERSARY))]
    manager(client, store).run_cycle()
    assert client.indicators[indicator_id]["x_opencti_score"] == 75

    client.relationships["obs-1"].append(related("obs-1", entity(*VICTIM)))
    manager(client, store).run_cycle()
    assert client.indicators[indicator_id]["x_opencti_score"] == 100


def test_score_falls_when_the_victim_link_is_removed(store):
    client, indicator_id = promoted(store)
    client.relationships["obs-1"] = [
        related("obs-1", entity(*ADVERSARY)),
        related("obs-1", entity(*VICTIM)),
    ]
    manager(client, store).run_cycle()
    client.relationships["obs-1"].pop()
    manager(client, store).run_cycle()
    assert client.indicators[indicator_id]["x_opencti_score"] == 75


def test_platform_score_drift_is_corrected(store):
    client, indicator_id = promoted(store)
    client.indicators[indicator_id]["x_opencti_score"] = 42
    manager(client, store).run_cycle()
    assert client.indicators[indicator_id]["x_opencti_score"] == 50


def test_every_observable_marking_reaches_the_indicator(store):
    client = FakeClient()
    client.qualifying = [ap_link(ipv4(markings=[CLEAR, RED]))]
    manager(client, store).run_cycle()
    indicator = next(iter(client.indicators.values()))
    assert {m["definition"] for m in indicator["objectMarking"]} == {"TLP:CLEAR", "TLP:RED"}


def test_unmarked_observable_gets_amber_strict(store):
    client = FakeClient()
    client.qualifying = [ap_link(ipv4(markings=[]))]
    manager(client, store).run_cycle()
    indicator = next(iter(client.indicators.values()))
    assert indicator["objectMarking"] == [AMBER_STRICT]


def test_excluded_types_and_labels_are_skipped(store):
    client = FakeClient()
    port = {"id": "nt", "entity_type": "Network-Traffic", "objectMarking": []}
    allowlisted = ipv4("obs-2", "8.8.8.8", labels=[{"value": "allowlist"}])
    client.qualifying = [ap_link(port), ap_link(allowlisted)]
    result = manager(client, store, INDICATOR_EXCLUDED_LABELS="allowlist").run_cycle()
    assert result.stats["promoted"] == 0


def test_second_cycle_syncs_instead_of_recreating(store):
    client, _ = promoted(store)
    result = manager(client, store).run_cycle()
    assert result.stats["promoted"] == 0
    assert result.stats["synced"] == 1
    assert len(client.indicators) == 1


def test_sync_updates_score_and_types_together(store):
    client, indicator_id = promoted(store)
    client.relationships["obs-1"] = [related("obs-1", entity(*ADVERSARY))]
    manager(client, store).run_cycle()
    assert client.indicators[indicator_id]["confidence"] == 75
    assert client.indicators[indicator_id]["indicator_types"] == ["malicious-activity"]


def test_created_indicator_is_queued_for_todays_grouping(store):
    client, indicator_id = promoted(store)
    assert store.pending_grouping() == [("2026-11-05", indicator_id)]


def test_dry_run_queues_nothing_for_grouping(store):
    client = FakeClient(dry_run=True, author=None)
    client.qualifying = [ap_link(ipv4())]
    manager(client, store).run_cycle()
    assert store.pending_grouping() == []


def test_sync_adds_a_raised_marking(store):
    client, indicator_id = promoted(store)
    raised = ipv4(markings=[RED])
    client.qualifying = [ap_link(raised)]
    client.based_on[indicator_id] = raised
    manager(client, store).run_cycle()
    assert ("marking", indicator_id, "m-red") in client.writes


def test_sync_adds_new_and_removes_stale_attack_patterns(store):
    observable = ipv4()
    client, indicator_id = promoted(store, observable)
    client.qualifying = [ap_link(observable, "ap-2")]
    manager(client, store).run_cycle()
    assert client.active_edges(indicator_id) == {"ap-2"}
    # The stale edge is revoked, not deleted.
    assert client.edges[indicator_id]["ap-1"][0]["revoked"] is True
    assert not any(write[0] == "delete" for write in client.writes)


def test_returning_attack_pattern_restores_the_revoked_edge(store):
    observable = ipv4()
    client, indicator_id = promoted(store, observable)
    client.qualifying = [ap_link(observable, "ap-2")]
    manager(client, store).run_cycle()
    client.qualifying = [ap_link(observable, "ap-1"), ap_link(observable, "ap-2")]
    client.writes.clear()
    manager(client, store).run_cycle()
    assert client.active_edges(indicator_id) == {"ap-1", "ap-2"}
    assert len(client.edges[indicator_id]["ap-1"]) == 1
    assert ("restore_edge", f"edge-{indicator_id}-ap-1") in client.writes
    assert not any(w[0] == "relationship" and w[3] == "ap-1" for w in client.writes)


def test_edges_authored_by_others_are_never_revoked(store):
    observable = ipv4()
    client, indicator_id = promoted(store, observable)
    client.edges[indicator_id]["ap-analyst"] = [
        {"id": "analyst-edge", "revoked": False, "creator": "analyst"}
    ]
    manager(client, store).run_cycle()
    assert "ap-analyst" in client.active_edges(indicator_id)
    assert not any(w[0] == "revoke_edge" for w in client.writes)


def test_foreign_revoked_edge_is_not_overridden(store):
    observable = ipv4()
    client, indicator_id = promoted(store, observable)
    client.edges[indicator_id]["ap-2"] = [
        {"id": "analyst-edge", "revoked": True, "creator": "analyst"}
    ]
    client.qualifying = [ap_link(observable, "ap-1"), ap_link(observable, "ap-2")]
    manager(client, store).run_cycle()
    assert client.edges[indicator_id]["ap-2"] == [
        {"id": "analyst-edge", "revoked": True, "creator": "analyst"}
    ]
    assert not any(w[0] == "relationship" and w[3] == "ap-2" for w in client.writes)


def test_dry_run_revokes_nothing(store):
    observable = ipv4()
    client, indicator_id = promoted(store, observable)
    client.dry_run = True
    client.qualifying = [ap_link(observable, "ap-2")]
    manager(client, store).run_cycle()
    assert client.active_edges(indicator_id) == {"ap-1"}


def test_pattern_held_by_someone_else_is_left_alone(store):
    client = FakeClient()
    observable = ipv4()
    client.qualifying = [ap_link(observable)]
    stix_id = Indicator.generate_id("[ipv4-addr:value = '1.2.3.4']")
    client.foreign[stix_id] = {"id": "theirs", "createdBy": {"id": "someone-else"}}
    result = manager(client, store).run_cycle()
    assert result.stats["collisions"] == 1
    assert result.stats["promoted"] == 0
    assert client.writes == []


def test_collision_counts_in_dry_run_before_the_author_exists(store):
    client = FakeClient(dry_run=True, author=None)
    client.qualifying = [ap_link(ipv4())]
    stix_id = Indicator.generate_id("[ipv4-addr:value = '1.2.3.4']")
    client.foreign[stix_id] = {"id": "theirs", "createdBy": {"id": "someone-else"}}
    result = manager(client, store).run_cycle()
    assert result.stats["collisions"] == 1


def test_lost_based_on_link_is_repaired(store):
    client, indicator_id = promoted(store)
    del client.based_on[indicator_id]
    result = manager(client, store).run_cycle()
    assert result.stats["promoted"] == 0
    assert any(w[0] == "relationship" and w[2] == "based-on" for w in client.writes)


def test_lapsed_condition_enters_decay_once(store):
    client, indicator_id = promoted(store)
    other = ipv4("obs-2", "5.6.7.8")
    client.qualifying = [ap_link(other)]

    result = manager(client, store).run_cycle()
    assert result.stats["decay_entered"] == 1
    assert indicator_id in result.decaying
    expected = (NOW + timedelta(days=30)).isoformat()
    assert client.indicators[indicator_id]["valid_until"] == expected

    again = manager(client, store).run_cycle()
    assert again.stats["decay_entered"] == 0
    assert indicator_id in again.decaying


def test_platform_set_valid_until_does_not_mean_decay(store):
    # Indicators can carry a valid_until from the platform. That alone must not
    # read as decay, or sync would clear it on every cycle.
    client, indicator_id = promoted(store)
    assert client.indicators[indicator_id]["valid_until"]
    result = manager(client, store).run_cycle()
    assert result.stats["restored"] == 0
    assert not [w for w in client.writes if w[0] == "valid_until"]


def test_requalifying_restores_the_original_valid_until(store):
    observable = ipv4()
    client, indicator_id = promoted(store, observable)
    original = client.indicators[indicator_id]["valid_until"]

    client.qualifying = [ap_link(ipv4("obs-2", "5.6.7.8"))]
    manager(client, store).run_cycle()
    client.qualifying = [ap_link(observable)]
    result = manager(client, store).run_cycle()

    assert result.stats["restored"] == 1
    assert client.indicators[indicator_id]["valid_until"] == original
    assert store.get_decay(indicator_id) is None


def test_decay_window_end_revokes(store):
    client, indicator_id = promoted(store)
    client.qualifying = [ap_link(ipv4("obs-2", "5.6.7.8"))]
    manager(client, store).run_cycle()

    later = NOW + timedelta(days=31)
    result = manager(client, store, clock=lambda: later).run_cycle()
    assert result.stats["revoked"] == 1
    assert client.indicators[indicator_id]["revoked"] is True


def test_deleted_observable_also_decays(store):
    client, indicator_id = promoted(store)
    del client.based_on[indicator_id]
    client.qualifying = [ap_link(ipv4("obs-2", "5.6.7.8"))]
    manager(client, store).run_cycle()
    assert store.get_decay(indicator_id).reason == "OBSERVABLE_MISSING"


def test_revoked_indicator_is_not_silently_reactivated(store):
    client, indicator_id = promoted(store)
    client.indicators[indicator_id]["revoked"] = True
    result = manager(client, store).run_cycle()
    assert result.stats["revoked_but_qualifying"] == 1
    assert client.indicators[indicator_id]["revoked"] is True


def test_empty_query_result_cannot_decay_everything(store):
    client, indicator_id = promoted(store)
    client.qualifying = []
    result = manager(client, store).run_cycle()
    assert result.stats["decay_entered"] == 0
    assert result.stats["errors"] == 1
    assert store.get_decay(indicator_id) is None


def test_failure_on_one_observable_does_not_decay_it(store):
    observable = ipv4()
    client, indicator_id = promoted(store, observable)
    client.fail_relationships_for = {"obs-1"}
    result = manager(client, store).run_cycle()
    assert result.stats["errors"] == 1
    assert result.stats["decay_entered"] == 0


def test_one_failure_does_not_stop_the_others(store):
    client = FakeClient()
    client.qualifying = [ap_link(ipv4()), ap_link(ipv4("obs-2", "5.6.7.8"))]
    client.fail_relationships_for = {"obs-1"}
    result = manager(client, store).run_cycle()
    assert result.stats["errors"] == 1
    assert result.stats["promoted"] == 1


def test_error_limit_stops_the_cycle_without_decaying(store):
    client, indicator_id = promoted(store)
    client.qualifying = [ap_link(ipv4("obs-2", "5.6.7.8"))]
    client.fail_relationships_for = {"obs-2"}
    result = manager(client, store, INDICATOR_MAX_ERRORS="1").run_cycle()
    assert result.stats["decay_entered"] == 0


def test_dry_run_writes_nothing_anywhere(store):
    client = FakeClient(dry_run=True, author=None)
    client.qualifying = [ap_link(ipv4())]
    result = manager(client, store).run_cycle()
    assert result.stats["promoted"] == 1
    assert client.indicators == {}
    assert client.writes == []
    assert result.previews[0]["pattern"] == "[ipv4-addr:value = '1.2.3.4']"


def test_dry_run_decay_leaves_no_local_state(store):
    client, indicator_id = promoted(store)
    client.dry_run = True
    client.qualifying = [ap_link(ipv4("obs-2", "5.6.7.8"))]
    result = manager(client, store).run_cycle()
    assert indicator_id in result.decaying
    assert store.get_decay(indicator_id) is None


def test_failed_valid_until_write_leaves_decay_unrecorded(store):
    client, indicator_id = promoted(store)

    def fail(*_):
        raise RuntimeError("api down")

    client.set_valid_until = fail
    client.qualifying = [ap_link(ipv4("obs-2", "5.6.7.8"))]
    result = manager(client, store).run_cycle()
    assert result.stats["errors"] == 1
    assert store.get_decay(indicator_id) is None


def test_decay_survives_a_restart():
    platform = FakeStateHelper()
    first = StateStore(platform)
    first.put_decay("ind-1", DecayEntry("2026-12-01T00:00:00+00:00", None, "X"))
    first.save()
    second = StateStore(platform)
    assert second.get_decay("ind-1").reason == "X"


def test_unsaved_changes_do_not_reach_the_platform():
    platform = FakeStateHelper()
    first = StateStore(platform)
    first.put_decay("ind-1", DecayEntry("2026-12-01T00:00:00+00:00", None, "X"))
    assert StateStore(platform).get_decay("ind-1") is None


def test_only_allowlisted_observable_types_are_promoted(store):
    client = FakeClient()
    software = {"id": "sw", "entity_type": "Software", "name": "Slack", "objectMarking": []}
    account = {"id": "ua", "entity_type": "User-Account", "account_login": "root", "objectMarking": []}
    client.qualifying = [ap_link(software), ap_link(account), ap_link(ipv4())]
    result = manager(client, store).run_cycle()
    assert result.stats["promoted"] == 1
    assert [i["pattern"] for i in client.indicators.values()] == ["[ipv4-addr:value = '1.2.3.4']"]


def test_allowlist_is_configurable_but_never_blank(store):
    assert settings().allowed_observable_types == frozenset(
        ["IPv4-Addr", "IPv6-Addr", "StixFile", "Domain-Name", "Url"]
    )
    assert settings(INDICATOR_ALLOWED_OBSERVABLE_TYPES="").allowed_observable_types == (
        settings().allowed_observable_types
    )
    assert settings(INDICATOR_ALLOWED_OBSERVABLE_TYPES="Url").allowed_observable_types == frozenset(["Url"])


def test_valid_from_is_creation_time_not_first_link(store):
    # IE-VALIDFROM-NOW-V1: a backdated valid_from makes OpenCTI create the
    # Indicator already expired.
    client = FakeClient()
    client.qualifying = [ap_link(ipv4(), created_at="2026-04-01T00:00:00Z")]
    manager(client, store).run_cycle()
    assert next(iter(client.indicators.values()))["valid_from"] == NOW.isoformat()


def test_decayed_score_is_not_pushed_back(store):
    # IE-DECAY-BASESCORE-V1: decay lowered the score; the base score still
    # matches the Diamond score, so no assessment write.
    client, indicator_id = promoted(store)
    client.indicators[indicator_id]["x_opencti_score"] = 20
    client.indicators[indicator_id]["decay_base_score"] = 50
    manager(client, store).run_cycle()
    assert not any(w[0] == "assessment" for w in client.writes)


def test_changed_diamond_score_is_still_written(store):
    client, indicator_id = promoted(store)
    client.indicators[indicator_id]["x_opencti_score"] = 20
    client.indicators[indicator_id]["decay_base_score"] = 75
    manager(client, store).run_cycle()
    assert ("assessment", indicator_id, 50) in client.writes
