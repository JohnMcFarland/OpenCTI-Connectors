"""Indicators inherit Guide5-permitted edges from their observable (IE-INHERIT-EDGES-V1)."""

import pytest

from src.inherit import MANAGED_TARGET_TYPES, inherited_edges
from src.lifecycle import LifecycleManager
from src.store import StateStore

from .fakes import RED, FakeClient, FakeLogger, FakeStateHelper, ap_link, entity, ipv4, related, settings
from .test_connector import real_client


@pytest.fixture
def store():
    return StateStore(FakeStateHelper())


def run(client, store):
    return LifecycleManager(client, store, settings(), FakeLogger()).run_cycle()


def links(client, indicator_id):
    return {(w[2], w[3]) for w in client.writes
            if w[0] == "relationship" and w[1] == indicator_id and w[2] != "based-on"}


def test_inherits_permitted_types_with_guide5_verbs(store):
    obs = ipv4()
    client = FakeClient()
    client.qualifying = [ap_link(obs)]
    client.relationships[obs["id"]] = [
        related(obs["id"], entity("Malware", "Emotet")),
        related(obs["id"], entity("Threat-Actor-Group", "FIN7"), reverse=True),
        related(obs["id"], entity("Threat-Actor-Individual", "Someone")),
        related(obs["id"], entity("Campaign", "Op X")),
        related(obs["id"], entity("Infrastructure", "C2 Cluster")),
        related(obs["id"], entity("Tool", "Cobalt Strike")),
        related(obs["id"], entity("Intrusion-Set", "APT29")),
        related(obs["id"], entity("Organization", "Victim Corp")),
        related(obs["id"], entity("Vulnerability", "CVE-2026-1")),
        related(obs["id"], entity("Country", "France")),
    ]
    result = run(client, store)
    ind = next(iter(client.indicators))
    assert links(client, ind) == {
        ("indicates", "ap-1"),
        ("indicates", "Malware-Emotet"),
        ("indicates", "Threat-Actor-Group-FIN7"),
        ("indicates", "Threat-Actor-Individual-Someone"),
        ("indicates", "Campaign-Op X"),
        ("indicates", "Infrastructure-C2 Cluster"),
        ("indicates", "Tool-Cobalt Strike"),
        ("related-to", "Intrusion-Set-APT29"),
    }
    assert result.stats["inherited_edges"] == 7


def test_inherited_edge_carries_source_markings(store):
    obs = ipv4()
    client = FakeClient()
    client.qualifying = [ap_link(obs)]
    client.relationships[obs["id"]] = [related(obs["id"], entity("Malware", "Emotet"), markings=[RED])]
    run(client, store)
    ind = next(iter(client.indicators))
    marks = {w[3]: w[4] for w in client.writes if w[0] == "relationship" and w[1] == ind}
    assert "m-red" in marks["Malware-Emotet"]
    assert "m-red" not in marks["ap-1"]


def test_revoked_source_edge_is_not_inherited():
    rel = related("o", entity("Malware", "Old"))
    rel["revoked"] = True
    assert inherited_edges("o", [rel]) == {}


def test_lost_source_link_revokes_only_our_inherited_edge(store):
    obs = ipv4()
    client = FakeClient()
    client.qualifying = [ap_link(obs)]
    client.relationships[obs["id"]] = [related(obs["id"], entity("Malware", "Emotet"))]
    run(client, store)
    ind = next(iter(client.indicators))
    client.based_on[ind] = obs
    client.edges[ind]["Malware-Analyst"] = [
        {"id": "analyst-edge", "revoked": False, "creator": "analyst", "type": "indicates"}
    ]
    client.relationships[obs["id"]] = []
    client.writes.clear()
    run(client, store)
    assert ("revoke_edge", f"edge-{ind}-Malware-Emotet") in client.writes
    assert "Malware-Analyst" in client.active_edges(ind)
    assert "ap-1" in client.active_edges(ind)


def test_dry_run_counts_inherited_edges_and_writes_nothing(store):
    obs = ipv4()
    client = FakeClient(dry_run=True)
    client.qualifying = [ap_link(obs)]
    client.relationships[obs["id"]] = [
        related(obs["id"], entity("Malware", "Emotet")),
        related(obs["id"], entity("Intrusion-Set", "APT29")),
    ]
    result = run(client, store)
    assert result.stats["inherited_edges"] == 2
    assert not client.indicators and not client.edges


def test_edge_query_covers_both_managed_types():
    client, api = real_client(dry_run=False)
    api.stix_core_relationship.list.return_value = []
    client.managed_edges("i")
    calls = {c.kwargs["relationship_type"]: c.kwargs["toTypes"] for c in api.stix_core_relationship.list.call_args_list}
    assert calls == {k: list(v) for k, v in MANAGED_TARGET_TYPES.items()}
    assert "Attack-Pattern" in calls["indicates"] and calls["related-to"] == ["Intrusion-Set"]
