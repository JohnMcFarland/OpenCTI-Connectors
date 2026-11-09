"""SP-FEED-REPORTS-V2: feed Reports hold AS/Country context and the attributed entity."""

import pytest

from stix_builder import SilentPushStixBuilder

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
FEEDS = {
    "bp": {"name": "Bulletproof Hosting IPs", "tags": []},
    "bp3": {"name": "Bulletproof Hosting IPs Part 3", "tags": []},
    "fin7-d": {"name": "Threat Actor - FIN7 Domains", "tags": []},
    "fin7-i": {"name": "Threat Actor - Fin7 IPs", "tags": []},
    "cs": {"name": "Cobaltstrike C2 IPs", "tags": []},
}


@pytest.fixture
def builder():
    return SilentPushStixBuilder(MARKING, 70)


def ip_row(*uuids):
    return {
        "ip": "203.0.113.9",
        "sp_risk_score": 100,
        "asn": 64500,
        "asname": "EXAMPLE-AS",
        "ip_location": {"country_code": "US"},
        "listing_score_explain": {"listed_first": 20260518, "listed_recent": 20261106},
        "listing_score_feeds_explain": [
            {"feed_uuid": u, "listed_first": 20260518, "listed_recent": 20261106}
            for u in uuids
        ],
    }


def build(builder, row):
    objects = builder.build_indicator("203.0.113.9", "ipv4-addr", row, FEEDS)
    return objects, builder.iofa_feed_members(row, FEEDS, objects)


def ids_of(objects, stix_type, **match):
    return [
        obj.id for obj in objects
        if obj.type == stix_type and all(getattr(obj, k) == v for k, v in match.items())
    ]


def context(objects):
    return [
        ids_of(objects, "autonomous-system")[0],
        ids_of(objects, "relationship", relationship_type="belongs-to")[0],
        ids_of(objects, "location")[0],
        ids_of(objects, "relationship", relationship_type="located-at")[0],
    ]


def test_attributed_feed_gets_context_entity_and_edge(builder):
    objects, members = build(builder, ip_row("fin7-i"))
    observable = objects[0].id
    entity = ids_of(objects, "intrusion-set")[0]
    edge = ids_of(objects, "relationship", relationship_type="related-to", target_ref=entity)[0]
    assert members == {
        "Threat Actor - Fin7 IPs": [observable] + context(objects) + [entity, edge]
    }


def test_unattributed_feed_gets_observable_and_context(builder):
    objects, members = build(builder, ip_row("bp", "bp3"))
    assert members == {"Bulletproof Hosting IPs": [objects[0].id] + context(objects)}


def test_notes_and_authors_never_members(builder):
    objects, members = build(builder, ip_row("fin7-i", "cs", "bp"))
    refs = {ref for ids in members.values() for ref in ids}
    for stix_type in ("note", "identity"):
        assert not refs & set(ids_of(objects, stix_type))


def test_each_feed_gets_its_own_entity(builder):
    objects, members = build(builder, ip_row("fin7-i", "cs"))
    actor = ids_of(objects, "intrusion-set")[0]
    tool = ids_of(objects, "tool")[0]
    assert actor in members["Threat Actor - Fin7 IPs"]
    assert tool not in members["Threat Actor - Fin7 IPs"]
    assert tool in members["Cobaltstrike C2 IPs"]
    assert actor not in members["Cobaltstrike C2 IPs"]


def test_paired_feeds_share_one_entity_and_edge(builder):
    objects, members = build(builder, ip_row("fin7-d", "fin7-i"))
    entity = ids_of(objects, "intrusion-set")
    edges = ids_of(objects, "relationship", relationship_type="related-to")
    assert len(entity) == 1 and len(edges) == 1
    for feed in ("Threat Actor - FIN7 Domains", "Threat Actor - Fin7 IPs"):
        assert members[feed] == [objects[0].id] + context(objects) + [entity[0], edges[0]]


def test_no_feed_goes_to_unattributed_with_context(builder):
    objects, members = build(builder, ip_row())
    assert members == {None: [objects[0].id] + context(objects)}


def test_domain_has_no_context(builder):
    row = ip_row("fin7-d")
    objects = builder.build_indicator("bad.example", "domain-name", row, FEEDS)
    members = builder.iofa_feed_members(row, FEEDS, objects)
    entity = ids_of(objects, "intrusion-set")[0]
    edge = ids_of(objects, "relationship", relationship_type="related-to")[0]
    assert members == {"Threat Actor - FIN7 Domains": [objects[0].id, entity, edge]}
