from datetime import datetime, timezone

import pytest

from stix_builder import (
    SilentPushStixBuilder,
    classify,
    feed_entity,
    is_excluded,
    parse_listing_date,
    risk_to_score,
    row_value,
)

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
FEEDS = {
    "bp": {"name": "Bulletproof Hosting IPs", "tags": ["iofa", "bulletproof"]},
    "fin7-d": {"name": "Threat Actor - FIN7 Domains", "tags": ["fin7", "iofa"]},
    "fin7-i": {"name": "Threat Actor - Fin7 IPs", "tags": ["fin7", "iofa"]},
    "cs": {"name": "Cobaltstrike C2 IPs", "tags": ["c2", "iofa"]},
    "ztds": {"name": "zTDS C2 IPs", "tags": ["c2", "iofa"]},
}


@pytest.fixture
def builder():
    return SilentPushStixBuilder(MARKING, 70)


def listing(uuid, first=20260518):
    return {"feed_uuid": uuid, "listed_first": first, "listed_recent": 20261106}


def ip_row(*listings):
    return {
        "ip": "203.0.113.9",
        "sp_risk_score": 100,
        "asn": 64500,
        "asname": "EXAMPLE-AS",
        "ip_location": {"country_code": "US"},
        "listing_score_explain": {"listed_first": 20260518, "listed_recent": 20261106},
        "listing_score_feeds_explain": list(listings),
    }


def of_type(objects, stix_type):
    return [obj for obj in objects if obj.type == stix_type]


@pytest.mark.parametrize(
    "name,expected",
    [
        ("Threat Actor - FIN7 Domains", ("intrusion-set", "FIN7 (SilentPush)")),
        ("Threat Actor - Fin7 IPs", ("intrusion-set", "FIN7 (SilentPush)")),
        ("APT - APT28 IPs", ("intrusion-set", "APT28 (SilentPush)")),
        (
            "APT - Salt Typhoon / UNC4841 Domains",
            ("intrusion-set", "Salt Typhoon / UNC4841 (SilentPush)"),
        ),
        ("Cobaltstrike C2 Domains", ("tool", "Cobalt Strike")),
        ("zTDS C2 IPs", ("malware", "zTDS")),
        ("Botnet - Nosviak4 C2 IPs", ("malware", "Nosviak4")),
        ("Botnet - Socks5Systemz IPs", ("malware", "Socks5Systemz")),
        ("Botnet API - TCPSYN Domains", ("malware", "TCPSYN")),
        (
            "Screen Connect RMM leveraged by Threat Actors IPs",
            ("tool", "ScreenConnect"),
        ),
        ("Infostealer - Lumma C2 Domains", None),
        ("Russian Intelligence Agency Phishing Domains", None),
        ("Bulletproof Hosting IPs Part 2", None),
    ],
)
def test_feed_entity(name, expected):
    assert feed_entity(name) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("8.8.8.8", ("ipv4-addr", "8.8.8.8")),
        ("Example.COM.", ("domain-name", "example.com")),
        ("not a value", None),
        ("", None),
        (None, None),
    ],
)
def test_classify(raw, expected):
    assert classify(raw) == expected


def test_parse_listing_date():
    assert parse_listing_date(20260518) == datetime(2026, 5, 18, tzinfo=timezone.utc)
    assert parse_listing_date("20260518").day == 18
    for bad in (None, 0, "UNKNOWN", 20261399):
        assert parse_listing_date(bad) is None


def test_risk_to_score_clamps():
    assert risk_to_score("100") == 100
    assert risk_to_score(500) == 100
    assert risk_to_score(-1) == 0
    assert risk_to_score("x") is None


@pytest.mark.parametrize(
    "row,expected",
    [
        ({"benign_info": {"known_benign": True}}, True),
        ({"sinkhole_info": {"known_sinkhole_ip": True}}, True),
        ({"ns_reputation": {"is_sinkholed": True}}, True),
        ({"benign_info": {"known_benign": False}}, False),
        ({"benign_info": "garbage"}, False),
        ({}, False),
    ],
)
def test_is_excluded(row, expected):
    assert is_excluded(row) is expected


def test_row_value():
    assert row_value("ipv4", {"ip": "1.1.1.1"}) == "1.1.1.1"
    assert row_value("domain", {"domaininfo": {"domain": "A.com"}}) == "a.com"
    assert row_value("domain", {"domaininfo": {"query": "b.com"}}) == "b.com"
    assert row_value("domain", {"domain": "c.com"}) == "c.com"
    assert row_value("domain", {}) is None


def test_ip_gets_context_and_identity_floor(builder):
    objects = builder.build_indicator(
        "203.0.113.9", "ipv4-addr", ip_row(listing("bp")), FEEDS
    )
    observable = of_type(objects, "ipv4-addr")[0]

    assert observable.x_opencti_score == 100
    assert observable.x_opencti_create_indicator is False
    description = observable.x_opencti_description
    assert "Bulletproof Hosting IPs" in description
    assert "First listed: 2026-05-18." in description
    assert "Feed tags: bulletproof." in description

    edges = {
        (rel.relationship_type, rel.target_ref)
        for rel in of_type(objects, "relationship")
    }
    assert ("related-to", builder.author.id) in edges
    assert ("belongs-to", of_type(objects, "autonomous-system")[0].id) in edges
    assert ("located-at", of_type(objects, "location")[0].id) in edges
    assert not of_type(objects, "intrusion-set")
    assert not of_type(objects, "malware")
    assert not of_type(objects, "tool")


def test_actor_feed_creates_intrusion_set_edge_and_note(builder):
    objects = builder.build_indicator(
        "203.0.113.9", "ipv4-addr", ip_row(listing("fin7-i")), FEEDS
    )
    entity = of_type(objects, "intrusion-set")[0]
    note = of_type(objects, "note")[0]

    assert entity.name == "FIN7 (SilentPush)"
    assert note.object_refs == [entity.id]
    assert note.x_opencti_note_types == ["assessment"]
    assert entity.id in {rel.target_ref for rel in of_type(objects, "relationship")}


def test_c2_framework_feed_creates_tool_without_suffix(builder):
    objects = builder.build_indicator(
        "203.0.113.9", "ipv4-addr", ip_row(listing("cs")), FEEDS
    )
    tool = of_type(objects, "tool")[0]
    note = of_type(objects, "note")[0]
    assert tool.name == "Cobalt Strike"
    assert note.object_refs == [tool.id]
    assert tool.id in {rel.target_ref for rel in of_type(objects, "relationship")}
    assert not of_type(objects, "malware")


def test_tds_feed_creates_malware_without_suffix(builder):
    objects = builder.build_indicator(
        "203.0.113.9", "ipv4-addr", ip_row(listing("ztds")), FEEDS
    )
    malware = of_type(objects, "malware")[0]
    assert malware.name == "zTDS"
    assert malware.is_family is True
    assert not of_type(objects, "tool")


def test_feed_pair_gives_one_entity_and_one_edge_from_the_earliest_listing(builder):
    objects = builder.build_indicator(
        "203.0.113.9",
        "ipv4-addr",
        ip_row(listing("fin7-d", 20260601), listing("fin7-i", 20260101)),
        FEEDS,
    )
    entity = of_type(objects, "intrusion-set")[0]
    edges = [
        rel for rel in of_type(objects, "relationship") if rel.target_ref == entity.id
    ]
    assert len(edges) == 1
    assert edges[0].start_time.month == 1


def test_non_iofa_attribution_is_ignored(builder):
    objects = builder.build_indicator(
        "203.0.113.9", "ipv4-addr", ip_row(listing("an-org-feed")), FEEDS
    )
    description = of_type(objects, "ipv4-addr")[0].x_opencti_description
    assert "no feed attribution" in description


def test_output_is_deterministic_across_runs(builder):
    row = ip_row(listing("fin7-i"))
    first = builder.build_indicator("203.0.113.9", "ipv4-addr", row, FEEDS)
    second = builder.build_indicator("203.0.113.9", "ipv4-addr", row, FEEDS)
    assert {obj.id for obj in first} == {obj.id for obj in second}


def test_bare_value_still_meets_the_identity_floor(builder):
    objects = builder.build_indicator("evil.example", "domain-name", {}, FEEDS)
    assert of_type(objects, "domain-name")
    assert of_type(objects, "relationship")[0].target_ref == builder.author.id


def test_wrong_type_for_the_file_is_unusable(builder):
    assert builder.build_indicator("2001:db8::1", "ipv4-addr", {}, FEEDS) == []
    assert builder.build_indicator("nonsense value", "domain-name", {}, FEEDS) == []


def test_report_is_stable_per_slot_and_named_for_it(builder):
    slot = datetime(2026, 11, 7, 6, tzinfo=timezone.utc)
    objects = builder.build_indicator("evil.example", "domain-name", {}, FEEDS)
    report = builder.build_report(slot, [objects[0].id])
    assert report.name == "Silent Push IOFA - 2026-11-07 06:00 UTC"
    assert report.report_types == ["observable-feed"]
    assert report.published == slot
    assert report.id == builder.build_report(slot, [objects[1].id]).id
    later = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)
    assert report.id != builder.build_report(later, [objects[0].id]).id
