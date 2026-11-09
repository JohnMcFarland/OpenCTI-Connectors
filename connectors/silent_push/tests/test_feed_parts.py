"""SP-FEED-PARTS-V1: numbered feed parts fold into their base feed's Report."""

from stix_builder import SilentPushStixBuilder, report_feed_name

MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"

FEEDS = {
    "a": {"uuid": "a", "name": "Bulletproof Hosting IPs", "category": "iofa"},
    "b": {"uuid": "b", "name": "Bulletproof Hosting IPs Part 3", "category": "iofa"},
    "c": {"uuid": "c", "name": "Bulletproof Hosting Domains Part 2", "category": "iofa"},
    "d": {"uuid": "d", "name": "Keitaro C2 IPs", "category": "iofa"},
}


def row(*uuids):
    return {"listing_score_feeds_explain": [{"feed_uuid": u, "listed_first": 20261101} for u in uuids]}


def test_part_suffix_is_dropped_and_other_names_kept():
    assert report_feed_name("Bulletproof Hosting IPs Part 5") == "Bulletproof Hosting IPs"
    assert report_feed_name("Bulletproof Hosting Domains part 12 ") == "Bulletproof Hosting Domains"
    assert report_feed_name("Keitaro C2 IPs") == "Keitaro C2 IPs"
    assert report_feed_name("Partners Feed") == "Partners Feed"
    assert report_feed_name("Part 2") == "Part 2"


def test_iofa_parts_collapse_to_one_report_feed():
    builder = SilentPushStixBuilder(MARKING, 70)
    names = builder.iofa_feed_names(row("a", "b", "c", "d"), FEEDS)
    assert names == ["Bulletproof Hosting Domains", "Bulletproof Hosting IPs", "Keitaro C2 IPs"]


def test_osint_parts_collapse_too():
    rows = [{"feed": "Some List Part 2"}, {"feed": "Some List"}, {"feed": "Other"}]
    assert SilentPushStixBuilder.osint_feed_names(rows) == ["Other", "Some List"]
