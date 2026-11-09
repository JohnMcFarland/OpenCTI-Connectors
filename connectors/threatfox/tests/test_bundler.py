"""THREATFOX-REPORT-IN-BUNDLE-V1: chunked bundles carry the day's Report."""

import pytest

from src import config
from src.bundler import build_report, chunk_bundles
from src.mitre_lookup import MitreLookup
from src.stix_converter import StixConverter
from src.uuid_generator import report_id

DATE = "2026-11-09"
TS = "2026-11-09T12:00:00.000Z"
TYPES = ["observable-feed"]


def entry(n, ioc_type="ip:port", malware="Cobalt Strike", reporter="alice", tags=None):
    value = {
        "ip:port": f"203.0.113.{n % 250}:{1000 + n}",
        "domain": f"bad{n}.example",
        "url": f"http://bad{n}.example/x",
        "sha256_hash": f"{n:064x}",
    }[ioc_type]
    return {
        "ioc": value, "ioc_type": ioc_type, "threat_type": "botnet_cc",
        "malware_printable": malware, "confidence_level": 75,
        "first_seen_utc": "2026-11-09 01:00:00", "reporter": reporter,
        "tags": tags if tags is not None else ["AS64500"],
    }


@pytest.fixture(scope="module")
def converter():
    return StixConverter(MitreLookup())


def convert(converter, entries):
    return converter.convert({str(i): [e] for i, e in enumerate(entries)})


def check_self_contained(chunk):
    ids = {o["id"] for o in chunk}
    for obj in chunk:
        for field in ("source_ref", "target_ref", "created_by_ref"):
            if obj.get(field):
                assert obj[field] in ids, (field, obj[field])


def test_report_shape():
    report = build_report(DATE, TS, ["b", "a", "a"], TYPES)
    assert report["id"] == report_id(DATE)
    assert report["name"] == f"Threat Fox Feed {DATE}"
    assert report["object_refs"] == ["a", "b"]
    assert report["created_by_ref"] == config.THREATFOX_IDENTITY_ID
    assert report["object_marking_refs"] == [config.TLP_CLEAR_ID]
    assert report["report_types"] == TYPES


def test_single_chunk_holds_everything(converter):
    objects = convert(converter, [entry(i) for i in range(5)])
    chunks = chunk_bundles(objects, DATE, TS, TYPES)
    assert len(chunks) == 1
    chunk = chunks[0]
    report = chunk[-1]
    assert report["type"] == "report"
    expected = {o["id"] for o in objects if o["id"] != config.THREATFOX_IDENTITY_ID}
    assert set(report["object_refs"]) == expected
    assert {o["id"] for o in chunk[:-1]} == {o["id"] for o in objects}
    check_self_contained(chunk)


def test_chunks_are_self_contained_and_cover_all(converter):
    entries = [entry(i, ioc_type=t) for i, t in
               enumerate(["ip:port", "domain", "url", "sha256_hash"] * 60)]
    objects = convert(converter, entries)
    chunks = chunk_bundles(objects, DATE, TS, TYPES, chunk_size=50)
    assert len(chunks) > 3
    sent, referenced = set(), set()
    for chunk in chunks:
        check_self_contained(chunk)
        report = chunk[-1]
        assert report["type"] == "report" and report["id"] == report_id(DATE)
        assert config.THREATFOX_IDENTITY_ID not in report["object_refs"]
        assert set(report["object_refs"]) <= {o["id"] for o in chunk}
        sent |= {o["id"] for o in chunk[:-1]}
        referenced |= set(report["object_refs"])
    assert sent == {o["id"] for o in objects}
    assert referenced == {o["id"] for o in objects} - {config.THREATFOX_IDENTITY_ID}


def test_observable_never_split_from_its_edges(converter):
    objects = convert(converter, [entry(i) for i in range(40)])
    chunks = chunk_bundles(objects, DATE, TS, TYPES, chunk_size=7)
    for chunk in chunks:
        ids = {o["id"] for o in chunk}
        for obj in chunk:
            if obj["type"] == "relationship":
                assert obj["source_ref"] in ids and obj["target_ref"] in ids


def test_unreferenced_shared_object_still_sent(converter):
    objects = convert(converter, [entry(1)])
    orphan = {"type": "malware", "spec_version": "2.1", "id": "malware--orphan",
              "name": "Orphan", "is_family": True}
    chunks = chunk_bundles(objects + [orphan], DATE, TS, TYPES)
    assert any(o["id"] == "malware--orphan" for o in chunks[-1])


def test_no_content_sends_no_report(converter):
    objects = convert(converter, [])
    chunks = chunk_bundles(objects, DATE, TS, TYPES)
    assert len(chunks) == 1
    assert [o["type"] for o in chunks[0]] == ["identity"]
