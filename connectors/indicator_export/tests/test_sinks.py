import csv
import glob
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import stix2

from src.config import MODE_DEBUG, MODE_STREAM
from src.records import ExportRecord
from src.sinks import CsvSink, ExportError, StixStreamSink, build_sink, neutralize_formula
from src.store import StateStore

from .fakes import settings

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
STIX_ID = "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"


def record(**overrides):
    values = dict(
        stix_id=STIX_ID,
        name="IPv4-Addr: 1.2.3.4",
        pattern="[ipv4-addr:value = '1.2.3.4']",
        pattern_type="stix",
        observable_type="IPv4-Addr",
        observable_value="1.2.3.4",
        indicator_types=("malicious-activity",),
        confidence=85,
        markings=("TLP:CLEAR",),
        marking_refs=("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",),
        status="active",
        created="2026-01-01T00:00:00.000Z",
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until=None,
        revoked=False,
        labels=("intrusion-set:APT29", "malware:Emotet"),
        labels_dropped={"excluded_type": 2, "marking": 1},
    )
    values.update(overrides)
    return ExportRecord(**values)


def read_rows(path):
    with open(path, newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


class Receiver:
    """A real local HTTP server, so stream tests cross an actual socket."""

    def __init__(self):
        self.bundles = []
        self.headers = []
        self.status = 200
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                receiver.headers.append(dict(self.headers))
                if 200 <= receiver.status < 300:
                    receiver.bundles.append(json.loads(body))
                self.send_response(receiver.status)
                if receiver.status == 302:
                    self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.end_headers()

            def log_message(self, *_):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/stix"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def receiver():
    instance = Receiver()
    yield instance
    instance.server.shutdown()
    instance.server.server_close()


@pytest.fixture
def store(tmp_path):
    state = StateStore(str(tmp_path / "state"))
    yield state
    state.close()


def stream_sink(url, store, **overrides):
    options = dict(batch_size=500, timeout_seconds=5, verify_tls=True, clock=lambda: NOW)
    options.update(overrides)
    return StixStreamSink(url, store, **options)


def test_location_picks_the_sink(tmp_path, store):
    debug = build_sink(settings(EXPORT_DATA_DIR=str(tmp_path)), store)
    stream = build_sink(settings(EXPORT_LOCATION="10.0.0.50", EXPORT_PORT="8443"), store)
    assert settings().target.mode == MODE_DEBUG
    assert isinstance(debug, CsvSink)
    assert isinstance(stream, StixStreamSink)
    assert stream.url == "https://10.0.0.50:8443/"
    assert settings(EXPORT_LOCATION="10.0.0.50").target.mode == MODE_STREAM


def test_csv_has_the_agreed_columns_and_values(tmp_path):
    message = CsvSink(str(tmp_path), 5, clock=lambda: NOW).deliver([record()], dry_run=False)
    path = str(tmp_path / "indicators_20261106T120000Z.csv")
    assert path in message
    row = read_rows(path)[0]
    assert row["indicator_id"] == STIX_ID
    assert row["labels"] == "intrusion-set:APT29 | malware:Emotet"
    assert row["label_count"] == "2"
    assert row["labels_dropped"] == "excluded_type=2;marking=1"
    assert row["status"] == "active"
    assert row["marking"] == "TLP:CLEAR"


def test_csv_is_written_in_dry_run(tmp_path):
    CsvSink(str(tmp_path), 5, clock=lambda: NOW).deliver(
        [record(status="would_create")], dry_run=True
    )
    assert read_rows(glob.glob(str(tmp_path / "*.csv"))[0])[0]["status"] == "would_create"


def test_csv_handles_commas_quotes_and_newlines(tmp_path):
    awkward = 'evil,"name"\nnext'
    CsvSink(str(tmp_path), 5, clock=lambda: NOW).deliver(
        [record(observable_value=awkward)], dry_run=False
    )
    rows = read_rows(glob.glob(str(tmp_path / "*.csv"))[0])
    assert len(rows) == 1
    assert rows[0]["observable_value"] == awkward


@pytest.mark.parametrize("value", ["=cmd|calc", "+1+1", "-2", "@SUM(A1)", "\tx", "\rx"])
def test_formula_prefixes_are_neutralized(value):
    assert neutralize_formula(value) == "'" + value


def test_safe_values_and_numbers_are_unchanged():
    assert neutralize_formula("1.2.3.4") == "1.2.3.4"
    assert neutralize_formula(85) == 85


def test_csv_neutralizes_attacker_values_but_keeps_the_pattern(tmp_path):
    CsvSink(str(tmp_path), 5, clock=lambda: NOW).deliver(
        [record(observable_value="=HYPERLINK(1)", name="=bad", labels=("=x",))], dry_run=False
    )
    row = read_rows(glob.glob(str(tmp_path / "*.csv"))[0])[0]
    assert row["observable_value"] == "'=HYPERLINK(1)"
    assert row["name"] == "'=bad"
    assert row["labels"] == "'=x"
    assert row["pattern"] == "[ipv4-addr:value = '1.2.3.4']"


def test_retention_keeps_the_newest_files(tmp_path):
    for hour in range(4):
        moment = NOW + timedelta(hours=hour)
        CsvSink(str(tmp_path), 2, clock=lambda m=moment: m).deliver([record()], dry_run=False)
    names = sorted(os.path.basename(p) for p in glob.glob(str(tmp_path / "*.csv")))
    assert names == ["indicators_20261106T140000Z.csv", "indicators_20261106T150000Z.csv"]


def test_failed_write_leaves_no_partial_file(tmp_path, monkeypatch):
    def fail(*_):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(ExportError):
        CsvSink(str(tmp_path), 5, clock=lambda: NOW).deliver([record()], dry_run=False)
    assert os.listdir(tmp_path) == []


def test_stream_sends_a_valid_stix_bundle(receiver, store):
    stream_sink(receiver.url, store).deliver([record()], dry_run=False)
    assert len(receiver.bundles) == 1
    bundle = receiver.bundles[0]
    assert bundle["type"] == "bundle"
    assert receiver.headers[0]["Content-Type"] == "application/stix+json;version=2.1"

    parsed = stix2.parse(json.dumps(bundle), allow_custom=False)
    indicator = parsed.objects[0]
    assert indicator.type == "indicator"
    assert indicator.labels == ["intrusion-set:APT29", "malware:Emotet"]
    assert indicator.pattern == "[ipv4-addr:value = '1.2.3.4']"


def test_stream_does_not_send_csv_only_fields(receiver, store):
    stream_sink(receiver.url, store).deliver([record()], dry_run=False)
    obj = receiver.bundles[0]["objects"][0]
    assert not {"status", "labels_dropped", "observable_value"} & set(obj)


def test_stream_sends_auth_token_when_set(receiver, store):
    stream_sink(receiver.url, store, auth_token="secret").deliver([record()], dry_run=False)
    assert receiver.headers[0]["Authorization"] == "Bearer secret"


def test_stream_skips_what_the_destination_already_has(receiver, store):
    sink = stream_sink(receiver.url, store)
    sink.deliver([record()], dry_run=False)
    sink.deliver([record()], dry_run=False)
    assert len(receiver.bundles) == 1


def test_label_change_alone_resends_with_a_newer_modified(receiver, store):
    later = NOW + timedelta(hours=1)
    stream_sink(receiver.url, store).deliver([record()], dry_run=False)
    stream_sink(receiver.url, store, clock=lambda: later).deliver(
        [record(labels=("malware:Emotet",))], dry_run=False
    )
    first, second = (bundle["objects"][0] for bundle in receiver.bundles)
    assert second["labels"] == ["malware:Emotet"]
    assert second["modified"] > first["modified"]


def test_revocation_is_sent(receiver, store):
    sink = stream_sink(receiver.url, store)
    sink.deliver([record()], dry_run=False)
    sink.deliver([record(revoked=True, status="revoked")], dry_run=False)
    assert receiver.bundles[1]["objects"][0]["revoked"] is True


def test_status_change_alone_is_not_resent(receiver, store):
    sink = stream_sink(receiver.url, store)
    sink.deliver([record()], dry_run=False)
    sink.deliver([record(status="decaying")], dry_run=False)
    assert len(receiver.bundles) == 1


def test_rejected_batch_is_retried_next_cycle(receiver, store):
    sink = stream_sink(receiver.url, store)
    receiver.status = 500
    with pytest.raises(ExportError):
        sink.deliver([record()], dry_run=False)
    assert store.sent_fingerprints() == {}

    receiver.status = 200
    sink.deliver([record()], dry_run=False)
    assert len(receiver.bundles) == 1


def test_batches_already_confirmed_are_not_resent_after_a_failure(store):
    class Session:
        def __init__(self):
            self.calls = 0

        def post(self, *_, **__):
            self.calls += 1
            return type("R", (), {"status_code": 200 if self.calls == 1 else 500})()

    first = record()
    second = record(stix_id="indicator--9e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
    sink = stream_sink("http://unused", store, batch_size=1, session=Session())
    with pytest.raises(ExportError):
        sink.deliver([first, second], dry_run=False)
    assert set(store.sent_fingerprints()) == {first.stix_id}


def test_unreachable_destination_is_an_export_error(store):
    sink = stream_sink("http://127.0.0.1:1/stix", store, timeout_seconds=1)
    with pytest.raises(ExportError):
        sink.deliver([record()], dry_run=False)


def test_redirects_are_not_followed(receiver, store):
    receiver.status = 302
    with pytest.raises(ExportError, match="302"):
        stream_sink(receiver.url, store).deliver([record()], dry_run=False)
    assert len(receiver.headers) == 1


def test_stream_sends_nothing_in_dry_run(receiver, store):
    message = stream_sink(receiver.url, store).deliver([record()], dry_run=True)
    assert "would stream 1 of 1" in message
    assert receiver.headers == []
    assert store.sent_fingerprints() == {}


def test_stix_leaves_out_empty_optional_fields():
    stix = record(labels=(), marking_refs=(), confidence=None).to_stix(NOW)
    assert not {"labels", "object_marking_refs", "confidence", "valid_until"} & set(stix)
