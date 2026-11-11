"""Tests for wire_crucible_classify.py against a deliberately messy override."""

from pathlib import Path

import pytest
from ruamel.yaml import YAML

import wire_crucible_classify as wire

MESSY = """\
# Local override - never committed.
services:
  bleepingcomputer:
    environment:
      - OPENCTI_URL=http://opencti:8080   # platform
      - OPENCTI_TOKEN=abc
      - CRUCIBLE_COLLECTOR_URL=http://old:1
  the-hacker-news:
      environment:
          OPENCTI_URL: http://opencti:8080
          OPENCTI_TOKEN: abc
      volumes:
          - ./data:/data
          - ./old-ms:/microservices
  security-affairs:
   restart: always
  unrelated:
    image: busybox   # must not change
"""

URL = "http://collector.example:8004"
MS = "./connectors/microservices"


def _run(tmp_path, *extra, apply=True, services=("bleepingcomputer", "the-hacker-news",
                                                 "security-affairs")):
    f = tmp_path / "docker-compose.override.yml"
    if not f.exists():
        f.write_text(MESSY, encoding="utf-8")
    argv = ["--file", str(f), "--collector-url", URL, "--microservices-path", MS,
            "--services", *services, *extra]
    if apply:
        argv.append("--apply")
    return wire.main(argv), f


def _load(f):
    return YAML().load(f.read_text(encoding="utf-8"))["services"]


def test_dry_run_writes_nothing(tmp_path):
    rc, f = _run(tmp_path, apply=False)
    assert rc == 0
    assert f.read_text(encoding="utf-8") == MESSY
    assert not list(tmp_path.glob("*.bak.*"))


def test_apply_wires_every_form(tmp_path):
    rc, f = _run(tmp_path)
    assert rc == 0
    s = _load(f)
    # list-form env: existing value replaced, not duplicated
    env = list(s["bleepingcomputer"]["environment"])
    assert env.count(f"CRUCIBLE_COLLECTOR_URL={URL}") == 1
    assert not any("old:1" in e for e in env)
    assert s["bleepingcomputer"]["volumes"] == [f"{MS}:/microservices:ro"]
    # mapping-form env and an existing /microservices mount replaced in place
    assert s["the-hacker-news"]["environment"]["CRUCIBLE_COLLECTOR_URL"] == URL
    assert list(s["the-hacker-news"]["volumes"]) == ["./data:/data", f"{MS}:/microservices:ro"]
    # service with neither block gets both
    assert s["security-affairs"]["environment"] == [f"CRUCIBLE_COLLECTOR_URL={URL}"]
    # untouched service and comments survive
    assert s["unrelated"] == {"image": "busybox"}
    text = f.read_text(encoding="utf-8")
    assert "# Local override - never committed." in text and "# must not change" in text
    assert len(list(tmp_path.glob("*.bak.*"))) == 1


def test_idempotent(tmp_path):
    _run(tmp_path)
    first = (tmp_path / "docker-compose.override.yml").read_text(encoding="utf-8")
    rc, f = _run(tmp_path)
    assert rc == 0 and f.read_text(encoding="utf-8") == first
    assert len(list(tmp_path.glob("*.bak.*"))) == 1   # no second backup


def test_missing_service_reported_and_others_still_wired(tmp_path):
    rc, f = _run(tmp_path, services=("bleepingcomputer", "not-there"))
    assert rc == 1
    assert "not-there" not in _load(f)
    assert f"CRUCIBLE_COLLECTOR_URL={URL}" in list(_load(f)["bleepingcomputer"]["environment"])


def test_optional_timeout(tmp_path):
    _run(tmp_path, "--timeout", "180", services=("security-affairs",))
    assert "CRUCIBLE_CLASSIFY_TIMEOUT=180" in list(
        _load(tmp_path / "docker-compose.override.yml")["security-affairs"]["environment"])
