"""Settings loading/validation and the read-only OpenCTI lookups."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from src import config as cfg
from src.opencti_lookup import OpenCTILookup

REQUIRED = {"OPENCTI_URL": "http://x", "OPENCTI_TOKEN": "t", "CONNECTOR_ID": "c",
            "SPLUNK_BASE_URL": "https://s:8089", "SPLUNK_ORGANIZATION_NAME": "Acme"}


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no stray config.yml
    for k in list(REQUIRED) + ["SPLUNK_TOKEN", "SPLUNK_CA_BUNDLE", "SPLUNK_VERIFY_SSL"]:
        monkeypatch.delenv(k, raising=False)
    for k, v in REQUIRED.items():
        monkeypatch.setenv(k, v)
    return monkeypatch


def test_defaults(env):
    s = cfg.load_settings()
    assert s.splunk_tlp == "TLP:AMBER+STRICT"
    assert s.splunk_results_api == "v2"
    assert s.verify is True


def test_config_yml_fills_gaps_but_env_wins(env, tmp_path):
    (tmp_path / "config.yml").write_text(
        "splunk:\n  token: from-file\n  organization_name: FileOrg\n  verify_ssl: false\n",
        encoding="utf-8")
    s = cfg.load_settings()
    assert s.splunk_token == "from-file"
    assert s.splunk_organization_name == "Acme"  # env wins
    assert s.verify is False


def test_empty_yaml_sections_are_ignored(env, tmp_path):
    (tmp_path / "config.yml").write_text("opencti:\nconnector:\nsplunk:\n", encoding="utf-8")
    assert cfg.load_settings().splunk_organization_name == "Acme"


def test_blank_yaml_keys_are_not_seeded_as_the_string_none(env, tmp_path):
    (tmp_path / "config.yml").write_text("splunk:\n  token:\n", encoding="utf-8")
    env.delenv("SPLUNK_TOKEN", raising=False)
    assert cfg.load_settings().splunk_token == ""


def test_ca_bundle_overrides_verify_flag(env):
    env.setenv("SPLUNK_CA_BUNDLE", "/ca.pem")
    env.setenv("SPLUNK_VERIFY_SSL", "false")
    assert cfg.load_settings().verify == "/ca.pem"


@pytest.mark.parametrize("key, value", [
    ("SPLUNK_ORGANIZATION_NAME", ""),
    ("SPLUNK_BASE_URL", ""),
    ("SPLUNK_RESULTS_API", "v3"),
    ("SPLUNK_INITIAL_LOOKBACK", "-1d@d"),
    ("SPLUNK_CONFIDENCE", "101"),
    ("SPLUNK_PAGE_SIZE", "0"),
    ("SPLUNK_MAX_OBJECTS_PER_CASE", "10"),
    ("SPLUNK_INGEST_LAG_SECONDS", "-1"),
    ("SPLUNK_AUTHOR_NAME", ""),
])
def test_invalid_settings_fail(env, key, value):
    env.setenv(key, value)
    with pytest.raises(ValidationError):
        cfg.load_settings()


def _lookup(read):
    helper = MagicMock()
    helper.api.attack_pattern.read.side_effect = read
    helper.api.marking_definition.read.side_effect = read
    return OpenCTILookup(helper), helper


def test_attack_pattern_hits_cached_misses_retried_next_run():
    known = {"T1059": {"standard_id": "attack-pattern--1"}}
    lk, helper = _lookup(lambda filters: known.get(filters["filters"][0]["values"][0]))
    assert lk.attack_pattern("T1059") == "attack-pattern--1"
    assert lk.attack_pattern("T1059") == "attack-pattern--1"
    assert lk.attack_pattern("T0000") is None
    assert lk.attack_pattern("T0000") is None
    assert helper.api.attack_pattern.read.call_count == 2  # both cached within a run

    known["T0000"] = {"standard_id": "attack-pattern--0"}
    lk.begin_run()
    assert lk.attack_pattern("T0000") == "attack-pattern--0"
    assert lk.attack_pattern("T1059") == "attack-pattern--1"
    assert helper.api.attack_pattern.read.call_count == 3  # hit stayed cached


def test_lookup_filter_shape_and_errors_are_misses():
    lk, helper = _lookup(lambda filters: {"standard_id": "marking-definition--1"})
    assert lk.marking("TLP:AMBER+STRICT") == "marking-definition--1"
    f = helper.api.marking_definition.read.call_args.kwargs["filters"]
    assert f == {"mode": "and", "filterGroups": [],
                 "filters": [{"key": "definition", "values": ["TLP:AMBER+STRICT"]}]}

    def boom(filters):
        raise ConnectionError("down")
    lk, helper = _lookup(boom)
    assert lk.marking("TLP:RED") is None
    helper.connector_logger.warning.assert_called_once()


def test_attack_pattern_api_error_propagates_and_is_not_cached():
    calls = []

    def flaky(filters):
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionError("down")
        return {"standard_id": "attack-pattern--1"}
    lk, _ = _lookup(flaky)
    with pytest.raises(ConnectionError):
        lk.attack_pattern("T1059")
    assert lk.attack_pattern("T1059") == "attack-pattern--1"
