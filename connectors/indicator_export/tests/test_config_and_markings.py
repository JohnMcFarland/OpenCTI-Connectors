import pytest

from src.config import MODE_DEBUG, MODE_STREAM, parse_export_location
from src.markings import is_blocked

from .fakes import settings


@pytest.mark.parametrize("value", ["debug", "DEBUG", " Debug "])
def test_debug_selects_csv(value):
    assert parse_export_location(value).mode == MODE_DEBUG


@pytest.mark.parametrize(
    "value, host",
    [("10.0.0.50", "10.0.0.50"), (" 10.0.0.50 ", "10.0.0.50"), ("2001:db8::1", "2001:db8::1")],
)
def test_ip_selects_stream(value, host):
    target = parse_export_location(value)
    assert (target.mode, target.host) == (MODE_STREAM, host)


@pytest.mark.parametrize(
    "value", ["", None, "siem.example.com", "10.0.0.50:8443", "999.1.1.1", "http://10.0.0.50"]
)
def test_anything_else_is_rejected(value):
    with pytest.raises(ValueError):
        parse_export_location(value)


def test_stream_url_with_port_and_path():
    config = settings(
        EXPORT_LOCATION="10.0.0.50", EXPORT_PORT="8443", EXPORT_PATH="stix"
    )
    assert config.stream_url == "https://10.0.0.50:8443/stix"


def test_stream_url_brackets_ipv6():
    config = settings(EXPORT_LOCATION="2001:db8::1", EXPORT_PORT="8443")
    assert config.stream_url == "https://[2001:db8::1]:8443/"


def test_dry_run_is_on_unless_explicitly_off():
    assert settings().dry_run is True
    assert settings(INDICATOR_DRY_RUN="false").dry_run is False


def test_network_traffic_can_never_be_promoted():
    config = settings(INDICATOR_EXCLUDED_OBSERVABLE_TYPES="Process")
    assert {"Network-Traffic", "Persona", "Process"} <= config.excluded_observable_types


@pytest.mark.parametrize(
    "overrides",
    [
        {"EXPORT_SCHEME": "ftp"},
        {"EXPORT_PORT": "70000"},
        {"EXPORT_PORT": "abc"},
        {"EXPORT_MAX_LABELS": "0"},
    ],
)
def test_bad_values_stop_startup(overrides):
    with pytest.raises(ValueError):
        settings(**overrides)


def test_missing_token_stops_startup():
    with pytest.raises(ValueError, match="OPENCTI_TOKEN"):
        settings(OPENCTI_TOKEN="")


BLOCKED = ["Sensitive"]


def test_sensitive_is_blocked_by_default_and_blank_cannot_clear_it():
    assert settings().blocked_markings == {"Sensitive"}
    assert settings(EXPORT_BLOCKED_MARKINGS="").blocked_markings == {"Sensitive"}


@pytest.mark.parametrize(
    "definition",
    ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED",
     "PAP:RED", "Limited", "Restricted", "Highly Restricted"],
)
def test_every_other_marking_can_leave(definition):
    assert not is_blocked([{"definition": definition}], BLOCKED)


@pytest.mark.parametrize("definition", ["Sensitive", "SENSITIVE", "Highly Sensitive"])
def test_sensitive_is_blocked_in_any_form(definition):
    assert is_blocked([{"definition": definition}], BLOCKED)


def test_one_blocked_marking_among_several_blocks():
    assert is_blocked([{"definition": "TLP:CLEAR"}, {"definition": "Sensitive"}], BLOCKED)


def test_marking_with_no_definition_is_blocked():
    assert is_blocked([{"definition": None}], BLOCKED)


def test_unmarked_is_not_blocked():
    assert not is_blocked([], BLOCKED)
