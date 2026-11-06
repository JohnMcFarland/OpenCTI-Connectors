import pytest

from src.config import MODE_DEBUG, MODE_STREAM, parse_export_location
from src.markings import highest_rank, rank, within_ceiling

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
        {"EXPORT_MARKING_CEILING": "SECRET"},
        {"EXPORT_SCHEME": "ftp"},
        {"EXPORT_PORT": "70000"},
        {"EXPORT_PORT": "abc"},
        {"INDICATOR_CONFIDENCE_FLOOR": "90"},
        {"EXPORT_MAX_LABELS": "0"},
    ],
)
def test_bad_values_stop_startup(overrides):
    with pytest.raises(ValueError):
        settings(**overrides)


def test_missing_token_stops_startup():
    with pytest.raises(ValueError, match="OPENCTI_TOKEN"):
        settings(OPENCTI_TOKEN="")


def test_clear_ranks_lowest_not_highest():
    assert rank("TLP:CLEAR") < rank("TLP:GREEN") < rank("TLP:AMBER")
    assert rank("TLP:AMBER") < rank("TLP:AMBER+STRICT") < rank("TLP:RED")


def test_clear_and_red_together_resolve_to_red():
    pair = [{"definition": "TLP:CLEAR"}, {"definition": "TLP:RED"}]
    assert highest_rank(pair) == rank("TLP:RED")
    assert not within_ceiling(pair, "TLP:AMBER+STRICT")


def test_unknown_marking_never_passes():
    assert not within_ceiling([{"definition": "PAP:RED"}], "TLP:RED")
    assert not within_ceiling([{"definition": None}], "TLP:RED")


def test_unmarked_counts_as_amber_strict():
    assert within_ceiling([], "TLP:AMBER+STRICT")
    assert not within_ceiling([], "TLP:AMBER")
