"""searches.yml parsing and validation (stdlib + PyYAML only)."""

from __future__ import annotations

import pytest

from src.searches import SearchConfigError, SearchDef, load_searches, parse_relative


def _write(tmp_path, body: str) -> str:
    p = tmp_path / "searches.yml"
    p.write_text(body, encoding="utf-8")
    return str(p)


def _one(tmp_path, extra: str = "") -> SearchDef:
    return load_searches(_write(tmp_path, f"searches:\n  - name: a\n    spl: x\n{extra}"))[0]


def test_load_sample_file_parses():
    searches = load_searches("searches.yml.sample")
    assert [s.name for s in searches] == ["ES true-positive notables", "Outbound to known-bad"]
    es = searches[0]
    assert es.spl.startswith("search `notable`")
    assert es.lookback == "-7d" and es.time_mode == "event"
    assert es.group_by == ["event_id"]
    assert es.title == "{rule_name} on {dest} ({event_id})"  # covers group_by: unchanged
    assert es.observables["dest_port"] == "port"
    saved = searches[1]
    assert saved.spl == '| savedsearch "Threat - Outbound Connection to Known Bad - Rule"'
    assert saved.enabled is False and saved.group_by == ["src", "dest_ip"]


def test_defaults(tmp_path):
    s = _one(tmp_path)
    assert (s.app, s.enabled, s.time_mode, s.lookback, s.time_field) == (
        "search", True, "index", "", "_time")
    assert s.title == "{search_name}: {group}" and s.max_results == 10000


@pytest.mark.parametrize("body, msg", [
    ("searches: []", "non-empty"),
    ("searches:\n  - just-a-string\n", "must be a mapping"),
    ("searches:\n  - spl: x\n", "name is required"),
    ("searches:\n  - name: a\n", "exactly one"),
    ("searches:\n  - name: a\n    spl: x\n    saved_search: y\n", "exactly one"),
    ("searches:\n  - name: a\n    spl: x\n    observables: {f: hash}\n", "unknown kind"),
    ("searches:\n  - name: a\n    spl: x\n    observables: [f]\n", "must map field"),
    ("searches:\n  - name: a\n    spl: x\n  - name: a\n    spl: y\n", "Duplicate"),
    ("searches:\n  - name: a\n    spl: x\n    time_mode: wall\n", "time_mode"),
    ("searches:\n  - name: a\n    spl: x\n    group_by: g\n    lookback: '-7d@d'\n", "lookback"),
    ("searches:\n  - name: a\n    spl: x\n    lookback: -7d\n", "requires group_by"),
    ("searches:\n  - name: a\n    spl: x\n    severity_map: {sev1: urgent}\n", "severity_map"),
    ("searches:\n  - name: a\n    spl: x\n    title: '{rule} x{count}'\n", "must not use"),
    ("searches:\n  - name: a\n    spl: x\n    title: 'until {last_seen}'\n", "must not use"),
    ("searches:\n  - name: a\n    spl: x\n    max_results: 0\n", "max_results"),
    ("searches:\n  - name: a\n    spl: x\n    max_results: lots\n", "max_results"),
])
def test_invalid_files_fail_at_load(tmp_path, body, msg):
    with pytest.raises(SearchConfigError, match=msg):
        load_searches(_write(tmp_path, body))


def test_blank_keys_take_their_defaults(tmp_path):
    s = _one(tmp_path, "    app:\n    time_field:\n    incident_type:\n    time_mode:\n")
    assert (s.app, s.time_field, s.incident_type, s.time_mode) == (
        "search", "_time", "alert", "index")


def test_missing_file_fails_at_load(tmp_path):
    with pytest.raises(SearchConfigError, match="not found"):
        load_searches(str(tmp_path / "nope.yml"))


@pytest.mark.parametrize("spl, expected", [
    ("'| tstats count'", "| tstats count"),
    ("'search index=a'", "search index=a"),
    ("'SEARCH index=a'", "SEARCH index=a"),
    ("'index=a'", "search index=a"),
    ("'searchable=1'", "search searchable=1"),
])
def test_search_prefix(tmp_path, spl, expected):
    s = load_searches(_write(tmp_path, f"searches:\n  - name: a\n    spl: {spl}\n"))[0]
    assert s.spl == expected


def test_saved_search_quotes_are_stripped(tmp_path):
    s = load_searches(_write(tmp_path, "searches:\n  - name: a\n    saved_search: 'Bad\"Name'\n"))[0]
    assert s.spl == '| savedsearch "BadName"'


@pytest.mark.parametrize("value, expected", [
    ("false", False), ("'false'", False), ("'No'", False), ("'0'", False),
    ("true", True), ("'yes'", True),
])
def test_enabled_accepts_quoted_booleans(tmp_path, value, expected):
    assert _one(tmp_path, f"    enabled: {value}\n").enabled is expected


def test_enabled_rejects_garbage(tmp_path):
    with pytest.raises(SearchConfigError, match="enabled"):
        _one(tmp_path, "    enabled: maybe\n")


def test_list_fields_accept_comma_strings_and_lists(tmp_path):
    s = _one(tmp_path, "    group_by: 'a, b'\n    system_fields: [c, d]\n")
    assert s.group_by == ["a", "b"] and s.system_fields == ["c", "d"]


def test_severity_map_override_is_case_insensitive(tmp_path):
    s = _one(tmp_path, "    severity_map: {SEV1: Critical}\n")
    assert s.severity_map["sev1"] == "critical" and s.severity_map["high"] == "high"


@pytest.mark.parametrize("title, group_by, expected", [
    ("{rule} on {dest}", "event_id", "{rule} on {dest} ({group})"),
    ("{rule} ({event_id})", "event_id", "{rule} ({event_id})"),
    ("{rule} {src} {dest}", "src, dest", "{rule} {src} {dest}"),
    ("{rule} {src}", "src, dest", "{rule} {src} ({group})"),
    ("{rule} [{group}]", "", "{rule} [{group}]"),
    ("{rule}", "", "{rule} ({group})"),
])
def test_title_always_distinguishes_groups(tmp_path, title, group_by, expected):
    s = _one(tmp_path, f"    title: '{title}'\n    group_by: '{group_by}'\n")
    assert s.title == expected


def test_referenced_fields_cover_every_read_column():
    s = SearchDef(name="n", spl="search x", group_by=["g"], system_fields=["sys"],
                  observables={"ip": "ip"}, attack_pattern_fields=["m"], severity_field="u",
                  title="{rule} {group}", description="{why} at {first_seen}")
    assert s.referenced_fields() == ["_time", "g", "sys", "ip", "m", "u", "rule", "why"]


def test_columns_named_like_builtins_are_still_fetched():
    s = SearchDef(name="n", spl="| stats", time_field="first_seen", group_by=["search_name"],
                  system_fields=["group"], observables={"count": "port"},
                  severity_field="last_seen", title="{count} {group}")
    assert s.referenced_fields() == ["first_seen", "search_name", "group", "count", "last_seen"]


def test_parse_relative():
    assert parse_relative("-24h") == 86400
    assert parse_relative(" -2w ") == 1209600
    assert parse_relative("-90s") == 90 and parse_relative("-5m") == 300
    for bad in ("24h", "-1y", "-1d@d", "now"):
        with pytest.raises(SearchConfigError):
            parse_relative(bad)
