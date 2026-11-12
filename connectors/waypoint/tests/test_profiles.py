"""sources.yml: generated content, quoting, and per-entry validation."""

import subprocess
import sys

import pytest
import yaml

from conftest import PROFILE_ERRORS, PROFILES, ROOT, SOURCES
from engine.profile import build_profile, load_sources

REPO = ROOT.parents[1]
LIVE = {"bleepingcomputer", "the_hacker_news", "security_affairs", "techcrunch",
        "the_register", "the_record", "cyberscoop", "dark_web_informer"}


def test_all_78_profiles_load_without_errors():
    assert PROFILE_ERRORS == {}
    assert len(PROFILES) == 78


def test_the_eight_phase_1_sources_are_enabled():
    """Enabled flags are operational (sources.yml is hand-maintained since
    WAYPOINT-SOURCES-HAND-V1); the eight Phase 1 sources stay on."""
    assert LIVE <= {s for s, p in PROFILES.items() if p.enabled}


def test_long_war_journal_name_quoted_correctly():
    """Its generated config.yml is invalid YAML (an unescaped apostrophe);
    the registry entry must parse and keep the apostrophe."""
    raw = yaml.safe_load(SOURCES.read_text(encoding="utf-8"))
    assert raw["long_war_journal"]["name"] == "FDD's Long War Journal"
    assert PROFILES["long_war_journal"].author_name == "FDD's Long War Journal"


def test_the_two_forks_are_profile_options():
    assert PROFILES["bleepingcomputer"].render_headers == {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"}
    assert PROFILES["dark_web_informer"].skip_if == "members_only_paywall"
    others = [p for s, p in PROFILES.items() if s != "dark_web_informer"]
    assert all(p.skip_if is None for p in others)


# Sources whose renders send the Chrome 130 User-Agent. BleepingComputer's came
# from its generated connector; the rest were added by hand on 2026-11-12 after
# pdf-renderer's default UA got HTTP 403 (WAYPOINT-SOURCES-HAND-V1).
CHROME_130_UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                               "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"}
RENDER_UA_SOURCES = {"bleepingcomputer", "ahnlab_asec", "bankinfosecurity",
                     "breaking_defense", "climate_and_security", "space_news"}


def test_render_headers_only_where_needed():
    with_headers = {s for s, p in PROFILES.items() if p.render_headers}
    assert with_headers == RENDER_UA_SOURCES
    assert all(PROFILES[s].render_headers == CHROME_130_UA for s in RENDER_UA_SOURCES)


def test_sources_yml_is_ascii():
    assert all(b < 128 for b in SOURCES.read_bytes())


@pytest.mark.skip(reason="sources.yml is hand-maintained since 2026-11-12 "
                         "(WAYPOINT-SOURCES-HAND-V1); test_equivalence still checks "
                         "every site constant against the generated connectors")
def test_registry_matches_the_extractor():
    """sources.yml was exactly what scripts/extract_profiles.py writes."""
    generated = ROOT.parent / "bleepingcomputer" / "main.py"
    if not generated.is_file():
        pytest.skip("generated connectors retired")
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "extract_profiles.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


# --------------------------------------------------------------------------- #
# Validation: invalid entries name the field and disable only that source
# --------------------------------------------------------------------------- #

MINIMAL = {"name": "X", "author_name": "X Org", "feed_urls": ["https://x.example/feed"],
           "allowed_hosts": ["x.example"]}


def test_minimal_entry_gets_schema_defaults():
    p = build_profile("x", dict(MINIMAL))
    assert (p.enabled, p.discovery, p.discovery_config, p.poll_interval, p.request_delay,
            p.max_age_days, p.content_selectors, p.hide_selectors, p.byline_author,
            p.file_prefix, p.slug_from_id, p.render_headers, p.skip_if, p.confidence,
            p.tlp, p.report_type) == (
        True, "feed", {}, 3600, 3, 30, "generic", (), True, "x", False, {}, None, 50,
        "TLP:CLEAR", "open-source-reporting")


@pytest.mark.parametrize("change,field", [
    ({"name": ""}, "name"),
    ({"feed_urls": []}, "feed_urls"),
    ({"feed_urls": ["ftp://x.example/feed"]}, "feed_urls"),
    ({"allowed_hosts": None}, "allowed_hosts"),
    ({"discovery": "rss"}, "discovery"),
    ({"discovery": "listing"}, "discovery_config.link_re"),
    ({"discovery": "json", "discovery_config": {"items": "a"}}, "discovery_config.link"),
    ({"exclude_title_re": "(unclosed"}, "exclude_title_re"),
    ({"poll_interval": 5}, "poll_interval"),
    ({"poll_interval": "3600"}, "poll_interval"),
    ({"enabled": "yes"}, "enabled"),
    ({"content_selectors": []}, "content_selectors"),
    ({"render_headers": {"User-Agent": 5}}, "render_headers"),
    ({"skip_if": "(bad"}, "skip_if"),
    ({"tlp": "CLEAR"}, "tlp"),
    ({"poll_intervall": 60}, "poll_intervall"),
])
def test_invalid_field_is_named(change, field):
    with pytest.raises(ValueError) as exc:
        build_profile("x", dict(MINIMAL, **change))
    assert str(exc.value).startswith(field + ":")


def test_invalid_entry_disables_only_that_source(tmp_path):
    path = tmp_path / "sources.yml"
    path.write_text(yaml.safe_dump({
        "good": MINIMAL,
        "bad": dict(MINIMAL, exclude_url_re="([oops"),
        "also_good": dict(MINIMAL, name="Y"),
    }), encoding="utf-8")
    profiles, errors = load_sources(path)
    assert set(profiles) == {"good", "also_good"}
    assert list(errors) == ["bad"] and errors["bad"].startswith("exclude_url_re:")


def test_skip_if_accepts_a_class_regex():
    assert build_profile("x", dict(MINIMAL, skip_if="paywall|subscriber-only")).skip_if
