"""Equivalence: every profile reproduces its generated connector exactly.

For each sources.yml entry whose generated connector is still in the repo
(connectors/<slug>/, until migration phase 6), the connector's main.py is
imported and run at runtime (nothing parsed by hand), and its values are
compared with the profile:

- the 18 site constants (SOURCE_NAME ... DATE_TEXT_SELECTOR);
- the config the connector actually runs with: config.yml over its code
  defaults, as its own __init__ reads them (with OpenCTIConnectorHelper
  mocked);
- the author Organization description it creates;
- the render call's extra headers (BleepingComputer);
- the members-only precheck (Dark Web Informer), behaviourally.

scripts/extract_profiles.py reads the same connectors statically with
`ast`, so the two methods check each other.
"""

import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from conftest import PROFILES
from engine import scope
from engine.settings import (
    BROWSER_UA,
    MAX_DESCRIPTION_CHARS,
    MAX_PAGE_PROBES,
    MAX_PDF_BYTES,
    MAX_TRANSIENT_ATTEMPTS,
    EngineSettings,
)

CONNECTORS = Path(__file__).resolve().parents[2]
GENERATED = sorted(s for s in PROFILES if (CONNECTORS / s / "main.py").is_file())

pytestmark = pytest.mark.skipif(
    not GENERATED, reason="generated connectors retired (migration phase 6)")


def _load(slug):
    """Import connectors/<slug>/main.py under a unique module name."""
    name = f"generated_{slug}"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, CONNECTORS / slug / "main.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _instance(slug, mod):
    """Run the connector's own __init__ with the helper mocked and no env overrides.

    long_war_journal's config.yml is invalid YAML (the connector would crash
    at startup); for it the code defaults are used, which is what its
    config.yml intended (the values match line for line).
    """
    cls = next(v for k, v in vars(mod).items() if k.endswith("Connector") and isinstance(v, type))
    env = {k: v for k, v in os.environ.items() if not k.startswith(slug.upper() + "_")}
    patches = [patch.object(mod, "OpenCTIConnectorHelper", MagicMock()),
               patch.dict(os.environ, env, clear=True)]
    try:
        yaml.safe_load((CONNECTORS / slug / "config.yml").read_text(encoding="utf-8"))
    except yaml.YAMLError:
        patches.append(patch.object(mod.yaml, "safe_load", lambda fh: {}))
    for p in patches:
        p.start()
    try:
        return cls()
    finally:
        for p in reversed(patches):
            p.stop()


@pytest.fixture(params=GENERATED)
def pair(request):
    slug = request.param
    mod = _load(slug)
    return slug, mod, PROFILES[slug]


def _pattern(value):
    return None if value is None else value.pattern


def test_every_generated_connector_has_a_profile():
    generated = {d.name for d in CONNECTORS.iterdir()
                 if (d / "main.py").is_file()
                 and "def _resolve_redirects" in (d / "main.py").read_text(encoding="utf-8")}
    assert generated == set(PROFILES)
    assert len(PROFILES) == 78


def test_site_constants(pair):
    slug, m, p = pair
    assert p.name == m.SOURCE_NAME
    assert p.file_prefix == m.FILE_PREFIX
    assert p.allowed_hosts == set(m.ALLOWED_HOSTS)
    assert p.content_selectors == list(m.CONTENT_SELECTORS)
    assert p.content_selectors[0] == m.CONTENT_SELECTOR
    assert list(p.hide_selectors) == list(m.HIDE_SELECTORS)
    assert p.category_keep == set(m.CATEGORY_KEEP)
    assert p.category_allow == set(m.CATEGORY_ALLOW)
    assert p.category_deny == set(m.CATEGORY_DENY)
    assert _pattern(p.exclude_url_re) == _pattern(m.EXCLUDE_URL_RE)
    assert _pattern(p.exclude_title_re) == _pattern(m.EXCLUDE_TITLE_RE)
    assert (p.exclude_url_re.flags if p.exclude_url_re else None) == (
        m.EXCLUDE_URL_RE.flags if m.EXCLUDE_URL_RE else None)
    assert (p.exclude_title_re.flags if p.exclude_title_re else None) == (
        m.EXCLUDE_TITLE_RE.flags if m.EXCLUDE_TITLE_RE else None)
    assert p.max_age_days == m.MAX_AGE_DAYS
    assert p.slug_from_id == m.SLUG_FROM_ID
    assert p.byline_author == m.BYLINE_AUTHOR
    assert p.no_content_is_transient == m.NO_CONTENT_IS_TRANSIENT
    assert p.discovery == m.DISCOVERY
    assert p.discovery_config == m.DISCOVERY_CONFIG
    assert p.resolve_redirect_hosts == set(m.RESOLVE_REDIRECT_HOSTS)
    assert p.date_text_selector == m.DATE_TEXT_SELECTOR


def test_engine_constants_match(pair):
    _slug, m, _p = pair
    assert m.MAX_PDF_BYTES == MAX_PDF_BYTES
    assert m.MAX_TRANSIENT_ATTEMPTS == MAX_TRANSIENT_ATTEMPTS
    assert m.MAX_PAGE_PROBES == MAX_PAGE_PROBES
    assert m.MAX_DESCRIPTION_CHARS == MAX_DESCRIPTION_CHARS
    assert m.BROWSER_UA == BROWSER_UA


def test_runtime_config(pair):
    slug, m, p = pair
    c = _instance(slug, m)
    assert tuple(c.feed_urls) == p.feed_urls
    assert c.poll_interval == p.poll_interval
    assert c.request_delay == p.request_delay
    assert c.max_age_days == p.max_age_days
    assert c.confidence == p.confidence
    assert c.report_type == p.report_type
    assert c.tlp_name == p.tlp
    assert c.author_name == p.author_name
    defaults = EngineSettings()
    assert c.render_retries == defaults.render_retries
    assert c.render_timeout == defaults.render_timeout
    assert c.max_reports == 0


def test_author_description(pair):
    slug, m, p = pair
    c = _instance(slug, m)
    c.helper = MagicMock()
    c.helper.api.identity.create.return_value = {"id": "a"}
    c.helper.api.marking_definition.read.return_value = {"id": "m"}
    c._resolve_graph_references()
    kw = c.helper.api.identity.create.call_args.kwargs
    assert kw["name"] == p.author_name and kw["description"] == p.author_description


def test_render_headers(pair):
    slug, m, p = pair
    c = _instance(slug, m)
    item = {"link": "https://x.example/a", "title": "t", "creator": ""}
    with patch.object(m, "render_live_pdf", return_value=b"%PDF") as rl:
        c._render_live(item, "2026-11-09T00:00:00+00:00")
    assert rl.call_args.kwargs.get("headers", {}) == p.render_headers


def test_precheck_matches_skip_if(pair):
    """Only Dark Web Informer overrides the precheck; its check and the
    engine's members_only_paywall agree on every case."""
    slug, m, p = pair
    has_fork = hasattr(m, "_is_members_only")
    assert (p.skip_if == "members_only_paywall") is has_fork
    if not has_fork:
        return
    assert scope.PAYWALL_RE.pattern == m.PAYWALL_RE.pattern
    assert scope.ARTICLE_START_RE.pattern == m.ARTICLE_START_RE.pattern
    assert scope.ARTICLE_END_RE.pattern == m.ARTICLE_END_RE.pattern
    pages = [
        "<article class='c-post post'>x</article>",
        '<aside class="gh-post-upgrade-cta">',
        "<article class='c-post'>a</article><div class='c-section c-section--related'>"
        "<span class='c-visibility-label--members'></span></div>",
        (CONNECTORS / slug / "tests" / "public_post.html").read_text(encoding="utf-8"),
    ]
    for page in pages:
        assert scope.is_members_only(page) == m._is_members_only(page)
