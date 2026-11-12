"""Shared test harness: profiles, per-source cases, a fake graph, a worker.

Any test that takes the `slug` argument runs once per sources.yml profile
(all 78), which is how the generated connectors' per-source suites are
ported: the same cases, against the engine, with that source's profile.
"""

import dataclasses
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import engine  # noqa: E402,F401  (puts the shared microservices package on sys.path)
from engine import timing  # noqa: E402
from engine.profile import load_sources  # noqa: E402
from engine.settings import EngineSettings  # noqa: E402
from engine.worker import SourceWorker  # noqa: E402

SOURCES = ROOT / "sources.yml"
FIXTURES = HERE / "fixtures"
PROFILES, PROFILE_ERRORS = load_sources(SOURCES)
CASES = yaml.safe_load((FIXTURES / "cases.yml").read_text(encoding="utf-8"))
SLUGS = sorted(PROFILES)
# The eight Phase 1 sources the invariant and dry-run tests exercise. Fixed,
# not derived from enabled flags: those are operational since
# WAYPOINT-SOURCES-HAND-V1 (sources.yml hand-maintained).
LIVE = sorted(["bleepingcomputer", "cyberscoop", "dark_web_informer", "security_affairs",
               "techcrunch", "the_hacker_news", "the_record", "the_register"])
PDF = b"%PDF-1.7 body"


def pytest_generate_tests(metafunc):
    """`slug` -> every profile; `live_slug` -> the enabled (live) profiles."""
    if "slug" in metafunc.fixturenames:
        metafunc.parametrize("slug", SLUGS)
    if "live_slug" in metafunc.fixturenames:
        metafunc.parametrize("live_slug", LIVE)


class Site:
    """One source's real profile, a neutral copy, and its test data."""

    def __init__(self, slug):
        self.slug = slug
        self.real = PROFILES[slug]
        self.cases = CASES[slug]
        self.host = self.cases["host"]
        self.feed_url = self.real.feed_urls[0]
        # Generic tests run with neutral site switches (the generated suites'
        # autouse fixture did the same); TestSiteScope uses the real ones.
        # skip_if and render_headers stay: the generated suites kept them.
        self.p = dataclasses.replace(
            self.real, category_keep=frozenset(), category_allow=frozenset(),
            category_deny=frozenset(), exclude_url_re=None, exclude_title_re=None,
            byline_author=True, no_content_is_transient=False, discovery="feed",
            discovery_config={}, resolve_redirect_hosts=frozenset(),
            date_text_selector=None, max_age_days=0, request_delay=0)

    def link(self, n):
        return f"https://{self.host}/{self.cases['link_path']}{n}/"

    def wrap(self, inner):
        """Markup inside the site's content container."""
        return self.cases["content_open"] + inner + self.cases["content_close"]

    def sample(self):
        return (FIXTURES / self.slug / "feed_sample.xml").read_bytes()


def make_feed(links, pub="Mon, 09 Nov 2026 12:00:00 GMT"):
    body = "".join(
        f"<item><title>Story {i}</title><link>{l}</link>"
        f"<pubDate>{pub}</pubDate><description>Summary {i}</description></item>"
        for i, l in enumerate(links)
    )
    return f"<rss><channel>{body}</channel></rss>".encode()


class FakeGraph:
    """Minimal graph: External References (by url) and the Reports citing them.

    External References upsert on url, as in OpenCTI (their standard id is
    derived from the url).
    """

    def __init__(self):
        self.refs = {}      # ref id -> url
        self.reports = {}   # report id -> list of cited ref ids

    def _ref_for(self, url):
        for ref_id, ref_url in self.refs.items():
            if ref_url == url:
                return ref_id
        ref_id = f"ref-{len(self.refs)}"
        self.refs[ref_id] = url
        return ref_id

    def add_ingested(self, url, report_id=None):
        """Simulate a Report (any connector) citing this url."""
        ref_id = self._ref_for(url)
        self.reports[report_id or f"other-{ref_id}"] = [ref_id]

    def add_orphan_ref(self, url):
        """Simulate a reference left behind by a failed Report create."""
        self._ref_for(url)

    def ref_create(self, **kw):
        return {"id": self._ref_for(kw["url"])}

    def ref_list(self, **kw):
        urls = set(kw["filters"]["filters"][0]["values"])
        return [{"id": r, "url": u} for r, u in self.refs.items() if u in urls]

    def report_list(self, **kw):
        ids = set(kw["filters"]["filters"][0]["values"])
        return [{"id": k, "externalReferencesIds": v}
                for k, v in self.reports.items() if ids & set(v)]

    def report_create(self, **kw):
        self.reports[kw["stix_id"]] = list(kw["externalReferences"])
        return {"id": kw["stix_id"]}

    def created(self):
        """Report ids created by Waypoint (uuid5 STIX ids)."""
        return {k for k in self.reports if k.startswith("report--")}


def wire_graph(api, graph):
    """Point a MagicMock pycti api at a FakeGraph."""
    api.report.list.side_effect = graph.report_list
    api.report.create.side_effect = graph.report_create
    api.external_reference.list.side_effect = graph.ref_list
    api.external_reference.create.side_effect = graph.ref_create
    api.work.initiate_work.return_value = "work-id"


def test_settings(**over):
    """Engine settings for unit tests: no per-poll cap, 2 render attempts."""
    base = dict(render_retries=2, max_reports_per_source_poll=0, reports_per_cycle=0)
    base.update(over)
    return EngineSettings(**base)


test_settings.__test__ = False


def make_worker(profile, settings=None, graph=None):
    """A SourceWorker with mocked session/api/log, wired to a FakeGraph."""
    w = SourceWorker(profile, settings or test_settings(), MagicMock(), MagicMock(),
                     session=MagicMock())
    w.session.get.return_value = MagicMock(content=b"", text="", status_code=200)
    w.author_id = "author-id"
    w.marking_id = "marking-id"
    w.graph = graph or FakeGraph()
    wire_graph(w.api, w.graph)
    return w


@pytest.fixture
def site(slug):
    return Site(slug)


@pytest.fixture
def render_mock():
    """The house pdf-renderer client (make_pdf.render_live_pdf), mocked."""
    with patch("engine.render.render_live_pdf", return_value=PDF) as mock:
        yield mock


@pytest.fixture
def w(site, render_mock):
    """A worker for this source with the neutral profile (as the generated
    suites' `connector` fixture)."""
    worker = make_worker(site.p)
    worker.feed_urls = [site.feed_url]
    worker.render_mock = render_mock
    return worker


@pytest.fixture(autouse=True)
def no_sleep_or_classifier(monkeypatch):
    """Standalone by default (tests that need the Collector set it), no real
    sleeps, and a pass-through classifier."""
    monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
    with patch.object(timing, "sleep") as sleep, \
         patch("engine.report.classify_report", side_effect=lambda **kw: kw["default_types"]):
        yield sleep
