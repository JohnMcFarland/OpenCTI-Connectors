"""Unit tests for the The Record connector."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

import main
from main import (
    ALLOWED_HOSTS,
    CONTENT_SELECTOR,
    CONTENT_SELECTORS,
    HIDE_SELECTORS,
    MAX_DESCRIPTION_CHARS,
    MAX_PDF_BYTES,
    MAX_TRANSIENT_ATTEMPTS,
    ContentUnavailable,
    RendererUnavailable,
    TheRecordConnector,
    _canonical_link,
    _html_to_text,
    _parse_feed,
    _parse_date,
    _parse_rfc2822,
    _report_id,
    _slug_from_url,
)

HOST = "therecord.media"
FIXTURE = Path(__file__).parent / "tests" / "feed_sample.xml"


def _link(n):
    return f"https://{HOST}/story-{n}/"


def _feed(links, pub="Mon, 09 Nov 2026 12:00:00 GMT"):
    body = "".join(
        f"<item><title>Story {i}</title><link>{l}</link>"
        f"<pubDate>{pub}</pubDate><description>Summary {i}</description></item>"
        for i, l in enumerate(links)
    )
    return f"<rss><channel>{body}</channel></rss>".encode()


PDF = b"%PDF-1.7 body"


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
        """Simulate a Report (any connector, e.g. Feedly) citing this url."""
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
        """Report ids created by this connector (uuid5 STIX ids)."""
        return {k for k in self.reports if k.startswith("report--")}


@pytest.fixture
def render_mock():
    """The house pdf-renderer client (make_pdf.render_live_pdf), mocked."""
    with patch.object(main, "render_live_pdf", return_value=PDF) as mock:
        yield mock


@pytest.fixture
def connector(render_mock):
    with patch.object(TheRecordConnector, "__init__", lambda self: None):
        c = TheRecordConnector()
    c.render_mock = render_mock
    c.feed_urls = ["https://therecord.media/feed/"]
    c.fetch_complete = True
    c.session = MagicMock()
    c.session.get.return_value = MagicMock(content=b"", text="", status_code=200)
    c.request_delay = 0
    c.render_retries = 2
    c.render_timeout = 120
    c.confidence = 50
    c.report_type = "open-source-reporting"
    c.tlp_name = "TLP:CLEAR"
    c.max_reports = 0
    c.max_age_days = 0
    c.author_id = "author-id"
    c.author_name = "The Record"
    c.marking_id = "marking-id"
    c.poll_interval = 900
    c.poll_count = 0
    c.prev_poll_clean = True
    c.permanent_skips = {}
    c.transient_failures = {}
    c.helper = MagicMock()
    c.graph = FakeGraph()
    c.helper.api.report.list.side_effect = c.graph.report_list
    c.helper.api.report.create.side_effect = c.graph.report_create
    c.helper.api.external_reference.list.side_effect = c.graph.ref_list
    c.helper.api.external_reference.create.side_effect = c.graph.ref_create
    c.helper.api.work.initiate_work.return_value = "work-id"
    return c


# The site's real scope filters and switches, captured before the neutral
# fixture below resets them for the generic tests.
SITE_SCOPE = {
    "CATEGORY_KEEP": main.CATEGORY_KEEP,
    "CATEGORY_ALLOW": main.CATEGORY_ALLOW, "CATEGORY_DENY": main.CATEGORY_DENY,
    "EXCLUDE_URL_RE": main.EXCLUDE_URL_RE, "EXCLUDE_TITLE_RE": main.EXCLUDE_TITLE_RE,
    "BYLINE_AUTHOR": main.BYLINE_AUTHOR,
    "NO_CONTENT_IS_TRANSIENT": main.NO_CONTENT_IS_TRANSIENT,
}


@pytest.fixture(autouse=True)
def no_sleep_or_classifier(monkeypatch):
    # Standalone by default; tests that need the Collector set it themselves.
    monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
    # Generic tests run with neutral site switches; TestSiteScope checks the
    # real ones.
    monkeypatch.setattr(main, "CATEGORY_KEEP", set())
    monkeypatch.setattr(main, "CATEGORY_ALLOW", set())
    monkeypatch.setattr(main, "CATEGORY_DENY", set())
    monkeypatch.setattr(main, "EXCLUDE_URL_RE", None)
    monkeypatch.setattr(main, "EXCLUDE_TITLE_RE", None)
    monkeypatch.setattr(main, "BYLINE_AUTHOR", True)
    monkeypatch.setattr(main, "NO_CONTENT_IS_TRANSIENT", False)
    with patch.object(main.time, "sleep"), \
         patch.object(main, "classify_report", side_effect=lambda **kw: kw["default_types"]):
        yield


def _serve(c, xml_bytes, render=None):
    c.session.get.return_value = MagicMock(content=xml_bytes, text="", status_code=200)
    c.render_mock.side_effect = render


def _down(*a, **k):
    raise RendererUnavailable("HTTP 503: renderer busy")


def _site_down(*a, **k):
    raise ContentUnavailable('HTTP 422: {"detail":"HTTP 503 from https://site/"}')


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>t</title>
  <entry>
    <title>Atom &amp; story</title>
    <link rel="self" href="https://elsewhere.example/self"/>
    <link rel="alternate" href="{link}"/>
    <published>2026-11-09T17:09:33Z</published>
    <updated>2026-11-10T00:00:00Z</updated>
    <author><name>Jane Doe</name></author>
    <summary type="html">&lt;p&gt;Short summary&lt;/p&gt;</summary>
    <content type="html">&lt;p&gt;Full atom body&lt;/p&gt;</content>
  </entry>
  <entry>
    <title>No published</title>
    <link href="{link2}"/>
    <updated>2026-11-08T10:00:00+02:00</updated>
  </entry>
  <entry>
    <title>Off-site</title>
    <link href="https://evil.example/x"/>
    <updated>2026-11-08T10:00:00Z</updated>
  </entry>
</feed>"""


class TestFeedFormats:
    def test_atom_xhtml_content(self):
        xml = (f"<feed xmlns='http://www.w3.org/2005/Atom'><entry><title>x</title>"
               f"<link href='{_link(1)}'/><updated>2026-11-09T00:00:00Z</updated>"
               f"<content type='xhtml'><div xmlns='http://www.w3.org/1999/xhtml'>"
               f"<p>Inline <b>xhtml</b> body &amp; more</p></div></content></entry></feed>").encode()
        item = _parse_feed(xml)[0]
        assert item["full_text"] == "Inline xhtml body & more"
        assert item["description"] == "Inline xhtml body & more"

    def test_atom_entries_parsed(self):
        xml = ATOM.format(link=_link(1), link2=_link(2)).encode()
        items = _parse_feed(xml)
        assert [i["link"] for i in items] == [_link(1), _link(2)]
        first, second = items
        assert first["title"] == "Atom & story"
        assert first["description"] == "Short summary"
        assert first["full_text"] == "Full atom body"
        assert first["creator"] == "Jane Doe"
        assert _parse_date(first["pub_date"]) == "2026-11-09T17:09:33+00:00"
        # updated is the fallback date when there is no published
        assert _parse_date(second["pub_date"]) == "2026-11-08T08:00:00+00:00"
        assert second["creator"] == "" and second["full_text"] == ""

    @pytest.mark.parametrize("raw,expected", [
        ("Mon, 09 Nov 2026 17:09:33 -0500", "2026-11-09T22:09:33+00:00"),
        ("2026-11-09T17:09:33Z", "2026-11-09T17:09:33+00:00"),
        ("2026-11-09T17:09:33.123+01:00", "2026-11-09T16:09:33+00:00"),
        ("2026-11-09", "2026-11-09T00:00:00+00:00"),
        ("1970-01-01T00:00:00Z", None),
        ("not a date", None),
        ("", None),
    ])
    def test_parse_date(self, raw, expected):
        assert _parse_date(raw) == expected

    def test_several_feeds_merged_and_deduplicated(self, connector):
        connector.feed_urls = ["https://a.example/feed", "https://b.example/feed"]
        feeds = {
            "https://a.example/feed": _feed([_link(1), _link(2)]),
            "https://b.example/feed": ATOM.format(link=_link(2), link2=_link(3)).encode(),
        }
        connector.session.get.side_effect = lambda url, **k: MagicMock(
            content=feeds[url], status_code=200, raise_for_status=lambda: None)
        items = connector._fetch_feed()
        assert [i["link"] for i in items] == [_link(1), _link(2), _link(3)]
        assert connector.fetch_complete is True

    def test_one_failed_feed_keeps_the_others_and_bookkeeping(self, connector):
        connector.feed_urls = ["https://a.example/feed", "https://b.example/feed"]
        connector.transient_failures = {_link(9): 2}
        connector._precheck = lambda item: None   # site prechecks tested separately

        def get(url, **k):
            if url.startswith("https://b."):
                raise requests.ConnectionError("down")
            return MagicMock(content=_feed([_link(1)]), status_code=200,
                             raise_for_status=lambda: None)

        connector.session.get.side_effect = get
        connector._process()
        assert connector.fetch_complete is False
        assert connector.graph.created() == {_report_id(_link(1))}
        # _link(9) may live in the failed feed: its retry count is kept.
        assert connector.transient_failures == {_link(9): 2}

    def test_all_feeds_failed_writes_nothing(self, connector):
        connector.feed_urls = ["https://a.example/feed", "https://b.example/feed"]
        connector.session.get.side_effect = requests.ConnectionError("down")
        assert connector._fetch_feed() is None
        connector._process()
        connector.helper.api.work.initiate_work.assert_not_called()


class TestScope:
    def test_utm_parameters_stripped(self):
        url = _link(1) + "?utm_source=rss&utm_medium=rss&id=7#frag"
        assert _canonical_link(url) == _link(1) + "?id=7"
        assert _canonical_link(_link(1) + "?utm_campaign=x") == _link(1)

    @pytest.mark.parametrize("query", ["?s=a%20b&x", "?a&b", "?p=1;q=2", "?q=%7Ehome+page"])
    def test_other_query_strings_kept_byte_for_byte(self, query):
        assert _canonical_link(_link(1) + query) == _link(1) + query
        assert _canonical_link(_link(1) + query + "&utm_medium=rss") == _link(1) + query

    def test_cdata_link_survives_xml_repair(self):
        xml = (f"<rss><channel><item><title>Bad & title</title>"
               f"<link><![CDATA[{_link(1)}?id=5&utm_source=x&utm_medium=rss]]></link>"
               f"<pubDate>Mon, 09 Nov 2026 12:00:00 GMT</pubDate></item>"
               f"</channel></rss>").encode()
        items = _parse_feed(xml)
        assert items[0]["link"] == _link(1) + "?id=5"
        assert items[0]["title"] == "Bad & title"

    def test_html_named_entities_repaired(self):
        xml = (f"<rss><channel><item><title>A&nbsp;B &rsquo;C&rsquo; &bogus; D</title>"
               f"<link>{_link(1)}</link></item></channel></rss>").encode()
        assert _parse_feed(xml)[0]["title"] == "A\u00a0B \u2019C\u2019 &bogus; D"

    def test_bare_ampersand_feed_still_parses(self):
        xml = (f"<rss><channel><item><title>A & B</title>"
               f"<link>{_link(1)}?utm_source=rss&utm_medium=rss</link>"
               f"<pubDate>Mon, 09 Nov 2026 12:00:00 GMT</pubDate></item>"
               f"</channel></rss>").encode()
        items = _parse_feed(xml)
        assert items[0]["link"] == _link(1) and items[0]["title"] == "A & B"

    def test_really_broken_xml_still_raises(self):
        with pytest.raises(main.ElementTree.ParseError):
            _parse_feed(b"<rss><channel><item>")

    def test_categories_parsed(self):
        xml = (f"<rss><channel><item><title>a</title><link>{_link(1)}</link>"
               f"<category>Threat Intel</category><category>Malware &amp; Co</category>"
               f"</item></channel></rss>").encode()
        assert _parse_feed(xml)[0]["categories"] == ["Threat Intel", "Malware & Co"]

    def test_category_allow(self, monkeypatch):
        monkeypatch.setattr(main, "CATEGORY_ALLOW", {"Threat Intel"})
        item = {"link": _link(1), "title": "t", "categories": ["threat intel"]}
        assert main._out_of_scope(item, 0) is None
        assert main._out_of_scope(dict(item, categories=["Product"]), 0)
        assert main._out_of_scope(dict(item, categories=[]), 0)

    def test_category_deny(self, monkeypatch):
        monkeypatch.setattr(main, "CATEGORY_DENY", {"Threat Source newsletter"})
        item = {"link": _link(1), "title": "t", "categories": ["threat source newsletter"]}
        assert main._out_of_scope(item, 0) == "category excluded"
        assert main._out_of_scope(dict(item, categories=["Threats"]), 0) is None
        assert main._out_of_scope(dict(item, categories=[]), 0) is None

    def test_category_keep_overrides_deny_and_title(self, monkeypatch):
        monkeypatch.setattr(main, "CATEGORY_KEEP", {"Research"})
        monkeypatch.setattr(main, "CATEGORY_DENY", {"Expert Perspective"})
        monkeypatch.setattr(main, "CATEGORY_ALLOW", {"Threat Intel"})
        monkeypatch.setattr(main, "EXCLUDE_TITLE_RE", main.re.compile(r"Vendor"))
        item = {"link": _link(1), "title": "Vendor RAT analysis",
                "categories": ["Expert Perspective", "research"]}
        assert main._out_of_scope(item, 0) is None
        assert main._out_of_scope(dict(item, categories=["Expert Perspective"]), 0)
        assert main._out_of_scope(dict(item, categories=[], title="RAT"), 0)
        assert main._out_of_scope(dict(item, categories=["Threat Intel"], title="RAT"), 0) is None
        # Kept items still age out.
        old = dict(item, pub_date="Mon, 02 Nov 2026 00:00:00 GMT")
        now = main.datetime(2026, 11, 11, tzinfo=main.timezone.utc)
        assert main._out_of_scope(old, 7, now) == "older than max_age_days"

    def test_control_characters_removed(self):
        xml = (f"<rss><channel><item><title>A\x0bB</title><link>{_link(1)}</link>"
               f"</item></channel></rss>").encode()
        assert _parse_feed(xml)[0]["title"] == "AB"

    def test_url_and_title_exclusions(self, monkeypatch):
        monkeypatch.setattr(main, "EXCLUDE_URL_RE", main.re.compile(r"/events/"))
        monkeypatch.setattr(main, "EXCLUDE_TITLE_RE", main.re.compile(r"^Webinar"))
        assert main._out_of_scope({"link": f"https://{HOST}/events/x", "title": "t"}, 0)
        assert main._out_of_scope({"link": _link(1), "title": "Webinar: x"}, 0)
        assert main._out_of_scope({"link": _link(1), "title": "Real research"}, 0) is None

    def test_max_age(self):
        now = main.datetime(2026, 11, 11, tzinfo=main.timezone.utc)
        old = {"link": _link(1), "title": "t", "pub_date": "Mon, 02 Nov 2026 00:00:00 GMT"}
        new = dict(old, pub_date="Tue, 10 Nov 2026 00:00:00 GMT")
        undated = dict(old, pub_date="")
        assert main._out_of_scope(old, 7, now) == "older than max_age_days"
        assert main._out_of_scope(new, 7, now) is None
        assert main._out_of_scope(old, 0, now) is None
        # Undated items stay in scope and are skipped later, with a reason.
        assert main._out_of_scope(undated, 7, now) is None

    def test_out_of_scope_items_never_reach_dedup(self, connector):
        connector.max_age_days = 30
        _serve(connector, _feed([_link(1), _link(2)], pub="Mon, 01 Jan 2001 00:00:00 GMT"))
        connector._process()
        connector.helper.api.external_reference.list.assert_not_called()
        connector.render_mock.assert_not_called()
        connector.helper.api.work.initiate_work.assert_not_called()


class TestSiteScope:
    """The site's real scope filters, applied to its real feed sample."""

    def test_configured_switches(self):
        assert SITE_SCOPE == {
            "CATEGORY_KEEP": set(),
            "CATEGORY_ALLOW": set(),
            "CATEGORY_DENY": set(),
            "EXCLUDE_URL_RE": None,
            "EXCLUDE_TITLE_RE": None,
            "BYLINE_AUTHOR": True,
            "NO_CONTENT_IS_TRANSIENT": False,
        }

    # Real titles seen in the live feed: (title, categories, in scope?).
    SCOPE_CASES = []

    def test_real_titles(self, monkeypatch):
        for name, value in SITE_SCOPE.items():
            monkeypatch.setattr(main, name, value)
        for title, cats, keep in self.SCOPE_CASES:
            item = {"link": _link(1), "title": title, "categories": cats}
            assert (main._out_of_scope(item, 0) is None) == keep, title

    def test_real_feed_sample_scoped_without_error(self, monkeypatch):
        for name, value in SITE_SCOPE.items():
            monkeypatch.setattr(main, name, value)
        for item in _parse_feed(FIXTURE.read_bytes()):
            main._out_of_scope(item, 0)


class TestSiteFlags:
    def test_slug_from_id(self, monkeypatch):
        monkeypatch.setattr(main, "SLUG_FROM_ID", True)
        assert _slug_from_url(f"https://{HOST}/en/96477/") == f"{main.FILE_PREFIX}-96477"
        # No numeric segment: falls back to the descriptive slug.
        assert _slug_from_url(f"https://{HOST}/blog/some-post/") == "some-post"

    def test_byline_author_switch(self, connector, monkeypatch):
        monkeypatch.setattr(main, "BYLINE_AUTHOR", False)
        connector._render_with_retry(dict(_item(), creator="login@example.com"),
                                     "2026-11-09T00:00:00+00:00")
        assert "author" not in connector.render_mock.call_args.kwargs["byline"]

    def test_no_content_transient_switch(self, connector, monkeypatch):
        monkeypatch.setattr(main, "NO_CONTENT_IS_TRANSIENT", True)
        connector.render_mock.side_effect = ContentUnavailable("HTTP 422: no body")
        assert connector._ingest_item(_item()) == "failed"
        connector.helper.api.report.create.assert_not_called()
        # Not retried within the poll (a challenge will not clear in seconds).
        assert connector.render_mock.call_count == 1


class TestPureHelpers:
    def test_report_id_deterministic_and_distinct(self):
        assert _report_id(_link(1)) == _report_id(_link(1))
        assert _report_id(_link(1)) != _report_id(_link(2))
        assert _report_id(_link(1)).startswith("report--")

    @pytest.mark.parametrize("raw,expected", [
        ("Mon, 09 Nov 2026 17:09:33 -0500", "2026-11-09T22:09:33+00:00"),
        ("Tue, 10 Nov 2026 21:13:00 GMT", "2026-11-10T21:13:00+00:00"),
        ("Wed, 11 Nov 2026 13:47:53 +0530", "2026-11-11T08:17:53+00:00"),
        ("Thu, 01 Jan 1970 00:00:00 GMT", None),
        ("", None),
        (None, None),
        ("not a date", None),
    ])
    def test_parse_rfc2822(self, raw, expected):
        assert _parse_rfc2822(raw) == expected

    def test_html_to_text(self):
        assert _html_to_text("<p>A &amp; B <b>bold</b></p>\n\n more [...]") == "A & B bold more"
        assert _html_to_text(None) == ""
        long = _html_to_text("x" * (MAX_DESCRIPTION_CHARS + 50))
        assert len(long) == MAX_DESCRIPTION_CHARS and long.endswith("...")

    @pytest.mark.parametrize("link,ok", [
        (f"https://{HOST}/a/b/", True),
        (f"http://{HOST}/a/", False),
        ("https://evil.example/a/", False),
        (f"https://{HOST}.evil.example/a/", False),
        ("javascript:alert(1)", False),
        (None, False),
    ])
    def test_canonical_link(self, link, ok):
        assert (_canonical_link(link) is not None) is ok

    def test_canonical_link_drops_fragment(self):
        assert _canonical_link(f"https://{HOST}/a/#comments") == f"https://{HOST}/a/"

    def test_slug(self):
        assert _slug_from_url("https://therecord.media/us-army-member-arrested-in-uk") == "us-army-member-arrested-in-uk"
        assert _slug_from_url(f"https://{HOST}/") == "report"

    def test_allowed_hosts_cover_primary(self):
        assert HOST in ALLOWED_HOSTS


class TestLiveFeedSample:
    """Parses a trimmed copy of the real feed captured during recon."""

    def test_parses_real_feed(self):
        items = _parse_feed(FIXTURE.read_bytes())
        assert len(items) >= 2
        for item in items:
            assert item["link"].startswith(f"https://{HOST}/")
            assert item["title"]
            assert _parse_date(item["pub_date"]) is not None
            assert "<" not in item["description"]
            assert len(item["description"]) <= MAX_DESCRIPTION_CHARS

    def test_drops_foreign_duplicate_and_linkless_items(self):
        xml = (
            f"<rss><channel>"
            f"<item><title>a</title><link>{_link(1)}</link></item>"
            f"<item><title>dup</title><link>{_link(1)}</link></item>"
            f"<item><title>x</title><link>https://evil.example/a</link></item>"
            f"<item><title>nolink</title></item>"
            f"</channel></rss>"
        ).encode()
        assert [i["title"] for i in _parse_feed(xml)] == ["a"]

    def test_malformed_raises(self):
        with pytest.raises(Exception):
            _parse_feed(b"<rss><channel><item>")


# --------------------------------------------------------------------------- #
# Graph lookups (Elasticsearch footprint)
# --------------------------------------------------------------------------- #

class TestDedupByExternalReferenceUrl:
    def test_two_batched_exact_match_queries(self, connector):
        items = [{"link": _link(i)} for i in range(5)]
        connector.graph.add_ingested(_link(2))
        assert connector._ingested_links(items) == {_link(2)}

        ref_kw = connector.helper.api.external_reference.list.call_args.kwargs
        assert connector.helper.api.external_reference.list.call_count == 1
        assert ref_kw["filters"]["filters"][0] == {
            "key": "url", "values": sorted(i["link"] for i in items)}
        assert ref_kw["customAttributes"] == "id url" and "search" not in ref_kw

        rep_kw = connector.helper.api.report.list.call_args.kwargs
        assert connector.helper.api.report.list.call_count == 1
        assert rep_kw["filters"]["filters"][0]["key"] == "externalReferences"
        assert "search" not in rep_kw
        connector.helper.api.report.read.assert_not_called()

    def test_no_matching_reference_skips_second_query(self, connector):
        assert connector._ingested_links([{"link": _link(1)}]) == set()
        connector.helper.api.report.list.assert_not_called()

    def test_orphan_reference_is_retried(self, connector):
        connector.graph.add_orphan_ref(_link(1))
        assert connector._ingested_links([{"link": _link(1)}]) == set()

    def test_reference_cited_by_another_connector_counts(self, connector):
        # e.g. the deprecated Feedly connector already ingested this article.
        connector.graph.add_ingested(_link(1), report_id="feedly-report")
        assert connector._ingested_links([{"link": _link(1)}]) == {_link(1)}

    def test_citing_query_failure_is_conservative(self, connector):
        connector.graph.add_orphan_ref(_link(1))
        connector.helper.api.report.list.side_effect = Exception("bad filter")
        items = [{"link": _link(1)}, {"link": _link(2)}]
        assert connector._ingested_links(items) == {_link(1)}

    def test_reference_query_failure_skips_the_poll(self, connector):
        connector.helper.api.external_reference.list.side_effect = Exception("down")
        _serve(connector, _feed([_link(1)]))
        connector._process()
        connector.helper.api.work.initiate_work.assert_not_called()
        connector.render_mock.assert_not_called()
        connector.helper.api.report.create.assert_not_called()

    def test_empty(self, connector):
        assert connector._ingested_links([]) == set()
        connector.helper.api.external_reference.list.assert_not_called()


# --------------------------------------------------------------------------- #
# Render
# --------------------------------------------------------------------------- #

class TestRender:
    def test_house_client_called_with_site_selectors_and_byline(self, connector):
        item = dict(_item(), creator="Jane Doe")
        assert connector._render_with_retry(item, "2026-11-09T22:09:33+00:00") == PDF
        args, kw = connector.render_mock.call_args
        assert args == (_link(1), "Story", main.SOURCE_NAME)
        assert kw["selectors"] == CONTENT_SELECTORS and CONTENT_SELECTORS[0] == CONTENT_SELECTOR
        assert CONTENT_SELECTOR == "article.article"
        assert kw["strip"] == HIDE_SELECTORS
        assert kw["timeout"] == 120
        assert kw["byline"] == {"author": "Jane Doe", "publisher": "The Record",
                                "published": "2026-11-09"}

    def test_byline_without_creator_has_no_author(self, connector):
        connector._render_with_retry(_item(), "2026-11-09T22:09:33+00:00")
        assert "author" not in connector.render_mock.call_args.kwargs["byline"]

    def test_renderer_unavailable_retried_then_raised(self, connector):
        connector.render_mock.side_effect = _down
        with pytest.raises(RendererUnavailable):
            connector._render_with_retry(_item(), "2026-11-09T00:00:00+00:00")
        assert connector.render_mock.call_count == connector.render_retries

    def test_retry_then_success(self, connector):
        connector.render_mock.side_effect = [RendererUnavailable("504"), PDF]
        assert connector._render_with_retry(_item(), "2026-11-09T00:00:00+00:00") == PDF

    def test_content_unavailable_is_not_retried(self, connector):
        connector.render_mock.side_effect = ContentUnavailable("HTTP 422: no body")
        assert connector._render_with_retry(_item(), "2026-11-09T00:00:00+00:00") is None
        assert connector.render_mock.call_count == 1

    def test_non_pdf_payload_is_transient(self, connector):
        connector.render_mock.return_value = b"<html>"
        with pytest.raises(RendererUnavailable):
            connector._render_with_retry(_item(), "2026-11-09T00:00:00+00:00")


# --------------------------------------------------------------------------- #
# Ingestion + data model
# --------------------------------------------------------------------------- #

def _item(n=1, title="Story", pub="Mon, 09 Nov 2026 17:09:33 -0500"):
    return {"title": title, "link": _link(n), "description": "Summary.", "pub_date": pub}


class TestDescription:
    def test_wordpress_trailer_stripped(self):
        text = main._html_to_text(
            "<p>Real summary.</p><p>The post <a href='x'>A Story: Part 2</a> appeared "
            "first on <a href='y'>Some Site</a>.</p>")
        assert text == "Real summary."
        assert main._html_to_text("The post office reopened.") == "The post office reopened."

    def test_meta_description_any_attribute_order(self):
        page = (b"<html><head><meta content='Named &amp; summary' name='description'>"
                b"<meta property='og:description' content='OG summary'></head></html>")
        assert main._meta_description(page) == "OG summary"
        assert main._meta_description(page.replace(b"og:description", b"og:title")) == (
            "Named & summary")
        assert main._meta_description(b"<html><meta name='description' content=' '></html>") == ""
        assert main._meta_description(
            b"<meta property='og:description' content=' '><meta name='description' content='Real'>"
        ) == "Real"
        assert main._meta_description(b"") == ""

    def test_meta_description_used_when_feed_has_none(self, connector, monkeypatch):
        monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
        connector._precheck = lambda item: None
        connector.session.get.return_value = MagicMock(
            content=b"<meta name='description' content='Page summary.'>", status_code=200)
        assert connector._ingest_item(dict(_item(), description="")) == "created"
        assert connector.session.get.call_args.args[0] == _link(1)
        assert connector.helper.api.report.create.call_args.kwargs["description"] == (
            "Page summary.")

    def test_no_page_fetch_when_feed_has_summary(self, connector, monkeypatch):
        monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
        connector._precheck = lambda item: None
        assert connector._ingest_item(_item()) == "created"
        connector.session.get.assert_not_called()
        assert connector.helper.api.report.create.call_args.kwargs["description"] == "Summary."

    def test_page_fetch_failure_still_creates_report(self, connector, monkeypatch):
        monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
        connector._precheck = lambda item: None
        connector.session.get.side_effect = requests.ConnectionError("down")
        assert connector._ingest_item(dict(_item(), description="")) == "created"
        assert connector.helper.api.report.create.call_args.kwargs["description"] == ""
        connector.helper.log_warning.assert_called()


class TestIngestItem:
    def test_single_create_mutation_with_inline_pdf(self, connector):
        assert connector._ingest_item(_item()) == "created"

        kw = connector.helper.api.report.create.call_args.kwargs
        assert kw["stix_id"] == _report_id(_link(1))
        assert kw["published"] == "2026-11-09T22:09:33+00:00"
        assert kw["createdBy"] == "author-id"
        assert kw["objectMarking"] == ["marking-id"]
        ref_kw = connector.helper.api.external_reference.create.call_args.kwargs
        assert ref_kw["url"] == _link(1) and ref_kw["source_name"] == "The Record"
        assert kw["externalReferences"] == [connector.graph.ref_create(url=_link(1))["id"]]
        assert kw["report_types"] == ["open-source-reporting"]
        # The new Report is found by the URL-based dedup on the next poll.
        assert connector._ingested_links([{"link": _link(1)}]) == {_link(1)}
        assert kw["update"] is False
        assert "content" not in kw
        assert "objectLabel" not in kw and "labels" not in kw
        assert "objects" not in kw
        # House standard: exactly one PDF, the file itself TLP-marked.
        assert len(kw["files"]) == 1
        pdf = kw["files"][0]
        assert pdf.name.startswith("the_record-rendered-") and pdf.name.endswith(".pdf")
        assert pdf.mime == "application/pdf" and pdf.data == PDF
        assert kw["filesMarkings"] == [["marking-id"]]
        connector.helper.api.stix_domain_object.add_file.assert_not_called()

    def test_atom_iso_date_item_ingested(self, connector):
        assert connector._ingest_item(_item(pub="2026-11-09T17:09:33Z")) == "created"
        kw = connector.helper.api.report.create.call_args.kwargs
        assert kw["published"] == "2026-11-09T17:09:33+00:00"

    def test_undated_item_is_skipped_never_stamped_now(self, connector):
        assert connector._ingest_item(_item(pub="garbage")) == "skipped-permanent"
        connector.render_mock.assert_not_called()
        connector.helper.api.report.create.assert_not_called()
        assert _link(1) in connector.permanent_skips

    def test_renderer_down_creates_nothing(self, connector):
        connector.render_mock.side_effect = _down
        assert connector._ingest_item(_item()) == "renderer-down"
        connector.helper.api.report.create.assert_not_called()
        connector.helper.api.external_reference.create.assert_not_called()
        assert _link(1) not in connector.permanent_skips

    @pytest.mark.parametrize("detail", [
        'HTTP 422: {"detail":"navigation failed: net::ERR_NAME_NOT_RESOLVED"}',
        'HTTP 422: {"detail":"HTTP 503 from https://site/x"}',
        'HTTP 422: {"detail":"HTTP 429 from https://site/x"}',
        'HTTP 422: {"detail":"bot challenge interstitial detected"}',
    ])
    def test_site_failure_is_transient_not_a_pdfless_report(self, connector, detail):
        connector.render_mock.side_effect = ContentUnavailable(detail)
        assert connector._ingest_item(_item()) == "failed"
        connector.helper.api.report.create.assert_not_called()
        assert connector.render_mock.call_count == 1

    def test_request_validation_error_is_a_renderer_problem(self, connector):
        connector.render_mock.side_effect = ContentUnavailable(
            'HTTP 422: {"detail":[{"type":"missing","loc":["body","title"]}]}')
        assert connector._ingest_item(_item()) == "renderer-down"
        connector.helper.api.report.create.assert_not_called()

    def test_content_unavailable_creates_report_without_pdf(self, connector):
        connector.render_mock.side_effect = ContentUnavailable("HTTP 422: no article")
        assert connector._ingest_item(_item()) == "created"
        kw = connector.helper.api.report.create.call_args.kwargs
        assert "files" not in kw and "filesMarkings" not in kw
        assert any("No PDF for" in str(c) for c in connector.helper.log_warning.call_args_list)
        assert any("(no PDF)" in str(c) for c in connector.helper.log_info.call_args_list)

    def test_oversized_pdf_creates_report_without_pdf(self, connector):
        connector.render_mock.return_value = b"%PDF" + b"0" * MAX_PDF_BYTES
        assert connector._ingest_item(_item()) == "created"
        assert "files" not in connector.helper.api.report.create.call_args.kwargs

    def test_empty_title_uses_url(self, connector):
        connector._ingest_item(_item(title=""))
        assert connector.helper.api.report.create.call_args.kwargs["name"] == _link(1)
        assert connector.render_mock.call_args.args[1] == _link(1)


class TestResolveGraphReferences:
    def test_resolves(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "a"}
        connector.helper.api.marking_definition.read.return_value = {"id": "m"}
        connector._resolve_graph_references()
        assert (connector.author_id, connector.marking_id) == ("a", "m")
        kw = connector.helper.api.identity.create.call_args.kwargs
        assert kw["type"] == "Organization" and kw["name"] == "The Record"

    def test_missing_marking_is_fatal(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "a"}
        connector.helper.api.marking_definition.read.return_value = None
        with pytest.raises(RuntimeError):
            connector._resolve_graph_references()

    def test_vocabulary_failure_is_only_a_warning(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "a"}
        connector.helper.api.marking_definition.read.return_value = {"id": "m"}
        connector.helper.api.vocabulary.create.side_effect = Exception("exists")
        connector._resolve_graph_references()
        connector.helper.log_warning.assert_called()


# --------------------------------------------------------------------------- #
# Report-type classification
# --------------------------------------------------------------------------- #

class TestClassification:
    def _content_sent(self, connector, item, page_bytes, monkeypatch=None):
        connector._precheck = lambda item: None   # site prechecks tested separately
        if page_bytes is not None:
            monkeypatch.setenv("CRUCIBLE_COLLECTOR_URL", "http://collector.example:8004")
            connector.session.get.return_value = MagicMock(
                content=page_bytes, text="", status_code=200)
        with patch.object(main, "classify_report",
                          side_effect=lambda **kw: ["threat-report"]) as clf:
            assert connector._ingest_item(item) == "created"
        assert connector.helper.api.report.create.call_args.kwargs["report_types"] == ["threat-report"]
        assert any("report_types=['threat-report']" in str(c)
                   for c in connector.helper.log_info.call_args_list)
        return clf.call_args.kwargs

    def test_feed_full_text_preferred(self, connector):
        item = dict(_item(), full_text="Full feed body about ransomware.")
        kw = self._content_sent(connector, item, None)
        assert kw["content"] == "Full feed body about ransomware."
        connector.session.get.assert_not_called()   # no page fetch needed
        assert kw["description"] == "Summary."
        assert kw["source"] == main.SOURCE_NAME and kw["source_url"] == _link(1)
        assert kw["default_types"] == ["open-source-reporting"]
        # Failures are logged as WARNINGs through the connector's logger.
        assert kw["logger"] == connector.helper.log_warning

    def test_never_defaults_to_threat_report(self, connector):
        kw = self._content_sent(connector, _item(), None)
        assert "threat-report" not in kw["default_types"]

    def test_standalone_without_shared_helper(self, connector, monkeypatch):
        monkeypatch.setattr(main, "classify_report", None)
        assert connector._ingest_item(_item()) == "created"
        assert connector.helper.api.report.create.call_args.kwargs["report_types"] == [
            "open-source-reporting"]

    def test_page_article_text_when_feed_has_none(self, connector, monkeypatch):
        page = (
            "<html><body><nav>Menu Login</nav>"
            + '<article class="article extra-class"><h1>Title</h1><p>Article body text</p><script>tracker()</script></article>'
            + "<footer>Copyright</footer></body></html>"
        ).encode()
        kw = self._content_sent(connector, _item(), page, monkeypatch)
        assert "Article body text" in kw["content"]
        assert connector.session.get.call_args.args[0] == _link(1)
        assert "Menu Login" not in kw["content"] and "Copyright" not in kw["content"]
        assert "tracker()" not in kw["content"]

    def test_falls_back_to_summary_without_any_text(self, connector):
        kw = self._content_sent(connector, _item(), None)
        assert kw["content"] == "Summary."

    def test_no_page_fetch_in_standalone_mode(self, connector, monkeypatch):
        monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
        self._content_sent(connector, _item(), None)
        connector.session.get.assert_not_called()

    def test_page_fetch_failure_falls_back_to_summary(self, connector, monkeypatch):
        monkeypatch.setenv("CRUCIBLE_COLLECTOR_URL", "http://collector.example:8004")
        connector.session.get.side_effect = requests.ConnectionError("down")
        kw = self._content_sent(connector, _item(), None)
        assert kw["content"] == "Summary."

    def test_one_page_fetch_serves_description_and_classifier(self, connector, monkeypatch):
        page = ("<html><head><meta property='og:description' content='Page summary.'>"
                "</head><body>" + '<article class="article extra-class"><h1>Title</h1><p>Article body text</p><script>tracker()</script></article>' + "</body></html>").encode()
        kw = self._content_sent(connector, dict(_item(), description=""), page, monkeypatch)
        assert connector.session.get.call_count == 1
        assert "Article body text" in kw["content"]
        assert kw["description"] == "Page summary."

    def test_article_text_never_stored_on_report(self, connector):
        item = dict(_item(), full_text="SECRET-LONG-BODY " * 50)
        self._content_sent(connector, item, None)
        kw = connector.helper.api.report.create.call_args.kwargs
        assert "SECRET-LONG-BODY" not in kw["description"] and "content" not in kw

    def test_article_text_skips_hidden_chrome(self):
        hidden = [s for s in main.HIDE_SELECTORS if not any(ch in s for ch in "~[ >")]
        if not hidden:
            pytest.skip("site has no simple hide selectors")
        tag, ident, classes = main._selector_parts(hidden[0])
        attrs = (f' id="{ident}"' if ident else "") + (
            f' class="{" ".join(sorted(classes))}"' if classes else "")
        chrome = f"<{tag or 'div'}{attrs}><p>Most Popular junk</p></{tag or 'div'}>"
        page = ('<article class="article extra-class">' + "<p>Real story</p>" + chrome + "<p>More story</p>"
                + '</article>').encode()
        text = main._article_text(page)
        assert "Real story" in text and "More story" in text
        assert "Most Popular junk" not in text

    def test_article_text_is_full_not_truncated(self):
        page = ('<article class="article extra-class">' + "word " * 20000 + "THE-END" + '</article>').encode()
        text = main._article_text(page)
        assert text.endswith("THE-END") and len(text) > 100000

    def test_article_text_tries_fallback_selectors(self):
        fallbacks = CONTENT_SELECTORS[1:]
        if not fallbacks:
            pytest.skip("no fallback selectors for this site")
        tag, ident, classes = main._selector_parts(fallbacks[0])
        attrs = (f' id="{ident}"' if ident else "") + (
            f' class="{" ".join(sorted(classes))}"' if classes else "")
        page = (f"<html><body><nav>Menu</nav><{tag or 'div'}{attrs}><p>Fallback body</p>"
                f"</{tag or 'div'}></body></html>").encode()
        assert main._article_text(page) == "Fallback body"

    def test_article_text_falls_back_to_page(self):
        assert main._article_text(b"<html><body><p>Only text</p></body></html>") == "Only text"
        assert main._article_text(None) == ""

    def test_feed_creator_parsed_for_byline(self):
        xml = (f"<rss xmlns:dc='http://purl.org/dc/elements/1.1/'><channel>"
               f"<item><title>a</title><link>{_link(1)}</link>"
               f"<dc:creator><![CDATA[Jane &amp; Doe]]></dc:creator></item>"
               f"</channel></rss>").encode()
        assert _parse_feed(xml)[0]["creator"] == "Jane & Doe"
        assert _parse_feed(_feed([_link(1)]))[0]["creator"] == ""

    def test_feed_full_text_parsed_in_full(self):
        body = "<p>" + "x " * 60000 + "THE-END</p>"
        xml = (f"<rss xmlns:content='http://purl.org/rss/1.0/modules/content/'><channel>"
               f"<item><title>a</title><link>{_link(1)}</link>"
               f"<content:encoded><![CDATA[{body}]]></content:encoded></item>"
               f"</channel></rss>").encode()
        text = _parse_feed(xml)[0]["full_text"]
        assert text.endswith("THE-END") and "<p>" not in text

    def test_startup_reports_standalone_mode(self, connector, monkeypatch):
        monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
        connector._resolve_graph_references = lambda: None
        connector._process = MagicMock(side_effect=KeyboardInterrupt)
        with pytest.raises(KeyboardInterrupt):
            connector.run()
        assert any("standalone mode" in str(c) for c in connector.helper.log_info.call_args_list)
        connector.helper.log_warning.assert_not_called()


# --------------------------------------------------------------------------- #
# Poll cycle
# --------------------------------------------------------------------------- #

class TestProcess:
    def test_idle_poll_writes_nothing(self, connector):
        connector.graph.add_ingested(_link(1))
        _serve(connector, _feed([_link(1)]))
        connector._process()
        connector.helper.api.work.initiate_work.assert_not_called()
        connector.helper.api.report.create.assert_not_called()

    def test_feed_failure_writes_nothing(self, connector):
        connector.session.get.side_effect = requests.ConnectionError("down")
        connector._process()
        connector.helper.api.work.initiate_work.assert_not_called()

    def test_max_reports(self, connector):
        connector.max_reports = 1
        _serve(connector, _feed([_link(1), _link(2)]))
        connector._process()
        assert connector.helper.api.report.create.call_count == 1

    def test_one_bad_item_does_not_stop_the_poll(self, connector):
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                _site_down()
            return PDF

        _serve(connector, _feed([_link(1), _link(2)]), render=flaky)
        connector._process()
        assert connector.helper.api.report.create.call_count == 1
        assert connector.helper.api.work.to_processed.call_args.kwargs["in_error"] is True
        assert connector.transient_failures == {_link(1): 1}

    def test_transient_failure_gives_up_after_cap(self, connector):
        _serve(connector, _feed([_link(1)]), render=_site_down)
        for _ in range(MAX_TRANSIENT_ATTEMPTS):
            connector._process()
        assert _link(1) in connector.permanent_skips
        renders = connector.render_mock.call_count
        connector._process()
        assert connector.render_mock.call_count == renders  # no more renders

    def test_renderer_outage_never_gives_up_on_items(self, connector):
        """A long pdf-renderer outage stops polls early but does not count
        against items, so they are all ingested once it recovers."""
        _serve(connector, _feed([_link(1), _link(2)]), render=_down)
        connector._process()
        # The poll stops at the first item: the second is not even tried.
        assert connector.render_mock.call_count == connector.render_retries
        for _ in range(MAX_TRANSIENT_ATTEMPTS * 2):
            connector._process()
        assert connector.permanent_skips == {} and connector.transient_failures == {}
        assert connector.helper.api.work.to_processed.call_args.kwargs["in_error"] is True
        connector.render_mock.side_effect = None
        connector._process()
        assert connector.graph.created() == {_report_id(_link(1)), _report_id(_link(2))}

    def test_no_gap_warning_when_feed_reaches_past_max_age(self, connector):
        """A quiet site: one new post, everything else older than max_age."""
        connector.max_age_days = 30
        connector.poll_count = 5
        recent = main.datetime.now(main.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        xml = _feed([_link(1)], pub=recent)[:-len(b"</channel></rss>")] + _feed(
            [_link(2)], pub="Mon, 01 Jan 2001 00:00:00 GMT")[len(b"<rss><channel>"):]
        _serve(connector, xml)
        connector._process()
        assert not any("scrolled off" in str(c) for c in connector.helper.log_warning.call_args_list)
        assert connector.graph.created() == {_report_id(_link(1))}

    def test_no_gap_warning_after_all_failed_poll(self, connector):
        """An outage poll leaves nothing ingested; the next poll must not
        misreport that as posts scrolling off the feed."""
        down = {"on": True}

        def render(*a, **k):
            if down["on"]:
                raise RendererUnavailable("render down")
            return PDF

        _serve(connector, _feed([_link(1), _link(2)]), render=render)
        connector._process()                       # first poll: all fail
        down["on"] = False
        connector.helper.log_warning.reset_mock()
        connector._process()                       # recovery poll
        assert not any("scrolled off" in str(c)
                       for c in connector.helper.log_warning.call_args_list)
        assert connector.helper.api.report.create.call_count == 2

    def test_multi_poll_moving_feed(self, connector):
        """Feed slides forward; a render outage heals on retry; nothing is
        duplicated; the scroll-off warning fires only when polls lose overlap."""
        state = {"failed": False}

        def render(url, *a, **kw):
            if url == _link(12) and not state["failed"]:
                state["failed"] = True
                raise RendererUnavailable("render outage")
            return PDF

        connector.render_retries = 1
        windows = [range(10, 0, -1), range(14, 4, -1), range(18, 8, -1),
                   range(40, 30, -1)]  # last window has no overlap -> gap
        for n, window in enumerate(windows):
            _serve(connector, _feed([_link(i) for i in window]), render=render)
            connector.helper.log_warning.reset_mock()
            connector._process()
            gap = any("scrolled off" in str(c) for c in connector.helper.log_warning.call_args_list)
            assert gap is (n == 3), f"poll {n}"

        expected = {_report_id(_link(i)) for i in list(range(1, 19)) + list(range(31, 41))}
        assert connector.graph.created() == expected
        assert connector.helper.api.report.create.call_count == len(expected)
        assert connector.transient_failures == {}
        # One reference lookup per poll; dedup never reads Reports one by one.
        assert connector.helper.api.external_reference.list.call_count == len(windows)
        connector.helper.api.report.read.assert_not_called()

    def test_feedly_ingested_article_is_not_duplicated(self, connector):
        connector.graph.add_ingested(_link(1), report_id="feedly-report")
        _serve(connector, _feed([_link(1), _link(2)]))
        connector._process()
        assert connector.graph.created() == {_report_id(_link(2))}

    def test_orphan_reference_from_failed_create_is_retried(self, connector):
        _serve(connector, _feed([_link(1)]))
        connector.helper.api.report.create.side_effect = Exception("API 500")
        connector._process()                     # reference created, Report not
        assert connector.graph.refs and not connector.graph.created()
        connector.helper.api.report.create.side_effect = connector.graph.report_create
        connector._process()                     # retried, now created
        assert connector.graph.created() == {_report_id(_link(1))}
