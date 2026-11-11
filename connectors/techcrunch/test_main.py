"""Unit tests for the TechCrunch connector."""

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
    TechCrunchConnector,
    _canonical_link,
    _html_to_text,
    _parse_feed,
    _parse_rfc2822,
    _report_id,
    _slug_from_url,
)

HOST = "techcrunch.com"
FIXTURE = Path(__file__).parent / "tests" / "feed_sample.xml"


def _link(n):
    return f"https://{HOST}/2026/11/10/story-{n}/"


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
    with patch.object(TechCrunchConnector, "__init__", lambda self: None):
        c = TechCrunchConnector()
    c.render_mock = render_mock
    c.feed_url = "https://techcrunch.com/feed/"
    c.session = MagicMock()
    c.session.get.return_value = MagicMock(content=b"", text="", status_code=200)
    c.request_delay = 0
    c.render_retries = 2
    c.render_timeout = 120
    c.confidence = 50
    c.report_type = "open-source-reporting"
    c.tlp_name = "TLP:CLEAR"
    c.max_reports = 0
    c.author_id = "author-id"
    c.author_name = "TechCrunch"
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


@pytest.fixture(autouse=True)
def no_sleep_or_classifier(monkeypatch):
    # Standalone by default; tests that need the Collector set it themselves.
    monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
    with patch.object(main.time, "sleep"), \
         patch.object(main, "classify_report", side_effect=lambda **kw: kw["default_types"]):
        yield


def _serve(c, xml_bytes, render=None):
    c.session.get.return_value = MagicMock(content=xml_bytes, text="", status_code=200)
    c.render_mock.side_effect = render


def _down(*a, **k):
    raise RendererUnavailable("HTTP 503: renderer busy")


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

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
        assert _slug_from_url("https://techcrunch.com/2026/11/10/nvidias-crisis-has-corporate-governance/") == "nvidias-crisis-has-corporate-governance"
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
            assert _parse_rfc2822(item["pub_date"]) is not None
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
        assert CONTENT_SELECTOR == ".seamless-scroll-container"
        assert kw["strip"] == HIDE_SELECTORS
        assert kw["timeout"] == 120
        assert kw["byline"] == {"author": "Jane Doe", "publisher": "TechCrunch",
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


class TestIngestItem:
    def test_single_create_mutation_with_inline_pdf(self, connector):
        assert connector._ingest_item(_item()) == "created"

        kw = connector.helper.api.report.create.call_args.kwargs
        assert kw["stix_id"] == _report_id(_link(1))
        assert kw["published"] == "2026-11-09T22:09:33+00:00"
        assert kw["createdBy"] == "author-id"
        assert kw["objectMarking"] == ["marking-id"]
        ref_kw = connector.helper.api.external_reference.create.call_args.kwargs
        assert ref_kw["url"] == _link(1) and ref_kw["source_name"] == "TechCrunch"
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
        assert pdf.name.startswith("techcrunch-rendered-") and pdf.name.endswith(".pdf")
        assert pdf.mime == "application/pdf" and pdf.data == PDF
        assert kw["filesMarkings"] == [["marking-id"]]
        connector.helper.api.stix_domain_object.add_file.assert_not_called()

    def test_undated_item_is_skipped_never_stamped_now(self, connector):
        assert connector._ingest_item(_item(pub="garbage")) == "skipped-permanent"
        connector.render_mock.assert_not_called()
        connector.helper.api.report.create.assert_not_called()
        assert _link(1) in connector.permanent_skips

    def test_renderer_down_creates_nothing(self, connector):
        connector.render_mock.side_effect = _down
        assert connector._ingest_item(_item()) == "failed"
        connector.helper.api.report.create.assert_not_called()
        connector.helper.api.external_reference.create.assert_not_called()
        assert _link(1) not in connector.permanent_skips

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
        assert kw["type"] == "Organization" and kw["name"] == "TechCrunch"

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
            + '<div class="seamless-scroll-container extra-class"><h1>Title</h1><p>Article body text</p><script>tracker()</script></div>'
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

    def test_article_text_never_stored_on_report(self, connector):
        item = dict(_item(), full_text="SECRET-LONG-BODY " * 50)
        self._content_sent(connector, item, None)
        kw = connector.helper.api.report.create.call_args.kwargs
        assert "SECRET-LONG-BODY" not in kw["description"] and "content" not in kw

    def test_article_text_skips_hidden_chrome(self):
        hidden = [s for s in main.HIDE_SELECTORS if not any(ch in s for ch in "~[ >")]
        tag, ident, classes = main._selector_parts(hidden[0])
        attrs = (f' id="{ident}"' if ident else "") + (
            f' class="{" ".join(sorted(classes))}"' if classes else "")
        chrome = f"<{tag or 'div'}{attrs}><p>Most Popular junk</p></{tag or 'div'}>"
        page = ('<div class="seamless-scroll-container extra-class">' + "<p>Real story</p>" + chrome + "<p>More story</p>"
                + '</div>').encode()
        text = main._article_text(page)
        assert "Real story" in text and "More story" in text
        assert "Most Popular junk" not in text

    def test_article_text_is_full_not_truncated(self):
        page = ('<div class="seamless-scroll-container extra-class">' + "word " * 20000 + "THE-END" + '</div>').encode()
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
            if calls["n"] <= connector.render_retries:
                raise RendererUnavailable("render down")
            return PDF

        _serve(connector, _feed([_link(1), _link(2)]), render=flaky)
        connector._process()
        assert connector.helper.api.report.create.call_count == 1
        assert connector.helper.api.work.to_processed.call_args.kwargs["in_error"] is True
        assert connector.transient_failures == {_link(1): 1}

    def test_transient_failure_gives_up_after_cap(self, connector):
        _serve(connector, _feed([_link(1)]), render=_down)
        for _ in range(MAX_TRANSIENT_ATTEMPTS):
            connector._process()
        assert _link(1) in connector.permanent_skips
        renders = connector.render_mock.call_count
        connector._process()
        assert connector.render_mock.call_count == renders  # no more renders

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
