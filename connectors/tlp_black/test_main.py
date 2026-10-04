"""Unit tests for the TLP Black connector."""

from unittest.mock import MagicMock, patch

import pytest

from main import (
    TlpBlackConnector,
    _parse_rfc2822,
    _report_id,
    _slug_from_url,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def connector():
    with patch.object(TlpBlackConnector, "__init__", lambda self: None):
        c = TlpBlackConnector()
    c.base_url = "https://tlpblack.net"
    c.rss_url = "https://tlpblack.net/rss.xml"
    c.session = MagicMock()
    c.request_delay = 0
    c.render_retries = 3
    c.render_url = "http://pdf-renderer:8080/render"
    c.render_timeout = 120
    c.confidence = 50
    c.report_type = "open-source-reporting"
    c.tlp_name = "TLP:CLEAR"
    c.max_reports = 0
    c.author_id = "test-author-id"
    c.author_name = "TLPBLACK"
    c.marking_id = "test-marking-id"
    c.helper = MagicMock()
    c.poll_interval = 0
    return c


def _make_item(title="Test Post", link="https://tlpblack.net/blog/20261001-test-post",
               description="A test blog post.", pub_date="Tue, 01 Oct 2026 00:00:00 GMT"):
    return {
        "title": title,
        "link": link,
        "description": description,
        "pub_date": pub_date,
    }


RSS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>TLPBLACK Blog</title>
    <link>https://tlpblack.net/blog</link>
    <item>
      <title>First Post</title>
      <link>https://tlpblack.net/blog/20260101-first</link>
      <description>Description one</description>
      <pubDate>Thu, 01 Jan 2026 00:00:00 GMT</pubDate>
    </item>
    <item>
      <title>Second Post</title>
      <link>https://tlpblack.net/blog/20260201-second</link>
      <description>Description two</description>
      <pubDate>Sun, 01 Feb 2026 00:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"""


# --------------------------------------------------------------------------- #
# Pure function tests
# --------------------------------------------------------------------------- #

class TestReportId:
    def test_deterministic(self):
        url = "https://tlpblack.net/blog/20260101-test"
        assert _report_id(url) == _report_id(url)

    def test_starts_with_report(self):
        assert _report_id("https://example.com/post").startswith("report--")

    def test_different_urls_differ(self):
        assert _report_id("https://a.com/1") != _report_id("https://a.com/2")

    def test_format(self):
        rid = _report_id("https://example.com")
        assert rid.startswith("report--")
        parts = rid.split("--")
        assert len(parts) == 2
        assert len(parts[1]) == 36


class TestSlugFromUrl:
    def test_blog_post(self):
        assert _slug_from_url("https://tlpblack.net/blog/20260101-first") == "20260101-first"

    def test_nested_path(self):
        assert _slug_from_url("https://example.com/a/b/c") == "c"

    def test_trailing_slash(self):
        assert _slug_from_url("https://example.com/a/b/") == "b"

    def test_root(self):
        assert _slug_from_url("https://example.com/") == "report"

    def test_bare_domain(self):
        assert _slug_from_url("https://example.com") == "report"


class TestParseRfc2822:
    def test_valid_date(self):
        result = _parse_rfc2822("Thu, 01 Jan 2026 00:00:00 GMT")
        assert result == "2026-01-01T00:00:00+00:00"

    def test_with_offset(self):
        result = _parse_rfc2822("Mon, 17 Mar 2026 12:30:00 +0500")
        assert result == "2026-03-17T07:30:00+00:00"

    def test_none(self):
        assert _parse_rfc2822(None) is None

    def test_empty(self):
        assert _parse_rfc2822("") is None

    def test_garbage(self):
        assert _parse_rfc2822("not a date") is None


# --------------------------------------------------------------------------- #
# _fetch_rss
# --------------------------------------------------------------------------- #

class TestFetchRss:
    def test_parses_items(self, connector):
        resp = MagicMock()
        resp.content = RSS_XML.encode()
        resp.raise_for_status = MagicMock()
        connector.session.get.return_value = resp

        items = connector._fetch_rss()
        assert len(items) == 2
        assert items[0]["title"] == "First Post"
        assert items[0]["link"] == "https://tlpblack.net/blog/20260101-first"
        assert items[0]["description"] == "Description one"
        assert items[0]["pub_date"] == "Thu, 01 Jan 2026 00:00:00 GMT"
        assert items[1]["title"] == "Second Post"

    def test_skips_items_without_link(self, connector):
        xml = """<?xml version="1.0"?>
        <rss version="2.0"><channel>
          <item><title>No Link</title></item>
          <item><title>Has Link</title><link>https://example.com/a</link></item>
        </channel></rss>"""
        resp = MagicMock()
        resp.content = xml.encode()
        resp.raise_for_status = MagicMock()
        connector.session.get.return_value = resp

        items = connector._fetch_rss()
        assert len(items) == 1
        assert items[0]["title"] == "Has Link"

    def test_http_error_returns_none(self, connector):
        connector.session.get.side_effect = Exception("connection refused")
        assert connector._fetch_rss() is None

    def test_malformed_xml_returns_none(self, connector):
        resp = MagicMock()
        resp.content = b"<not>xml<"
        resp.raise_for_status = MagicMock()
        connector.session.get.return_value = resp

        assert connector._fetch_rss() is None

    def test_empty_feed(self, connector):
        xml = '<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>'
        resp = MagicMock()
        resp.content = xml.encode()
        resp.raise_for_status = MagicMock()
        connector.session.get.return_value = resp

        items = connector._fetch_rss()
        assert items == []

    def test_missing_optional_fields(self, connector):
        xml = """<?xml version="1.0"?>
        <rss version="2.0"><channel>
          <item><link>https://example.com/x</link></item>
        </channel></rss>"""
        resp = MagicMock()
        resp.content = xml.encode()
        resp.raise_for_status = MagicMock()
        connector.session.get.return_value = resp

        items = connector._fetch_rss()
        assert len(items) == 1
        assert items[0]["title"] == ""
        assert items[0]["description"] == ""
        assert items[0]["pub_date"] == ""


# --------------------------------------------------------------------------- #
# _render_config
# --------------------------------------------------------------------------- #

class TestRenderConfig:
    def test_structure(self, connector):
        cfg = connector._render_config("https://tlpblack.net/blog/test")
        assert cfg["url"] == "https://tlpblack.net/blog/test"
        assert cfg["content_selector"] == "article"
        assert cfg["hide_selectors"] == []
        assert cfg["timeout_sec"] == 120

    def test_uses_render_timeout(self, connector):
        connector.render_timeout = 60
        cfg = connector._render_config("https://example.com")
        assert cfg["timeout_sec"] == 60


# --------------------------------------------------------------------------- #
# _render_with_retry
# --------------------------------------------------------------------------- #

class TestRenderWithRetry:
    def test_success_first_try(self, connector):
        connector._render_via_service = MagicMock(return_value=(b"pdf", b"html", "Title"))
        pdf, html, title = connector._render_with_retry("https://example.com")
        assert pdf == b"pdf"
        assert html == b"html"
        assert title == "Title"
        assert connector._render_via_service.call_count == 1

    def test_retry_on_failure(self, connector):
        connector._render_via_service = MagicMock(
            side_effect=[Exception("fail"), Exception("fail"), (b"pdf", b"html", "T")]
        )
        pdf, html, title = connector._render_with_retry("https://example.com")
        assert pdf == b"pdf"
        assert connector._render_via_service.call_count == 3

    def test_all_retries_exhausted(self, connector):
        connector._render_via_service = MagicMock(side_effect=Exception("fail"))
        pdf, html, title = connector._render_with_retry("https://example.com")
        assert pdf is None
        assert html is None
        assert title is None
        assert connector._render_via_service.call_count == 3


# --------------------------------------------------------------------------- #
# _create_report
# --------------------------------------------------------------------------- #

class TestCreateReport:
    def test_creates_report_with_pdf_and_html(self, connector):
        item = _make_item()
        connector._create_report(item, "2026-10-01T00:00:00+00:00", b"pdf", b"html")

        connector.helper.api.external_reference.create.assert_called_once()
        connector.helper.api.report.create.assert_called_once()
        assert connector.helper.api.stix_domain_object.add_file.call_count == 2

    def test_skips_html_when_none(self, connector):
        item = _make_item()
        connector._create_report(item, "2026-10-01T00:00:00+00:00", b"pdf", None)

        assert connector.helper.api.stix_domain_object.add_file.call_count == 1

    def test_skips_html_when_empty(self, connector):
        item = _make_item()
        connector._create_report(item, "2026-10-01T00:00:00+00:00", b"pdf", b"")

        assert connector.helper.api.stix_domain_object.add_file.call_count == 1

    def test_report_params(self, connector):
        ext_ref = {"id": "ext-ref-123"}
        connector.helper.api.external_reference.create.return_value = ext_ref
        report_obj = {"id": "report-456"}
        connector.helper.api.report.create.return_value = report_obj

        item = _make_item(title="My Title", description="My Desc")
        connector._create_report(item, "2026-10-01T00:00:00+00:00", b"pdf", b"html")

        call_kwargs = connector.helper.api.report.create.call_args
        assert call_kwargs.kwargs["name"] == "My Title"
        assert call_kwargs.kwargs["description"] == "My Desc"
        assert call_kwargs.kwargs["published"] == "2026-10-01T00:00:00+00:00"
        assert call_kwargs.kwargs["report_types"] == ["open-source-reporting"]
        assert call_kwargs.kwargs["confidence"] == 50
        assert call_kwargs.kwargs["createdBy"] == "test-author-id"
        assert call_kwargs.kwargs["objectMarking"] == ["test-marking-id"]
        assert call_kwargs.kwargs["externalReferences"] == ["ext-ref-123"]
        assert call_kwargs.kwargs["update"] is True

    def test_uses_url_as_name_when_title_empty(self, connector):
        connector.helper.api.external_reference.create.return_value = {"id": "x"}
        connector.helper.api.report.create.return_value = {"id": "r"}

        item = _make_item(title="")
        connector._create_report(item, "2026-10-01T00:00:00+00:00", b"pdf", b"html")

        call_kwargs = connector.helper.api.report.create.call_args
        assert call_kwargs.kwargs["name"] == item["link"]

    def test_pdf_filename(self, connector):
        connector.helper.api.external_reference.create.return_value = {"id": "x"}
        connector.helper.api.report.create.return_value = {"id": "r"}

        item = _make_item(link="https://tlpblack.net/blog/20260101-first")
        connector._create_report(item, "2026-10-01T00:00:00+00:00", b"pdf", b"html")

        pdf_call = connector.helper.api.stix_domain_object.add_file.call_args_list[0]
        assert pdf_call.kwargs["file_name"] == "tlpblack-20260101-first.pdf"

    def test_html_filename(self, connector):
        connector.helper.api.external_reference.create.return_value = {"id": "x"}
        connector.helper.api.report.create.return_value = {"id": "r"}

        item = _make_item(link="https://tlpblack.net/blog/20260101-first")
        connector._create_report(item, "2026-10-01T00:00:00+00:00", b"pdf", b"html")

        html_call = connector.helper.api.stix_domain_object.add_file.call_args_list[1]
        assert html_call.kwargs["file_name"] == "tlpblack-raw-20260101-first.html"


# --------------------------------------------------------------------------- #
# _ingest_item
# --------------------------------------------------------------------------- #

class TestIngestItem:
    def test_skips_existing_report(self, connector):
        connector.helper.api.report.read.return_value = {"id": "exists"}
        assert connector._ingest_item(_make_item()) == "skipped"

    def test_creates_new_report(self, connector):
        connector.helper.api.report.read.return_value = None
        connector._render_with_retry = MagicMock(return_value=(b"pdf", b"html", "T"))
        connector._create_report = MagicMock()

        assert connector._ingest_item(_make_item()) == "created"
        connector._create_report.assert_called_once()

    def test_failed_render(self, connector):
        connector.helper.api.report.read.return_value = None
        connector._render_with_retry = MagicMock(return_value=(None, None, None))

        assert connector._ingest_item(_make_item()) == "failed"

    def test_uses_ingestion_time_on_bad_date(self, connector):
        connector.helper.api.report.read.return_value = None
        connector._render_with_retry = MagicMock(return_value=(b"pdf", b"html", "T"))
        connector._create_report = MagicMock()

        item = _make_item(pub_date="garbage")
        connector._ingest_item(item)

        call_args = connector._create_report.call_args
        published = call_args.args[1]
        assert published.endswith("+00:00")
        connector.helper.log_warning.assert_called()


# --------------------------------------------------------------------------- #
# _resolve_graph_references
# --------------------------------------------------------------------------- #

class TestResolveGraphReferences:
    def test_resolves_all(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "author-123"}
        connector.helper.api.marking_definition.read.return_value = {"id": "marking-456"}

        connector._resolve_graph_references()

        assert connector.author_id == "author-123"
        assert connector.marking_id == "marking-456"
        connector.helper.api.vocabulary.create.assert_called_once()

    def test_raises_on_missing_marking(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "a"}
        connector.helper.api.marking_definition.read.return_value = None

        with pytest.raises(RuntimeError, match="Could not resolve marking"):
            connector._resolve_graph_references()

    def test_vocabulary_failure_is_warning(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "a"}
        connector.helper.api.marking_definition.read.return_value = {"id": "m"}
        connector.helper.api.vocabulary.create.side_effect = Exception("conflict")

        connector._resolve_graph_references()
        connector.helper.log_warning.assert_called()


# --------------------------------------------------------------------------- #
# _process
# --------------------------------------------------------------------------- #

class TestProcess:
    def test_full_cycle(self, connector):
        connector.helper.api.work.initiate_work.return_value = "work-1"
        connector._fetch_rss = MagicMock(return_value=[_make_item(), _make_item(
            link="https://tlpblack.net/blog/20260201-second"
        )])
        connector._ingest_item = MagicMock(return_value="created")

        connector._process()

        assert connector._ingest_item.call_count == 2
        connector.helper.api.work.to_processed.assert_called_once()

    def test_rss_failure(self, connector):
        connector.helper.api.work.initiate_work.return_value = "work-1"
        connector._fetch_rss = MagicMock(return_value=None)

        connector._process()

        call_args = connector.helper.api.work.to_processed.call_args
        assert call_args.kwargs.get("in_error") is True or call_args[1].get("in_error") is True

    def test_max_reports_limit(self, connector):
        connector.max_reports = 1
        connector.helper.api.work.initiate_work.return_value = "work-1"
        connector._fetch_rss = MagicMock(return_value=[
            _make_item(), _make_item(link="https://tlpblack.net/blog/second")
        ])
        connector._ingest_item = MagicMock(return_value="created")

        connector._process()

        assert connector._ingest_item.call_count == 1

    def test_counts_outcomes(self, connector):
        connector.helper.api.work.initiate_work.return_value = "work-1"
        connector._fetch_rss = MagicMock(return_value=[
            _make_item(link="https://tlpblack.net/blog/a"),
            _make_item(link="https://tlpblack.net/blog/b"),
            _make_item(link="https://tlpblack.net/blog/c"),
        ])
        connector._ingest_item = MagicMock(side_effect=["created", "skipped", "failed"])

        connector._process()

        msg = connector.helper.api.work.to_processed.call_args[0][1]
        assert "1 created" in msg
        assert "1 already present" in msg
        assert "1 failed" in msg
