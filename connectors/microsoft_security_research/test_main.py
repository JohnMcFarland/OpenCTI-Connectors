"""Unit tests for the Microsoft Security Research connector."""

from unittest.mock import MagicMock, patch

import pytest

from main import (
    MicrosoftSecurityResearchConnector,
    _post_description,
    _post_title,
    _published_iso,
    _report_id,
    _slug_from_url,
    _strip_html,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def connector():
    with patch.object(
        MicrosoftSecurityResearchConnector, "__init__", lambda self: None
    ):
        c = MicrosoftSecurityResearchConnector()
    c.base_url = "https://www.microsoft.com/en-us/security/blog"
    c.api_url = f"{c.base_url}/wp-json/wp/v2/posts"
    c.content_type_id = 3663
    c.per_page = 100
    c.session = MagicMock()
    c.request_delay = 0
    c.render_retries = 3
    c.confidence = 50
    c.report_type = "open-source-reporting"
    c.tlp_name = "TLP:CLEAR"
    c.max_reports = 0
    c.nav_timeout_ms = 60000
    c.author_id = "test-author-id"
    c.author_name = "Microsoft Security Research"
    c.marking_id = "test-marking-id"
    c.helper = MagicMock()
    c.poll_interval = 0
    return c


def _make_post(post_id=1, date="2026-01-15T12:00:00", title="Test Post",
               excerpt="A test.", link="https://www.microsoft.com/en-us/security/blog/2026/01/15/test-post/"):
    return {
        "id": post_id,
        "date_gmt": date,
        "modified_gmt": date,
        "link": link,
        "title": {"rendered": title},
        "excerpt": {"rendered": f"<p>{excerpt}</p>"},
    }


# --------------------------------------------------------------------------- #
# Pure function tests
# --------------------------------------------------------------------------- #

class TestStripHtml:
    def test_none(self):
        assert _strip_html(None) == ""

    def test_empty(self):
        assert _strip_html("") == ""

    def test_plain_text(self):
        assert _strip_html("hello world") == "hello world"

    def test_strips_tags(self):
        assert _strip_html("<p>hello <b>world</b></p>") == "hello world"

    def test_decodes_entities(self):
        assert _strip_html("a &amp; b &lt; c") == "a & b < c"

    def test_strips_whitespace(self):
        assert _strip_html("  <p> spaced </p>  ") == "spaced"

    def test_nested_tags(self):
        assert _strip_html("<div><span>deep</span></div>") == "deep"


class TestReportId:
    def test_deterministic(self):
        url = "https://example.com/article/"
        assert _report_id(url) == _report_id(url)

    def test_starts_with_report_prefix(self):
        assert _report_id("https://example.com/a/").startswith("report--")

    def test_different_urls_differ(self):
        assert _report_id("https://a.com/1/") != _report_id("https://a.com/2/")

    def test_trailing_slash_matters(self):
        assert _report_id("https://a.com/x") != _report_id("https://a.com/x/")


class TestPublishedIso:
    def test_normal_date_gmt(self):
        post = {"date_gmt": "2026-03-15T10:30:00", "modified_gmt": "2026-03-16T08:00:00"}
        assert _published_iso(post) == "2026-03-15T10:30:00+00:00"

    def test_falls_back_to_modified_gmt(self):
        post = {"date_gmt": "", "modified_gmt": "2025-12-01T09:00:00"}
        assert _published_iso(post) == "2025-12-01T09:00:00+00:00"

    def test_both_missing(self):
        assert _published_iso({}) is None
        assert _published_iso({"date_gmt": None, "modified_gmt": None}) is None

    def test_year_below_2000_rejected(self):
        post = {"date_gmt": "1999-01-01T00:00:00", "modified_gmt": "1998-06-15T00:00:00"}
        assert _published_iso(post) is None

    def test_malformed_date(self):
        post = {"date_gmt": "not-a-date", "modified_gmt": "also-bad"}
        assert _published_iso(post) is None

    def test_prefers_date_over_modified(self):
        post = {"date_gmt": "2020-01-01T00:00:00", "modified_gmt": "2026-06-01T00:00:00"}
        assert _published_iso(post) == "2020-01-01T00:00:00+00:00"


class TestSlugFromUrl:
    def test_trailing_slash(self):
        assert _slug_from_url(
            "https://microsoft.com/blog/2026/01/15/my-article/"
        ) == "my-article"

    def test_no_trailing_slash(self):
        assert _slug_from_url(
            "https://microsoft.com/blog/2026/01/15/my-article"
        ) == "my-article"

    def test_root_url(self):
        assert _slug_from_url("https://microsoft.com/") == "report"

    def test_empty_string(self):
        assert _slug_from_url("") == "report"


class TestPostTitle:
    def test_normal(self):
        post = {"title": {"rendered": "Hello World"}}
        assert _post_title(post) == "Hello World"

    def test_html_entities(self):
        post = {"title": {"rendered": "Threat &amp; Response"}}
        assert _post_title(post) == "Threat & Response"

    def test_missing_title(self):
        assert _post_title({}) == ""
        assert _post_title({"title": None}) == ""

    def test_html_tags_stripped(self):
        post = {"title": {"rendered": "<em>Bold</em> Move"}}
        assert _post_title(post) == "Bold Move"


class TestPostDescription:
    def test_normal(self):
        post = {"excerpt": {"rendered": "<p>Short summary.</p>\n"}}
        assert _post_description(post) == "Short summary."

    def test_missing(self):
        assert _post_description({}) == ""


# --------------------------------------------------------------------------- #
# Connector method tests
# --------------------------------------------------------------------------- #

class TestScopeSig:
    def test_returns_content_type_id_string(self, connector):
        assert connector._scope_sig() == "3663"

    def test_changes_with_content_type_id(self, connector):
        connector.content_type_id = 9999
        assert connector._scope_sig() == "9999"


class TestSaveCursor:
    def test_persists_state(self, connector):
        connector._save_cursor(3, 7)
        connector.helper.set_state.assert_called_once_with(
            {"page": 3, "index": 7, "scope_sig": "3663"}
        )


class TestFetchPage:
    def test_success(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"id": 1}, {"id": 2}]
        connector.session.get.return_value = mock_resp

        result = connector._fetch_page(1)
        assert result == [{"id": 1}, {"id": 2}]

    def test_http_400_returns_empty(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        connector.session.get.return_value = mock_resp

        assert connector._fetch_page(99) == []

    def test_http_500_returns_none(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        connector.session.get.return_value = mock_resp

        assert connector._fetch_page(1) is None
        connector.helper.log_error.assert_called()

    def test_network_error_returns_none(self, connector):
        connector.session.get.side_effect = ConnectionError("timeout")

        assert connector._fetch_page(1) is None
        connector.helper.log_error.assert_called()

    def test_non_json_returns_none(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("not json")
        connector.session.get.return_value = mock_resp

        assert connector._fetch_page(1) is None

    def test_non_list_json_returns_none(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"error": "something"}
        connector.session.get.return_value = mock_resp

        assert connector._fetch_page(1) is None

    def test_passes_correct_params(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        connector.session.get.return_value = mock_resp

        connector._fetch_page(5)
        call_kwargs = connector.session.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert params["content-type"] == 3663
        assert params["page"] == 5
        assert params["orderby"] == "id"
        assert params["order"] == "asc"


class TestRenderWithRetry:
    def test_success_first_try(self, connector):
        connector._render_pdf = MagicMock(return_value=b"pdf-bytes")
        result = connector._render_with_retry(MagicMock(), "https://example.com/")
        assert result == b"pdf-bytes"
        assert connector._render_pdf.call_count == 1

    def test_retries_on_failure(self, connector):
        connector._render_pdf = MagicMock(
            side_effect=[RuntimeError("timeout"), b"pdf-bytes"]
        )
        result = connector._render_with_retry(MagicMock(), "https://example.com/")
        assert result == b"pdf-bytes"
        assert connector._render_pdf.call_count == 2

    def test_exhausts_retries(self, connector):
        connector._render_pdf = MagicMock(side_effect=RuntimeError("fail"))
        result = connector._render_with_retry(MagicMock(), "https://example.com/")
        assert result is None
        assert connector._render_pdf.call_count == 3


class TestIngestPost:
    def test_no_url_returns_no_url(self, connector):
        post = {"id": 1, "title": {"rendered": "X"}}
        assert connector._ingest_post(MagicMock(), post) == "no_url"

    def test_already_ingested_returns_skipped(self, connector):
        post = _make_post()
        connector.helper.api.report.read.return_value = {"id": "existing"}
        assert connector._ingest_post(MagicMock(), post) == "skipped"

    def test_render_failure_returns_failed(self, connector):
        post = _make_post()
        connector.helper.api.report.read.return_value = None
        connector._render_with_retry = MagicMock(return_value=None)
        assert connector._ingest_post(MagicMock(), post) == "failed"

    def test_success_returns_created(self, connector):
        post = _make_post()
        connector.helper.api.report.read.return_value = None
        connector._render_with_retry = MagicMock(return_value=b"pdf")
        connector.helper.api.external_reference.create.return_value = {"id": "ref-1"}
        connector.helper.api.report.create.return_value = {"id": "report-1"}

        assert connector._ingest_post(MagicMock(), post) == "created"
        connector.helper.api.report.create.assert_called_once()
        connector.helper.api.stix_domain_object.add_file.assert_called_once()

    def test_missing_date_uses_ingestion_time(self, connector):
        post = _make_post(date="")
        post["modified_gmt"] = ""
        connector.helper.api.report.read.return_value = None
        connector._render_with_retry = MagicMock(return_value=b"pdf")
        connector.helper.api.external_reference.create.return_value = {"id": "ref-1"}
        connector.helper.api.report.create.return_value = {"id": "report-1"}

        assert connector._ingest_post(MagicMock(), post) == "created"
        connector.helper.log_warning.assert_called()
        create_call = connector.helper.api.report.create.call_args
        published = create_call.kwargs.get("published")
        assert published is not None
        assert "+00:00" in published


class TestCreateReport:
    def test_creates_all_graph_objects(self, connector):
        post = _make_post(title="My Title", excerpt="My desc")
        connector.helper.api.external_reference.create.return_value = {"id": "ref-1"}
        connector.helper.api.report.create.return_value = {"id": "report-1"}

        connector._create_report(post, "2026-01-15T12:00:00+00:00", b"pdf")

        connector.helper.api.external_reference.create.assert_called_once()
        ext_ref_call = connector.helper.api.external_reference.create.call_args
        assert ext_ref_call.kwargs["source_name"] == "Microsoft Security Research"
        assert ext_ref_call.kwargs["url"] == post["link"]

        connector.helper.api.report.create.assert_called_once()
        report_call = connector.helper.api.report.create.call_args
        assert report_call.kwargs["name"] == "My Title"
        assert report_call.kwargs["description"] == "My desc"
        assert report_call.kwargs["confidence"] == 50
        assert report_call.kwargs["createdBy"] == "test-author-id"
        assert report_call.kwargs["objectMarking"] == ["test-marking-id"]
        assert report_call.kwargs["update"] is True

        connector.helper.api.stix_domain_object.add_file.assert_called_once()
        file_call = connector.helper.api.stix_domain_object.add_file.call_args
        assert file_call.kwargs["file_name"] == "msft-research-test-post.pdf"
        assert file_call.kwargs["data"] == b"pdf"
        assert file_call.kwargs["mime_type"] == "application/pdf"

    def test_falls_back_to_url_as_name(self, connector):
        post = _make_post(title="")
        connector.helper.api.external_reference.create.return_value = {"id": "ref-1"}
        connector.helper.api.report.create.return_value = {"id": "report-1"}

        connector._create_report(post, "2026-01-15T12:00:00+00:00", b"pdf")

        report_call = connector.helper.api.report.create.call_args
        assert report_call.kwargs["name"] == post["link"]


class TestResolveGraphReferences:
    def test_happy_path(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "author-1"}
        connector.helper.api.marking_definition.read.return_value = {"id": "mark-1"}
        connector._probe_total = MagicMock(return_value=501)

        connector._resolve_graph_references()

        assert connector.author_id == "author-1"
        assert connector.marking_id == "mark-1"
        connector.helper.api.vocabulary.create.assert_called_once()
        connector.helper.log_info.assert_called()

    def test_missing_marking_raises(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "author-1"}
        connector.helper.api.marking_definition.read.return_value = None

        with pytest.raises(RuntimeError, match="Could not resolve marking"):
            connector._resolve_graph_references()

    def test_vocabulary_failure_continues(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "author-1"}
        connector.helper.api.marking_definition.read.return_value = {"id": "mark-1"}
        connector.helper.api.vocabulary.create.side_effect = RuntimeError("conflict")
        connector._probe_total = MagicMock(return_value=100)

        connector._resolve_graph_references()

        connector.helper.log_warning.assert_called()
        assert connector.marking_id == "mark-1"

    def test_probe_total_none_logs_error(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "author-1"}
        connector.helper.api.marking_definition.read.return_value = {"id": "mark-1"}
        connector._probe_total = MagicMock(return_value=None)

        connector._resolve_graph_references()

        error_calls = [
            str(c) for c in connector.helper.log_error.call_args_list
        ]
        assert any("unreachable" in c for c in error_calls)


class TestProbeTotal:
    def test_returns_total_from_header(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"X-WP-Total": "501"}
        mock_resp.raise_for_status = MagicMock()
        connector.session.get.return_value = mock_resp

        assert connector._probe_total() == 501

    def test_returns_none_on_network_error(self, connector):
        connector.session.get.side_effect = ConnectionError()
        assert connector._probe_total() is None

    def test_returns_zero_on_missing_header(self, connector):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.raise_for_status = MagicMock()
        connector.session.get.return_value = mock_resp

        assert connector._probe_total() == 0
