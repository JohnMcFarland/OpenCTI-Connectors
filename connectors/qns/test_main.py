"""Unit tests for the QNS connector."""

from unittest.mock import MagicMock, patch

import pytest

from main import (
    QnsConnector,
    _report_id,
    _slug_from_url,
    _strip_html,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def connector():
    with patch.object(QnsConnector, "__init__", lambda self: None):
        c = QnsConnector()
    c.base_url = "https://qns.com"
    c.api_url = f"{c.base_url}/wp-json/wp/v2/posts"
    c.per_page = 100
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
    c.author_name = "QNS"
    c.marking_id = "test-marking-id"
    c.helper = MagicMock()
    c.poll_interval = 0
    c._wp_authors = {1: "Shane O'Brien", 2: "The Old Timer"}
    c._wp_categories = {31: "News", 116: "Neighborhoods", 247: "Jamaica"}
    return c


def _make_post(post_id=1, date="2026-10-03T09:33:51", title="Test Article",
               excerpt="A test article.", link="https://qns.com/2026/10/test-article/",
               author=1, categories=None):
    return {
        "id": post_id,
        "date_gmt": date,
        "modified_gmt": date,
        "link": link,
        "title": {"rendered": title},
        "excerpt": {"rendered": f"<p>{excerpt}</p>"},
        "author": author,
        "categories": categories or [31, 247],
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

    def test_unicode_entities(self):
        assert _strip_html("don&#8217;t") == "don’t"


class TestReportId:
    def test_deterministic(self):
        url = "https://qns.com/2026/10/test/"
        assert _report_id(url) == _report_id(url)

    def test_starts_with_report_prefix(self):
        assert _report_id("https://qns.com/a/").startswith("report--")

    def test_different_urls_differ(self):
        assert _report_id("https://qns.com/1/") != _report_id("https://qns.com/2/")

    def test_trailing_slash_matters(self):
        assert _report_id("https://qns.com/x") != _report_id("https://qns.com/x/")


class TestSlugFromUrl:
    def test_trailing_slash(self):
        assert _slug_from_url(
            "https://qns.com/2026/10/my-article/"
        ) == "my-article"

    def test_no_trailing_slash(self):
        assert _slug_from_url(
            "https://qns.com/2026/10/my-article"
        ) == "my-article"

    def test_root_url(self):
        assert _slug_from_url("https://qns.com/") == "article"

    def test_empty_string(self):
        assert _slug_from_url("") == "article"


# --------------------------------------------------------------------------- #
# Static method tests
# --------------------------------------------------------------------------- #

class TestPublishedIso:
    def test_normal_date_gmt(self):
        post = {"date_gmt": "2026-10-03T09:33:51", "modified_gmt": "2026-10-03T10:00:00"}
        assert QnsConnector._published_iso(post) == "2026-10-03T09:33:51+00:00"

    def test_falls_back_to_modified_gmt(self):
        post = {"date_gmt": "", "modified_gmt": "2025-12-01T09:00:00"}
        assert QnsConnector._published_iso(post) == "2025-12-01T09:00:00+00:00"

    def test_both_missing(self):
        assert QnsConnector._published_iso({}) is None
        assert QnsConnector._published_iso({"date_gmt": None, "modified_gmt": None}) is None

    def test_year_below_2000_rejected(self):
        post = {"date_gmt": "1999-01-01T00:00:00", "modified_gmt": "1998-06-15T00:00:00"}
        assert QnsConnector._published_iso(post) is None

    def test_malformed_date(self):
        post = {"date_gmt": "not-a-date", "modified_gmt": "also-bad"}
        assert QnsConnector._published_iso(post) is None

    def test_prefers_date_over_modified(self):
        post = {"date_gmt": "2020-01-01T00:00:00", "modified_gmt": "2026-06-01T00:00:00"}
        assert QnsConnector._published_iso(post) == "2020-01-01T00:00:00+00:00"


class TestPostTitle:
    def test_normal(self):
        post = {"title": {"rendered": "Hello World"}}
        assert QnsConnector._post_title(post) == "Hello World"

    def test_html_entities(self):
        post = {"title": {"rendered": "Arts &amp; Entertainment"}}
        assert QnsConnector._post_title(post) == "Arts & Entertainment"

    def test_missing_title(self):
        assert QnsConnector._post_title({}) == ""
        assert QnsConnector._post_title({"title": None}) == ""

    def test_html_tags_stripped(self):
        post = {"title": {"rendered": "<em>Bold</em> Move"}}
        assert QnsConnector._post_title(post) == "Bold Move"


# --------------------------------------------------------------------------- #
# Instance method tests
# --------------------------------------------------------------------------- #

class TestScopeSig:
    def test_returns_all(self, connector):
        assert connector._scope_sig() == "all"


class TestSaveCursor:
    def test_persists_state(self, connector):
        connector._save_cursor(3, 7)
        connector.helper.set_state.assert_called_once_with(
            {"page": 3, "index": 7, "window_after": None, "scope_sig": "all"}
        )

    def test_with_window_after(self, connector):
        connector._save_cursor(1, 0, "2026-10-01T00:00:00")
        connector.helper.set_state.assert_called_once_with({
            "page": 1, "index": 0,
            "window_after": "2026-10-01T00:00:00", "scope_sig": "all",
        })


class TestAuthorByline:
    def test_known_author(self, connector):
        post = {"author": 1}
        assert connector._author_byline(post) == "Shane O'Brien"

    def test_unknown_author(self, connector):
        post = {"author": 999}
        assert connector._author_byline(post) == ""

    def test_no_author_field(self, connector):
        assert connector._author_byline({}) == ""


class TestCategoryNames:
    def test_known_categories(self, connector):
        post = {"categories": [31, 247]}
        assert connector._category_names(post) == ["News", "Jamaica"]

    def test_unknown_category_shows_id(self, connector):
        post = {"categories": [31, 99999]}
        assert connector._category_names(post) == ["News", "99999"]

    def test_empty_categories(self, connector):
        assert connector._category_names({"categories": []}) == []
        assert connector._category_names({}) == []


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

    def test_passes_window_after(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        connector.session.get.return_value = mock_resp

        connector._fetch_page(1, window_after="2026-01-01T00:00:00")
        call_kwargs = connector.session.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert params["after"] == "2026-01-01T00:00:00"

    def test_no_window_after_omits_param(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        connector.session.get.return_value = mock_resp

        connector._fetch_page(1)
        call_kwargs = connector.session.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert "after" not in params


class TestRenderConfig:
    def test_builds_payload(self, connector):
        cfg = connector._render_config("https://qns.com/2026/10/test/")
        assert cfg["url"] == "https://qns.com/2026/10/test/"
        assert cfg["content_selector"] == "article"
        assert cfg["timeout_sec"] == 120
        assert isinstance(cfg["hide_selectors"], list)
        assert ".addthis_inline_share_toolbox" in cfg["hide_selectors"]


class TestRenderWithRetry:
    def test_success_first_try(self, connector):
        connector._render_via_service = MagicMock(
            return_value=(b"pdf", b"html", "Title")
        )
        pdf, html, title = connector._render_with_retry("https://qns.com/test/")
        assert pdf == b"pdf"
        assert html == b"html"
        assert connector._render_via_service.call_count == 1

    def test_retries_on_failure(self, connector):
        connector._render_via_service = MagicMock(
            side_effect=[RuntimeError("fail"), (b"pdf", b"html", "Title")]
        )
        pdf, html, title = connector._render_with_retry("https://qns.com/test/")
        assert pdf == b"pdf"
        assert connector._render_via_service.call_count == 2

    def test_exhausts_retries(self, connector):
        connector._render_via_service = MagicMock(
            side_effect=RuntimeError("fail")
        )
        pdf, html, title = connector._render_with_retry("https://qns.com/test/")
        assert pdf is None
        assert html is None
        assert title is None
        assert connector._render_via_service.call_count == 3


class TestCreateReport:
    def test_creates_all_graph_objects(self, connector):
        post = _make_post(title="Queens Murder", excerpt="A man was stabbed.")
        connector.helper.api.external_reference.create.return_value = {"id": "ref-1"}
        connector.helper.api.report.create.return_value = {"id": "report-1"}

        connector._create_report(
            post, "2026-10-03T09:33:51+00:00", b"pdf-bytes", b"html-bytes"
        )

        connector.helper.api.external_reference.create.assert_called_once()
        ext_ref_call = connector.helper.api.external_reference.create.call_args
        assert ext_ref_call.kwargs["source_name"] == "QNS"
        assert ext_ref_call.kwargs["url"] == post["link"]

        connector.helper.api.report.create.assert_called_once()
        report_call = connector.helper.api.report.create.call_args
        assert report_call.kwargs["name"] == "Queens Murder"
        assert "A man was stabbed." in report_call.kwargs["description"]
        assert "Shane O'Brien" in report_call.kwargs["description"]
        assert "[News, Jamaica]" in report_call.kwargs["description"]
        assert report_call.kwargs["confidence"] == 50
        assert report_call.kwargs["createdBy"] == "test-author-id"
        assert report_call.kwargs["objectMarking"] == ["test-marking-id"]
        assert report_call.kwargs["update"] is True

        assert connector.helper.api.stix_domain_object.add_file.call_count == 2

    def test_pdf_filename(self, connector):
        post = _make_post(link="https://qns.com/2026/10/my-article/")
        connector.helper.api.external_reference.create.return_value = {"id": "ref-1"}
        connector.helper.api.report.create.return_value = {"id": "report-1"}

        connector._create_report(post, "2026-10-03T09:33:51+00:00", b"pdf", b"html")

        file_calls = connector.helper.api.stix_domain_object.add_file.call_args_list
        assert file_calls[0].kwargs["file_name"] == "qns-my-article.pdf"
        assert file_calls[1].kwargs["file_name"] == "qns-raw-my-article.html"

    def test_no_html_skips_second_attachment(self, connector):
        post = _make_post()
        connector.helper.api.external_reference.create.return_value = {"id": "ref-1"}
        connector.helper.api.report.create.return_value = {"id": "report-1"}

        connector._create_report(post, "2026-10-03T09:33:51+00:00", b"pdf", None)

        assert connector.helper.api.stix_domain_object.add_file.call_count == 1

    def test_falls_back_to_url_as_name(self, connector):
        post = _make_post(title="")
        connector.helper.api.external_reference.create.return_value = {"id": "ref-1"}
        connector.helper.api.report.create.return_value = {"id": "report-1"}

        connector._create_report(post, "2026-10-03T09:33:51+00:00", b"pdf", None)

        report_call = connector.helper.api.report.create.call_args
        assert report_call.kwargs["name"] == post["link"]

    def test_no_byline_no_excerpt_uses_categories(self, connector):
        post = _make_post(excerpt="", author=999)
        connector.helper.api.external_reference.create.return_value = {"id": "ref-1"}
        connector.helper.api.report.create.return_value = {"id": "report-1"}

        connector._create_report(post, "2026-10-03T09:33:51+00:00", b"pdf", None)

        report_call = connector.helper.api.report.create.call_args
        assert report_call.kwargs["description"] == "[News, Jamaica]"


class TestPaginateWpEndpoint:
    def test_single_page(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"id": 1, "name": "News"},
            {"id": 2, "name": "Arts &amp; Entertainment"},
        ]
        connector.session.get.return_value = mock_resp

        result = connector._paginate_wp_endpoint("categories")
        assert result == {1: "News", 2: "Arts & Entertainment"}

    def test_html_entities_unescaped(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"id": 1, "name": "Dining &amp; Nightlife"},
        ]
        connector.session.get.return_value = mock_resp

        result = connector._paginate_wp_endpoint("categories")
        assert result[1] == "Dining & Nightlife"

    def test_400_stops_pagination(self, connector):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        connector.session.get.return_value = mock_resp

        result = connector._paginate_wp_endpoint("users")
        assert result == {}

    def test_network_error_stops(self, connector):
        connector.session.get.side_effect = ConnectionError("fail")

        result = connector._paginate_wp_endpoint("users")
        assert result == {}
        connector.helper.log_warning.assert_called()


class TestResolveGraphReferences:
    def test_happy_path(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "author-1"}
        connector.helper.api.marking_definition.read.return_value = {"id": "mark-1"}
        connector._paginate_wp_endpoint = MagicMock(return_value={})
        connector._probe_total = MagicMock(return_value=163121)

        connector._resolve_graph_references()

        assert connector.author_id == "author-1"
        assert connector.marking_id == "mark-1"
        connector.helper.api.vocabulary.create.assert_called_once()

    def test_missing_marking_raises(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "author-1"}
        connector.helper.api.marking_definition.read.return_value = None

        with pytest.raises(RuntimeError, match="Could not resolve marking"):
            connector._resolve_graph_references()

    def test_vocabulary_failure_continues(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "author-1"}
        connector.helper.api.marking_definition.read.return_value = {"id": "mark-1"}
        connector.helper.api.vocabulary.create.side_effect = RuntimeError("conflict")
        connector._paginate_wp_endpoint = MagicMock(return_value={})
        connector._probe_total = MagicMock(return_value=100)

        connector._resolve_graph_references()

        connector.helper.log_warning.assert_called()
        assert connector.marking_id == "mark-1"

    def test_probe_total_none_logs_error(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "author-1"}
        connector.helper.api.marking_definition.read.return_value = {"id": "mark-1"}
        connector._paginate_wp_endpoint = MagicMock(return_value={})
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
        mock_resp.headers = {"X-WP-Total": "163121"}
        mock_resp.raise_for_status = MagicMock()
        connector.session.get.return_value = mock_resp

        assert connector._probe_total() == 163121

    def test_returns_none_on_network_error(self, connector):
        connector.session.get.side_effect = ConnectionError()
        assert connector._probe_total() is None
