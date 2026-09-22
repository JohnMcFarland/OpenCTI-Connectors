"""Unit tests for the Hungarian Conservative connector."""

import sys
from unittest.mock import MagicMock, patch

import pytest

# WeasyPrint requires native GTK/Pango libraries not available in every
# environment.  Inject a stub before importing main so the pure-function tests
# can run without them.
if "weasyprint" not in sys.modules:
    _wp_mock = MagicMock()
    _wp_mock.default_url_fetcher = MagicMock(return_value={"string": b"", "mime_type": "text/plain"})
    sys.modules["weasyprint"] = _wp_mock

from main import (  # noqa: E402
    HungarianConservativeConnector,
    _build_pdf_html,
    _css_string_escape,
    _escape_html,
    _strip_html,
    PDF_VARIANT_LIVE_HTML,
    PDF_VARIANT_REST_API,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def connector():
    with patch.object(HungarianConservativeConnector, "__init__", lambda self: None):
        c = HungarianConservativeConnector()
    c.base_url = "https://www.hungarianconservative.com"
    c.api_url = f"{c.base_url}/wp-json/wp/v2/posts"
    c.session = MagicMock()
    c.request_delay = 0
    c.render_retries = 3
    c.per_page = 100
    c.poll_interval = 0
    c.max_reports = 0
    c.confidence = 50
    c.report_type = "open-source-reporting"
    c.tlp_name = "TLP:CLEAR"
    c.author_name = "Hungarian Conservative"
    c.author_id = "test-author-id"
    c.marking_id = "test-marking-id"
    c.helper = MagicMock()
    c._wp_authors = {1: "John Doe", 2: "Jane Smith"}
    c._wp_categories = {10: "Politics", 20: "Culture & Society", 30: "Opinion"}
    return c


# --------------------------------------------------------------------------- #
# _strip_html
# --------------------------------------------------------------------------- #

class TestStripHtml:
    def test_removes_tags(self):
        assert _strip_html("<p>Hello <b>world</b></p>") == "Hello world"

    def test_unescapes_entities(self):
        assert _strip_html("&amp; &lt;tag&gt;") == "& <tag>"

    def test_empty_string(self):
        assert _strip_html("") == ""

    def test_none(self):
        assert _strip_html(None) == ""

    def test_strips_whitespace(self):
        assert _strip_html("  <p> spaced </p>  ") == "spaced"

    def test_nested_tags(self):
        assert _strip_html("<div><p><span>deep</span></p></div>") == "deep"


# --------------------------------------------------------------------------- #
# _escape_html
# --------------------------------------------------------------------------- #

class TestEscapeHtml:
    def test_escapes_special_chars(self):
        assert "&amp;" in _escape_html("&")
        assert "&lt;" in _escape_html("<")
        assert "&gt;" in _escape_html(">")

    def test_empty(self):
        assert _escape_html("") == ""

    def test_none(self):
        assert _escape_html(None) == ""

    def test_plain_text_unchanged(self):
        assert _escape_html("hello world") == "hello world"


# --------------------------------------------------------------------------- #
# _css_string_escape
# --------------------------------------------------------------------------- #

class TestCssStringEscape:
    def test_escapes_backslash(self):
        assert _css_string_escape("a\\b") == "a\\\\b"

    def test_escapes_single_quote(self):
        assert _css_string_escape("it's") == "it\\'s"

    def test_escapes_newline(self):
        assert _css_string_escape("line\nbreak") == "line\\a break"

    def test_strips_carriage_return(self):
        assert _css_string_escape("line\rbreak") == "linebreak"

    def test_url_unchanged(self):
        url = "https://www.hungarianconservative.com/articles/politics/test/"
        assert _css_string_escape(url) == url

    def test_backslash_before_quote(self):
        assert _css_string_escape("\\'") == "\\\\\\'", "backslash doubled, then quote escaped"


# --------------------------------------------------------------------------- #
# _build_pdf_html
# --------------------------------------------------------------------------- #

class TestBuildPdfHtml:
    def test_contains_variant_meta(self):
        html = _build_pdf_html("Title", "Author", "<p>body</p>",
                               "https://example.com", "2024-01-01 00:00 UTC")
        assert "name='pdf-variant' content='rest-api'" in html

    def test_live_variant(self):
        html = _build_pdf_html("Title", "Author", "<p>body</p>",
                               "https://example.com", "2024-01-01 00:00 UTC",
                               variant=PDF_VARIANT_LIVE_HTML)
        assert "name='pdf-variant' content='live-html'" in html
        assert "[LIVE-HTML]" in html

    def test_contains_source_url(self):
        html = _build_pdf_html("T", "", "<p>b</p>",
                               "https://example.com/article", "now")
        assert "name='source-url' content='https://example.com/article'" in html

    def test_title_escaped(self):
        html = _build_pdf_html("Title <script>", "", "<p>b</p>",
                               "https://example.com", "now")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_byline_block_present(self):
        html = _build_pdf_html("T", "Some Author", "<p>b</p>",
                               "https://example.com", "now")
        assert 'class="byline"' in html
        assert "Some Author" in html

    def test_byline_block_absent_when_empty(self):
        html = _build_pdf_html("T", "", "<p>b</p>",
                               "https://example.com", "now")
        assert 'class="byline"' not in html

    def test_content_included(self):
        html = _build_pdf_html("T", "", "<p>article body text</p>",
                               "https://example.com", "now")
        assert "article body text" in html


# --------------------------------------------------------------------------- #
# _report_id
# --------------------------------------------------------------------------- #

class TestReportId:
    def test_deterministic(self):
        url = "https://www.hungarianconservative.com/articles/politics/test/"
        id1 = HungarianConservativeConnector._report_id(url)
        id2 = HungarianConservativeConnector._report_id(url)
        assert id1 == id2

    def test_starts_with_report_prefix(self):
        rid = HungarianConservativeConnector._report_id("https://example.com")
        assert rid.startswith("report--")

    def test_different_urls_different_ids(self):
        id1 = HungarianConservativeConnector._report_id("https://example.com/a")
        id2 = HungarianConservativeConnector._report_id("https://example.com/b")
        assert id1 != id2


# --------------------------------------------------------------------------- #
# _published_iso
# --------------------------------------------------------------------------- #

class TestPublishedIso:
    def test_date_gmt_preferred(self):
        post = {"date_gmt": "2024-06-15T10:30:00", "modified_gmt": "2024-07-01T12:00:00"}
        result = HungarianConservativeConnector._published_iso(post)
        assert result.startswith("2024-06-15")

    def test_falls_back_to_modified(self):
        post = {"date_gmt": None, "modified_gmt": "2024-07-01T12:00:00"}
        result = HungarianConservativeConnector._published_iso(post)
        assert result.startswith("2024-07-01")

    def test_returns_none_for_empty(self):
        assert HungarianConservativeConnector._published_iso({}) is None

    def test_rejects_pre_2000(self):
        post = {"date_gmt": "1999-01-01T00:00:00"}
        assert HungarianConservativeConnector._published_iso(post) is None

    def test_accepts_2000(self):
        post = {"date_gmt": "2000-01-01T00:00:00"}
        result = HungarianConservativeConnector._published_iso(post)
        assert result is not None
        assert result.startswith("2000-01-01")

    def test_output_format(self):
        post = {"date_gmt": "2024-06-15T10:30:00"}
        result = HungarianConservativeConnector._published_iso(post)
        assert result == "2024-06-15T10:30:00+00:00"

    def test_malformed_date_skipped(self):
        post = {"date_gmt": "not-a-date", "modified_gmt": "2024-07-01T12:00:00"}
        result = HungarianConservativeConnector._published_iso(post)
        assert result.startswith("2024-07-01")


# --------------------------------------------------------------------------- #
# _post_title
# --------------------------------------------------------------------------- #

class TestPostTitle:
    def test_strips_html(self):
        post = {"title": {"rendered": "<b>Bold Title</b>"}}
        assert HungarianConservativeConnector._post_title(post) == "Bold Title"

    def test_missing_title(self):
        assert HungarianConservativeConnector._post_title({}) == ""

    def test_none_title(self):
        assert HungarianConservativeConnector._post_title({"title": None}) == ""


# --------------------------------------------------------------------------- #
# _extract_live_content
# --------------------------------------------------------------------------- #

class TestExtractLiveContent:
    ELEMENTOR_HTML = """
    <html><body>
    <div class="elementor-widget-theme-post-content">
        <div class="elementor-widget-container">
            <p>Article body here.</p>
            <div class="adsense-middle-container">ad</div>
            <div class="hc-donation-box">donate</div>
        </div>
    </div>
    </body></html>
    """

    def test_extracts_content(self):
        content = HungarianConservativeConnector._extract_live_content(self.ELEMENTOR_HTML)
        assert content is not None
        text = content.get_text()
        assert "Article body here." in text

    def test_strips_ads(self):
        content = HungarianConservativeConnector._extract_live_content(self.ELEMENTOR_HTML)
        text = str(content)
        assert "adsense-middle-container" not in text
        assert "hc-donation-box" not in text

    def test_returns_none_when_no_content(self):
        html = "<html><body><div>no article</div></body></html>"
        assert HungarianConservativeConnector._extract_live_content(html) is None

    def test_fallback_selectors(self):
        html = '<html><body><div class="entry-content"><p>Fallback</p></div></body></html>'
        content = HungarianConservativeConnector._extract_live_content(html)
        assert content is not None
        assert "Fallback" in content.get_text()

    def test_article_fallback(self):
        html = "<html><body><article><p>Article tag</p></article></body></html>"
        content = HungarianConservativeConnector._extract_live_content(html)
        assert content is not None
        assert "Article tag" in content.get_text()


# --------------------------------------------------------------------------- #
# _format_byline (instance method)
# --------------------------------------------------------------------------- #

class TestFormatByline:
    def test_author_only(self, connector):
        post = {"author": 1, "categories": []}
        assert connector._format_byline(post) == "John Doe"

    def test_categories_only(self, connector):
        post = {"author": 999, "categories": [10, 20]}
        assert connector._format_byline(post) == "Politics, Culture & Society"

    def test_author_and_categories(self, connector):
        post = {"author": 1, "categories": [10, 30]}
        assert connector._format_byline(post) == "John Doe  |  Politics, Opinion"

    def test_unknown_author_no_categories(self, connector):
        post = {"author": 999, "categories": []}
        assert connector._format_byline(post) == ""

    def test_unknown_category_shows_id(self, connector):
        post = {"author": 999, "categories": [9999]}
        assert connector._format_byline(post) == "9999"


# --------------------------------------------------------------------------- #
# _retry (instance method)
# --------------------------------------------------------------------------- #

class TestRetry:
    def test_returns_on_first_success(self, connector):
        result = connector._retry(lambda: "ok", "test")
        assert result == "ok"

    def test_retries_on_failure(self, connector):
        call_count = {"n": 0}
        def flaky():
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise RuntimeError("fail")
            return "recovered"
        result = connector._retry(flaky, "test")
        assert result == "recovered"
        assert call_count["n"] == 3

    def test_returns_none_after_exhausted_retries(self, connector):
        connector.render_retries = 2
        result = connector._retry(lambda: (_ for _ in ()).throw(RuntimeError("always")), "test")
        assert result is None

    def test_logs_each_failure(self, connector):
        connector.render_retries = 2
        connector._retry(lambda: (_ for _ in ()).throw(RuntimeError("boom")), "test-label")
        assert connector.helper.log_warning.call_count == 2
        first_msg = connector.helper.log_warning.call_args_list[0][0][0]
        assert "test-label" in first_msg
        assert "1/2" in first_msg
