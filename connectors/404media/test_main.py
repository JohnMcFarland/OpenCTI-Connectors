"""Unit tests for the 404 Media connector."""

from unittest.mock import MagicMock, patch

import pytest
from bs4 import BeautifulSoup

from main import (
    FourZeroFourMediaConnector,
    _SkipArticle,
    _build_pdf_html,
    _escape_html,
    _strip_html,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def connector():
    with patch.object(FourZeroFourMediaConnector, "__init__", lambda self: None):
        c = FourZeroFourMediaConnector()
    c.base_url = "https://www.404media.co"
    c._host = "www.404media.co"
    c.session = MagicMock()
    c.request_delay = 0
    c.render_retries = 3
    c.early_stop_skips = 24
    c.confidence = 50
    c.report_type = "open-source-reporting"
    c.tlp_name = "TLP:CLEAR"
    c.max_posts = 0
    c.author_id = "test-author-id"
    c.marking_id = "test-marking-id"
    c.helper = MagicMock()
    c.poll_interval = 0
    return c


LISTING_CARD_HTML = """
<html><body>
<section class="section all-posts">
  <div class="post-card">
    <a class="post-card__image" href="/first-article-slug/">
      <img src="/img/1.jpg">
    </a>
    <div class="post-card__content">
      <h4 class="post-card__title">
        <a href="/first-article-slug/">First Article</a>
      </h4>
    </div>
  </div>
  <div class="post-card">
    <a class="post-card__image" href="/second-article/">
      <img src="/img/2.jpg">
    </a>
    <div class="post-card__content">
      <h4 class="post-card__title">
        <a href="/second-article/">Second Article</a>
      </h4>
    </div>
  </div>
</section>
<nav><a href="/about/">About</a><a href="/tag/tech/">Tech</a></nav>
</body></html>
"""

LISTING_RELATIVE_HTML = """
<html><body>
<div class="post-card">
  <a class="post-card__image" href="/relative-slug/">
    <img src="/img/r.jpg">
  </a>
  <h4 class="post-card__title"><a href="/relative-slug/">Relative</a></h4>
</div>
</body></html>
"""

LISTING_NO_CARDS_HTML = """
<html><body>
<a href="https://www.404media.co/generic-article/">Article</a>
<a href="https://www.404media.co/about/">About</a>
<a href="https://www.404media.co/tag/tech/">Tech Tag</a>
<a href="https://www.404media.co/another-article/">Another</a>
<a href="https://other-site.com/external/">External</a>
</body></html>
"""

ARTICLE_OG_HTML = """
<html><head>
<title>Test Article</title>
<meta property="og:title" content="OG Title">
<meta property="og:description" content="OG description text">
<meta property="article:published_time" content="2026-01-15T12:00:00.000Z">
</head><body>
<article class="post">
  <div class="post__content">
    <p>Article body.</p>
    <div class="outpost-pub-container">Subscribe!</div>
    <p>More content.</p>
  </div>
</article>
</body></html>
"""

ARTICLE_JSONLD_HTML = """
<html><head>
<title>Fallback Title</title>
</head><body>
<script type="application/ld+json">
{"@type": "Article", "datePublished": "2025-06-01T08:30:00.000Z"}
</script>
<article class="post">
  <div class="post__content"><p>Body text.</p></div>
</article>
</body></html>
"""

ARTICLE_NO_DATE_HTML = """
<html><head>
<meta property="og:title" content="No Date Article">
</head><body>
<div class="post__content"><p>Body.</p></div>
</body></html>
"""

ARTICLE_NO_CONTENT_HTML = """
<html><head>
<meta property="og:title" content="Missing Content">
<meta property="article:published_time" content="2026-01-01T00:00:00Z">
</head><body>
<div class="unrelated">No article container here.</div>
</body></html>
"""


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


class TestEscapeHtml:
    def test_none(self):
        assert _escape_html(None) == ""

    def test_empty(self):
        assert _escape_html("") == ""

    def test_special_chars(self):
        result = _escape_html('<a href="x">&')
        assert "&lt;" in result
        assert "&amp;" in result
        assert "&quot;" in result


class TestSlugFromUrl:
    def test_trailing_slash(self):
        assert FourZeroFourMediaConnector._slug_from_url(
            "https://www.404media.co/some-article/"
        ) == "some-article"

    def test_no_trailing_slash(self):
        assert FourZeroFourMediaConnector._slug_from_url(
            "https://www.404media.co/some-article"
        ) == "some-article"

    def test_root_url(self):
        assert FourZeroFourMediaConnector._slug_from_url(
            "https://www.404media.co/"
        ) == "article"


class TestBuildPdfHtml:
    def test_structure(self):
        result = _build_pdf_html(
            "Title", "<p>Body</p>", "https://example.com/a/", "2026-01-01"
        )
        assert "<!DOCTYPE html>" in result
        assert "<h1>Title</h1>" in result
        assert "<p>Body</p>" in result
        assert "example.com/a/" in result
        assert "2026-01-01" in result

    def test_escapes_title(self):
        result = _build_pdf_html(
            "A <script> & B", "<p>x</p>", "https://x.com/", "now"
        )
        assert "&lt;script&gt;" in result
        assert "&amp;" in result
        assert "<script>" not in result

    def test_strips_single_quotes_from_url(self):
        result = _build_pdf_html(
            "T", "<p>x</p>", "https://x.com/it's-here/", "now"
        )
        assert "its-here" in result
        assert "it's" not in result


# --------------------------------------------------------------------------- #
# Extraction method tests
# --------------------------------------------------------------------------- #

class TestExtractArticleUrls:
    def test_card_links(self, connector):
        urls = connector._extract_article_urls(LISTING_CARD_HTML)
        assert urls == [
            "https://www.404media.co/first-article-slug/",
            "https://www.404media.co/second-article/",
        ]

    def test_dedup_within_page(self, connector):
        urls = connector._extract_article_urls(LISTING_CARD_HTML)
        assert len(urls) == len(set(urls))

    def test_ignores_nav_links_when_cards_present(self, connector):
        urls = connector._extract_article_urls(LISTING_CARD_HTML)
        slugs = [u.rstrip("/").split("/")[-1] for u in urls]
        assert "about" not in slugs
        assert "tech" not in slugs

    def test_relative_urls(self, connector):
        urls = connector._extract_article_urls(LISTING_RELATIVE_HTML)
        assert "https://www.404media.co/relative-slug/" in urls

    def test_fallback_filters_non_article_slugs(self, connector):
        urls = connector._extract_article_urls(LISTING_NO_CARDS_HTML)
        slugs = [u.rstrip("/").split("/")[-1] for u in urls]
        assert "generic-article" in slugs
        assert "another-article" in slugs
        assert "about" not in slugs

    def test_fallback_excludes_external(self, connector):
        urls = connector._extract_article_urls(LISTING_NO_CARDS_HTML)
        assert not any("other-site.com" in u for u in urls)

    def test_fallback_excludes_multi_segment(self, connector):
        urls = connector._extract_article_urls(LISTING_NO_CARDS_HTML)
        assert not any("tag/tech" in u for u in urls)

    def test_empty_page(self, connector):
        assert connector._extract_article_urls("<html><body></body></html>") == []


class TestExtractMetadata:
    def test_og_tags(self):
        soup = BeautifulSoup(ARTICLE_OG_HTML, "lxml")
        meta = FourZeroFourMediaConnector._extract_metadata(soup)
        assert meta["title"] == "OG Title"
        assert meta["description"] == "OG description text"
        assert meta["published"] == "2026-01-15T12:00:00.000Z"

    def test_jsonld_fallback_for_date(self):
        soup = BeautifulSoup(ARTICLE_JSONLD_HTML, "lxml")
        meta = FourZeroFourMediaConnector._extract_metadata(soup)
        assert meta["published"] == "2025-06-01T08:30:00.000Z"

    def test_title_falls_back_to_title_tag(self):
        soup = BeautifulSoup(ARTICLE_JSONLD_HTML, "lxml")
        meta = FourZeroFourMediaConnector._extract_metadata(soup)
        assert meta["title"] == "Fallback Title"

    def test_no_date(self):
        soup = BeautifulSoup(ARTICLE_NO_DATE_HTML, "lxml")
        meta = FourZeroFourMediaConnector._extract_metadata(soup)
        assert meta["title"] == "No Date Article"
        assert meta["published"] is None

    def test_empty_page(self):
        soup = BeautifulSoup("<html><head></head><body></body></html>", "lxml")
        meta = FourZeroFourMediaConnector._extract_metadata(soup)
        assert meta["title"] == ""
        assert meta["published"] is None
        assert meta["description"] == ""


class TestExtractContent:
    def test_finds_post_content(self):
        soup = BeautifulSoup(ARTICLE_OG_HTML, "lxml")
        content = FourZeroFourMediaConnector._extract_content(soup)
        assert "Article body" in content.get_text()
        assert "More content" in content.get_text()

    def test_strips_cta_banners(self):
        soup = BeautifulSoup(ARTICLE_OG_HTML, "lxml")
        content = FourZeroFourMediaConnector._extract_content(soup)
        assert "Subscribe!" not in content.get_text()

    def test_falls_back_to_article_tag(self):
        html = "<html><body><article><p>Fallback</p></article></body></html>"
        soup = BeautifulSoup(html, "lxml")
        content = FourZeroFourMediaConnector._extract_content(soup)
        assert "Fallback" in content.get_text()

    def test_raises_when_no_container(self):
        soup = BeautifulSoup(ARTICLE_NO_CONTENT_HTML, "lxml")
        with pytest.raises(RuntimeError, match="No article content container"):
            FourZeroFourMediaConnector._extract_content(soup)


# --------------------------------------------------------------------------- #
# Retry logic tests
# --------------------------------------------------------------------------- #

class TestLoadWithRetry:
    def test_success_first_try(self, connector):
        meta = {"title": "T", "published": "2026-01-01"}
        connector._load_article = MagicMock(return_value=(meta, b"pdf"))
        result = connector._load_with_retry("https://example.com/a/")
        assert result == (meta, b"pdf")
        assert connector._load_article.call_count == 1

    def test_retries_on_transient_failure(self, connector):
        meta = {"title": "T", "published": "2026-01-01"}
        connector._load_article = MagicMock(
            side_effect=[RuntimeError("timeout"), (meta, b"pdf")]
        )
        result = connector._load_with_retry("https://example.com/a/")
        assert result == (meta, b"pdf")
        assert connector._load_article.call_count == 2

    def test_exhausts_retries(self, connector):
        connector._load_article = MagicMock(side_effect=RuntimeError("fail"))
        result = connector._load_with_retry("https://example.com/a/")
        assert result == (None, None)
        assert connector._load_article.call_count == 3

    def test_skip_article_not_retried(self, connector):
        connector._load_article = MagicMock(
            side_effect=_SkipArticle("no date")
        )
        with pytest.raises(_SkipArticle):
            connector._load_with_retry("https://example.com/a/")
        assert connector._load_article.call_count == 1
