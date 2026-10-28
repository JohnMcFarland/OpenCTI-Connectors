"""Unit tests for the MERICS connector."""

import base64
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import main
from main import (
    MericsConnector,
    _SkipArticle,
    _article_match,
    _extract_metadata,
    _parse_iso_datetime,
    _report_id,
    _truncate,
)


REPORT_URL = "https://merics.org/en/report/germany-and-china-cleantech"
BRIEF_URL = "https://merics.org/en/merics-briefs/eu-china-trade-talks"
PDF_PATH = "/sites/default/files/2026-10/MER-Report-Cleantech.pdf"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def connector():
    with patch.object(MericsConnector, "__init__", lambda self: None):
        c = MericsConnector()
    c.base_url = "https://merics.org"
    c.host = "merics.org"
    c.sitemap_url = "https://merics.org/en/sitemap.xml"
    c.session = MagicMock()
    c.request_delay = 0
    c.render_retries = 3
    c.render_url = "http://pdf-renderer:8080/render"
    c.render_timeout = 120
    c.confidence = 50
    c.report_type = "open-source-reporting"
    c.tlp_name = "TLP:CLEAR"
    c.max_reports = 0
    c.author_id = "author-id"
    c.author_name = "MERICS"
    c.marking_id = "marking-id"
    c.helper = MagicMock()
    c.helper.api.external_reference.create.return_value = {"id": "ext-ref"}
    c.helper.api.report.create.return_value = {"id": "report-id"}
    c.poll_interval = 0
    c._work_id = None
    return c


@pytest.fixture(autouse=True)
def _no_classifier():
    with patch.object(
        main, "classify_report",
        side_effect=lambda **kw: kw["default_types"],
    ):
        yield


def _page(title="Cleantech report", description="Summary text.",
          date="2026-10-15T13:37:05Z", pdf_href=PDF_PATH,
          related_date="2020-01-01T00:00:00Z"):
    date_block = (
        f'<section class="block-field-blocknodemicrositefield-date-published">'
        f'<time datetime="{date}">Oct 15, 2026</time></section>'
        if date else ""
    )
    pdf_block = (
        f'<section class="block-field-blocknodemicrositefield-download">'
        f'<a class="file-download file-download-pdf" href="{pdf_href}">Download</a>'
        f'</section>'
        if pdf_href else ""
    )
    og_title = f'<meta property="og:title" content="{title}">' if title else ""
    return f"""<html><head>
    {og_title}
    <meta name="description" content="{description}">
    </head><body>
    <article class="content--type-microsite">{date_block}{pdf_block}<p>Body</p></article>
    <div class="related-content-about">
      <time datetime="{related_date}">Jan 1, 2020</time>
      <a class="file-download-pdf" href="/sites/default/files/other.pdf">x</a>
    </div>
    </body></html>"""


def _resp(status=200, text="", content=b""):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.content = content
    if status >= 400:
        r.raise_for_status.side_effect = Exception(f"HTTP {status}")
    return r


def _article(native=b"%PDF-native"):
    return {
        "title": "Cleantech report",
        "description": "Summary text.",
        "published": datetime(2026, 10, 15, 13, 37, 5, tzinfo=timezone.utc),
        "pdf_url": "https://merics.org" + PDF_PATH if native else None,
        "pdf": b"%PDF-rendered",
        "html": b"<html></html>",
        "native_pdf": native,
    }


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

class TestReportId:
    def test_deterministic(self):
        assert _report_id(REPORT_URL) == _report_id(REPORT_URL)

    def test_prefix(self):
        assert _report_id(REPORT_URL).startswith("report--")

    def test_distinct(self):
        assert _report_id(REPORT_URL) != _report_id(BRIEF_URL)


class TestArticleMatch:
    def test_report(self):
        m = _article_match(REPORT_URL, "merics.org")
        assert m.group("type") == "report"
        assert m.group("slug") == "germany-and-china-cleantech"

    def test_brief(self):
        assert _article_match(BRIEF_URL, "merics.org").group("type") == "merics-briefs"

    def test_trailing_slash(self):
        assert _article_match(REPORT_URL + "/", "merics.org") is not None

    @pytest.mark.parametrize("url", [
        "https://merics.org/en/comment/some-comment",
        "https://merics.org/en/podcast/episode",
        "https://merics.org/de/studie/german-report",
        "https://merics.org/en/report",
        "https://merics.org/en/report/slug/extra",
        "https://evil.example/en/report/slug",
    ])
    def test_out_of_scope(self, url):
        assert _article_match(url, "merics.org") is None

    def test_host_follows_config(self):
        url = "https://staging.merics.org/en/report/x"
        assert _article_match(url, "staging.merics.org") is not None
        assert _article_match(url, "merics.org") is None


class TestParseIsoDatetime:
    def test_zulu(self):
        assert _parse_iso_datetime("2026-10-15T13:37:05Z") == datetime(
            2026, 10, 15, 13, 37, 5, tzinfo=timezone.utc
        )

    def test_offset_normalised_to_utc(self):
        assert _parse_iso_datetime("2026-10-15T15:00:00+02:00").hour == 13

    def test_naive_assumed_utc(self):
        assert _parse_iso_datetime("2026-10-15T00:00:00").tzinfo == timezone.utc

    @pytest.mark.parametrize("value", [None, "", "garbage", "1970-01-01T00:00:00Z"])
    def test_rejects(self, value):
        assert _parse_iso_datetime(value) is None


class TestTruncate:
    def test_short_unchanged(self):
        assert _truncate("short") == "short"

    def test_long_cut_on_word(self):
        out = _truncate("word " * 1000, limit=20)
        assert out.endswith("...")
        assert len(out) <= 23


class TestExtractMetadata:
    def test_full_page(self):
        md = _extract_metadata(_page(), REPORT_URL)
        assert md["title"] == "Cleantech report"
        assert md["description"] == "Summary text."
        assert md["published"] == datetime(2026, 10, 15, 13, 37, 5, tzinfo=timezone.utc)
        assert md["pdf_url"] == "https://merics.org" + PDF_PATH

    def test_ignores_related_content_date(self):
        md = _extract_metadata(_page(date=None), REPORT_URL)
        assert md["published"] is None

    def test_ignores_pdf_outside_download_block(self):
        md = _extract_metadata(_page(pdf_href=None), REPORT_URL)
        assert md["pdf_url"] is None

    def test_h1_fallback_for_title(self):
        html = "<html><body><h1> Heading </h1></body></html>"
        assert _extract_metadata(html, REPORT_URL)["title"] == "Heading"

    def test_missing_title(self):
        assert _extract_metadata("<html></html>", REPORT_URL)["title"] is None

    def test_description_truncated(self):
        md = _extract_metadata(_page(description="word " * 1000), REPORT_URL)
        assert len(md["description"]) <= main.MAX_DESCRIPTION_CHARS + 3


# --------------------------------------------------------------------------- #
# Sitemap
# --------------------------------------------------------------------------- #

SITEMAP = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <url><loc>{REPORT_URL}</loc><lastmod>2026-10-15</lastmod>
    <xhtml:link rel="alternate" hreflang="de" href="https://merics.org/de/studie/x"/></url>
  <url><loc>{BRIEF_URL}</loc><lastmod>2026-10-08</lastmod></url>
  <url><loc>https://merics.org/en/comment/ignored</loc></url>
  <url><loc>{REPORT_URL}</loc></url>
</urlset>""".encode()


class TestEnumeratePosts:
    def test_filters_and_dedups(self, connector):
        connector.session.get.return_value = _resp(content=SITEMAP)
        assert connector._enumerate_posts() == [REPORT_URL, BRIEF_URL]

    def test_http_error(self, connector):
        connector.session.get.return_value = _resp(status=503)
        assert connector._enumerate_posts() is None
        connector.helper.log_error.assert_called()

    def test_connection_error(self, connector):
        connector.session.get.side_effect = Exception("boom")
        assert connector._enumerate_posts() is None

    def test_malformed_xml(self, connector):
        connector.session.get.return_value = _resp(content=b"<urlset><url>")
        assert connector._enumerate_posts() is None


# --------------------------------------------------------------------------- #
# PDF acquisition
# --------------------------------------------------------------------------- #

class TestRenderConfig:
    def test_structure(self, connector):
        cfg = connector._render_config(REPORT_URL)
        assert cfg["url"] == REPORT_URL
        assert cfg["content_selector"] == "article.content--type-microsite"
        assert cfg["hide_selectors"] == main.STRIP_SELECTORS
        assert cfg["timeout_sec"] == 120


class TestRenderViaService:
    def test_decodes_pdf_and_html(self, connector):
        resp = MagicMock()
        resp.json.return_value = {
            "pdf": base64.b64encode(b"%PDF-x").decode(),
            "html": base64.b64encode(b"<html/>").decode(),
            "title": "T",
        }
        connector.session.post.return_value = resp
        assert connector._render_via_service(REPORT_URL) == (b"%PDF-x", b"<html/>")
        assert connector.session.post.call_args.kwargs["timeout"] == 150

    def test_http_error_propagates(self, connector):
        resp = MagicMock()
        resp.raise_for_status.side_effect = Exception("503")
        connector.session.post.return_value = resp
        with pytest.raises(Exception, match="503"):
            connector._render_via_service(REPORT_URL)


class TestDownloadNativePdf:
    def test_valid_pdf(self, connector):
        connector.session.get.return_value = _resp(content=b"%PDF-1.7 data")
        assert connector._download_native_pdf("u") == b"%PDF-1.7 data"

    def test_rejects_non_pdf(self, connector):
        connector.session.get.return_value = _resp(content=b"<html>challenge</html>")
        with pytest.raises(RuntimeError, match="not a PDF"):
            connector._download_native_pdf("u")

    def test_server_error_is_transient(self, connector):
        connector.session.get.return_value = _resp(status=500)
        with pytest.raises(Exception):
            connector._download_native_pdf("u")

    @pytest.mark.parametrize("status", [404, 410])
    def test_dead_link_returns_none(self, connector, status):
        connector.session.get.return_value = _resp(status=status)
        assert connector._download_native_pdf("u") is None
        connector.helper.log_warning.assert_called()


# --------------------------------------------------------------------------- #
# Article loading
# --------------------------------------------------------------------------- #

class TestLoadArticle:
    def test_full_load(self, connector):
        connector.session.get.side_effect = [
            _resp(text=_page()),
            _resp(content=b"%PDF-native"),
        ]
        connector._render_via_service = MagicMock(return_value=(b"%PDF-r", b"<h/>"))
        art = connector._load_article(REPORT_URL)
        assert art["pdf"] == b"%PDF-r"
        assert art["html"] == b"<h/>"
        assert art["native_pdf"] == b"%PDF-native"

    def test_native_failure_skips_render(self, connector):
        connector.session.get.side_effect = [
            _resp(text=_page()),
            _resp(content=b"<html>challenge</html>"),
        ]
        connector._render_via_service = MagicMock()
        with pytest.raises(RuntimeError, match="not a PDF"):
            connector._load_article(REPORT_URL)
        connector._render_via_service.assert_not_called()

    def test_no_native_pdf(self, connector):
        connector.session.get.return_value = _resp(text=_page(pdf_href=None))
        connector._render_via_service = MagicMock(return_value=(b"%PDF-r", b"<h/>"))
        art = connector._load_article(BRIEF_URL)
        assert art["native_pdf"] is None
        assert connector.session.get.call_count == 1

    @pytest.mark.parametrize("status", [404, 410])
    def test_gone_is_permanent(self, connector, status):
        connector.session.get.return_value = _resp(status=status)
        with pytest.raises(_SkipArticle):
            connector._load_article(REPORT_URL)

    def test_server_error_is_transient(self, connector):
        connector.session.get.return_value = _resp(status=500)
        with pytest.raises(Exception) as exc_info:
            connector._load_article(REPORT_URL)
        assert not isinstance(exc_info.value, _SkipArticle)

    def test_missing_title_is_permanent_and_skips_render(self, connector):
        connector.session.get.return_value = _resp(text=_page(title=None))
        connector._render_via_service = MagicMock()
        with pytest.raises(_SkipArticle, match="title"):
            connector._load_article(REPORT_URL)
        connector._render_via_service.assert_not_called()

    def test_missing_date_is_permanent_and_skips_render(self, connector):
        connector.session.get.return_value = _resp(text=_page(date=None))
        connector._render_via_service = MagicMock()
        with pytest.raises(_SkipArticle, match="date"):
            connector._load_article(REPORT_URL)
        connector._render_via_service.assert_not_called()


class TestLoadWithRetry:
    def test_success_first_try(self, connector):
        connector._load_article = MagicMock(return_value={"ok": 1})
        assert connector._load_with_retry(REPORT_URL) == {"ok": 1}

    def test_retries_transient(self, connector):
        connector._load_article = MagicMock(
            side_effect=[Exception("a"), Exception("b"), {"ok": 1}]
        )
        assert connector._load_with_retry(REPORT_URL) == {"ok": 1}
        assert connector._load_article.call_count == 3

    def test_exhausted_returns_none(self, connector):
        connector._load_article = MagicMock(side_effect=Exception("x"))
        assert connector._load_with_retry(REPORT_URL) is None
        assert connector._load_article.call_count == 3

    def test_permanent_not_retried(self, connector):
        connector._load_article = MagicMock(side_effect=_SkipArticle("gone"))
        with pytest.raises(_SkipArticle):
            connector._load_with_retry(REPORT_URL)
        assert connector._load_article.call_count == 1


# --------------------------------------------------------------------------- #
# Report creation
# --------------------------------------------------------------------------- #

class TestCreateReport:
    def test_report_params(self, connector):
        connector._create_report(REPORT_URL, _article())
        kw = connector.helper.api.report.create.call_args.kwargs
        assert kw["stix_id"] == _report_id(REPORT_URL)
        assert kw["name"] == "Cleantech report"
        assert kw["description"] == "Summary text."
        assert kw["published"] == "2026-10-15T13:37:05+00:00"
        assert kw["report_types"] == ["open-source-reporting"]
        assert kw["confidence"] == 50
        assert kw["createdBy"] == "author-id"
        assert kw["objectMarking"] == ["marking-id"]
        assert kw["externalReferences"] == ["ext-ref"]
        assert kw["update"] is True

    def test_attaches_rendered_raw_and_native(self, connector):
        connector._create_report(REPORT_URL, _article())
        calls = connector.helper.api.stix_domain_object.add_file.call_args_list
        assert [c.kwargs["file_name"] for c in calls] == [
            "merics-report-rendered-germany-and-china-cleantech.pdf",
            "merics-report-raw-germany-and-china-cleantech.html",
            "MER-Report-Cleantech.pdf",
        ]
        assert [c.kwargs["mime_type"] for c in calls] == [
            "application/pdf", "text/html", "application/pdf",
        ]
        assert all(c.kwargs["id"] == "report-id" for c in calls)

    def test_native_filename_is_url_decoded(self, connector):
        art = _article()
        art["pdf_url"] = (
            "https://merics.org/sites/default/files/2026-10/"
            "OCt.%208%202026_MERICS%20China%20Essentials%20EN.pdf"
        )
        connector._create_report(BRIEF_URL, art)
        calls = connector.helper.api.stix_domain_object.add_file.call_args_list
        assert calls[-1].kwargs["file_name"] == "OCt. 8 2026_MERICS China Essentials EN.pdf"

    def test_brief_without_native(self, connector):
        connector._create_report(BRIEF_URL, _article(native=None))
        calls = connector.helper.api.stix_domain_object.add_file.call_args_list
        assert [c.kwargs["file_name"] for c in calls] == [
            "merics-merics-briefs-rendered-eu-china-trade-talks.pdf",
            "merics-merics-briefs-raw-eu-china-trade-talks.html",
        ]

    def test_skips_empty_html(self, connector):
        art = _article(native=None)
        art["html"] = b""
        connector._create_report(REPORT_URL, art)
        assert connector.helper.api.stix_domain_object.add_file.call_count == 1


# --------------------------------------------------------------------------- #
# Per-article ingestion
# --------------------------------------------------------------------------- #

class TestIngestPost:
    def test_existing_skipped_without_fetch(self, connector):
        connector.helper.api.report.read.return_value = {"id": "x"}
        connector._load_with_retry = MagicMock()
        assert connector._ingest_post(REPORT_URL) == "skipped"
        connector._load_with_retry.assert_not_called()

    def test_created(self, connector):
        connector.helper.api.report.read.return_value = None
        connector._load_with_retry = MagicMock(return_value=_article())
        connector._create_report = MagicMock()
        assert connector._ingest_post(REPORT_URL) == "created"
        connector._create_report.assert_called_once()

    def test_failed_writes_nothing(self, connector):
        connector.helper.api.report.read.return_value = None
        connector._load_with_retry = MagicMock(return_value=None)
        assert connector._ingest_post(REPORT_URL) == "failed"
        connector.helper.api.report.create.assert_not_called()

    def test_invalid_writes_nothing(self, connector):
        connector.helper.api.report.read.return_value = None
        connector._load_with_retry = MagicMock(side_effect=_SkipArticle("no date"))
        assert connector._ingest_post(REPORT_URL) == "invalid"
        connector.helper.api.report.create.assert_not_called()


# --------------------------------------------------------------------------- #
# Graph references
# --------------------------------------------------------------------------- #

class TestResolveGraphReferences:
    def test_resolves_all(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "a-1"}
        connector.helper.api.marking_definition.read.return_value = {"id": "m-1"}
        connector._resolve_graph_references()
        assert connector.author_id == "a-1"
        assert connector.marking_id == "m-1"
        assert connector.helper.api.identity.create.call_args.kwargs["type"] == "Organization"

    def test_missing_marking_raises(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "a"}
        connector.helper.api.marking_definition.read.return_value = None
        with pytest.raises(RuntimeError, match="Could not resolve marking"):
            connector._resolve_graph_references()

    def test_vocabulary_failure_is_warning(self, connector):
        connector.helper.api.identity.create.return_value = {"id": "a"}
        connector.helper.api.marking_definition.read.return_value = {"id": "m"}
        connector.helper.api.vocabulary.create.side_effect = Exception("dup")
        connector._resolve_graph_references()
        connector.helper.log_warning.assert_called()


# --------------------------------------------------------------------------- #
# Run loop
# --------------------------------------------------------------------------- #

class TestProcess:
    def test_counts_outcomes(self, connector):
        connector._enumerate_posts = MagicMock(return_value=["a", "b", "c", "d"])
        connector._ingest_post = MagicMock(
            side_effect=["created", "skipped", "invalid", "failed"]
        )
        connector._process()
        msg = connector.helper.api.work.to_processed.call_args.args[1]
        assert "1 created" in msg
        assert "1 already present" in msg
        assert "1 invalid" in msg
        assert "1 failed" in msg
        assert "out of 4" in msg

    def test_sitemap_failure_marks_error(self, connector):
        connector._enumerate_posts = MagicMock(return_value=None)
        connector._ingest_post = MagicMock()
        connector._process()
        assert connector.helper.api.work.to_processed.call_args.kwargs["in_error"] is True
        connector._ingest_post.assert_not_called()

    def test_max_reports_counts_only_created(self, connector):
        connector.max_reports = 1
        connector._enumerate_posts = MagicMock(return_value=["a", "b", "c"])
        connector._ingest_post = MagicMock(side_effect=["skipped", "created", "created"])
        connector._process()
        assert connector._ingest_post.call_count == 2
