"""Unit tests for the Regional Cybersecurity connector."""
import sys
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(__file__))

from scrapers import (
    DiscoveredEntry,
    extract_page_title,
    extract_description,
    find_direct_pdf,
    enrich_from_page,
    make_pdf_filename,
    parse_published,
    truncate_summary,
    SCRAPER_REGISTRY,
    _CERTIN_DATE_RE,
)
from sources import SOURCES


# ── Source registry integrity ────────────────────────────────────────


class TestSourceRegistry:
    def test_keys_unique(self):
        keys = [s.key for s in SOURCES]
        assert len(keys) == len(set(keys)), f"Duplicate keys: {keys}"

    def test_all_sources_have_feed_or_scraper(self):
        for s in SOURCES:
            assert s.feeds or s.scraper, f"{s.key} has neither feeds nor scraper"

    def test_feed_urls_not_empty(self):
        for s in SOURCES:
            for f in s.feeds:
                assert f.url, f"{s.key} has empty feed URL"
                assert f.url.startswith("http"), f"{s.key} feed URL not HTTP: {f.url}"

    def test_scraper_keys_valid(self):
        for s in SOURCES:
            if s.scraper:
                assert s.scraper in SCRAPER_REGISTRY, (
                    f"{s.key} references unknown scraper '{s.scraper}'"
                )

    def test_keys_are_snake_case(self):
        import re

        for s in SOURCES:
            assert re.fullmatch(r"[a-z][a-z0-9_]*", s.key), (
                f"Key '{s.key}' is not snake_case"
            )


# ── extract_page_title ──────────────────────────────────────────────


class TestExtractPageTitle:
    def test_h1_preferred(self):
        soup = BeautifulSoup(
            "<h1>Advisory Title</h1><title>Site | CERT</title>", "lxml"
        )
        assert extract_page_title(soup) == "Advisory Title"

    def test_empty_h1_falls_through_to_title(self):
        soup = BeautifulSoup("<h1>  </h1><title>Fallback Title</title>", "lxml")
        assert extract_page_title(soup) == "Fallback Title"

    def test_title_strips_pipe_suffix(self):
        soup = BeautifulSoup("<title>Advisory Title | CERT-FR</title>", "lxml")
        assert extract_page_title(soup) == "Advisory Title"

    def test_title_strips_dash_suffix(self):
        soup = BeautifulSoup("<title>Alert - National CSIRT</title>", "lxml")
        assert extract_page_title(soup) == "Alert"

    def test_title_strips_emdash_suffix(self):
        soup = BeautifulSoup("<title>Alert — NCSC</title>", "lxml")
        assert extract_page_title(soup) == "Alert"

    def test_title_strips_double_colon_suffix(self):
        soup = BeautifulSoup("<title>Alert :: CERT</title>", "lxml")
        assert extract_page_title(soup) == "Alert"

    def test_no_title_returns_default(self):
        soup = BeautifulSoup("<div>No title here</div>", "lxml")
        assert extract_page_title(soup) == "Untitled Advisory"

    def test_title_no_separator(self):
        soup = BeautifulSoup("<title>Simple Title</title>", "lxml")
        assert extract_page_title(soup) == "Simple Title"


# ── extract_description ─────────────────────────────────────────────


class TestExtractDescription:
    def test_drupal_field(self):
        soup = BeautifulSoup(
            '<div class="field--name-field-description">Description.</div>', "lxml"
        )
        assert extract_description(soup) == "Description."

    def test_meta_description(self):
        soup = BeautifulSoup(
            '<meta name="description" content="Meta desc.">', "lxml"
        )
        assert extract_description(soup) == "Meta desc."

    def test_og_description(self):
        soup = BeautifulSoup(
            '<meta property="og:description" content="OG desc.">', "lxml"
        )
        assert extract_description(soup) == "OG desc."

    def test_paragraph_fallback_skips_short(self):
        soup = BeautifulSoup(
            "<p>Short.</p>"
            "<p>" + "A" * 100 + "</p>",
            "lxml",
        )
        result = extract_description(soup)
        assert result.startswith("A")

    def test_truncated_at_500(self):
        soup = BeautifulSoup(
            f'<meta name="description" content="{"x" * 600}">', "lxml"
        )
        assert len(extract_description(soup)) == 500

    def test_empty_page(self):
        soup = BeautifulSoup("<div>Nothing</div>", "lxml")
        assert extract_description(soup) == ""


# ── find_direct_pdf ─────────────────────────────────────────────────


class TestFindDirectPdf:
    def test_enisa_btn_download_file(self):
        soup = BeautifulSoup(
            '<div class="btn-download-file"><a href="/pub/report.pdf">DL</a></div>',
            "lxml",
        )
        assert find_direct_pdf(soup, "https://enisa.europa.eu/page") == (
            "https://enisa.europa.eu/pub/report.pdf"
        )

    def test_btn_download_class(self):
        soup = BeautifulSoup(
            '<a class="btn-download" href="/doc.pdf">PDF</a>', "lxml"
        )
        assert find_direct_pdf(soup, "https://example.com/p") == (
            "https://example.com/doc.pdf"
        )

    def test_no_pdf_returns_none(self):
        soup = BeautifulSoup('<a href="/page.html">Link</a>', "lxml")
        assert find_direct_pdf(soup, "https://example.com") is None

    def test_relative_url_resolved(self):
        soup = BeautifulSoup(
            '<div class="btn-download-file"><a href="../dl/r.pdf">DL</a></div>',
            "lxml",
        )
        result = find_direct_pdf(soup, "https://example.com/pub/page")
        assert result == "https://example.com/dl/r.pdf"


# ── enrich_from_page ────────────────────────────────────────────────


class TestEnrichFromPage:
    def test_fills_title_and_summary(self):
        entry = DiscoveredEntry(url="https://example.com/adv")
        html = '<h1>Alert</h1><meta name="description" content="Desc.">'
        enrich_from_page(entry, html)
        assert entry.title == "Alert"
        assert entry.summary == "Desc."

    def test_preserves_existing_title(self):
        entry = DiscoveredEntry(url="https://example.com/adv", title="Keep")
        enrich_from_page(entry, "<h1>New</h1>")
        assert entry.title == "Keep"

    def test_enisa_date_parsed(self):
        entry = DiscoveredEntry(url="https://example.com/adv")
        html = '<p class="publish-date"><span class="date">March 15, 2026</span></p>'
        enrich_from_page(entry, html)
        assert entry.published == datetime(2026, 3, 15, tzinfo=timezone.utc)

    def test_returns_pdf_url(self):
        entry = DiscoveredEntry(url="https://example.com/adv")
        html = (
            "<h1>T</h1>"
            '<div class="btn-download-file"><a href="/r.pdf">DL</a></div>'
        )
        assert enrich_from_page(entry, html) == "https://example.com/r.pdf"

    def test_returns_none_when_no_pdf(self):
        entry = DiscoveredEntry(url="https://example.com/adv")
        assert enrich_from_page(entry, "<h1>Title</h1>") is None


# ── CERT-In date regex ──────────────────────────────────────────────


class TestCertinDateRegex:
    def test_standard(self):
        m = _CERTIN_DATE_RE.search("CIAD-2026-0001 (March 15, 2026) Advisory")
        assert m and m.group(1) == "March 15, 2026"

    def test_single_digit_day(self):
        m = _CERTIN_DATE_RE.search("(January 5, 2025)")
        assert m and m.group(1) == "January 5, 2025"

    def test_no_match(self):
        assert _CERTIN_DATE_RE.search("No date here") is None

    def test_parses_to_datetime(self):
        m = _CERTIN_DATE_RE.search("(September 9, 2026)")
        dt = datetime.strptime(m.group(1), "%B %d, %Y")
        assert dt == datetime(2026, 9, 9)


# ── make_pdf_filename ───────────────────────────────────────────────


class TestMakePdfFilename:
    def test_simple_path(self):
        assert make_pdf_filename("https://ex.com/advisories/cve-2026-1234") == "cve-2026-1234.pdf"

    def test_already_pdf(self):
        assert make_pdf_filename("https://ex.com/report.pdf") == "report.pdf"

    def test_trailing_slash(self):
        assert make_pdf_filename("https://ex.com/advisory/") == "advisory.pdf"

    def test_root_path(self):
        assert make_pdf_filename("https://ex.com/") == "advisory.pdf"

    def test_query_params_excluded(self):
        assert make_pdf_filename("https://ex.com/path?q=1&f=2") == "path.pdf"

    def test_unsafe_chars_sanitized(self):
        result = make_pdf_filename("https://ex.com/file:name")
        assert ":" not in result

    def test_long_slug_truncated(self):
        result = make_pdf_filename(f"https://ex.com/{'a' * 300}")
        assert len(result) <= 204


# ── parse_published ─────────────────────────────────────────────────


class TestParsePublished:
    def test_published_parsed(self):
        e = MagicMock()
        e.published_parsed = (2026, 3, 15, 10, 0, 0, 0, 0, 0)
        e.updated_parsed = None
        assert parse_published(e) == datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)

    def test_updated_parsed_fallback(self):
        e = MagicMock()
        e.published_parsed = None
        e.updated_parsed = (2026, 6, 1, 12, 0, 0, 0, 0, 0)
        assert parse_published(e) == datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_no_date_returns_utc_now(self):
        e = MagicMock()
        e.published_parsed = None
        e.updated_parsed = None
        result = parse_published(e)
        assert result.tzinfo == timezone.utc
        assert (datetime.now(tz=timezone.utc) - result).total_seconds() < 5


# ── truncate_summary ────────────────────────────────────────────────


class TestTruncateSummary:
    def test_short_unchanged(self):
        assert truncate_summary("short") == "short"

    def test_long_truncated_with_ellipsis(self):
        result = truncate_summary("x" * 600)
        assert len(result) == 500
        assert result.endswith("...")

    def test_exactly_at_limit(self):
        assert truncate_summary("x" * 500) == "x" * 500

    def test_custom_limit(self):
        result = truncate_summary("x" * 200, limit=100)
        assert len(result) == 100


# ── max_per_source=0 means unlimited ────────────────────────────────


class TestMaxPerSourceZero:
    def test_zero_means_unlimited(self):
        max_per_source = 0
        ingested = 100
        should_stop = max_per_source > 0 and ingested >= max_per_source
        assert not should_stop

    def test_positive_enforces_limit(self):
        max_per_source = 20
        ingested = 20
        should_stop = max_per_source > 0 and ingested >= max_per_source
        assert should_stop

    def test_under_limit_continues(self):
        max_per_source = 20
        ingested = 5
        should_stop = max_per_source > 0 and ingested >= max_per_source
        assert not should_stop
