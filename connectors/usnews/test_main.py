"""Unit tests for the US News connector pure helpers."""

import uuid
from xml.etree import ElementTree as ET

from main import (
    _strip_html,
    _parse_author,
    _published_iso,
    _report_id,
    _parse_feed_xml,
    _DC_NS,
)


# --------------------------------------------------------------------------- #
# _strip_html
# --------------------------------------------------------------------------- #

class TestStripHtml:
    def test_removes_tags(self):
        assert _strip_html("<p>Hello <b>world</b></p>") == "Hello world"

    def test_decodes_entities(self):
        assert _strip_html("AT&amp;T &lt;3") == "AT&T <3"

    def test_combined(self):
        assert _strip_html("<a href='x'>foo &amp; bar</a>") == "foo & bar"

    def test_none_returns_empty(self):
        assert _strip_html(None) == ""

    def test_empty_returns_empty(self):
        assert _strip_html("") == ""

    def test_strips_whitespace(self):
        assert _strip_html("  <p> hello </p>  ") == "hello"

    def test_plain_text_passthrough(self):
        assert _strip_html("no tags here") == "no tags here"


# --------------------------------------------------------------------------- #
# _parse_author
# --------------------------------------------------------------------------- #

def _make_item_xml(author_tag="", creator_tag=""):
    """Build a minimal RSS <item> element for testing."""
    xml = f"<item>{author_tag}{creator_tag}</item>"
    return ET.fromstring(xml)


class TestParseAuthor:
    def test_email_paren_format(self):
        item = _make_item_xml(author_tag="<author>ehayes@usnews.com (Emily Hayes)</author>")
        assert _parse_author(item) == "Emily Hayes"

    def test_plain_author(self):
        item = _make_item_xml(author_tag="<author>John Smith</author>")
        assert _parse_author(item) == "John Smith"

    def test_dc_creator(self):
        xml = f'<item xmlns:dc="{_DC_NS}"><dc:creator>Whitney Blair Wyckoff</dc:creator></item>'
        item = ET.fromstring(xml)
        assert _parse_author(item) == "Whitney Blair Wyckoff"

    def test_author_takes_precedence_over_creator(self):
        xml = (
            f'<item xmlns:dc="{_DC_NS}">'
            f"<author>a@b.com (Author Name)</author>"
            f"<dc:creator>Creator Name</dc:creator>"
            f"</item>"
        )
        item = ET.fromstring(xml)
        assert _parse_author(item) == "Author Name"

    def test_no_author_returns_none(self):
        item = _make_item_xml()
        assert _parse_author(item) is None

    def test_empty_author_falls_through(self):
        item = _make_item_xml(author_tag="<author></author>")
        assert _parse_author(item) is None

    def test_strips_whitespace(self):
        item = _make_item_xml(author_tag="<author>x@y.com ( Ray Frager )</author>")
        assert _parse_author(item) == "Ray Frager"


# --------------------------------------------------------------------------- #
# _published_iso
# --------------------------------------------------------------------------- #

class TestPublishedIso:
    def test_standard_rss_date(self):
        result = _published_iso("Mon, 31 Aug 2026 21:12:19 GMT")
        assert result == "2026-08-31T21:12:19+00:00"

    def test_with_offset(self):
        result = _published_iso("Fri, 31 Jul 2026 10:00:18 +0000")
        assert result == "2026-07-31T10:00:18+00:00"

    def test_non_utc_converted(self):
        result = _published_iso("Mon, 01 Sep 2026 10:00:00 -0500")
        assert result == "2026-09-01T15:00:00+00:00"

    def test_none_returns_none(self):
        assert _published_iso(None) is None

    def test_empty_returns_none(self):
        assert _published_iso("") is None

    def test_garbage_returns_none(self):
        assert _published_iso("not a date") is None

    def test_too_old_returns_none(self):
        assert _published_iso("Mon, 01 Jan 1900 00:00:00 GMT") is None

    def test_whitespace_stripped(self):
        result = _published_iso("  Mon, 31 Aug 2026 21:12:19 GMT  ")
        assert result == "2026-08-31T21:12:19+00:00"


# --------------------------------------------------------------------------- #
# _report_id
# --------------------------------------------------------------------------- #

class TestReportId:
    def test_deterministic(self):
        url = "https://money.usnews.com/investing/articles/example"
        assert _report_id(url) == _report_id(url)

    def test_prefix(self):
        result = _report_id("https://example.com/article")
        assert result.startswith("report--")

    def test_valid_uuid5(self):
        result = _report_id("https://example.com/article")
        uuid_part = result.replace("report--", "")
        parsed = uuid.UUID(uuid_part)
        assert parsed.version == 5

    def test_different_urls_differ(self):
        a = _report_id("https://example.com/a")
        b = _report_id("https://example.com/b")
        assert a != b


# --------------------------------------------------------------------------- #
# _parse_feed_xml
# --------------------------------------------------------------------------- #

_SAMPLE_RSS = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss xmlns:dc="{_DC_NS}" version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>Article One</title>
      <link>https://example.com/one</link>
      <description>&lt;p&gt;First article.&lt;/p&gt;</description>
      <pubDate>Mon, 31 Aug 2026 21:12:19 GMT</pubDate>
      <author>a@b.com (Alice)</author>
    </item>
    <item>
      <title>Article Two</title>
      <link>https://example.com/two</link>
      <description>Second article.</description>
      <pubDate>Sun, 30 Aug 2026 10:00:00 GMT</pubDate>
      <dc:creator>Bob</dc:creator>
    </item>
    <item>
      <title>No Link Item</title>
      <description>Skipped.</description>
    </item>
  </channel>
</rss>"""


class TestParseFeedXml:
    def test_parses_items(self):
        items = _parse_feed_xml(_SAMPLE_RSS, "money")
        assert len(items) == 2

    def test_skips_items_without_link(self):
        items = _parse_feed_xml(_SAMPLE_RSS, "money")
        links = [i["link"] for i in items]
        assert "https://example.com/one" in links
        assert "https://example.com/two" in links

    def test_strips_html_from_description(self):
        items = _parse_feed_xml(_SAMPLE_RSS, "money")
        assert items[0]["description"] == "First article."

    def test_parses_author_email_format(self):
        items = _parse_feed_xml(_SAMPLE_RSS, "money")
        assert items[0]["author"] == "Alice"

    def test_parses_dc_creator(self):
        items = _parse_feed_xml(_SAMPLE_RSS, "money")
        assert items[1]["author"] == "Bob"

    def test_parses_pubdate(self):
        items = _parse_feed_xml(_SAMPLE_RSS, "money")
        assert items[0]["published"] == "2026-08-31T21:12:19+00:00"

    def test_feed_key_attached(self):
        items = _parse_feed_xml(_SAMPLE_RSS, "health")
        assert all(i["feed"] == "health" for i in items)

    def test_title_fallback_to_link(self):
        xml = f"""<?xml version="1.0"?>
        <rss version="2.0">
          <channel>
            <item>
              <link>https://example.com/notitle</link>
            </item>
          </channel>
        </rss>"""
        items = _parse_feed_xml(xml, "money")
        assert items[0]["title"] == "https://example.com/notitle"

    def test_malformed_xml_raises(self):
        import pytest
        with pytest.raises(ET.ParseError):
            _parse_feed_xml("<not valid xml", "money")

    def test_empty_feed(self):
        xml = '<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>'
        assert _parse_feed_xml(xml, "money") == []
