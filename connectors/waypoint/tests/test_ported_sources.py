"""The generated connectors' per-source test suite, ported to the engine.

Every test here takes `slug` and so runs once per sources.yml profile, with
that source's host, link pattern, content markup, feed sample and scope
cases (tests/fixtures, extracted by scripts/extract_profiles.py --fixtures).
The cases and assertions are the generated test_main.py's; only the calls
change (module constants -> the source's profile, connector methods ->
SourceWorker / engine functions).

Not ported here: TestSiteScope.test_configured_switches (the profile vs the
connector's constants is test_equivalence.py) and the run() startup log
(test_main_entry.py; engine-level, not per source).
"""

import dataclasses
import re
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse
from xml.etree import ElementTree

import pytest
import requests

from conftest import PDF, make_feed
from engine import dates, discovery, render, report, scope, text, timing
from engine.render import ContentUnavailable, RendererUnavailable
from engine.settings import MAX_DESCRIPTION_CHARS


def _replace(w, **kw):
    """Change the worker's profile (the generated tests monkeypatched constants)."""
    w.profile = dataclasses.replace(w.profile, **kw)


def _serve(w, xml_bytes, render=None):
    w.session.get.return_value = MagicMock(content=xml_bytes, text="", status_code=200)
    w.render_mock.side_effect = render


def _down(*a, **k):
    raise RendererUnavailable("HTTP 503: renderer busy")


def _site_down(*a, **k):
    raise ContentUnavailable('HTTP 422: {"detail":"HTTP 503 from https://site/"}')


def _item(site, n=1, title="Story", pub="Mon, 09 Nov 2026 17:09:33 -0500"):
    return {"title": title, "link": site.link(n), "description": "Summary.", "pub_date": pub}


def _render(w, item, published):
    return render.render_with_retry(item, published, w.profile, w.settings, w.log)


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


# --------------------------------------------------------------------------- #
# Feed formats
# --------------------------------------------------------------------------- #

class TestFeedFormats:
    def test_atom_xhtml_content(self, site):
        xml = (f"<feed xmlns='http://www.w3.org/2005/Atom'><entry><title>x</title>"
               f"<link href='{site.link(1)}'/><updated>2026-11-09T00:00:00Z</updated>"
               f"<content type='xhtml'><div xmlns='http://www.w3.org/1999/xhtml'>"
               f"<p>Inline <b>xhtml</b> body &amp; more</p></div></content></entry></feed>").encode()
        item = discovery.parse_feed(xml, site.p)[0]
        assert item["full_text"] == "Inline xhtml body & more"
        assert item["description"] == "Inline xhtml body & more"

    def test_atom_entries_parsed(self, site):
        xml = ATOM.format(link=site.link(1), link2=site.link(2)).encode()
        items = discovery.parse_feed(xml, site.p)
        assert [i["link"] for i in items] == [site.link(1), site.link(2)]
        first, second = items
        assert first["title"] == "Atom & story"
        assert first["description"] == "Short summary"
        assert first["full_text"] == "Full atom body"
        assert first["creator"] == "Jane Doe"
        assert dates.parse_date(first["pub_date"]) == "2026-11-09T17:09:33+00:00"
        # updated is the fallback date when there is no published
        assert dates.parse_date(second["pub_date"]) == "2026-11-08T08:00:00+00:00"
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
    def test_parse_date(self, site, raw, expected):
        assert dates.parse_date(raw) == expected

    def test_several_feeds_merged_and_deduplicated(self, site, w):
        w.feed_urls = ["https://a.example/feed", "https://b.example/feed"]
        feeds = {
            "https://a.example/feed": make_feed([site.link(1), site.link(2)]),
            "https://b.example/feed": ATOM.format(link=site.link(2), link2=site.link(3)).encode(),
        }
        w.session.get.side_effect = lambda url, **k: MagicMock(
            content=feeds[url], status_code=200, raise_for_status=lambda: None)
        items = w.discover()
        assert [i["link"] for i in items] == [site.link(1), site.link(2), site.link(3)]
        assert w.fetch_complete is True

    def test_one_failed_feed_keeps_the_others_and_bookkeeping(self, site, w):
        w.feed_urls = ["https://a.example/feed", "https://b.example/feed"]
        w.transient_failures = {site.link(9): 2}
        _replace(w, skip_if=None)   # site prechecks tested separately

        def get(url, **k):
            if url.startswith("https://b."):
                raise requests.ConnectionError("down")
            return MagicMock(content=make_feed([site.link(1)]), status_code=200,
                             raise_for_status=lambda: None)

        w.session.get.side_effect = get
        w.process()
        assert w.fetch_complete is False
        assert w.graph.created() == {report.report_id(site.link(1))}
        # link 9 may live in the failed feed: its retry count is kept.
        assert w.transient_failures == {site.link(9): 2}

    def test_all_feeds_failed_writes_nothing(self, site, w):
        w.feed_urls = ["https://a.example/feed", "https://b.example/feed"]
        w.session.get.side_effect = requests.ConnectionError("down")
        assert w.discover() is None
        w.process()
        w.api.work.initiate_work.assert_not_called()


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

class TestScope:
    def test_utm_parameters_stripped(self, site):
        url = site.link(1) + "?utm_source=rss&utm_medium=rss&id=7#frag"
        assert discovery.canonical_link(url, site.p) == site.link(1) + "?id=7"
        assert discovery.canonical_link(site.link(1) + "?utm_campaign=x", site.p) == site.link(1)

    @pytest.mark.parametrize("query", ["?s=a%20b&x", "?a&b", "?p=1;q=2", "?q=%7Ehome+page"])
    def test_other_query_strings_kept_byte_for_byte(self, site, query):
        assert discovery.canonical_link(site.link(1) + query, site.p) == site.link(1) + query
        assert discovery.canonical_link(
            site.link(1) + query + "&utm_medium=rss", site.p) == site.link(1) + query

    def test_cdata_link_survives_xml_repair(self, site):
        xml = (f"<rss><channel><item><title>Bad & title</title>"
               f"<link><![CDATA[{site.link(1)}?id=5&utm_source=x&utm_medium=rss]]></link>"
               f"<pubDate>Mon, 09 Nov 2026 12:00:00 GMT</pubDate></item>"
               f"</channel></rss>").encode()
        items = discovery.parse_feed(xml, site.p)
        assert items[0]["link"] == site.link(1) + "?id=5"
        assert items[0]["title"] == "Bad & title"

    def test_html_named_entities_repaired(self, site):
        xml = (f"<rss><channel><item><title>A&nbsp;B &rsquo;C&rsquo; &bogus; D</title>"
               f"<link>{site.link(1)}</link></item></channel></rss>").encode()
        assert discovery.parse_feed(xml, site.p)[0]["title"] == "A\u00a0B \u2019C\u2019 &bogus; D"

    def test_bare_ampersand_feed_still_parses(self, site):
        xml = (f"<rss><channel><item><title>A & B</title>"
               f"<link>{site.link(1)}?utm_source=rss&utm_medium=rss</link>"
               f"<pubDate>Mon, 09 Nov 2026 12:00:00 GMT</pubDate></item>"
               f"</channel></rss>").encode()
        items = discovery.parse_feed(xml, site.p)
        assert items[0]["link"] == site.link(1) and items[0]["title"] == "A & B"

    def test_really_broken_xml_still_raises(self, site):
        with pytest.raises(ElementTree.ParseError):
            discovery.parse_feed(b"<rss><channel><item>", site.p)

    def test_categories_parsed(self, site):
        xml = (f"<rss><channel><item><title>a</title><link>{site.link(1)}</link>"
               f"<category>Threat Intel</category><category>Malware &amp; Co</category>"
               f"</item></channel></rss>").encode()
        assert discovery.parse_feed(xml, site.p)[0]["categories"] == ["Threat Intel", "Malware & Co"]

    def test_category_allow(self, site):
        p = dataclasses.replace(site.p, category_allow=frozenset({"Threat Intel"}))
        item = {"link": site.link(1), "title": "t", "categories": ["threat intel"]}
        assert scope.out_of_scope(item, p, 0) is None
        assert scope.out_of_scope(dict(item, categories=["Product"]), p, 0)
        assert scope.out_of_scope(dict(item, categories=[]), p, 0)

    def test_category_deny(self, site):
        p = dataclasses.replace(site.p, category_deny=frozenset({"Threat Source newsletter"}))
        item = {"link": site.link(1), "title": "t", "categories": ["threat source newsletter"]}
        assert scope.out_of_scope(item, p, 0) == "category excluded"
        assert scope.out_of_scope(dict(item, categories=["Threats"]), p, 0) is None
        assert scope.out_of_scope(dict(item, categories=[]), p, 0) is None

    def test_category_keep_overrides_deny_and_title(self, site):
        p = dataclasses.replace(
            site.p, category_keep=frozenset({"Research"}),
            category_deny=frozenset({"Expert Perspective"}),
            category_allow=frozenset({"Threat Intel"}), exclude_title_re=re.compile(r"Vendor"))
        item = {"link": site.link(1), "title": "Vendor RAT analysis",
                "categories": ["Expert Perspective", "research"]}
        assert scope.out_of_scope(item, p, 0) is None
        assert scope.out_of_scope(dict(item, categories=["Expert Perspective"]), p, 0)
        assert scope.out_of_scope(dict(item, categories=[], title="RAT"), p, 0)
        assert scope.out_of_scope(dict(item, categories=["Threat Intel"], title="RAT"), p, 0) is None
        # Kept items still age out.
        old = dict(item, pub_date="Mon, 02 Nov 2026 00:00:00 GMT")
        now = datetime(2026, 11, 11, tzinfo=timezone.utc)
        assert scope.out_of_scope(old, p, 7, now) == "older than max_age_days"

    def test_control_characters_removed(self, site):
        xml = (f"<rss><channel><item><title>A\x0bB</title><link>{site.link(1)}</link>"
               f"</item></channel></rss>").encode()
        assert discovery.parse_feed(xml, site.p)[0]["title"] == "AB"

    def test_url_and_title_exclusions(self, site):
        p = dataclasses.replace(site.p, exclude_url_re=re.compile(r"/events/"),
                                exclude_title_re=re.compile(r"^Webinar"))
        assert scope.out_of_scope({"link": f"https://{site.host}/events/x", "title": "t"}, p, 0)
        assert scope.out_of_scope({"link": site.link(1), "title": "Webinar: x"}, p, 0)
        assert scope.out_of_scope({"link": site.link(1), "title": "Real research"}, p, 0) is None

    def test_max_age(self, site):
        now = datetime(2026, 11, 11, tzinfo=timezone.utc)
        old = {"link": site.link(1), "title": "t", "pub_date": "Mon, 02 Nov 2026 00:00:00 GMT"}
        new = dict(old, pub_date="Tue, 10 Nov 2026 00:00:00 GMT")
        undated = dict(old, pub_date="")
        assert scope.out_of_scope(old, site.p, 7, now) == "older than max_age_days"
        assert scope.out_of_scope(new, site.p, 7, now) is None
        assert scope.out_of_scope(old, site.p, 0, now) is None
        # Undated items stay in scope and are skipped later, with a reason.
        assert scope.out_of_scope(undated, site.p, 7, now) is None

    def test_out_of_scope_items_never_reach_dedup(self, site, w):
        _replace(w, max_age_days=30)
        _serve(w, make_feed([site.link(1), site.link(2)], pub="Mon, 01 Jan 2001 00:00:00 GMT"))
        w.process()
        w.api.external_reference.list.assert_not_called()
        w.render_mock.assert_not_called()
        w.api.work.initiate_work.assert_not_called()


class TestSiteScope:
    """The site's real scope filters, applied to its real feed sample."""

    def test_real_titles(self, site):
        for case in site.cases["scope_cases"]:
            title, cats, keep = case[:3]
            link = case[3] if len(case) > 3 else site.link(1)    # real URL when the rule is URL-based
            item = {"link": link, "title": title, "categories": cats}
            assert (scope.out_of_scope(item, site.real, 0) is None) == keep, title

    def test_real_feed_sample_scoped_without_error(self, site):
        for item in _sample_items(site):
            scope.out_of_scope(item, site.real, 0)


class TestSiteFlags:
    def test_slug_from_id(self, site):
        p = dataclasses.replace(site.p, slug_from_id=True)
        assert report.slug_from_url(f"https://{site.host}/en/96477/", p) == f"{p.file_prefix}-96477"
        assert report.slug_from_url(f"https://{site.host}/article/5357/1", p) == f"{p.file_prefix}-5357"
        # No numeric segment: falls back to the descriptive slug.
        assert report.slug_from_url(f"https://{site.host}/blog/some-post/", p) == "some-post"

    def test_byline_author_switch(self, site, w):
        _replace(w, byline_author=False)
        _render(w, dict(_item(site), creator="login@example.com"), "2026-11-09T00:00:00+00:00")
        assert "author" not in w.render_mock.call_args.kwargs["byline"]

    def test_no_content_transient_switch(self, site, w):
        _replace(w, no_content_is_transient=True, skip_if=None)
        w.render_mock.side_effect = ContentUnavailable("HTTP 422: no body")
        assert w.ingest_item(_item(site)) == "failed"
        w.api.report.create.assert_not_called()
        # Not retried within the poll (a challenge will not clear in seconds).
        assert w.render_mock.call_count == 1


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

class TestPureHelpers:
    def test_report_id_deterministic_and_distinct(self, site):
        assert report.report_id(site.link(1)) == report.report_id(site.link(1))
        assert report.report_id(site.link(1)) != report.report_id(site.link(2))
        assert report.report_id(site.link(1)).startswith("report--")

    @pytest.mark.parametrize("raw,expected", [
        ("Mon, 09 Nov 2026 17:09:33 -0500", "2026-11-09T22:09:33+00:00"),
        ("Tue, 10 Nov 2026 21:13:00 GMT", "2026-11-10T21:13:00+00:00"),
        ("Wed, 11 Nov 2026 13:47:53 +0530", "2026-11-11T08:17:53+00:00"),
        ("Thu, 01 Jan 1970 00:00:00 GMT", None),
        ("", None),
        (None, None),
        ("not a date", None),
    ])
    def test_parse_rfc2822(self, site, raw, expected):
        assert dates.parse_rfc2822(raw) == expected

    def test_html_to_text(self, site):
        assert text.html_to_text("<p>A &amp; B <b>bold</b></p>\n\n more [...]") == "A & B bold more"
        assert text.html_to_text(None) == ""
        long = text.html_to_text("x" * (MAX_DESCRIPTION_CHARS + 50))
        assert len(long) == MAX_DESCRIPTION_CHARS and long.endswith("...")

    @pytest.mark.parametrize("link_fmt,ok", [
        ("https://{host}/a/b/", True),
        ("http://{host}/a/", True),     # upgraded to https
        ("https://evil.example/a/", False),
        ("https://{host}.evil.example/a/", False),
        ("javascript:alert(1)", False),
        (None, False),
    ])
    def test_canonical_link(self, site, link_fmt, ok):
        link = link_fmt.format(host=site.host) if link_fmt else None
        assert (discovery.canonical_link(link, site.p) is not None) is ok

    def test_canonical_link_upgrades_http_and_escapes_spaces(self, site):
        assert discovery.canonical_link(
            f"http://{site.host}/a b/", site.p) == f"https://{site.host}/a%20b/"

    def test_canonical_link_drops_fragment(self, site):
        assert discovery.canonical_link(
            f"https://{site.host}/a/#comments", site.p) == f"https://{site.host}/a/"

    def test_slug(self, site):
        for url, out in site.cases["slug_cases"]:
            assert report.slug_from_url(url, site.real) == out
        assert report.slug_from_url(f"https://{site.host}/", site.real) == "report"

    def test_allowed_hosts_cover_primary(self, site):
        assert site.host in site.real.allowed_hosts


def _sample_items(site):
    """Parse the recon sample with the site's own discovery mode."""
    raw = site.sample()
    p = site.real
    if p.discovery == "feed":
        return discovery.parse_feed(raw, p)
    if p.discovery == "listing":
        return discovery.parse_listing(raw, p.feed_urls[0], p)
    if p.discovery == "json":
        return discovery.parse_json(raw, p)
    kind, items = discovery.parse_sitemap(raw, p)
    assert kind == "urlset"
    return items


class TestLiveFeedSample:
    """Parses a trimmed copy of the real feed captured during recon."""

    def test_parses_real_feed(self, site):
        items = _sample_items(site)
        assert len(items) >= 2
        for item in items:
            host = urlparse(item["link"]).hostname
            assert item["link"].startswith("https://")
            assert host in site.real.allowed_hosts or host in site.real.resolve_redirect_hosts
            assert bool(item["title"]) or not site.cases["sample_has_titles"]
            assert (dates.parse_date(item["pub_date"]) is not None) or not site.cases["sample_has_dates"]
            assert "<" not in item["description"]
            assert len(item["description"]) <= MAX_DESCRIPTION_CHARS

    def test_drops_foreign_duplicate_and_linkless_items(self, site):
        xml = (
            f"<rss><channel>"
            f"<item><title>a</title><link>{site.link(1)}</link></item>"
            f"<item><title>dup</title><link>{site.link(1)}</link></item>"
            f"<item><title>x</title><link>https://evil.example/a</link></item>"
            f"<item><title>nolink</title></item>"
            f"</channel></rss>"
        ).encode()
        assert [i["title"] for i in discovery.parse_feed(xml, site.p)] == ["a"]

    def test_malformed_raises(self, site):
        with pytest.raises(Exception):
            discovery.parse_feed(b"<rss><channel><item>", site.p)


# --------------------------------------------------------------------------- #
# Dates, titles and non-feed discovery
# --------------------------------------------------------------------------- #

class TestDatesTitlesAndDiscovery:
    @pytest.mark.parametrize("raw,iso", [
        ("Tue, 11 Nov 2026 12:00:00 AM CET", "2026-11-10T23:00:00+00:00"),
        ("Friday, October 30, 2026 - 17:15", "2026-10-30T17:15:00+00:00"),
        ("Nov 11, 2026 1:11pm", "2026-11-11T13:11:00+00:00"),
        ("November 11, 2026", "2026-11-11T00:00:00+00:00"),
        ("Posted 3rd March 2026 at noon", "2026-03-03T00:00:00+00:00"),
        ("2026-11-11 09:30 EST", "2026-11-11T14:30:00+00:00"),
        ("Oct 2, 2026 10:00 +02:00", "2026-10-02T08:00:00+00:00"),
        ("Somewhere 31, 2026", None),
        ("published just now", None),
        ("February 30, 2026", None),
        ("", None),
    ])
    def test_loose_dates(self, site, raw, iso):
        assert dates.parse_date(raw) == iso

    def test_relative_dates(self, site):
        now = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
        assert dates.parse_relative_date("8 hours ago", now) == "2026-11-11T04:00:00+00:00"
        assert dates.parse_relative_date("an hour ago", now) == "2026-11-11T11:00:00+00:00"
        assert dates.parse_relative_date("1 day ago", now) == "2026-11-10T12:00:00+00:00"
        assert dates.parse_relative_date("2 weeks ago", now) == "2026-10-28T12:00:00+00:00"
        assert dates.parse_relative_date("Yesterday", now) == "2026-11-10T12:00:00+00:00"
        assert dates.parse_relative_date("Today", now) == "2026-11-11T12:00:00+00:00"
        assert dates.parse_relative_date("ago", now) is None
        assert dates.parse_date("20 minutes ago") is not None

    def test_title_with_child_markup(self, site):
        xml = (f"<rss><channel><item><title>A <a href='x'>linked</a> &amp; title</title>"
               f"<link>{site.link(1)}</link></item></channel></rss>").encode()
        assert discovery.parse_feed(xml, site.p)[0]["title"] == "A linked & title"

    def test_invalid_utf8_feed_parses(self, site):
        xml = (b"<?xml version='1.0' encoding='utf-8'?><rss><channel><item>"
               b"<title>Space \xd0 race</title><link>" + site.link(1).encode()
               + b"</link></item></channel></rss>")
        assert discovery.parse_feed(xml, site.p)[0]["title"].startswith("Space")

    def test_page_date_sources(self, site):
        meta = b"<meta content='2026-11-01T10:00:00Z' property='article:published_time'>"
        ld = (b'<script type="application/ld+json">{"@graph": [{"@type": "NewsArticle",'
              b' "datePublished": "2026-11-02T10:00:00+00:00"}]}</script>')
        tm = b"<p><time datetime='2026-11-03'>3 Nov</time></p>"
        assert text.page_date(meta + ld + tm) == "2026-11-01T10:00:00+00:00"
        assert text.page_date(ld + tm) == "2026-11-02T10:00:00+00:00"
        assert text.page_date(tm) == "2026-11-03T00:00:00+00:00"
        assert text.page_date(b"<p class='byline'>By X | November 4, 2026</p>") is None
        assert text.page_date(
            b"<p class='byline'>By X | <b>November 4, 2026</b></p>",
            ".byline") == "2026-11-04T00:00:00+00:00"
        assert text.page_date(b'<script type="application/ld+json">{bad</script>') is None
        assert text.page_date(b"") is None

    def test_page_title_sources(self, site):
        name = site.real.name
        assert text.page_title(b"<meta property='og:title' content='OG &amp; T'>"
                               b"<h1>H</h1><title>T</title>", name) == "OG & T"
        assert text.page_title(b"<title>T | Site</title><h1> The <i>H</i> </h1>", name) == "The H"
        assert text.page_title(b"<title>Only title</title>", name) == "Only title"
        assert text.page_title(b"", name) == ""
        esc = text.html.escape(name).encode()
        assert text.page_title(b'<meta property="og:title" content="' + esc + b': Real">', name) == "Real"
        assert text.page_title(b"<title>Real | " + esc + b"</title>", name) == "Real"
        assert text.page_title(b"<title>" + esc + b"</title>", name) == name

    def _undated(self, site, w, page, **extra):
        _replace(w, skip_if=None)
        w.session.get.return_value = MagicMock(content=page, status_code=200)
        return w.ingest_item(dict(_item(site), pub_date="", **extra))

    def test_undated_item_uses_page_date(self, site, w):
        page = b"<meta property='article:published_time' content='2026-11-09T08:00:00Z'>"
        assert self._undated(site, w, page) == "created"
        kw = w.api.report.create.call_args.kwargs
        assert kw["published"] == "2026-11-09T08:00:00+00:00"
        assert w.session.get.call_count == 1      # one page fetch, reused

    def test_undated_item_too_old_on_page(self, site, w):
        _replace(w, max_age_days=30)
        page = b"<meta property='article:published_time' content='2015-01-01T00:00:00Z'>"
        assert self._undated(site, w, page) == "skipped-permanent"
        assert "from the article page" in w.permanent_skips[site.link(1)]

    def test_undated_item_page_fetch_failure_is_transient(self, site, w):
        _replace(w, skip_if=None)
        w.session.get.side_effect = requests.ConnectionError("down")
        assert w.ingest_item(dict(_item(site), pub_date="")) == "failed"
        assert site.link(1) not in w.permanent_skips

    def test_untitled_item_uses_page_title_and_rescopes(self, site, w):
        _replace(w, skip_if=None, exclude_title_re=re.compile(r"^Webinar"))
        w.session.get.return_value = MagicMock(
            content=b"<meta property='og:title' content='Webinar: join us'>", status_code=200)
        assert w.ingest_item(dict(_item(site), title="")) == "skipped-permanent"
        _replace(w, exclude_title_re=None)
        w.permanent_skips.clear()
        assert w.ingest_item(dict(_item(site), title="")) == "created"
        assert w.api.report.create.call_args.kwargs["name"] == "Webinar: join us"

    def test_page_probes_capped_per_poll(self, site, w):
        w.settings.max_page_probes = 1
        _replace(w, skip_if=None)
        xml = (f"<rss><channel><item><title>a</title><link>{site.link(1)}</link></item>"
               f"<item><title>b</title><link>{site.link(2)}</link></item></channel></rss>").encode()
        page = b"<meta property='article:published_time' content='2026-11-09T08:00:00Z'>"
        w.session.get.side_effect = lambda url, **k: MagicMock(
            content=xml if url == w.feed_urls[0] else page, status_code=200)
        w.process()
        assert w.api.report.create.call_count == 1
        w.process()
        assert w.api.report.create.call_count == 2

    def test_lastmod_age_filter(self, site):
        now = datetime(2026, 11, 11, tzinfo=timezone.utc)
        item = {"link": site.link(1), "title": "", "pub_date": "", "lastmod": "2026-01-01"}
        assert scope.out_of_scope(item, site.p, 30, now) == "older than max_age_days"
        assert scope.out_of_scope(dict(item, lastmod="2026-11-10"), site.p, 30, now) is None

    def test_sitemap_urlset_filtered_and_newest_first(self, site):
        p = dataclasses.replace(site.p, discovery_config={
            "url_re": re.escape(site.link(0)[:-2]), "max_items": 2})
        sm = ("<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
              f"<url><loc>{site.link(1)}</loc><lastmod>2026-11-01</lastmod></url>"
              f"<url><loc>https://{site.host}/about/</loc><lastmod>2026-11-09</lastmod></url>"
              f"<url><loc>{site.link(2)}</loc><lastmod>2026-11-05</lastmod></url>"
              f"<url><loc>{site.link(3)}</loc><lastmod>2026-10-01</lastmod></url>"
              "</urlset>").encode()
        kind, items = discovery.parse_sitemap(sm, p)
        assert kind == "urlset"
        assert [i["link"] for i in items] == [site.link(2), site.link(1)]
        assert items[0]["lastmod"] == "2026-11-05" and items[0]["title"] == ""

    def test_sitemap_index_reads_newest_children(self, site, w):
        _replace(w, discovery="sitemap",
                 discovery_config={"child_re": r"post-sitemap", "children": 1})
        ns = "xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'"
        index = (f"<sitemapindex {ns}><sitemap><loc>https://{site.host}/post-sitemap1.xml</loc></sitemap>"
                 f"<sitemap><loc>https://{site.host}/page-sitemap.xml</loc></sitemap>"
                 f"<sitemap><loc>https://{site.host}/post-sitemap2.xml</loc></sitemap></sitemapindex>")
        child = f"<urlset {ns}><url><loc>{site.link(7)}</loc></url></urlset>"
        pages = {"idx": index.encode(), f"https://{site.host}/post-sitemap2.xml": child.encode()}
        w.session.get.side_effect = lambda url, **k: MagicMock(
            content=pages.get(url, b"<x/>"), status_code=200)
        items = w.fetch_source("idx")
        assert [i["link"] for i in items] == [site.link(7)]

    def test_listing_links(self, site):
        p = dataclasses.replace(site.p, discovery_config={"link_re": r"/news/[^/]+$"})
        page = (b"<a href='/news/first item'>First <b>one</b></a>"
                b"<a href=\"https://" + site.host.encode() + b"/news/second\">Second</a>"
                b"<a href='/news/first item'>dup</a><a href='/about'>About</a>"
                b"<a href='https://evil.example/news/x'>Evil</a>")
        items = discovery.parse_listing(page, f"https://{site.host}/news/", p)
        assert [i["link"] for i in items] == [f"https://{site.host}/news/first%20item",
                                              f"https://{site.host}/news/second"]
        assert items[0]["title"] == "First one" and items[0]["pub_date"] == ""

    def test_listing_generic_anchor_text(self, site):
        p = dataclasses.replace(site.p, discovery_config={"link_re": r"/news/[^/]+$"})
        page = (b"<a href='/news/a'><img src='x'></a><a href='/news/a'>Read more &raquo;</a>"
                b"<a href='/news/a'>Real headline</a><a href='/news/a'>Later text</a>"
                b"<a href='/news/b'>Learn more</a><a href='/news/c'>Read more about tariffs</a>")
        items = discovery.parse_listing(page, f"https://{site.host}/news/", p)
        assert [i["title"] for i in items] == ["Real headline", "", "Read more about tariffs"]

    def test_json_items(self, site):
        p = dataclasses.replace(site.p, discovery_config={
            "items": "value", "title": "Title", "date": "Published", "description": "Summary",
            "link": f"https://{site.host}/item/{{UrlName}}"})
        raw = ('{"value": [{"Title": "Outbreak &amp; X", "Published": "2026-11-09T10:00:00Z",'
               ' "Summary": "<p>Text</p>", "UrlName": "2026-DON1"},'
               ' {"Title": "no url"}, "junk"]}').encode()
        items = discovery.parse_json(raw, p)
        assert len(items) == 1
        assert items[0]["link"] == f"https://{site.host}/item/2026-DON1"
        assert items[0]["title"] == "Outbreak & X" and items[0]["description"] == "Text"
        assert dates.parse_date(items[0]["pub_date"]) == "2026-11-09T10:00:00+00:00"

    def test_redirect_links_resolved_once(self, site, w):
        _replace(w, resolve_redirect_hosts=frozenset({"go.example"}))
        hops = {"https://go.example/r?id=1": f"https://{site.host}/real/1/",
                "https://go.example/r?id=2": "https://go.example/r?id=1",
                "https://go.example/r?id=3": "https://evil.example/x"}
        w.session.head.side_effect = lambda url, **k: MagicMock(
            headers={"Location": hops[url]} if url in hops else {})
        items = [{"link": "https://go.example/r?id=1"}, {"link": "https://go.example/r?id=2"},
                 {"link": "https://go.example/r?id=3"}, {"link": "https://go.example/r?id=9"},
                 {"link": site.link(5)}]
        out = w.resolve_redirects(items)
        assert [i["link"] for i in out] == [f"https://{site.host}/real/1/", site.link(5)]
        calls = w.session.head.call_count
        w.resolve_redirects(items)
        assert w.session.head.call_count == calls       # cached

    def test_redirect_loop_dropped(self, site, w):
        _replace(w, resolve_redirect_hosts=frozenset({"go.example"}))
        w.session.head.side_effect = lambda url, **k: MagicMock(headers={"Location": url + "x"})
        assert w.resolve_redirects([{"link": "https://go.example/r"}]) == []

    def test_double_escaped_html(self, site):
        assert text.html_to_text("&lt;p&gt;On &lt;b&gt;Tuesday&lt;/b&gt;&lt;/p&gt;") == "On Tuesday"

    def test_tag_only_hide_selector(self, site):
        page = site.wrap("<p>Body</p><figure><p>Caption junk</p></figure>").encode()
        assert text.article_text(page, site.p.content_selectors, ["figure"]) == "Body"

    def test_render_backoff_capped(self, site, w, no_sleep_or_classifier):
        _replace(w, request_delay=420)
        w.settings.render_retries = 3
        w.render_mock.side_effect = [RendererUnavailable("busy"), RendererUnavailable("busy"), PDF]
        assert _render(w, _item(site), "2026-11-09T00:00:00+00:00") == PDF
        assert [c.args[0] for c in no_sleep_or_classifier.call_args_list] == [30, 60]

    def test_redirect_errors_drop_the_link(self, site, w):
        _replace(w, resolve_redirect_hosts=frozenset({"go.example"}))
        w.session.head.side_effect = requests.ConnectionError("down")
        assert w.resolve_redirects([{"link": "https://go.example/r?id=1"}]) == []
        w.log.log_warning.assert_called()


# --------------------------------------------------------------------------- #
# Graph lookups (Elasticsearch footprint)
# --------------------------------------------------------------------------- #

class TestDedupByExternalReferenceUrl:
    def test_two_batched_exact_match_queries(self, site, w):
        items = [{"link": site.link(i)} for i in range(5)]
        w.graph.add_ingested(site.link(2))
        assert w.ingested_links(items) == {site.link(2)}

        ref_kw = w.api.external_reference.list.call_args.kwargs
        assert w.api.external_reference.list.call_count == 1
        assert ref_kw["filters"]["filters"][0] == {
            "key": "url", "values": sorted(i["link"] for i in items)}
        assert ref_kw["customAttributes"] == "id url" and "search" not in ref_kw

        rep_kw = w.api.report.list.call_args.kwargs
        assert w.api.report.list.call_count == 1
        assert rep_kw["filters"]["filters"][0]["key"] == "externalReferences"
        assert "search" not in rep_kw
        w.api.report.read.assert_not_called()

    def test_no_matching_reference_skips_second_query(self, site, w):
        assert w.ingested_links([{"link": site.link(1)}]) == set()
        w.api.report.list.assert_not_called()

    def test_orphan_reference_is_retried(self, site, w):
        w.graph.add_orphan_ref(site.link(1))
        assert w.ingested_links([{"link": site.link(1)}]) == set()

    def test_reference_cited_by_another_connector_counts(self, site, w):
        # e.g. the per-source connector (or Feedly) already ingested this article.
        w.graph.add_ingested(site.link(1), report_id="feedly-report")
        assert w.ingested_links([{"link": site.link(1)}]) == {site.link(1)}

    def test_citing_query_failure_is_conservative(self, site, w):
        w.graph.add_orphan_ref(site.link(1))
        w.api.report.list.side_effect = Exception("bad filter")
        items = [{"link": site.link(1)}, {"link": site.link(2)}]
        assert w.ingested_links(items) == {site.link(1)}

    def test_reference_query_failure_skips_the_poll(self, site, w):
        w.api.external_reference.list.side_effect = Exception("down")
        _serve(w, make_feed([site.link(1)]))
        w.process()
        w.api.work.initiate_work.assert_not_called()
        w.render_mock.assert_not_called()
        w.api.report.create.assert_not_called()

    def test_empty(self, site, w):
        assert w.ingested_links([]) == set()
        w.api.external_reference.list.assert_not_called()


# --------------------------------------------------------------------------- #
# Render
# --------------------------------------------------------------------------- #

class TestRender:
    def test_house_client_called_with_site_selectors_and_byline(self, site, w):
        item = dict(_item(site), creator="Jane Doe")
        assert _render(w, item, "2026-11-09T22:09:33+00:00") == PDF
        args, kw = w.render_mock.call_args
        assert args == (site.link(1), "Story", site.real.name)
        assert kw["selectors"] == site.real.content_selectors
        assert kw["strip"] == list(site.real.hide_selectors)
        assert kw["timeout"] == 120
        assert kw["byline"] == {"author": "Jane Doe", "publisher": site.real.author_name,
                                "published": "2026-11-09"}
        # Site request headers only where the profile has them (BleepingComputer).
        assert kw.get("headers", {}) == site.real.render_headers

    def test_byline_without_creator_has_no_author(self, site, w):
        _render(w, _item(site), "2026-11-09T22:09:33+00:00")
        assert "author" not in w.render_mock.call_args.kwargs["byline"]

    def test_renderer_unavailable_retried_then_raised(self, site, w):
        w.render_mock.side_effect = _down
        with pytest.raises(RendererUnavailable):
            _render(w, _item(site), "2026-11-09T00:00:00+00:00")
        assert w.render_mock.call_count == w.settings.render_retries

    def test_retry_then_success(self, site, w):
        w.render_mock.side_effect = [RendererUnavailable("504"), PDF]
        assert _render(w, _item(site), "2026-11-09T00:00:00+00:00") == PDF

    def test_content_unavailable_is_not_retried(self, site, w):
        w.render_mock.side_effect = ContentUnavailable("HTTP 422: no body")
        assert _render(w, _item(site), "2026-11-09T00:00:00+00:00") is None
        assert w.render_mock.call_count == 1

    def test_non_pdf_payload_is_transient(self, site, w):
        w.render_mock.return_value = b"<html>"
        with pytest.raises(RendererUnavailable):
            _render(w, _item(site), "2026-11-09T00:00:00+00:00")


# --------------------------------------------------------------------------- #
# Ingestion + data model
# --------------------------------------------------------------------------- #

class TestDescription:
    def test_wordpress_trailer_stripped(self, site):
        out = text.html_to_text(
            "<p>Real summary.</p><p>The post <a href='x'>A Story: Part 2</a> appeared "
            "first on <a href='y'>Some Site</a>.</p>")
        assert out == "Real summary."
        assert text.html_to_text("The post office reopened.") == "The post office reopened."

    def test_meta_description_any_attribute_order(self, site):
        page = (b"<html><head><meta content='Named &amp; summary' name='description'>"
                b"<meta property='og:description' content='OG summary'></head></html>")
        assert text.meta_description(page) == "OG summary"
        assert text.meta_description(page.replace(b"og:description", b"og:title")) == (
            "Named & summary")
        assert text.meta_description(b"<html><meta name='description' content=' '></html>") == ""
        assert text.meta_description(
            b"<meta property='og:description' content=' '><meta name='description' content='Real'>"
        ) == "Real"
        assert text.meta_description(b"") == ""

    def test_meta_description_used_when_feed_has_none(self, site, w):
        _replace(w, skip_if=None)
        w.session.get.return_value = MagicMock(
            content=b"<meta name='description' content='Page summary.'>", status_code=200)
        assert w.ingest_item(dict(_item(site), description="")) == "created"
        assert w.session.get.call_args.args[0] == site.link(1)
        assert w.api.report.create.call_args.kwargs["description"] == "Page summary."

    def test_no_page_fetch_when_feed_has_summary(self, site, w):
        _replace(w, skip_if=None)
        assert w.ingest_item(_item(site)) == "created"
        w.session.get.assert_not_called()
        assert w.api.report.create.call_args.kwargs["description"] == "Summary."

    def test_page_fetch_failure_still_creates_report(self, site, w):
        _replace(w, skip_if=None)
        w.session.get.side_effect = requests.ConnectionError("down")
        assert w.ingest_item(dict(_item(site), description="")) == "created"
        assert w.api.report.create.call_args.kwargs["description"] == ""
        w.log.log_warning.assert_called()


class TestIngestItem:
    def test_single_create_mutation_with_inline_pdf(self, site, w):
        assert w.ingest_item(_item(site)) == "created"

        kw = w.api.report.create.call_args.kwargs
        assert kw["stix_id"] == report.report_id(site.link(1))
        assert kw["published"] == "2026-11-09T22:09:33+00:00"
        assert kw["createdBy"] == "author-id"
        assert kw["objectMarking"] == ["marking-id"]
        ref_kw = w.api.external_reference.create.call_args.kwargs
        assert ref_kw["url"] == site.link(1) and ref_kw["source_name"] == site.real.author_name
        assert kw["externalReferences"] == [w.graph.ref_create(url=site.link(1))["id"]]
        assert kw["report_types"] == ["open-source-reporting"]
        # The new Report is found by the URL-based dedup on the next poll.
        assert w.ingested_links([{"link": site.link(1)}]) == {site.link(1)}
        assert kw["update"] is False
        assert "content" not in kw
        assert "objectLabel" not in kw and "labels" not in kw
        assert "objects" not in kw
        # House standard: exactly one PDF, the file itself TLP-marked.
        assert len(kw["files"]) == 1
        pdf = kw["files"][0]
        assert pdf.name.startswith(f"{site.real.file_prefix}-rendered-") and pdf.name.endswith(".pdf")
        assert pdf.mime == "application/pdf" and pdf.data == PDF
        assert kw["filesMarkings"] == [["marking-id"]]
        w.api.stix_domain_object.add_file.assert_not_called()

    def test_atom_iso_date_item_ingested(self, site, w):
        assert w.ingest_item(_item(site, pub="2026-11-09T17:09:33Z")) == "created"
        kw = w.api.report.create.call_args.kwargs
        assert kw["published"] == "2026-11-09T17:09:33+00:00"

    def test_undated_item_is_skipped_never_stamped_now(self, site, w):
        assert w.ingest_item(_item(site, pub="garbage")) == "skipped-permanent"
        w.render_mock.assert_not_called()
        w.api.report.create.assert_not_called()
        assert site.link(1) in w.permanent_skips

    def test_renderer_down_creates_nothing(self, site, w):
        w.render_mock.side_effect = _down
        assert w.ingest_item(_item(site)) == "renderer-down"
        w.api.report.create.assert_not_called()
        w.api.external_reference.create.assert_not_called()
        assert site.link(1) not in w.permanent_skips

    @pytest.mark.parametrize("detail", [
        'HTTP 422: {"detail":"navigation failed: net::ERR_NAME_NOT_RESOLVED"}',
        'HTTP 422: {"detail":"HTTP 503 from https://site/x"}',
        'HTTP 422: {"detail":"HTTP 429 from https://site/x"}',
        'HTTP 422: {"detail":"bot challenge interstitial detected"}',
    ])
    def test_site_failure_is_transient_not_a_pdfless_report(self, site, w, detail):
        w.render_mock.side_effect = ContentUnavailable(detail)
        assert w.ingest_item(_item(site)) == "failed"
        w.api.report.create.assert_not_called()
        assert w.render_mock.call_count == 1

    def test_request_validation_error_is_a_renderer_problem(self, site, w):
        w.render_mock.side_effect = ContentUnavailable(
            'HTTP 422: {"detail":[{"type":"missing","loc":["body","title"]}]}')
        assert w.ingest_item(_item(site)) == "renderer-down"
        w.api.report.create.assert_not_called()

    def test_content_unavailable_creates_report_without_pdf(self, site, w):
        w.render_mock.side_effect = ContentUnavailable("HTTP 422: no article")
        assert w.ingest_item(_item(site)) == "created"
        kw = w.api.report.create.call_args.kwargs
        assert "files" not in kw and "filesMarkings" not in kw
        assert any("No PDF for" in str(c) for c in w.log.log_warning.call_args_list)
        assert any("(no PDF)" in str(c) for c in w.log.log_info.call_args_list)

    def test_oversized_pdf_creates_report_without_pdf(self, site, w):
        w.render_mock.return_value = b"%PDF" + b"0" * w.settings.max_pdf_bytes
        assert w.ingest_item(_item(site)) == "created"
        assert "files" not in w.api.report.create.call_args.kwargs

    def test_empty_title_uses_url(self, site, w):
        w.ingest_item(_item(site, title=""))
        assert w.api.report.create.call_args.kwargs["name"] == site.link(1)
        assert w.render_mock.call_args.args[1] == site.link(1)


class TestResolveGraphReferences:
    def test_resolves(self, site):
        api = MagicMock()
        api.identity.create.return_value = {"id": "a"}
        api.marking_definition.read.return_value = {"id": "m"}
        assert report.resolve_author(api, site.real) == "a"
        assert report.resolve_marking(api, site.real.tlp) == "m"
        kw = api.identity.create.call_args.kwargs
        assert kw["type"] == "Organization" and kw["name"] == site.real.author_name
        assert kw["description"] == site.real.author_description

    def test_missing_marking_is_fatal(self, site):
        api = MagicMock()
        api.marking_definition.read.return_value = None
        with pytest.raises(RuntimeError):
            report.resolve_marking(api, site.real.tlp)

    def test_vocabulary_failure_is_only_a_warning(self, site):
        api, log = MagicMock(), MagicMock()
        api.vocabulary.create.side_effect = Exception("exists")
        report.ensure_vocabulary(api, site.real.report_type, log)
        log.log_warning.assert_called()


# --------------------------------------------------------------------------- #
# Report-type classification
# --------------------------------------------------------------------------- #

class TestClassification:
    def _content_sent(self, w, item, page_bytes, monkeypatch=None):
        _replace(w, skip_if=None)   # site prechecks tested separately
        if page_bytes is not None:
            monkeypatch.setenv("CRUCIBLE_COLLECTOR_URL", "http://collector.example:8004")
            w.session.get.return_value = MagicMock(content=page_bytes, text="", status_code=200)
        with patch("engine.report.classify_report",
                   side_effect=lambda **kw: ["threat-report"]) as clf:
            assert w.ingest_item(item) == "created"
        assert w.api.report.create.call_args.kwargs["report_types"] == ["threat-report"]
        assert any("report_types=['threat-report']" in str(c)
                   for c in w.log.log_info.call_args_list)
        return clf.call_args.kwargs

    def test_feed_full_text_preferred(self, site, w):
        item = dict(_item(site), full_text="Full feed body about ransomware.")
        kw = self._content_sent(w, item, None)
        assert kw["content"] == "Full feed body about ransomware."
        w.session.get.assert_not_called()   # no page fetch needed
        assert kw["description"] == "Summary."
        assert kw["source"] == site.real.name and kw["source_url"] == site.link(1)
        assert kw["default_types"] == ["open-source-reporting"]
        # Failures are logged as WARNINGs through the source's logger.
        assert kw["logger"] == w.log.log_warning

    def test_never_defaults_to_threat_report(self, site, w):
        kw = self._content_sent(w, _item(site), None)
        assert "threat-report" not in kw["default_types"]

    def test_standalone_without_shared_helper(self, site, w):
        with patch("engine.report.classify_report", None):
            assert w.ingest_item(_item(site)) == "created"
        assert w.api.report.create.call_args.kwargs["report_types"] == ["open-source-reporting"]

    def test_page_article_text_when_feed_has_none(self, site, w, monkeypatch):
        page = ("<html><body><nav>Menu Login</nav>"
                + site.wrap("<h1>Title</h1><p>Article body text</p><script>tracker()</script>")
                + "<footer>Copyright</footer></body></html>").encode()
        kw = self._content_sent(w, _item(site), page, monkeypatch)
        assert "Article body text" in kw["content"]
        assert w.session.get.call_args.args[0] == site.link(1)
        assert "Menu Login" not in kw["content"] and "Copyright" not in kw["content"]
        assert "tracker()" not in kw["content"]

    def test_falls_back_to_summary_without_any_text(self, site, w):
        kw = self._content_sent(w, _item(site), None)
        assert kw["content"] == "Summary."

    def test_no_page_fetch_in_standalone_mode(self, site, w, monkeypatch):
        monkeypatch.delenv("CRUCIBLE_COLLECTOR_URL", raising=False)
        self._content_sent(w, _item(site), None)
        w.session.get.assert_not_called()

    def test_page_fetch_failure_falls_back_to_summary(self, site, w, monkeypatch):
        monkeypatch.setenv("CRUCIBLE_COLLECTOR_URL", "http://collector.example:8004")
        w.session.get.side_effect = requests.ConnectionError("down")
        kw = self._content_sent(w, _item(site), None)
        assert kw["content"] == "Summary."

    def test_one_page_fetch_serves_description_and_classifier(self, site, w, monkeypatch):
        page = ("<html><head><meta property='og:description' content='Page summary.'>"
                "</head><body>"
                + site.wrap("<h1>Title</h1><p>Article body text</p><script>tracker()</script>")
                + "</body></html>").encode()
        kw = self._content_sent(w, dict(_item(site), description=""), page, monkeypatch)
        assert w.session.get.call_count == 1
        assert "Article body text" in kw["content"]
        assert kw["description"] == "Page summary."

    def test_article_text_never_stored_on_report(self, site, w):
        item = dict(_item(site), full_text="SECRET-LONG-BODY " * 50)
        self._content_sent(w, item, None)
        kw = w.api.report.create.call_args.kwargs
        assert "SECRET-LONG-BODY" not in kw["description"] and "content" not in kw

    def test_article_text_skips_hidden_chrome(self, site):
        hidden = [s for s in site.real.hide_selectors if not any(ch in s for ch in "~[ >:+")]
        if not hidden:
            pytest.skip("site has no simple hide selectors")
        tag, ident, classes = text.selector_parts(hidden[0])
        attrs = (f' id="{ident}"' if ident else "") + (
            f' class="{" ".join(sorted(classes))}"' if classes else "")
        chrome = f"<{tag or 'div'}{attrs}><p>Most Popular junk</p></{tag or 'div'}>"
        page = site.wrap("<p>Real story</p>" + chrome + "<p>More story</p>").encode()
        out = text.article_text(page, site.real.content_selectors, site.real.hide_selectors)
        assert "Real story" in out and "More story" in out
        assert "Most Popular junk" not in out

    def test_article_text_is_full_not_truncated(self, site):
        page = site.wrap("word " * 20000 + "THE-END").encode()
        out = text.article_text(page, site.real.content_selectors, site.real.hide_selectors)
        assert out.endswith("THE-END") and len(out) > 100000

    def test_article_text_tries_fallback_selectors(self, site):
        fallbacks = site.real.content_selectors[1:]
        if not fallbacks:
            pytest.skip("no fallback selectors for this site")
        tag, ident, classes = text.selector_parts(fallbacks[0])
        attrs = (f' id="{ident}"' if ident else "") + (
            f' class="{" ".join(sorted(classes))}"' if classes else "")
        page = (f"<html><body><nav>Menu</nav><{tag or 'div'}{attrs}><p>Fallback body</p>"
                f"</{tag or 'div'}></body></html>").encode()
        assert text.article_text(page, site.real.content_selectors,
                                 site.real.hide_selectors) == "Fallback body"

    def test_article_text_falls_back_to_page(self, site):
        sel, hide = site.real.content_selectors, site.real.hide_selectors
        assert text.article_text(b"<html><body><p>Only text</p></body></html>", sel, hide) == "Only text"
        assert text.article_text(None, sel, hide) == ""

    def test_feed_creator_parsed_for_byline(self, site):
        xml = (f"<rss xmlns:dc='http://purl.org/dc/elements/1.1/'><channel>"
               f"<item><title>a</title><link>{site.link(1)}</link>"
               f"<dc:creator><![CDATA[Jane &amp; Doe]]></dc:creator></item>"
               f"</channel></rss>").encode()
        assert discovery.parse_feed(xml, site.p)[0]["creator"] == "Jane & Doe"
        assert discovery.parse_feed(make_feed([site.link(1)]), site.p)[0]["creator"] == ""

    def test_feed_full_text_parsed_in_full(self, site):
        body = "<p>" + "x " * 60000 + "THE-END</p>"
        xml = (f"<rss xmlns:content='http://purl.org/rss/1.0/modules/content/'><channel>"
               f"<item><title>a</title><link>{site.link(1)}</link>"
               f"<content:encoded><![CDATA[{body}]]></content:encoded></item>"
               f"</channel></rss>").encode()
        out = discovery.parse_feed(xml, site.p)[0]["full_text"]
        assert out.endswith("THE-END") and "<p>" not in out


# --------------------------------------------------------------------------- #
# Poll cycle
# --------------------------------------------------------------------------- #

class TestProcess:
    def test_idle_poll_writes_nothing(self, site, w):
        w.graph.add_ingested(site.link(1))
        _serve(w, make_feed([site.link(1)]))
        w.process()
        w.api.work.initiate_work.assert_not_called()
        w.api.report.create.assert_not_called()

    def test_feed_failure_writes_nothing(self, site, w):
        w.session.get.side_effect = requests.ConnectionError("down")
        w.process()
        w.api.work.initiate_work.assert_not_called()

    def test_max_reports(self, site, w):
        _serve(w, make_feed([site.link(1), site.link(2)]))
        w.process(max_reports=1)
        assert w.api.report.create.call_count == 1

    def test_one_bad_item_does_not_stop_the_poll(self, site, w):
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                _site_down()
            return PDF

        _serve(w, make_feed([site.link(1), site.link(2)]), render=flaky)
        w.process()
        assert w.api.report.create.call_count == 1
        assert w.api.work.to_processed.call_args.kwargs["in_error"] is True
        assert w.transient_failures == {site.link(1): 1}

    def test_transient_failure_gives_up_after_cap(self, site, w):
        _serve(w, make_feed([site.link(1)]), render=_site_down)
        for _ in range(w.settings.max_transient_attempts):
            w.process()
        assert site.link(1) in w.permanent_skips
        renders = w.render_mock.call_count
        w.process()
        assert w.render_mock.call_count == renders  # no more renders

    def test_renderer_outage_never_gives_up_on_items(self, site, w):
        """A long pdf-renderer outage stops polls early but does not count
        against items, so they are all ingested once it recovers."""
        _serve(w, make_feed([site.link(1), site.link(2)]), render=_down)
        w.process()
        # The poll stops at the first item: the second is not even tried.
        assert w.render_mock.call_count == w.settings.render_retries
        for _ in range(w.settings.max_transient_attempts * 2):
            w.process()
        assert w.permanent_skips == {} and w.transient_failures == {}
        assert w.api.work.to_processed.call_args.kwargs["in_error"] is True
        w.render_mock.side_effect = None
        w.process()
        assert w.graph.created() == {report.report_id(site.link(1)), report.report_id(site.link(2))}

    def test_no_gap_warning_when_feed_reaches_past_max_age(self, site, w):
        """A quiet site: one new post, everything else older than max_age."""
        _replace(w, max_age_days=30)
        w.poll_count = 5
        recent = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        xml = make_feed([site.link(1)], pub=recent)[:-len(b"</channel></rss>")] + make_feed(
            [site.link(2)], pub="Mon, 01 Jan 2001 00:00:00 GMT")[len(b"<rss><channel>"):]
        _serve(w, xml)
        w.process()
        assert not any("scrolled off" in str(c) for c in w.log.log_warning.call_args_list)
        assert w.graph.created() == {report.report_id(site.link(1))}

    def test_no_gap_warning_after_all_failed_poll(self, site, w):
        """An outage poll leaves nothing ingested; the next poll must not
        misreport that as posts scrolling off the feed."""
        down = {"on": True}

        def render_fn(*a, **k):
            if down["on"]:
                raise RendererUnavailable("render down")
            return PDF

        _serve(w, make_feed([site.link(1), site.link(2)]), render=render_fn)
        w.process()                       # first poll: all fail
        down["on"] = False
        w.log.log_warning.reset_mock()
        w.process()                       # recovery poll
        assert not any("scrolled off" in str(c) for c in w.log.log_warning.call_args_list)
        assert w.api.report.create.call_count == 2

    def test_multi_poll_moving_feed(self, site, w):
        """Feed slides forward; a render outage heals on retry; nothing is
        duplicated; the scroll-off warning fires only when polls lose overlap."""
        state = {"failed": False}

        def render_fn(url, *a, **kw):
            if url == site.link(12) and not state["failed"]:
                state["failed"] = True
                raise RendererUnavailable("render outage")
            return PDF

        w.settings.render_retries = 1
        windows = [range(10, 0, -1), range(14, 4, -1), range(18, 8, -1),
                   range(40, 30, -1)]  # last window has no overlap -> gap
        for n, window in enumerate(windows):
            _serve(w, make_feed([site.link(i) for i in window]), render=render_fn)
            w.log.log_warning.reset_mock()
            w.process()
            gap = any("scrolled off" in str(c) for c in w.log.log_warning.call_args_list)
            assert gap is (n == 3), f"poll {n}"

        expected = {report.report_id(site.link(i)) for i in list(range(1, 19)) + list(range(31, 41))}
        assert w.graph.created() == expected
        assert w.api.report.create.call_count == len(expected)
        assert w.transient_failures == {}
        # One reference lookup per poll; dedup never reads Reports one by one.
        assert w.api.external_reference.list.call_count == len(windows)
        w.api.report.read.assert_not_called()

    def test_already_ingested_article_is_not_duplicated(self, site, w):
        w.graph.add_ingested(site.link(1), report_id="feedly-report")
        _serve(w, make_feed([site.link(1), site.link(2)]))
        w.process()
        assert w.graph.created() == {report.report_id(site.link(2))}

    def test_orphan_reference_from_failed_create_is_retried(self, site, w):
        _serve(w, make_feed([site.link(1)]))
        w.api.report.create.side_effect = Exception("API 500")
        w.process()                     # reference created, Report not
        assert w.graph.refs and not w.graph.created()
        w.api.report.create.side_effect = w.graph.report_create
        w.process()                     # retried, now created
        assert w.graph.created() == {report.report_id(site.link(1))}


assert timing  # imported for fixtures that patch engine.timing.sleep
