"""Dark Web Informer's members-only tests, ported to skip_if: members_only_paywall.

The generated connector replaced _precheck with a members-only check; in
Waypoint that is the profile's skip_if. Same cases, same expectations.
"""

from unittest.mock import MagicMock

import pytest
import requests

from conftest import FIXTURES, PROFILES, make_worker
from engine.scope import is_members_only

THEME_CSS = (
    "<style>.gh-post-upgrade-cta{display:none}"
    ".c-visibility-label--paid .paid{display:block}</style>"
)
DWI = PROFILES["dark_web_informer"]


def _item(n=1):
    return {"title": "Story", "link": f"https://darkwebinformer.com/story-{n}/",
            "description": "Summary.", "pub_date": "Mon, 09 Nov 2026 17:09:33 -0500"}


@pytest.fixture
def dwi(render_mock):
    w = make_worker(DWI)
    w.render_mock = render_mock
    return w


def test_profile_uses_the_named_check():
    assert DWI.skip_if == "members_only_paywall"


class TestMembersOnly:
    def test_css_mentions_alone_are_not_a_paywall(self):
        assert is_members_only(THEME_CSS + "<article class='c-post post'>x</article>") is False

    @pytest.mark.parametrize("markup", [
        '<aside class="gh-post-upgrade-cta">Subscribe</aside>',
        "<div class='gh-post-upgrade-cta gh-post-upgrade-cta--x'>",
        '<span class="c-visibility-label c-visibility-label--paid">',
        '<span class="c-visibility-label c-visibility-label--members">',
    ])
    def test_paywall_elements_detected(self, markup):
        assert is_members_only(THEME_CSS + markup) is True

    def test_members_card_in_related_section_is_ignored(self):
        page = (
            THEME_CSS
            + "<article class='c-post post'><p>public body</p></article>"
            + "<div class='c-section c-section--related'>"
            + '<span class="c-visibility-label c-visibility-label--members">Members</span>'
            + "</div>"
        )
        assert is_members_only(page) is False

    def test_paywall_inside_post_still_detected(self):
        page = (
            "<article class='c-post post'><p>teaser</p>"
            '<aside class="gh-post-upgrade-cta">Subscribe</aside></article>'
            "<div class='c-section c-section--latest'></div>"
        )
        assert is_members_only(page) is True

    def test_public_post_saved_during_recon(self):
        page = (FIXTURES / "dark_web_informer" / "public_post.html").read_text(encoding="utf-8")
        assert is_members_only(page) is False

    def test_members_post_skipped_before_render(self, dwi):
        dwi.session.get.return_value = MagicMock(
            status_code=200, text='<aside class="gh-post-upgrade-cta">')
        assert dwi.ingest_item(_item()) == "skipped-permanent"
        dwi.render_mock.assert_not_called()
        dwi.api.report.create.assert_not_called()

    def test_public_post_proceeds_to_render(self, dwi):
        dwi.session.get.return_value = MagicMock(status_code=200, text="<article>")
        assert dwi.ingest_item(_item()) == "created"

    def test_page_fetch_error_is_transient(self, dwi):
        dwi.session.get.side_effect = requests.ConnectionError("down")
        with pytest.raises(requests.ConnectionError):
            dwi.ingest_item(_item())
        assert _item()["link"] not in dwi.permanent_skips

    def test_dead_page_is_permanent(self, dwi):
        dwi.session.get.return_value = MagicMock(status_code=404, text="")
        assert dwi.ingest_item(_item()) == "skipped-permanent"

    def test_fetch_error_inside_a_poll_counts_as_transient(self, dwi):
        """In a poll, the raised fetch error is the item's transient failure."""
        feed = (b"<rss><channel><item><title>a</title><link>https://darkwebinformer.com/story-1/"
                b"</link><pubDate>Mon, 09 Nov 2026 12:00:00 GMT</pubDate></item></channel></rss>")

        def get(url, **k):
            if url == DWI.feed_urls[0]:
                return MagicMock(content=feed, status_code=200)
            raise requests.ConnectionError("down")

        dwi.session.get.side_effect = get
        dwi.process()
        assert dwi.transient_failures == {"https://darkwebinformer.com/story-1/": 1}
