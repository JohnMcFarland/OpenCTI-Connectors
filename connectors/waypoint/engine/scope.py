"""Scope filters and skip checks.

out_of_scope() is the generated connectors' _out_of_scope with the site
constants taken from the profile. skip_reason() runs the profile's skip_if
check before rendering: the named check members_only_paywall (Dark Web
Informer's members-only precheck, ported unchanged) or an element-class
regex.
"""

import re
from datetime import datetime, timedelta, timezone

from .dates import parse_date


def out_of_scope(item, profile, max_age_days=None, now=None):
    """Return why an item is outside this source's scope, or None.

    max_age_days defaults to the profile's; 0 means no age limit.
    """
    if max_age_days is None:
        max_age_days = profile.max_age_days
    cats = {c.strip().lower() for c in item.get("categories", [])}
    keep = {c.lower() for c in profile.category_keep}
    allow = {c.lower() for c in profile.category_allow}
    deny = {c.lower() for c in profile.category_deny}
    if keep and cats & keep:
        pass  # always in scope; only the age limit below applies
    elif allow and not cats & allow:
        return "category not in scope"
    elif deny and cats & deny:
        return "category excluded"
    elif profile.exclude_url_re is not None and profile.exclude_url_re.search(item["link"]):
        return "url excluded"
    elif profile.exclude_title_re is not None and profile.exclude_title_re.search(item["title"]):
        return "title excluded"
    if max_age_days:
        # A sitemap lastmod is never earlier than publication, so an item
        # whose lastmod is already too old was published too long ago.
        published = parse_date(item.get("pub_date")) or parse_date(item.get("lastmod"))
        now = now or datetime.now(timezone.utc)
        if published and datetime.fromisoformat(published) < now - timedelta(days=max_age_days):
            return "older than max_age_days"
    return None


# --------------------------------------------------------------------------- #
# skip_if: members_only_paywall (ported from Dark Web Informer)
# --------------------------------------------------------------------------- #

# Matches the paywall CTA or a members/paid visibility label as an element
# class attribute. The theme's CSS also mentions these names, so plain
# substring matching would flag every page.
PAYWALL_RE = re.compile(
    r"""class\s*=\s*["'][^"']*\b(?:gh-post-upgrade-cta|"""
    r"""c-visibility-label--(?:members|paid|tiers))\b""",
    re.IGNORECASE,
)
ARTICLE_START_RE = re.compile(r"""<article\b[^>]*class\s*=\s*["'][^"']*\bc-post\b""", re.IGNORECASE)
ARTICLE_END_RE = re.compile(
    r"""class\s*=\s*["'][^"']*\bc-section--(?:related|latest)\b""", re.IGNORECASE
)


def main_article(page_html):
    """Return just the main post markup.

    The "related" and "latest" sections that follow the post show cards for
    other posts (possibly members-only ones), so they must not be scanned.
    """
    page_html = page_html or ""
    start = ARTICLE_START_RE.search(page_html)
    begin = start.start() if start else 0
    end = ARTICLE_END_RE.search(page_html, begin)
    return page_html[begin:end.start() if end else len(page_html)]


def is_members_only(page_html):
    """Return True when the main post shows a members-only paywall."""
    return bool(PAYWALL_RE.search(main_article(page_html)))


def _class_regex(pattern):
    """An element-class skip_if regex, matched against class attributes only."""
    return re.compile(r"""class\s*=\s*["'][^"']*\b(?:""" + pattern + r""")\b""", re.IGNORECASE)


def skip_reason(session, item, profile):
    """Run the profile's skip_if check; return a permanent-skip reason or None.

    Fetches the article page once (a cheap GET, before any render). A 404 or
    410 is permanent; any other HTTP error or network failure raises, so the
    caller treats it as transient and retries on a later poll.
    """
    if not profile.skip_if:
        return None
    resp = session.get(item["link"], timeout=60)
    if resp.status_code in (404, 410):
        return f"article page returned HTTP {resp.status_code}"
    resp.raise_for_status()
    if profile.skip_if == "members_only_paywall":
        if is_members_only(resp.text):
            return "members-only post (public posts only)"
        return None
    if _class_regex(profile.skip_if).search(resp.text or ""):
        return f"page matches skip_if ({profile.skip_if})"
    return None
