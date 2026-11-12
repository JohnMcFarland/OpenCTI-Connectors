"""Source profiles: load sources.yml and validate every entry.

One entry per publisher, keyed by slug. Validation is per entry: an entry
that fails is reported with the field that failed and that source does not
start; every other source still loads. Site-specific behaviour is always a
profile option (render_headers, skip_if), never a code fork.
"""

import re
from dataclasses import dataclass, field
from typing import Optional

import yaml

DISCOVERY_MODES = ("feed", "sitemap", "listing", "json")
# Named skip checks (skip_if). Any other skip_if value is an element-class
# regex (see scope.skip_reason).
NAMED_SKIP_CHECKS = ("members_only_paywall",)
_SLUG_RE = re.compile(r"^[a-z0-9_]+$")


@dataclass(frozen=True)
class Profile:
    """One publisher. Field meanings: docs/WAYPOINT_SCOPE.md, "Source profile schema"."""

    slug: str
    name: str
    author_name: str
    feed_urls: tuple
    allowed_hosts: frozenset
    enabled: bool = True
    author_description: str = ""
    discovery: str = "feed"
    discovery_config: dict = field(default_factory=dict)
    poll_interval: int = 3600
    request_delay: int = 3
    max_age_days: int = 30
    category_keep: frozenset = frozenset()
    category_allow: frozenset = frozenset()
    category_deny: frozenset = frozenset()
    exclude_url_re: Optional[re.Pattern] = None
    exclude_title_re: Optional[re.Pattern] = None
    content_selectors: object = "generic"      # list of CSS selectors, or "generic"
    hide_selectors: tuple = ()
    date_text_selector: Optional[str] = None
    byline_author: bool = True
    file_prefix: str = ""
    slug_from_id: bool = False
    resolve_redirect_hosts: frozenset = frozenset()
    no_content_is_transient: bool = False
    render_headers: dict = field(default_factory=dict)
    skip_if: Optional[str] = None
    confidence: int = 50
    tlp: str = "TLP:CLEAR"
    report_type: str = "open-source-reporting"
    # Days without a new Report before the once-a-day stale WARNING
    # (None = the engine default, AGG_STALE_AFTER_DAYS).
    stale_after_days: Optional[int] = None

    # Hashable by slug so profiles can key dicts and sets.
    def __hash__(self):
        return hash(self.slug)


class ProfileError(ValueError):
    """An entry failed validation; the message names the field."""


# --------------------------------------------------------------------------- #
# Field validators: each returns the normalised value or raises ProfileError
# --------------------------------------------------------------------------- #

def _str(key, value, allow_empty=False):
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ProfileError(f"{key}: must be a non-empty string")
    return value


def _opt_str(key, value):
    return None if value is None else _str(key, value)


def _bool(key, value):
    if not isinstance(value, bool):
        raise ProfileError(f"{key}: must be true or false")
    return value


def _int(key, value, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProfileError(f"{key}: must be an integer >= {minimum}")
    return value


def _str_list(key, value, allow_empty=True):
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ProfileError(f"{key}: must be a list of non-empty strings")
    if not allow_empty and not value:
        raise ProfileError(f"{key}: must not be empty")
    return value


def _regex(key, value):
    if value is None:
        return None
    _str(key, value)
    try:
        return re.compile(value)
    except re.error as exc:
        raise ProfileError(f"{key}: invalid regex ({exc})")


def _url_list(key, value):
    _str_list(key, value, allow_empty=False)
    for url in value:
        if not re.match(r"^https?://[^/\s]+", url):
            raise ProfileError(f"{key}: not an http(s) URL: {url}")
    return value


def _discovery_config(mode, value):
    if not isinstance(value, dict):
        raise ProfileError("discovery_config: must be a map")
    # Patterns must compile; the mode's required keys must be present.
    for k in ("url_re", "child_re", "link_re"):
        if k in value:
            _regex(f"discovery_config.{k}", value[k])
    if mode == "listing" and "link_re" not in value:
        raise ProfileError("discovery_config.link_re: required for listing discovery")
    if mode == "json" and "link" not in value:
        raise ProfileError("discovery_config.link: required for json discovery")
    for k in ("children", "max_items"):
        if k in value:
            _int(f"discovery_config.{k}", value[k], 1)
    return dict(value)


def _content_selectors(value):
    if value == "generic":
        return value
    return _str_list("content_selectors", value, allow_empty=False)


def _render_headers(value):
    if not isinstance(value, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise ProfileError("render_headers: must be a map of header name to string")
    return dict(value)


def _skip_if(value):
    if value is None or value in NAMED_SKIP_CHECKS:
        return value
    _regex("skip_if", value)     # an element-class regex
    return value


def _tlp(value):
    _str("tlp", value)
    if not value.startswith("TLP:"):
        raise ProfileError("tlp: must be a TLP marking definition such as TLP:CLEAR")
    return value


# --------------------------------------------------------------------------- #
# Entry -> Profile
# --------------------------------------------------------------------------- #

KNOWN_FIELDS = {
    "name", "enabled", "author_name", "author_description", "discovery",
    "discovery_config", "feed_urls", "allowed_hosts", "poll_interval",
    "request_delay", "max_age_days", "category_keep", "category_allow",
    "category_deny", "exclude_url_re", "exclude_title_re", "content_selectors",
    "hide_selectors", "date_text_selector", "byline_author", "file_prefix",
    "slug_from_id", "resolve_redirect_hosts", "no_content_is_transient",
    "render_headers", "skip_if", "confidence", "tlp", "report_type",
    "stale_after_days",
}
REQUIRED_FIELDS = ("name", "author_name", "feed_urls", "allowed_hosts")


def build_profile(slug, entry):
    """Validate one sources.yml entry and return its Profile.

    Raises ProfileError naming the first field that fails.
    """
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        raise ProfileError("slug: must be lower-case letters, digits and underscores")
    if not isinstance(entry, dict):
        raise ProfileError("entry: must be a map of fields")
    unknown = sorted(set(entry) - KNOWN_FIELDS)
    if unknown:
        raise ProfileError(f"{unknown[0]}: unknown field")
    for key in REQUIRED_FIELDS:
        if entry.get(key) in (None, "", []):
            raise ProfileError(f"{key}: required")

    g = entry.get
    discovery = g("discovery", "feed")
    if discovery not in DISCOVERY_MODES:
        raise ProfileError(f"discovery: must be one of {', '.join(DISCOVERY_MODES)}")
    hosts = _str_list("allowed_hosts", g("allowed_hosts"), allow_empty=False)
    stale = g("stale_after_days")
    return Profile(
        slug=slug,
        name=_str("name", g("name")),
        author_name=_str("author_name", g("author_name")),
        author_description=_str("author_description", g("author_description", ""), True),
        enabled=_bool("enabled", g("enabled", True)),
        discovery=discovery,
        discovery_config=_discovery_config(discovery, g("discovery_config", {}) or {}),
        feed_urls=tuple(_url_list("feed_urls", g("feed_urls"))),
        allowed_hosts=frozenset(hosts),
        poll_interval=_int("poll_interval", g("poll_interval", 3600), 60),
        request_delay=_int("request_delay", g("request_delay", 3), 0),
        max_age_days=_int("max_age_days", g("max_age_days", 30), 0),
        category_keep=frozenset(_str_list("category_keep", g("category_keep", []) or [])),
        category_allow=frozenset(_str_list("category_allow", g("category_allow", []) or [])),
        category_deny=frozenset(_str_list("category_deny", g("category_deny", []) or [])),
        exclude_url_re=_regex("exclude_url_re", g("exclude_url_re")),
        exclude_title_re=_regex("exclude_title_re", g("exclude_title_re")),
        content_selectors=_content_selectors(g("content_selectors", "generic")),
        hide_selectors=tuple(_str_list("hide_selectors", g("hide_selectors", []) or [])),
        date_text_selector=_opt_str("date_text_selector", g("date_text_selector")),
        byline_author=_bool("byline_author", g("byline_author", True)),
        file_prefix=_str("file_prefix", g("file_prefix", slug)),
        slug_from_id=_bool("slug_from_id", g("slug_from_id", False)),
        resolve_redirect_hosts=frozenset(_str_list(
            "resolve_redirect_hosts", g("resolve_redirect_hosts", []) or [])),
        no_content_is_transient=_bool("no_content_is_transient", g("no_content_is_transient", False)),
        render_headers=_render_headers(g("render_headers", {}) or {}),
        skip_if=_skip_if(g("skip_if")),
        confidence=_int("confidence", g("confidence", 50), 0),
        tlp=_tlp(g("tlp", "TLP:CLEAR")),
        report_type=_str("report_type", g("report_type", "open-source-reporting")),
        stale_after_days=None if stale is None else _int("stale_after_days", stale, 1),
    )


def load_sources(path):
    """Load and validate sources.yml.

    Returns (profiles, errors): profiles maps slug -> Profile for every valid
    entry (enabled or not); errors maps slug -> "<field>: <problem>" for
    every invalid one. A file that cannot be read or parsed at all raises.
    """
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a map of slug -> profile")
    profiles, errors = {}, {}
    for slug, entry in data.items():
        try:
            profiles[slug] = build_profile(slug, entry)
        except ProfileError as exc:
            errors[str(slug)] = str(exc)
    return profiles, errors
