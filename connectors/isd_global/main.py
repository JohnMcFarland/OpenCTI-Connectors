"""
Institute for Strategic Dialogue OpenCTI connector.

Purpose
-------
External-import connector that creates one container-only OpenCTI Report per
Institute for Strategic Dialogue article, with the live article page attached as one rendered PDF.
Added from the Crucible proposed-sources list; Institute for Strategic Dialogue was not
previously ingested by any connector.

Collection model
----------------
Feed only, new posts only. The connector polls https://www.isdglobal.org/feed/?post_type=digital-dispatch,https://www.isdglobal.org/feed/?post_type=publication
(RSS 2.0 or Atom; several feeds may be given, comma-separated) and never
backfills older articles.

ISD (isdglobal.org) is WordPress + GenerateBlocks behind Cloudflare. The site
main /feed/ is empty: content lives in custom post types, each with its own
RSS2 feed via /feed/?post_type=<cpt> (10 items each, excerpt only, no
categories). Two feeds merged: digital-dispatch (Digital Dispatches analysis,
~0.16/day, Jul-Oct 2026 in feed) and publication (research reports, ~0.06/day,
May-Oct 2026 in feed). Container is the whole <article>: it carries section
label, date, ISD office (ISD-US/UK/Germany), issue tags, headline, p.pub-
authors byline and the body (div.gb-headline-6629da80); sidebar/related/media
blocks are hidden. Publication pages are report landing pages that summarise a
downloadable PDF (130-350 words); that landing text is what is rendered.
dc:creator is the WP uploader login (e.g. 'Krystalle', 'Sid'), not the analyst
- real authors are in p.pub-authors on the page. Press releases and media
mentions are left out.

Data model conformance
----------------------
- Container-only: a Report (external assertion, "what the world says") with an
  author Organization, a TLP marking, one External Reference to the article,
  and the rendered PDF attached. No SDOs, Observables,
  Relationships, Sightings or Labels are created (feed categories are not
  collection requirements, so they are never applied as Labels).
- published = the article's own publication date from the feed. An item with
  no parseable date is skipped, never stamped with ingestion time.
- Author: one "Institute for Strategic Dialogue" Organization, resolved once at startup.

Elasticsearch footprint
-----------------------
OpenCTI stores every object, relation and work record in Elasticsearch, so the
connector keeps both query and write volume low:
- Dedup takes at most two batched queries per poll (External References by
  URL, then the Reports that cite them), returning only id/url fields,
  instead of one full read per item.
- Exact-match keyword filters only; no full-text ``search`` queries.
- A work record is opened only when a poll has new items, so idle polls write
  nothing to the history index.
- One mutation per new article: the Report is created with its PDF attached
  inline (``files``, marked via ``filesMarkings``) and update=False, so
  there is no follow-up file-upload update and no upsert rewrite of existing
  Reports.
- The Report description is plain text capped at MAX_DESCRIPTION_CHARS; full
  article text lives only in the attached PDF (object storage), never in
  the indexed Report document. The PDF is size-capped.
- Author, marking and vocabulary are resolved once at startup, not per item.

PDF creation
------------
House standard (PDF-RENDERER-CLIENT-V1): one PDF per Report, the live
article rendered by the pdf-renderer service through the shared client
microservices/make_pdf.py (render_live_pdf -> POST $PDF_RENDERER_URL/render/url,
default http://pdf-renderer:8000). The service extracts the article with the
site-specific CONTENT_SELECTORS, strips HIDE_SELECTORS plus its own default
chrome list, defangs links, and adds the feed title and a byline (author,
publisher, date). Failure policy:
- RendererUnavailable (service down, busy, timed out, 5xx): retried
  render_retries times with backoff; if it persists the poll stops and the
  remaining items wait for the next poll. A renderer outage is not counted
  against items, so no article is given up because the service was down;
- the site itself failing (the renderer reports a navigation failure, an
  HTTP 429/5xx from the site, or a bot challenge): transient for that item,
  retried on later polls up to MAX_TRANSIENT_ATTEMPTS;
- ContentUnavailable otherwise (page reached but no usable article, or URL
  blocked): the Report is created without a PDF and a WARNING is logged.

Report type (Crucible Collector)
--------------------------------
When CRUCIBLE_COLLECTOR_URL is set, each new article's full text (the feed's
content:encoded where present, otherwise the article page's text, fetched
with one plain GET only when the Collector is configured) is POSTed through
the shared microservices/classify_report.py helper, and the returned type
becomes report_types. The Collector's collection_requirements
are ignored (Labels are reserved for collection requirements). On error or
timeout the helper logs a WARNING and the Report gets open-source-reporting.
With the variable unset, or the shared helper not mounted, no call is made.

Deduplication, failures and state
---------------------------------
There is no persisted state. Dedup is graph-driven by External Reference URL:
an article counts as ingested when an External Reference with its URL exists
AND some Report cites that reference (so a reference orphaned by a failed
Report create does not block a retry, and an article already ingested by
any connector under the same URL is not duplicated). Anything ingested is
skipped before the expensive render. New Reports also get a deterministic
STIX id (uuid5 over the canonical article URL). Failures are split:
- permanent (no usable date): remembered in memory for the
  life of the process and never retried;
- transient (renderer unavailable or API error): retried on later polls
  while the item is still in the feed, up to MAX_TRANSIENT_ATTEMPTS polls.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import html
from html.parser import HTMLParser
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse, urlunparse
from xml.etree import ElementTree

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from pycti.api.opencti_api_client import File

# Shared Crucible classifier. In containers the microservices/ package is
# volume-mounted at /microservices (the parent of /app). Without it the
# connector still runs standalone and keeps its default report_type.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
try:
    from microservices.classify_report import classify_report  # noqa: E402
except ImportError:
    classify_report = None

# House pdf-renderer client (PDF-RENDERER-CLIENT-V1). Required: every Report
# carries the rendered live article, so the shared package must be mounted.
from microservices.make_pdf import (  # noqa: E402
    ContentUnavailable,
    RendererUnavailable,
    render_live_pdf,
)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

SOURCE_NAME = "Institute for Strategic Dialogue"
FILE_PREFIX = "isd_global"

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

# Only https article links on these hosts are accepted from the feed, so a
# malformed or hijacked item cannot make the renderer fetch arbitrary URLs.
ALLOWED_HOSTS = {"www.isdglobal.org"}

# Article container on the live site (verified against article markup,
# Nov 2026). It wraps the headline, byline and body.
CONTENT_SELECTOR = "article"

# Selectors tried in order, first match wins (renderer and text extraction).
# Fallbacks cover article layouts seen live that lack the primary container.
CONTENT_SELECTORS = [CONTENT_SELECTOR]

# Scope filters (checked before dedup, so out-of-scope items cost nothing).
# CATEGORY_KEEP: items carrying any of these categories are always in scope
# (the deny and title rules below do not apply to them; MAX_AGE_DAYS still
# does). CATEGORY_ALLOW: if non-empty, keep only items with one of these feed
# categories (case-insensitive). CATEGORY_DENY: drop items carrying any of
# these categories (digests, teasers, events). EXCLUDE_URL_RE / EXCLUDE_TITLE_RE: drop items
# whose link / title matches. MAX_AGE_DAYS: drop items published longer ago
# than this (0 = no limit); configurable as max_age_days.
CATEGORY_KEEP = set()
CATEGORY_ALLOW = set()
CATEGORY_DENY = set()
EXCLUDE_URL_RE = None
EXCLUDE_TITLE_RE = None
MAX_AGE_DAYS = 30

# Per-site behaviour switches.
# SLUG_FROM_ID: name the PDF after the URL's numeric post id (for sites whose
#   article URLs end in an id after a non-descriptive segment).
# BYLINE_AUTHOR: print the feed's author on the PDF byline (off when the feed
#   author is a login, email or team account rather than a person).
# NO_CONTENT_IS_TRANSIENT: treat "no usable article" from the renderer as a
#   transient failure (retried) instead of creating the Report without a PDF;
#   for sites whose bot challenge looks like an empty page.
SLUG_FROM_ID = False
BYLINE_AUTHOR = False
NO_CONTENT_IS_TRANSIENT = False

# Discovery: "feed" (RSS 2.0 / Atom), "sitemap" (XML sitemap or sitemap
# index), "listing" (article links matched on an HTML listing page) or "json"
# (a JSON API). Items found without a title or date get them from the
# article page itself (see _page_meta).
DISCOVERY = "feed"
DISCOVERY_CONFIG = {}
# Hosts whose feed links are redirectors: each link is resolved once (HEAD,
# no body) to the real article URL, which is what the Report cites.
RESOLVE_REDIRECT_HOSTS = set()
# Optional selector of an element whose text carries the article date, used
# only when the page has no machine-readable date.
DATE_TEXT_SELECTOR = None
# At most this many article pages are fetched per poll only to learn an
# item's date or title; the rest wait for the next poll.
MAX_PAGE_PROBES = 50

# Chrome inside (or around) the container that is not part of the story.
HIDE_SELECTORS = [
    ".related-col",                      # right column: issues terms + LATEST DIGITAL DISPATCHES / related publications list
    ".staff-profile-title",              # ISD CONTRIBUTORS heading
    ".staff-profile-cards",              # contributor cards with job titles (byline already in p.pub-authors)
    "div:has(> .media-bi)",              # publication pages: IN THE MEDIA press-mention carousel
    "div:has(> .see-also)",              # publication pages: SEE ALSO related-publications list
]

# Elasticsearch / storage guards. (Article text for the classifier is sent in
# full and is never stored on the Report.)
MAX_DESCRIPTION_CHARS = 2000
MAX_PDF_BYTES = 25 * 1024 * 1024

# Give up on an item after this many polls with transient failures.
MAX_TRANSIENT_ATTEMPTS = 5

# Feed dates earlier than this are treated as unusable.
MIN_VALID_YEAR = 1990

RSS_CONTENT_NS = "{http://purl.org/rss/1.0/modules/content/}encoded"
DC_CREATOR_NS = "{http://purl.org/dc/elements/1.1/}creator"
ATOM_NS = "{http://www.w3.org/2005/Atom}"


# The renderer reports some SITE problems as "no usable article" (HTTP 422):
# the page failed to load, the site answered 429/5xx, or a bot challenge.
# Those are transient for the item. A 422 whose detail is a validation-error
# list means the request itself was rejected (client/service mismatch), which
# is a renderer problem, not a content one.
_SITE_FAILURE_RE = re.compile(
    r"navigation failed|HTTP (?:408|425|429|5\d\d) from|bot challenge", re.IGNORECASE)
_VALIDATION_ERROR_RE = re.compile(r'"detail"\s*:\s*\[')


class _SiteUnavailable(Exception):
    """The article's site failed for this poll; retry the item later."""


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _report_id(link):
    """Return a deterministic STIX Report id derived from the article URL."""
    return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))


def _slug_from_url(url):
    """Return a filesystem-safe slug from the URL path ('report' for root)."""
    segments = [s for s in urlparse(url).path.split("/") if s]
    if SLUG_FROM_ID:
        # The longest numeric segment is the article id (/article/5357/1 -> 5357).
        ids = [seg for seg in segments if seg.isdigit()]
        if ids:
            return f"{FILE_PREFIX}-{max(ids, key=len)}"
    # Prefer the last non-numeric segment (some sites end with a numeric id).
    for seg in reversed(segments):
        if not seg.isdigit():
            seg = re.sub(r"\.html?$", "", seg)
            return re.sub(r"[^A-Za-z0-9._-]", "_", seg)[:120] or "report"
    return segments[-1] if segments else "report"


def _parse_date(date_str):
    """Parse a date (RFC 2822, ISO 8601, or a common written form such as
    "Friday, October 30, 2026 - 17:15" or "11 Nov 2026 12:00:00 AM CET") to
    an ISO-8601 UTC string."""
    if (date_str and _LOOSE_FIRST_RE.search(date_str)
            and not re.match(r"\s*\d{4}-", date_str)):
        return _parse_loose_date(date_str)
    parsed = _parse_rfc2822(date_str)
    if parsed or not date_str:
        return parsed
    try:
        dt = datetime.fromisoformat(date_str.strip().replace("Z", "+00:00"))
    except ValueError:
        return _parse_loose_date(date_str)
    if dt.year < MIN_VALID_YEAR:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


# Written dates the RFC 2822 parser gets wrong (it ignores AM/PM and a
# colon offset such as +02:00): parsed by _parse_loose_date first.
_LOOSE_FIRST_RE = re.compile(r"\d\s*[AaPp]\.?[Mm]\b|[+-]\d{2}:\d{2}\s*$")
_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
_TZ_HOURS = {"utc": 0, "gmt": 0, "z": 0, "wet": 0, "bst": 1, "cet": 1, "cest": 2,
             "eet": 2, "eest": 3, "est": -5, "edt": -4, "cst": -6, "cdt": -5,
             "mst": -7, "mdt": -6, "pst": -8, "pdt": -7, "aest": 10, "aedt": 11}
_LOOSE_DATE_RE = re.compile(
    r"(?:(?P<d1>\d{1,2})(?:st|nd|rd|th)?\s+(?P<m1>[A-Za-z]{3,9})\.?,?\s+(?P<y1>\d{4})"
    r"|(?P<m2>[A-Za-z]{3,9})\.?\s+(?P<d2>\d{1,2})(?:st|nd|rd|th)?,?\s+(?P<y2>\d{4})"
    r"|(?P<y3>\d{4})-(?P<o3>\d{1,2})-(?P<d3>\d{1,2}))"
    r"(?:[\sT,@-]{0,4}(?P<h>\d{1,2}):(?P<mi>\d{2})(?::(?P<s>\d{2}))?"
    r"\s*(?P<ap>[AaPp]\.?[Mm]\b\.?)?)?"
    r"(?:\s*(?P<tz>[A-Za-z]{1,4}\b|[+-]\d{2}:?\d{2}))?")


_RELATIVE_RE = re.compile(r"\b(\d+|an?|one)\s+(minute|hour|day|week)s?\s+ago\b"
    r"|\b(yesterday|today)\b", re.IGNORECASE)
_RELATIVE_UNITS = {"minute": 60, "hour": 3600, "day": 86400, "week": 604800}


def _parse_relative_date(date_str, now=None):
    """Parse "8 hours ago", "1 day ago", "yesterday" against `now` (UTC), or None."""
    match = _RELATIVE_RE.search(date_str or "")
    if not match:
        return None
    now = now or datetime.now(timezone.utc)
    if match.group(3):
        delta = timedelta(days=1 if match.group(3).lower() == "yesterday" else 0)
    else:
        count = match.group(1).lower()
        count = 1 if count in ("a", "an", "one") else int(count)
        delta = timedelta(seconds=count * _RELATIVE_UNITS[match.group(2).lower()])
    return (now - delta).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _parse_loose_date(date_str):
    """Parse a written date ("Nov 11, 2026 1:11pm", "30 October 2026"), or None.

    Known zone abbreviations and numeric offsets are applied; anything else
    is taken as UTC (the date is what matters for a Report).
    """
    for match in _LOOSE_DATE_RE.finditer(date_str or ""):
        g = match.groupdict()
        month_name = g["m1"] or g["m2"]
        if month_name:
            month = _MONTHS.get(month_name[:3].lower())
            day, year = int(g["d1"] or g["d2"]), int(g["y1"] or g["y2"])
        else:
            month, day, year = int(g["o3"]), int(g["d3"]), int(g["y3"])
        if not month:
            continue
        hour, minute, second = int(g["h"] or 0), int(g["mi"] or 0), int(g["s"] or 0)
        if g["ap"]:
            hour = hour % 12 + (12 if g["ap"][0] in "Pp" else 0)
        offset = timedelta(0)
        tz = (g["tz"] or "").lower()
        if tz[:1] in "+-" and tz:
            digits = tz[1:].replace(":", "")
            offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:] or 0))
            offset = offset if tz[0] == "+" else -offset
        elif tz in _TZ_HOURS:
            offset = timedelta(hours=_TZ_HOURS[tz])
        try:
            dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc) - offset
        except ValueError:
            continue
        if dt.year < MIN_VALID_YEAR:
            continue
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    # Listing/byline text such as "8 hours ago" (relative to now).
    return _parse_relative_date(date_str)


def _parse_rfc2822(date_str):
    """Parse an RFC 2822 date string and return an ISO-8601 UTC string."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None or dt.year < MIN_VALID_YEAR:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_NON_TEXT_RE = re.compile(r"<(script|style|noscript)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)


# Feed summaries end with a truncation marker; written as escapes so the
# source stays ASCII-only.
_ELLIPSIS = "\u2026"
_TRUNCATION_MARKERS = ("[...]", "[" + _ELLIPSIS + "]", _ELLIPSIS)
# WordPress feeds end each summary with "The post <title> appeared first on
# <site>." That boilerplate is not part of the article.
_WP_TRAILER_RE = re.compile(r"\s*The post .{1,500}? appeared first on .{1,150}?\s*\.?\s*$")


def _html_to_text(value, limit=MAX_DESCRIPTION_CHARS):
    """Strip tags, decode entities and collapse whitespace.

    Caps the result at `limit` characters; limit=None returns the full text.
    """
    if not value:
        return ""
    # Drop non-text blocks, then tags, then decode entities.
    text = _NON_TEXT_RE.sub(" ", value)
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    # Some feeds entity-encode their HTML twice ("&lt;p&gt;"): strip again.
    text = _TAG_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text).strip()
    text = _WP_TRAILER_RE.sub("", text)
    # Remove a trailing "read more" truncation marker.
    for marker in _TRUNCATION_MARKERS:
        if text.endswith(marker):
            text = text[: -len(marker)].rstrip()
            break
    # Cap (descriptions only).
    if limit is not None and len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
              "meta", "param", "source", "track", "wbr"}


def _selector_parts(selector):
    """Split the first compound of a CSS selector into (tag, id, classes)."""
    first = selector.split("~")[0].strip().split()[0]
    tag = re.match(r"[a-zA-Z][a-zA-Z0-9]*", first)
    return (
        tag.group(0).lower() if tag else None,
        (re.findall(r"#([A-Za-z0-9_-]+)", first) or [None])[0],
        set(re.findall(r"\.([A-Za-z0-9_-]+)", first)),
    )


def _matches(parts, tag, attrs):
    """True when a start tag matches a (tag, id, classes) compound."""
    want_tag, want_id, want_classes = parts
    a = dict(attrs)
    return ((want_tag is None or tag == want_tag)
            and (want_id is None or a.get("id") == want_id)
            and want_classes <= set((a.get("class") or "").split()))


def _hide_parts():
    """Simple hide selectors (tag / id / class compounds) usable by the text parser.

    Sibling (~), descendant, attribute and pseudo-class selectors are left to
    the renderer.
    """
    parts = []
    for sel in HIDE_SELECTORS:
        if any(ch in sel for ch in "~[ >:+"):
            continue
        p = _selector_parts(sel)
        if p[0] or p[1] or p[2]:
            parts.append(p)
    return parts


_META_KEYS = ("og:description", "description", "twitter:description")
_TITLE_KEYS = ("og:title", "twitter:title")
_DATE_KEYS = ("article:published_time", "og:published_time", "datepublished",
              "citation_publication_date", "dc.date.issued", "dcterms.issued",
              "dc.date", "date", "pubdate", "publish-date", "article.published")


class _PageMetaParser(HTMLParser):
    """Collect a page's description/title/date metadata (any attribute order).

    Gathers <meta> name/property/itemprop values, JSON-LD script bodies,
    <time datetime>, the first <h1> and <title> texts, and the text of the
    first element matching DATE_TEXT_SELECTOR.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found = {}
        self.ld_json = []
        self.times = []
        self.h1 = self.title = self.date_text = ""
        self._capture = None      # "h1" | "title" | "ld" | "date"
        self._buf = []
        self._date_parts = (_selector_parts(DATE_TEXT_SELECTOR)
                            if DATE_TEXT_SELECTOR else None)
        self._date_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta":
            key = (attrs.get("property") or attrs.get("name")
                   or attrs.get("itemprop") or "").strip().lower()
            if key and (attrs.get("content") or "").strip():
                self.found.setdefault(key, attrs["content"].strip())
            return
        if tag == "time" and attrs.get("datetime"):
            self.times.append(attrs["datetime"])
        if (attrs.get("itemprop") or "").lower() == "datepublished":
            value = attrs.get("datetime") or attrs.get("content")
            if value:
                self.found.setdefault("datepublished", value)
        if self._capture == "date" and tag not in _VOID_TAGS:
            self._date_depth += 1
            return
        if self._capture is None:
            if tag == "script" and "ld+json" in (attrs.get("type") or ""):
                self._capture, self._buf = "ld", []
            elif tag == "h1" and not self.h1:
                self._capture, self._buf = "h1", []
            elif tag == "title" and not self.title:
                self._capture, self._buf = "title", []
            elif (self._date_parts and not self.date_text
                  and _matches(self._date_parts, tag, attrs)):
                self._capture, self._buf, self._date_depth = "date", [], 1

    def handle_endtag(self, tag):
        if self._capture == "date":
            if tag in _VOID_TAGS:
                return
            self._date_depth -= 1
            if self._date_depth > 0:
                return
            self.date_text = " ".join(self._buf).strip()
        elif self._capture == "ld" and tag == "script":
            self.ld_json.append("".join(self._buf))
        elif self._capture in ("h1", "title") and tag == self._capture:
            setattr(self, self._capture, _WS_RE.sub(" ", " ".join(self._buf)).strip())
        else:
            return
        self._capture = None

    def handle_data(self, data):
        if self._capture:
            self._buf.append(data)


def _ld_values(node, key):
    """Every value of `key` anywhere in a parsed JSON-LD document."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, str):
                yield v
            else:
                yield from _ld_values(v, key)
    elif isinstance(node, list):
        for v in node:
            yield from _ld_values(v, key)


def _page_meta(html_bytes):
    """Parsed page metadata (a _PageMetaParser), or None for an empty page."""
    if not html_bytes:
        return None
    parser = _PageMetaParser()
    try:
        parser.feed(html_bytes.decode("utf-8", errors="replace"))
    except Exception:  # malformed markup: use whatever was collected
        pass
    return parser


def _meta_description(html_bytes):
    """The page's own summary (og:description, then description), or ""."""
    meta = _page_meta(html_bytes)
    if meta is None:
        return ""
    for key in _META_KEYS:
        if meta.found.get(key):
            return _html_to_text(html.escape(meta.found[key]))
    return ""


def _page_title(html_bytes):
    """The article's title from its page (og:title, h1, then <title>), or ""."""
    meta = _page_meta(html_bytes)
    if meta is None:
        return ""
    name = re.escape(SOURCE_NAME)
    affix = re.compile(rf"^\s*{name}\s*[:|\u2013-]\s*|\s*[:|\u2013-]\s*{name}\s*$",
                       re.IGNORECASE)
    for value in [meta.found.get(k) for k in _TITLE_KEYS] + [meta.h1, meta.title]:
        if value and value.strip():
            # Drop a "Site Name: " prefix or " | Site Name" suffix.
            title = html.unescape(_WS_RE.sub(" ", value)).strip()
            return affix.sub("", title).strip() or title
    return ""


def _page_date(html_bytes):
    """The article's publication date from its page (ISO-8601 UTC), or None.

    Order: publication <meta> tags, JSON-LD datePublished, the first
    <time datetime>, then the DATE_TEXT_SELECTOR element's text.
    """
    meta = _page_meta(html_bytes)
    if meta is None:
        return None
    candidates = [meta.found.get(k) for k in _DATE_KEYS]
    for block in meta.ld_json:
        try:
            candidates.extend(_ld_values(json.loads(block), "datePublished"))
        except ValueError:
            continue
    candidates += meta.times[:1] + [meta.date_text]
    for value in candidates:
        parsed = _parse_date(value) if value else None
        if parsed:
            return parsed
    return None


class _ArticleTextParser(HTMLParser):
    """Collect the text inside the first element matching the content selector,
    leaving out script/style and the same chrome the PDF render hides."""

    def __init__(self, selector):
        super().__init__(convert_charrefs=True)
        self.content = _selector_parts(selector)
        self.hide = _hide_parts()
        self.depth = 0          # nesting depth inside the matched element
        self.done = False
        self.skip_depth = 0     # >0 while inside a skipped subtree
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in _VOID_TAGS or self.done:
            return
        if not self.depth:
            if _matches(self.content, tag, attrs):
                self.depth = 1
            return
        self.depth += 1
        if self.skip_depth:
            self.skip_depth += 1
        elif tag in ("script", "style", "noscript") or any(
                _matches(p, tag, attrs) for p in self.hide):
            self.skip_depth = 1

    def handle_endtag(self, tag):
        if not self.depth or tag in _VOID_TAGS:
            return
        if self.skip_depth:
            self.skip_depth -= 1
        self.depth -= 1
        if not self.depth:
            self.done = True

    def handle_data(self, data):
        if self.depth and not self.skip_depth:
            self.parts.append(data)


def _article_text(html_bytes, limit=None):
    """Return the article's full plain text from the article page HTML.

    Uses the first CONTENT_SELECTORS element that yields text; falls back to
    the whole page's text when none matches. Not capped unless `limit` is
    given.
    """
    if not html_bytes:
        return ""
    page = html_bytes.decode("utf-8", errors="replace")
    for selector in CONTENT_SELECTORS:
        parser = _ArticleTextParser(selector)
        try:
            parser.feed(page)
        except Exception:  # malformed markup: try the next selector
            continue
        text = " ".join(parser.parts)
        if text.strip():
            return _html_to_text(html.escape(text), limit)
    return _html_to_text(page, limit)


def _canonical_link(link):
    """Return the https link without fragment or utm_* tracking parameters,
    or None if the host is not allowed."""
    try:
        parsed = urlparse((link or "").strip())
    except ValueError:
        return None
    host = parsed.hostname or ""
    if parsed.scheme not in ("https", "http") or (
            host not in ALLOWED_HOSTS and host not in RESOLVE_REDIRECT_HOSTS):
        return None
    # Allow-listed hosts all serve https; an http:// feed link is upgraded.
    parsed = parsed._replace(scheme="https", path=parsed.path.replace(" ", "%20"))
    # Drop utm_* pairs from the raw query; every other byte is kept as-is so
    # the URL still matches References stored by earlier runs.
    query = "&".join(p for p in parsed.query.split("&")
                     if p and not p.split("=", 1)[0].lower().startswith("utm_"))
    return urlunparse(parsed._replace(fragment="", query=query))


# Some feeds are invalid XML: a bare "&" in a link, an HTML named entity
# (&nbsp;) XML does not define, or a raw control character.
_CDATA_RE = re.compile(rb"(<!\[CDATA\[.*?\]\]>)", re.DOTALL)
_AMP_RE = re.compile(rb"&(#\d+;|#x[0-9A-Fa-f]+;|[A-Za-z][A-Za-z0-9]*;)?")
_XML_CTRL_RE = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_XML_ENTITIES = {b"amp;", b"lt;", b"gt;", b"quot;", b"apos;"}


def _fix_amp(match):
    """Keep valid XML references and escape every other ampersand.

    An HTML named entity such as &nbsp; becomes literal "&amp;nbsp;", which
    the text clean-up (html.unescape) decodes later.
    """
    ref = match.group(1)
    if ref is not None and (ref.startswith(b"#") or ref in _XML_ENTITIES):
        return b"&" + ref
    return b"&amp;" + (ref or b"")


def _repair_xml(xml_bytes):
    """Repair ampersands outside CDATA sections and drop control characters.

    CDATA content is left untouched: an "&" there is already literal text.
    """
    parts = _CDATA_RE.split(_XML_CTRL_RE.sub(b"", xml_bytes))
    return b"".join(part if part.startswith(b"<![CDATA[") else _AMP_RE.sub(_fix_amp, part)
                    for part in parts)


def _parse_xml(xml_bytes):
    """Parse feed XML, retrying once after _repair_xml.

    Raises ElementTree.ParseError when the feed is still malformed.
    """
    try:
        return ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError:
        repaired = _repair_xml(xml_bytes)
    try:
        return ElementTree.fromstring(repaired)
    except ElementTree.ParseError:
        # Last resort for a feed with invalid UTF-8 bytes (e.g. Mac-Roman
        # dashes): replace them and drop the encoding declaration.
        text = repaired.decode("utf-8", errors="replace")
        return ElementTree.fromstring(re.sub(r"^<\?xml[^>]*\?>", "", text.lstrip()))


def _out_of_scope(item, max_age_days=MAX_AGE_DAYS, now=None):
    """Return why an item is outside this connector's scope, or None."""
    cats = {c.strip().lower() for c in item.get("categories", [])}
    kept = bool(CATEGORY_KEEP and cats & {c.lower() for c in CATEGORY_KEEP})
    if kept:
        pass  # always in scope; only the age limit below applies
    elif CATEGORY_ALLOW and not cats & {c.lower() for c in CATEGORY_ALLOW}:
        return "category not in scope"
    elif CATEGORY_DENY and cats & {c.lower() for c in CATEGORY_DENY}:
        return "category excluded"
    elif EXCLUDE_URL_RE is not None and EXCLUDE_URL_RE.search(item["link"]):
        return "url excluded"
    elif EXCLUDE_TITLE_RE is not None and EXCLUDE_TITLE_RE.search(item["title"]):
        return "title excluded"
    if max_age_days:
        # A sitemap lastmod is never earlier than publication, so an item
        # whose lastmod is already too old was published too long ago.
        published = _parse_date(item.get("pub_date")) or _parse_date(item.get("lastmod"))
        now = now or datetime.now(timezone.utc)
        if published and datetime.fromisoformat(published) < now - timedelta(days=max_age_days):
            return "older than max_age_days"
    return None


def _el_text(el):
    """All text inside an element (child markup such as <a> included), unescaped."""
    if el is None:
        return ""
    return html.unescape(_WS_RE.sub(" ", "".join(el.itertext())).strip())


def _atom_link(entry):
    """Return the entry's alternate (article) link href, or None."""
    for link_el in entry.findall(ATOM_NS + "link"):
        if link_el.get("rel", "alternate") == "alternate" and link_el.get("href"):
            return link_el.get("href")
    return None


def _atom_text(el):
    """Text of an Atom text construct (text, html or inline xhtml)."""
    if el is None:
        return None
    if el.get("type") == "xhtml":
        return html.escape("".join(el.itertext()))
    return el.text


def _parse_atom(root):
    """Parse Atom <entry> elements into the same item dicts as RSS."""
    items = []
    seen = set()
    for entry in root.iter(ATOM_NS + "entry"):
        link = _canonical_link(_atom_link(entry))
        if not link or link in seen:
            continue
        seen.add(link)
        summary = _atom_text(entry.find(ATOM_NS + "summary"))
        content = _atom_text(entry.find(ATOM_NS + "content"))
        items.append({
            "title": _el_text(entry.find(ATOM_NS + "title")),
            "link": link,
            "description": _html_to_text(summary or content),
            # Published date; updated only when the feed has no published.
            "pub_date": (entry.findtext(ATOM_NS + "published")
                         or entry.findtext(ATOM_NS + "updated") or "").strip(),
            "full_text": _html_to_text(content, None),
            "creator": html.unescape(
                (entry.findtext(f"{ATOM_NS}author/{ATOM_NS}name") or "").strip()),
            "categories": [c.get("term", "") for c in entry.findall(ATOM_NS + "category")],
        })
    return items


def _parse_feed(xml_bytes):
    """Parse RSS 2.0 or Atom bytes into item dicts (deduplicated, allowed hosts only).

    Raises ElementTree.ParseError on malformed XML.
    """
    root = _parse_xml(xml_bytes)
    if root.tag == ATOM_NS + "feed":
        return _parse_atom(root)
    items = []
    seen = set()
    for item_el in root.iter("item"):
        link = _canonical_link(item_el.findtext("link"))
        if not link or link in seen:
            continue
        seen.add(link)
        items.append({
            "title": _el_text(item_el.find("title")),
            "link": link,
            "description": _html_to_text(item_el.findtext("description")),
            "pub_date": (item_el.findtext("pubDate") or "").strip(),
            # Byline author for the PDF header (dc:creator, when present).
            "creator": _el_text(item_el.find(DC_CREATOR_NS)),
            "categories": [html.unescape(c.text or "") for c in item_el.findall("category")],
            # Full text when the feed carries it; used only for classification.
            "full_text": _html_to_text(item_el.findtext(RSS_CONTENT_NS), None),
        })
    return items


SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
NEWS_NS = "{http://www.google.com/schemas/sitemap-news/0.9}"


def _new_item(link, title="", pub_date="", description="", lastmod=""):
    """An item dict as the feed parser makes them (no categories/full text)."""
    return {"title": title, "link": link, "description": description,
            "pub_date": pub_date, "lastmod": lastmod, "creator": "",
            "categories": [], "full_text": ""}


def _parse_sitemap(xml_bytes):
    """Parse a sitemap: ("index", [(loc, lastmod)]) or ("urlset", [items]).

    Article URLs are filtered by DISCOVERY_CONFIG["url_re"] when set; a
    news-sitemap publication date becomes the item's pub_date.
    """
    root = _parse_xml(xml_bytes)
    if root.tag == SITEMAP_NS + "sitemapindex":
        return "index", [((s.findtext(SITEMAP_NS + "loc") or "").strip(),
                          (s.findtext(SITEMAP_NS + "lastmod") or "").strip())
                         for s in root.iter(SITEMAP_NS + "sitemap")]
    url_re = DISCOVERY_CONFIG.get("url_re")
    items, seen = [], set()
    for url_el in root.iter(SITEMAP_NS + "url"):
        link = _canonical_link(url_el.findtext(SITEMAP_NS + "loc"))
        if not link or link in seen or (url_re and not re.search(url_re, link)):
            continue
        seen.add(link)
        items.append(_new_item(
            link,
            title=_el_text(url_el.find(f"{NEWS_NS}news/{NEWS_NS}title")),
            pub_date=(url_el.findtext(f"{NEWS_NS}news/{NEWS_NS}publication_date") or "").strip(),
            lastmod=(url_el.findtext(SITEMAP_NS + "lastmod") or "").strip()))
    # Newest first, so the item cap keeps the recent end.
    items.sort(key=lambda i: _parse_date(i["lastmod"] or i["pub_date"]) or "", reverse=True)
    return "urlset", items[:DISCOVERY_CONFIG.get("max_items", 200)]


_ANCHOR_RE = re.compile(r"<a\b[^>]*?\bhref\s*=\s*([\"'])(.*?)\1[^>]*>(.*?)</a\s*>",
                        re.IGNORECASE | re.DOTALL)
_GENERIC_ANCHOR_RE = re.compile(
    r"^\W*(?:(?:read|learn|see|view|find out)(?: the)? more|more|read|continue reading|"
    r"read (?:the )?(?:full )?(?:story|article|post)|full story|click here)\W*$", re.IGNORECASE)


def _parse_listing(html_bytes, base_url):
    """Article links on an HTML listing page: hrefs matching
    DISCOVERY_CONFIG["link_re"], in page order, anchor text as the title."""
    page = html_bytes.decode("utf-8", errors="replace")
    link_re = re.compile(DISCOVERY_CONFIG["link_re"])
    items, seen = [], {}
    for match in _ANCHOR_RE.finditer(page):
        href = html.unescape(match.group(2)).strip()
        link = _canonical_link(urljoin(base_url, href)) if link_re.search(href) else None
        if not link:
            continue
        # Cards often link an article twice (image or "Read more" plus the
        # headline): generic or empty anchor text is no title, and a later
        # anchor to the same article supplies it.
        title = _html_to_text(match.group(3), 300)
        title = "" if _GENERIC_ANCHOR_RE.match(title) else title
        if link in seen:
            if title and not seen[link]["title"]:
                seen[link]["title"] = title
            continue
        seen[link] = _new_item(link, title=title)
        items.append(seen[link])
    return items[:DISCOVERY_CONFIG.get("max_items", 200)]


def _json_path(node, path):
    for key in [k for k in (path or "").split(".") if k]:
        node = node.get(key) if isinstance(node, dict) else None
    return node


def _parse_json(raw):
    """Items from a JSON API: records at DISCOVERY_CONFIG["items"] (dotted
    path), fields mapped by DISCOVERY_CONFIG["title"/"date"/"description"],
    link built from DISCOVERY_CONFIG["link"] (a str.format template over the
    record's fields)."""
    records = _json_path(json.loads(raw), DISCOVERY_CONFIG.get("items", ""))
    items, seen = [], set()
    for rec in records if isinstance(records, list) else []:
        if not isinstance(rec, dict):
            continue
        try:
            link = _canonical_link(DISCOVERY_CONFIG["link"].format(**rec))
        except (KeyError, IndexError, ValueError):
            continue
        if not link or link in seen:
            continue
        seen.add(link)
        field = lambda name: str(_json_path(rec, DISCOVERY_CONFIG.get(name, "")) or "")  # noqa: E731
        items.append(_new_item(link, title=html.unescape(field("title")).strip(),
                               pub_date=field("date").strip(),
                               description=_html_to_text(field("description"))))
    return items


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

class IsdGlobalConnector:
    """External-import connector that mirrors Institute for Strategic Dialogue articles into Reports."""

    def __init__(self):
        """Load configuration and initialise the HTTP session."""
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = {}
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}

        self.helper = OpenCTIConnectorHelper(config)

        def setting(name, default, number=False):
            value = get_config_variable(
                f"ISD_GLOBAL_{name.upper()}", ["isd_global", name], config,
                isNumber=number, default=default,
            )
            if value in (None, ""):
                value = default
            return int(value) if number else value

        # One or more feed URLs, comma-separated.
        self.feed_urls = [u.strip() for u in str(setting("feed_url", "https://www.isdglobal.org/feed/?post_type=digital-dispatch,https://www.isdglobal.org/feed/?post_type=publication")).split(",")
                          if u.strip()]
        self.poll_interval = setting("poll_interval", 3600, number=True)
        self.request_delay = setting("request_delay", 3, number=True)
        self.max_reports = setting("max_reports", 0, number=True)
        self.max_age_days = setting("max_age_days", MAX_AGE_DAYS, number=True)
        self.render_retries = setting("render_retries", 3, number=True)
        self.confidence = setting("confidence", 50, number=True)
        self.report_type = setting("report_type", "open-source-reporting")
        self.tlp_name = setting("tlp", "TLP:CLEAR")
        self.author_name = setting("author_name", "Institute for Strategic Dialogue")

        # The renderer address comes from PDF_RENDERER_URL inside the shared
        # client (default http://pdf-renderer:8000); only the timeout is set here.
        self.render_timeout = setting("pdf_render_timeout", 120, number=True)

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA,
                                     "Accept-Language": "en-US,en;q=0.9"})
        self.resolved = {}             # redirector link -> article link (or None)

        self.author_id = None
        self.marking_id = None
        self.poll_count = 0
        self.prev_poll_clean = True    # False after a poll with transient failures
        self.permanent_skips = {}      # link -> reason
        self.transient_failures = {}   # link -> consecutive failed polls

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Create or look up the author identity, marking, and vocabulary."""
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Institute for Strategic Dialogue (ISD) - independent non-profit researching extremism, hate, disinformation and online manipulation.",
        )
        self.author_id = author["id"]
        self.helper.log_info(
            f"Resolved author identity '{self.author_name}': {self.author_id}"
        )

        marking = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [self.tlp_name]}],
                "filterGroups": [],
            }
        )
        if not marking:
            raise RuntimeError(
                f"Could not resolve marking '{self.tlp_name}'. Refusing to create "
                f"Reports without a resolved marking UUID."
            )
        self.marking_id = marking["id"]
        self.helper.log_info(f"Resolved marking {self.tlp_name}: {self.marking_id}")

        try:
            self.helper.api.vocabulary.create(
                name=self.report_type,
                category="report_types_ov",
                description="Open-source reporting ingested from public OSINT publishers.",
            )
        except Exception as exc:
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc}). "
                f"Add it under Settings -> Taxonomies -> Report types if missing."
            )

    # ------------------------------------------------------------------ #
    # Feed + graph lookups
    # ------------------------------------------------------------------ #

    def _fetch_feed(self):
        """Fetch and parse every configured feed.

        Returns the merged items (feed order, deduplicated by link), or None
        when every feed failed. Sets self.fetch_complete to False when any
        feed failed, so per-link bookkeeping is not pruned for its items.
        """
        items = []
        seen = set()
        failures = 0
        for feed_url in self.feed_urls:
            try:
                parsed = self._fetch_source(feed_url)
            except (ElementTree.ParseError, ValueError) as exc:
                self.helper.log_error(f"Failed to parse feed XML from {feed_url}: {exc}")
                failures += 1
                continue
            except Exception as exc:
                self.helper.log_error(f"Failed to fetch feed {feed_url}: {exc}")
                failures += 1
                continue
            for item in parsed:
                if item["link"] not in seen:
                    seen.add(item["link"])
                    items.append(item)
        self.fetch_complete = failures == 0
        if failures == len(self.feed_urls):
            return None
        return self._resolve_redirects(items)

    def _get(self, url):
        resp = self.session.get(url, timeout=60)
        resp.raise_for_status()
        return resp.content

    def _fetch_source(self, url):
        """Fetch one source URL and parse it with the site's discovery mode."""
        content = self._get(url)
        if DISCOVERY == "feed":
            return _parse_feed(content)
        if DISCOVERY == "listing":
            return _parse_listing(content, url)
        if DISCOVERY == "json":
            return _parse_json(content)
        kind, entries = _parse_sitemap(content)
        if kind == "urlset":
            return entries
        # Sitemap index: read the newest matching child sitemaps.
        child_re = DISCOVERY_CONFIG.get("child_re")
        children = [(loc, mod) for loc, mod in entries
                    if loc and (not child_re or re.search(child_re, loc))]
        if DISCOVERY_CONFIG.get("child_order") == "lastmod":
            children.sort(key=lambda c: _parse_date(c[1]) or "", reverse=True)
        else:   # numbered children (post-sitemap1..N): the last ones are newest
            children.reverse()
        items = []
        for loc, _mod in children[:DISCOVERY_CONFIG.get("children", 1)]:
            kind, child_items = _parse_sitemap(self._get(loc))
            if kind == "urlset":
                items.extend(child_items)
        items.sort(key=lambda i: _parse_date(i["lastmod"] or i["pub_date"]) or "", reverse=True)
        return items[:DISCOVERY_CONFIG.get("max_items", 200)]

    def _resolve_redirects(self, items):
        """Replace redirector links (RESOLVE_REDIRECT_HOSTS) by the article URL.

        One HEAD per new link (no body, redirects read from Location, at
        most 5 hops), cached for the life of the process. Links that do not
        resolve to an allow-listed host are dropped.
        """
        if not RESOLVE_REDIRECT_HOSTS:
            return items
        out, seen = [], set()
        for item in items:
            link = item["link"]
            if (urlparse(link).hostname or "") in RESOLVE_REDIRECT_HOSTS:
                if link not in self.resolved:
                    self.resolved[link] = self._follow(link)
                target = self.resolved[link]
                if not target:
                    continue
                item = dict(item, link=target)
            if item["link"] not in seen:
                seen.add(item["link"])
                out.append(item)
        return out

    def _follow(self, link):
        url = link
        try:
            for _ in range(5):
                if (urlparse(url).hostname or "") not in RESOLVE_REDIRECT_HOSTS:
                    break
                resp = self.session.head(url, timeout=30, allow_redirects=False)
                location = resp.headers.get("Location")
                if not location:
                    return None
                url = urljoin(url, location)
        except Exception as exc:
            self.helper.log_warning(f"Could not resolve redirect {link}: {exc}")
            return None
        target = _canonical_link(url)
        if not target or (urlparse(target).hostname or "") not in ALLOWED_HOSTS:
            return None
        return target

    def _ingested_links(self, items):
        """Return the item links already ingested, by External Reference URL.

        Graph-driven, two exact-match batched queries, id/url fields only:
        1. External References whose url is one of the feed links.
        2. Reports citing any of those references.
        A link counts as ingested when a Report cites a reference with its
        URL. A reference with no citing Report (left behind by a failed
        Report create) does not count, so that article is retried.
        If query 1 fails the exception propagates and the whole poll is
        skipped (nothing written). If query 2 fails, any matching reference
        counts as ingested (conservative: never duplicate).
        """
        links = sorted({item["link"] for item in items})
        if not links:
            return set()

        # Query 1: External References with these URLs.
        refs = self.helper.api.external_reference.list(
            filters={
                "mode": "and",
                "filters": [{"key": "url", "values": links}],
                "filterGroups": [],
            },
            first=max(100, 5 * len(links)),
            customAttributes="id url",
        ) or []
        url_by_ref = {r["id"]: r.get("url") for r in refs if r.get("url") in links}
        if not url_by_ref:
            return set()

        # Query 2: Reports citing those references.
        try:
            reports = self.helper.api.report.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "externalReferences",
                                 "values": sorted(url_by_ref)}],
                    "filterGroups": [],
                },
                first=max(100, 5 * len(url_by_ref)),
                customAttributes="id externalReferences { edges { node { id } } }",
            ) or []
        except Exception as exc:
            self.helper.log_warning(
                f"Citing-Report query failed ({exc}); treating every matching "
                f"External Reference as ingested."
            )
            return set(url_by_ref.values())

        cited = set()
        for report in reports:
            cited.update(report.get("externalReferencesIds") or [])
        return {url_by_ref[ref_id] for ref_id in cited if ref_id in url_by_ref}

    # ------------------------------------------------------------------ #
    # Per-item checks
    # ------------------------------------------------------------------ #

    def _precheck(self, item):
        """Return a permanent-skip reason for the item, or None to proceed."""
        return None

    # ------------------------------------------------------------------ #
    # PDF rendering (house pdf-renderer client)
    # ------------------------------------------------------------------ #

    def _render_live(self, item, published):
        """Render the live article to PDF bytes via the pdf-renderer service.

        Raises RendererUnavailable or ContentUnavailable (see module docstring).
        """
        byline = {"publisher": self.author_name, "published": published[:10]}
        if BYLINE_AUTHOR and item.get("creator"):
            byline["author"] = item["creator"]
        return render_live_pdf(
            item["link"],
            item["title"] or item["link"],   # verbatim feed title
            SOURCE_NAME,
            byline=byline,
            selectors=CONTENT_SELECTORS,
            strip=HIDE_SELECTORS,
            timeout=self.render_timeout,
        )

    def _render_with_retry(self, item, published):
        """Return PDF bytes, or None when there is no usable article.

        RendererUnavailable is retried with exponential backoff and re-raised
        after the last attempt (transient: no Report is written). A
        ContentUnavailable or oversized PDF returns None: the Report is still
        created, without a PDF, and a WARNING says why.
        """
        url = item["link"]
        # Backoff starts at request_delay (a site's crawl delay) but is capped:
        # these retries wait for the renderer, not the site.
        delay = min(max(self.request_delay, 1), 30)
        for attempt in range(1, self.render_retries + 1):
            try:
                pdf_bytes = self._render_live(item, published)
                if not pdf_bytes.startswith(b"%PDF"):
                    raise RendererUnavailable("pdf-renderer returned a non-PDF payload")
            except ContentUnavailable as exc:
                detail = str(exc)
                if _VALIDATION_ERROR_RE.search(detail):
                    raise RendererUnavailable(f"renderer rejected the request: {detail}")
                if NO_CONTENT_IS_TRANSIENT or _SITE_FAILURE_RE.search(detail):
                    # The site (or its bot challenge) failed: retry on a later poll.
                    raise _SiteUnavailable(detail)
                self.helper.log_warning(f"No PDF for {url}: {exc}")
                return None
            except RendererUnavailable as exc:
                self.helper.log_warning(
                    f"Render attempt {attempt}/{self.render_retries} failed for "
                    f"{url}: {exc}"
                )
                if attempt >= self.render_retries:
                    raise
                time.sleep(delay)
                delay *= 2
                continue
            if len(pdf_bytes) > MAX_PDF_BYTES:
                self.helper.log_warning(
                    f"No PDF for {url}: rendered PDF is {len(pdf_bytes)} bytes "
                    f"(cap {MAX_PDF_BYTES})"
                )
                return None
            return pdf_bytes
        raise RendererUnavailable("render_retries is 0")

    def _fetch_page(self, url):
        """One plain GET of the article page; None on any failure."""
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            return resp.content or b""
        except Exception as exc:
            self.helper.log_warning(f"Article page fetch failed for {url}: {exc}")
            return None

    def _page_for(self, item):
        """The item's article page, fetched at most once per ingest (None on failure)."""
        if "_page" not in item:
            item["_page"] = self._fetch_page(item["link"])
        return item["_page"]

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, item, published, pdf_bytes):
        """Create the External Reference and the Report, PDF attached inline.

        pdf_bytes may be None (ContentUnavailable): the Report is created
        without a file.
        """
        url = item["link"]
        name = item["title"] or url
        description = item["description"]

        # At most one plain GET of the article page, made only when it is
        # needed: the feed has no summary (the page's own meta description
        # is used), or the Collector is configured and the feed has no full
        # text (the page's article text is classified). Any failure is
        # logged and the Report is still created.
        classify = (classify_report is not None
                    and bool(os.environ.get("CRUCIBLE_COLLECTOR_URL")))
        page = b""
        if not description or (classify and not item.get("full_text")):
            page = self._page_for(item) or b""
        if not description:
            description = _meta_description(page)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description=f"Source article on {SOURCE_NAME}",
        )

        # Report type from the Crucible Collector, sent the full article text
        # (feed full text, else the article page's text). The shared
        # helper returns the default type and logs a WARNING on error or
        # timeout, and makes no call when CRUCIBLE_COLLECTOR_URL is unset.
        report_types = [self.report_type]
        if classify_report is not None:
            article_text = (item.get("full_text")
                            or (_article_text(page) if classify else "")
                            or description)
            report_types = classify_report(
                title=name, description=description, content=article_text,
                source=SOURCE_NAME, source_url=url,
                default_types=[self.report_type],
                logger=self.helper.log_warning,
            )

        # One PDF, the file itself marked with the Report's TLP (a file does
        # not inherit the Report's marking on its own).
        file_kwargs = {}
        if pdf_bytes:
            file_kwargs = {
                "files": [File(f"{FILE_PREFIX}-rendered-{_slug_from_url(url)}.pdf",
                               pdf_bytes, "application/pdf")],
                "filesMarkings": [[self.marking_id]],
            }
        self.helper.api.report.create(
            stix_id=_report_id(url),
            name=name,
            description=description,
            published=published,
            report_types=report_types,
            confidence=self.confidence,
            createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[external_reference["id"]],
            update=False,
            **file_kwargs,
        )
        # Log the report type actually applied (Collector result or default).
        self.helper.log_info(
            f"Created Report for {url} ({name[:80]}) report_types={report_types}"
            + ("" if pdf_bytes else " (no PDF)")
        )

    # ------------------------------------------------------------------ #
    # Per-item ingestion
    # ------------------------------------------------------------------ #

    def _skip_permanently(self, link, reason):
        self.permanent_skips[link] = reason
        self.transient_failures.pop(link, None)
        self.helper.log_warning(f"Skipping {link} permanently: {reason}")
        return "skipped-permanent"

    def _ingest_item(self, item):
        """Ingest one new feed item.

        Returns 'created', 'skipped-permanent', 'failed' (transient for this
        item) or 'renderer-down' (the pdf-renderer service is unavailable).
        """
        url = item["link"]

        # Cheap validation before any network or render work.
        published = _parse_date(item["pub_date"])
        if not published or not item["title"]:
            # Feed (or sitemap/listing/API) without a date or title: read
            # them from the article page, then re-apply the scope rules.
            fetched = "_page" not in item
            page = self._page_for(item)
            if fetched:
                time.sleep(self.request_delay)   # politeness between page probes
            if page is None:
                return "failed"     # page fetch failed: retry next poll
            published = published or _page_date(page)
            item["title"] = item["title"] or _page_title(page)
            if published:
                reason = _out_of_scope(dict(item, pub_date=published), self.max_age_days)
                if reason:
                    return self._skip_permanently(url, f"{reason} (from the article page)")
        if not published:
            return self._skip_permanently(url, "no usable publication date")

        reason = self._precheck(item)
        if reason:
            return self._skip_permanently(url, reason)

        try:
            pdf_bytes = self._render_with_retry(item, published)
        except _SiteUnavailable as exc:
            self.helper.log_warning(f"Site unavailable for {url}: {exc}")
            return "failed"
        except RendererUnavailable:
            return "renderer-down"   # house policy: renderer down -> skip, retry later

        self._create_report(item, published, pdf_bytes)
        return "created"

    def _record_transient(self, link):
        attempts = self.transient_failures.get(link, 0) + 1
        self.transient_failures[link] = attempts
        if attempts >= MAX_TRANSIENT_ATTEMPTS:
            self._skip_permanently(
                link, f"failed on {attempts} consecutive polls; giving up"
            )
        else:
            self.helper.log_warning(
                f"Transient failure for {link} (poll {attempts}/"
                f"{MAX_TRANSIENT_ATTEMPTS}); will retry while it stays in the feed."
            )

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        """Run one poll of the feed."""
        self.poll_count += 1
        items = self._fetch_feed()
        if items is None:
            return
        # Scope filters first: out-of-scope items never reach dedup or render.
        reasons = [_out_of_scope(i, self.max_age_days) for i in items]
        # When the feed reaches back past max_age_days, nothing can have
        # scrolled off it unseen (used by the gap warning below).
        reaches_back = "older than max_age_days" in reasons
        in_scope = [i for i, why in zip(items, reasons) if not why]
        if len(in_scope) != len(items):
            self.helper.log_debug(f"{len(items) - len(in_scope)} feed items out of scope.")
        items = in_scope

        # Graph-driven dedup by External Reference URL. If the lookup fails,
        # skip this poll entirely rather than risk duplicates.
        candidates = [i for i in items if i["link"] not in self.permanent_skips]
        try:
            existing = self._ingested_links(candidates)
        except Exception as exc:
            self.helper.log_error(f"Dedup lookup failed ({exc}); skipping this poll.")
            return
        new_items = [i for i in candidates if i["link"] not in existing]

        # Prune in-memory bookkeeping to links still in the feed(s); skipped
        # when a feed failed, since its items are missing from this poll.
        if self.fetch_complete:
            live = {i["link"] for i in items}
            self.permanent_skips = {k: v for k, v in self.permanent_skips.items() if k in live}
            self.transient_failures = {
                k: v for k, v in self.transient_failures.items() if k in live}

        if not new_items:
            self.prev_poll_clean = True
            self.helper.log_debug(f"Feed returned {len(items)} items; nothing new.")
            return

        # A previous poll whose items all failed leaves no ingested overlap, so
        # only warn when the previous poll actually ingested what it saw.
        if (candidates and not existing and not reaches_back
                and self.poll_count > 1 and self.prev_poll_clean):
            self.helper.log_warning(
                f"None of the {len(candidates)} feed items were already ingested; "
                f"posts may have scrolled off the feed between polls. Consider "
                f"lowering poll_interval (now {self.poll_interval}s)."
            )

        # Items that need their article page just to learn a date or title
        # are capped per poll; the rest wait for the next poll.
        probes = [i for i in new_items if not _parse_date(i["pub_date"]) or not i["title"]]
        if len(probes) > MAX_PAGE_PROBES:
            later = {i["link"] for i in probes[MAX_PAGE_PROBES:]}
            new_items = [i for i in new_items if i["link"] not in later]
            self.helper.log_info(f"{len(later)} undated items wait for the next poll.")

        # Work records are only opened when there is something to write.
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, f"{SOURCE_NAME} feed poll"
        )
        created = permanent = failed = 0
        renderer_down = False
        for item in new_items:
            if self.max_reports and created >= self.max_reports:
                self.helper.log_info(f"Reached max_reports={self.max_reports}; stopping run.")
                break
            try:
                outcome = self._ingest_item(item)
            except Exception as exc:
                self.helper.log_error(f"Failed to ingest {item['link']}: {exc}")
                outcome = "failed"

            if outcome == "renderer-down":
                # Not the item's fault: stop here, retry everything next poll,
                # and do not count it towards giving up on the item.
                renderer_down = True
                self.helper.log_warning(
                    "pdf-renderer unavailable; stopping this poll. Remaining items "
                    "are retried next poll.")
                break
            if outcome == "created":
                created += 1
                self.transient_failures.pop(item["link"], None)
                time.sleep(self.request_delay)
            elif outcome == "skipped-permanent":
                permanent += 1
            else:
                failed += 1
                self._record_transient(item["link"])

        message = (
            f"Feed returned {len(items)} items, {len(new_items)} new: {created} "
            f"created, {permanent} skipped permanently, {failed} failed (will retry)"
            + ("; pdf-renderer unavailable, poll stopped early." if renderer_down else ".")
        )
        self.prev_poll_clean = failed == 0 and not renderer_down
        self.helper.api.work.to_processed(
            work_id, message, in_error=failed > 0 or renderer_down)
        self.helper.log_info(message)

    def run(self):
        """Resolve graph references once, then poll forever."""
        self._resolve_graph_references()
        # State the report-type source once at startup.
        collector = os.environ.get("CRUCIBLE_COLLECTOR_URL")
        if classify_report is None:
            self.helper.log_info(
                "Shared microservices package not available; standalone mode, "
                f"report_types='{self.report_type}'."
            )
        elif collector:
            self.helper.log_info(f"Report types from the Crucible Collector at {collector}/classify.")
        else:
            self.helper.log_info(
                f"CRUCIBLE_COLLECTOR_URL not set; standalone mode, report_types='{self.report_type}'."
            )
        self.helper.log_info(f"{SOURCE_NAME} connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:
                self.helper.log_error(f"Unhandled error during poll: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        IsdGlobalConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
