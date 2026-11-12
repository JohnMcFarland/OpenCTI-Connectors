"""HTML to text, page metadata and article text (ported from the generated
connectors; site constants are now arguments taken from the profile)."""

import html
import json
import re
from html.parser import HTMLParser

from .dates import parse_date
from .settings import MAX_DESCRIPTION_CHARS

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


# --------------------------------------------------------------------------- #
# Plain text
# --------------------------------------------------------------------------- #

def html_to_text(value, limit=MAX_DESCRIPTION_CHARS):
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


def collapse_ws(value):
    """Collapse whitespace runs to single spaces."""
    return _WS_RE.sub(" ", value)


# --------------------------------------------------------------------------- #
# Minimal CSS selector matching (for the text parser only; the renderer
# applies the full selectors)
# --------------------------------------------------------------------------- #

_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
              "meta", "param", "source", "track", "wbr"}


def selector_parts(selector):
    """Split the first compound of a CSS selector into (tag, id, classes)."""
    first = selector.split("~")[0].strip().split()[0]
    tag = re.match(r"[a-zA-Z][a-zA-Z0-9]*", first)
    return (
        tag.group(0).lower() if tag else None,
        (re.findall(r"#([A-Za-z0-9_-]+)", first) or [None])[0],
        set(re.findall(r"\.([A-Za-z0-9_-]+)", first)),
    )


def matches(parts, tag, attrs):
    """True when a start tag matches a (tag, id, classes) compound."""
    want_tag, want_id, want_classes = parts
    a = dict(attrs)
    return ((want_tag is None or tag == want_tag)
            and (want_id is None or a.get("id") == want_id)
            and want_classes <= set((a.get("class") or "").split()))


def hide_parts(hide_selectors):
    """Simple hide selectors (tag / id / class compounds) usable by the text parser.

    Sibling (~), descendant, attribute and pseudo-class selectors are left to
    the renderer.
    """
    parts = []
    for sel in hide_selectors:
        if any(ch in sel for ch in "~[ >:+"):
            continue
        p = selector_parts(sel)
        if p[0] or p[1] or p[2]:
            parts.append(p)
    return parts


# --------------------------------------------------------------------------- #
# Page metadata: description, title, publication date
# --------------------------------------------------------------------------- #

_META_KEYS = ("og:description", "description", "twitter:description")
_TITLE_KEYS = ("og:title", "twitter:title")
_DATE_KEYS = ("article:published_time", "og:published_time", "datepublished",
              "citation_publication_date", "dc.date.issued", "dcterms.issued",
              "dc.date", "date", "pubdate", "publish-date", "article.published")


class PageMetaParser(HTMLParser):
    """Collect a page's description/title/date metadata (any attribute order).

    Gathers <meta> name/property/itemprop values, JSON-LD script bodies,
    <time datetime>, the first <h1> and <title> texts, and the text of the
    first element matching the profile's date_text_selector.
    """

    def __init__(self, date_text_selector=None):
        super().__init__(convert_charrefs=True)
        self.found = {}
        self.ld_json = []
        self.times = []
        self.h1 = self.title = self.date_text = ""
        self._capture = None      # "h1" | "title" | "ld" | "date"
        self._buf = []
        self._date_parts = selector_parts(date_text_selector) if date_text_selector else None
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
                  and matches(self._date_parts, tag, attrs)):
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


def ld_values(node, key):
    """Every value of `key` anywhere in a parsed JSON-LD document."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, str):
                yield v
            else:
                yield from ld_values(v, key)
    elif isinstance(node, list):
        for v in node:
            yield from ld_values(v, key)


def page_meta(html_bytes, date_text_selector=None):
    """Parsed page metadata (a PageMetaParser), or None for an empty page."""
    if not html_bytes:
        return None
    parser = PageMetaParser(date_text_selector)
    try:
        parser.feed(html_bytes.decode("utf-8", errors="replace"))
    except Exception:  # malformed markup: use whatever was collected
        pass
    return parser


def meta_description(html_bytes):
    """The page's own summary (og:description, then description), or ""."""
    meta = page_meta(html_bytes)
    if meta is None:
        return ""
    for key in _META_KEYS:
        if meta.found.get(key):
            return html_to_text(html.escape(meta.found[key]))
    return ""


def page_title(html_bytes, source_name):
    """The article's title from its page (og:title, h1, then <title>), or ""."""
    meta = page_meta(html_bytes)
    if meta is None:
        return ""
    name = re.escape(source_name)
    affix = re.compile(rf"^\s*{name}\s*[:|\u2013-]\s*|\s*[:|\u2013-]\s*{name}\s*$",
                       re.IGNORECASE)
    for value in [meta.found.get(k) for k in _TITLE_KEYS] + [meta.h1, meta.title]:
        if value and value.strip():
            # Drop a "Site Name: " prefix or " | Site Name" suffix.
            title = html.unescape(_WS_RE.sub(" ", value)).strip()
            return affix.sub("", title).strip() or title
    return ""


def page_date(html_bytes, date_text_selector=None):
    """The article's publication date from its page (ISO-8601 UTC), or None.

    Order: publication <meta> tags, JSON-LD datePublished, the first
    <time datetime>, then the date_text_selector element's text.
    """
    meta = page_meta(html_bytes, date_text_selector)
    if meta is None:
        return None
    candidates = [meta.found.get(k) for k in _DATE_KEYS]
    for block in meta.ld_json:
        try:
            candidates.extend(ld_values(json.loads(block), "datePublished"))
        except ValueError:
            continue
    candidates += meta.times[:1] + [meta.date_text]
    for value in candidates:
        parsed = parse_date(value) if value else None
        if parsed:
            return parsed
    return None


# --------------------------------------------------------------------------- #
# Article text (for the classifier; never stored on the Report)
# --------------------------------------------------------------------------- #

class ArticleTextParser(HTMLParser):
    """Collect the text inside the first element matching the content selector,
    leaving out script/style and the same chrome the PDF render hides."""

    def __init__(self, selector, hide_selectors):
        super().__init__(convert_charrefs=True)
        self.content = selector_parts(selector)
        self.hide = hide_parts(hide_selectors)
        self.depth = 0          # nesting depth inside the matched element
        self.done = False
        self.skip_depth = 0     # >0 while inside a skipped subtree
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in _VOID_TAGS or self.done:
            return
        if not self.depth:
            if matches(self.content, tag, attrs):
                self.depth = 1
            return
        self.depth += 1
        if self.skip_depth:
            self.skip_depth += 1
        elif tag in ("script", "style", "noscript") or any(
                matches(p, tag, attrs) for p in self.hide):
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


def article_text(html_bytes, content_selectors, hide_selectors, limit=None):
    """Return the article's full plain text from the article page HTML.

    Uses the first content selector element that yields text; falls back to
    the whole page's text when none matches (or the profile uses the
    renderer's "generic" extraction). Not capped unless `limit` is given.
    """
    if not html_bytes:
        return ""
    page = html_bytes.decode("utf-8", errors="replace")
    selectors = content_selectors if isinstance(content_selectors, list) else []
    for selector in selectors:
        parser = ArticleTextParser(selector, hide_selectors)
        try:
            parser.feed(page)
        except Exception:  # malformed markup: try the next selector
            continue
        text = " ".join(parser.parts)
        if text.strip():
            return html_to_text(html.escape(text), limit)
    return html_to_text(page, limit)
