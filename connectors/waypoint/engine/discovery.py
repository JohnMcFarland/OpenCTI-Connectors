"""Discovery: turn a source URL into item dicts (ported from the generated
connectors; ALLOWED_HOSTS, DISCOVERY_CONFIG etc. now come from the profile).

Every mode yields the same item shape:
    {"title", "link", "description", "pub_date", "lastmod", "creator",
     "categories", "full_text"}
Links are canonical (https, no fragment, no utm_*), on the profile's allowed
hosts (or its redirector hosts, resolved later), deduplicated in feed order.
"""

import html
import json
import re
from urllib.parse import urljoin, urlparse, urlunparse
from xml.etree import ElementTree

from .dates import parse_date
from .text import collapse_ws, html_to_text

RSS_CONTENT_NS = "{http://purl.org/rss/1.0/modules/content/}encoded"
DC_CREATOR_NS = "{http://purl.org/dc/elements/1.1/}creator"
ATOM_NS = "{http://www.w3.org/2005/Atom}"
SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
NEWS_NS = "{http://www.google.com/schemas/sitemap-news/0.9}"


# --------------------------------------------------------------------------- #
# Links
# --------------------------------------------------------------------------- #

def canonical_link(link, profile):
    """Return the https link without fragment or utm_* tracking parameters,
    or None if the host is not allowed for this profile."""
    try:
        parsed = urlparse((link or "").strip())
    except ValueError:
        return None
    host = parsed.hostname or ""
    if parsed.scheme not in ("https", "http") or (
            host not in profile.allowed_hosts and host not in profile.resolve_redirect_hosts):
        return None
    # Allow-listed hosts all serve https; an http:// feed link is upgraded.
    parsed = parsed._replace(scheme="https", path=parsed.path.replace(" ", "%20"))
    # Drop utm_* pairs from the raw query; every other byte is kept as-is so
    # the URL still matches References stored by earlier runs.
    query = "&".join(p for p in parsed.query.split("&")
                     if p and not p.split("=", 1)[0].lower().startswith("utm_"))
    return urlunparse(parsed._replace(fragment="", query=query))


# --------------------------------------------------------------------------- #
# XML repair (some feeds are invalid XML)
# --------------------------------------------------------------------------- #

# A bare "&" in a link, an HTML named entity (&nbsp;) XML does not define,
# or a raw control character.
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


def repair_xml(xml_bytes):
    """Repair ampersands outside CDATA sections and drop control characters.

    CDATA content is left untouched: an "&" there is already literal text.
    """
    parts = _CDATA_RE.split(_XML_CTRL_RE.sub(b"", xml_bytes))
    return b"".join(part if part.startswith(b"<![CDATA[") else _AMP_RE.sub(_fix_amp, part)
                    for part in parts)


def parse_xml(xml_bytes):
    """Parse feed XML, retrying once after repair_xml.

    Raises ElementTree.ParseError when the feed is still malformed.
    """
    try:
        return ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError:
        repaired = repair_xml(xml_bytes)
    try:
        return ElementTree.fromstring(repaired)
    except ElementTree.ParseError:
        # Last resort for a feed with invalid UTF-8 bytes (e.g. Mac-Roman
        # dashes): replace them and drop the encoding declaration.
        text = repaired.decode("utf-8", errors="replace")
        return ElementTree.fromstring(re.sub(r"^<\?xml[^>]*\?>", "", text.lstrip()))


# --------------------------------------------------------------------------- #
# RSS 2.0 / Atom
# --------------------------------------------------------------------------- #

def el_text(el):
    """All text inside an element (child markup such as <a> included), unescaped."""
    if el is None:
        return ""
    return html.unescape(collapse_ws("".join(el.itertext())).strip())


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


def _parse_atom(root, profile):
    """Parse Atom <entry> elements into the same item dicts as RSS."""
    items = []
    seen = set()
    for entry in root.iter(ATOM_NS + "entry"):
        link = canonical_link(_atom_link(entry), profile)
        if not link or link in seen:
            continue
        seen.add(link)
        summary = _atom_text(entry.find(ATOM_NS + "summary"))
        content = _atom_text(entry.find(ATOM_NS + "content"))
        items.append({
            "title": el_text(entry.find(ATOM_NS + "title")),
            "link": link,
            "description": html_to_text(summary or content),
            # Published date; updated only when the feed has no published.
            "pub_date": (entry.findtext(ATOM_NS + "published")
                         or entry.findtext(ATOM_NS + "updated") or "").strip(),
            "full_text": html_to_text(content, None),
            "creator": html.unescape(
                (entry.findtext(f"{ATOM_NS}author/{ATOM_NS}name") or "").strip()),
            "categories": [c.get("term", "") for c in entry.findall(ATOM_NS + "category")],
        })
    return items


def parse_feed(xml_bytes, profile):
    """Parse RSS 2.0 or Atom bytes into item dicts (deduplicated, allowed hosts only).

    Raises ElementTree.ParseError on malformed XML.
    """
    root = parse_xml(xml_bytes)
    if root.tag == ATOM_NS + "feed":
        return _parse_atom(root, profile)
    items = []
    seen = set()
    for item_el in root.iter("item"):
        link = canonical_link(item_el.findtext("link"), profile)
        if not link or link in seen:
            continue
        seen.add(link)
        items.append({
            "title": el_text(item_el.find("title")),
            "link": link,
            "description": html_to_text(item_el.findtext("description")),
            "pub_date": (item_el.findtext("pubDate") or "").strip(),
            # Byline author for the PDF header (dc:creator, when present).
            "creator": el_text(item_el.find(DC_CREATOR_NS)),
            "categories": [html.unescape(c.text or "") for c in item_el.findall("category")],
            # Full text when the feed carries it; used only for classification.
            "full_text": html_to_text(item_el.findtext(RSS_CONTENT_NS), None),
        })
    return items


# --------------------------------------------------------------------------- #
# Sitemap, listing page, JSON API
# --------------------------------------------------------------------------- #

def new_item(link, title="", pub_date="", description="", lastmod=""):
    """An item dict as the feed parser makes them (no categories/full text)."""
    return {"title": title, "link": link, "description": description,
            "pub_date": pub_date, "lastmod": lastmod, "creator": "",
            "categories": [], "full_text": ""}


def _newest_key(item):
    return parse_date(item["lastmod"] or item["pub_date"]) or ""


def parse_sitemap(xml_bytes, profile):
    """Parse a sitemap: ("index", [(loc, lastmod)]) or ("urlset", [items]).

    Article URLs are filtered by discovery_config["url_re"] when set; a
    news-sitemap publication date becomes the item's pub_date.
    """
    cfg = profile.discovery_config
    root = parse_xml(xml_bytes)
    if root.tag == SITEMAP_NS + "sitemapindex":
        return "index", [((s.findtext(SITEMAP_NS + "loc") or "").strip(),
                          (s.findtext(SITEMAP_NS + "lastmod") or "").strip())
                         for s in root.iter(SITEMAP_NS + "sitemap")]
    url_re = cfg.get("url_re")
    items, seen = [], set()
    for url_el in root.iter(SITEMAP_NS + "url"):
        link = canonical_link(url_el.findtext(SITEMAP_NS + "loc"), profile)
        if not link or link in seen or (url_re and not re.search(url_re, link)):
            continue
        seen.add(link)
        items.append(new_item(
            link,
            title=el_text(url_el.find(f"{NEWS_NS}news/{NEWS_NS}title")),
            pub_date=(url_el.findtext(f"{NEWS_NS}news/{NEWS_NS}publication_date") or "").strip(),
            lastmod=(url_el.findtext(SITEMAP_NS + "lastmod") or "").strip()))
    # Newest first, so the item cap keeps the recent end.
    items.sort(key=_newest_key, reverse=True)
    return "urlset", items[:cfg.get("max_items", 200)]


_ANCHOR_RE = re.compile(r"<a\b[^>]*?\bhref\s*=\s*([\"'])(.*?)\1[^>]*>(.*?)</a\s*>",
                        re.IGNORECASE | re.DOTALL)
_GENERIC_ANCHOR_RE = re.compile(
    r"^\W*(?:(?:read|learn|see|view|find out)(?: the)? more|more|read|continue reading|"
    r"read (?:the )?(?:full )?(?:story|article|post)|full story|click here)\W*$", re.IGNORECASE)


def parse_listing(html_bytes, base_url, profile):
    """Article links on an HTML listing page: hrefs matching
    discovery_config["link_re"], in page order, anchor text as the title."""
    cfg = profile.discovery_config
    page = html_bytes.decode("utf-8", errors="replace")
    link_re = re.compile(cfg["link_re"])
    items, seen = [], {}
    for match in _ANCHOR_RE.finditer(page):
        href = html.unescape(match.group(2)).strip()
        link = canonical_link(urljoin(base_url, href), profile) if link_re.search(href) else None
        if not link:
            continue
        # Cards often link an article twice (image or "Read more" plus the
        # headline): generic or empty anchor text is no title, and a later
        # anchor to the same article supplies it.
        title = html_to_text(match.group(3), 300)
        title = "" if _GENERIC_ANCHOR_RE.match(title) else title
        if link in seen:
            if title and not seen[link]["title"]:
                seen[link]["title"] = title
            continue
        seen[link] = new_item(link, title=title)
        items.append(seen[link])
    return items[:cfg.get("max_items", 200)]


def json_path(node, path):
    """Follow a dotted path ("a.b.c") through nested dicts; None when missing."""
    for key in [k for k in (path or "").split(".") if k]:
        node = node.get(key) if isinstance(node, dict) else None
    return node


def parse_json(raw, profile):
    """Items from a JSON API: records at discovery_config["items"] (dotted
    path), fields mapped by discovery_config["title"/"date"/"description"],
    link built from discovery_config["link"] (a str.format template over the
    record's fields)."""
    cfg = profile.discovery_config
    records = json_path(json.loads(raw), cfg.get("items", ""))
    items, seen = [], set()
    for rec in records if isinstance(records, list) else []:
        if not isinstance(rec, dict):
            continue
        try:
            link = canonical_link(cfg["link"].format(**rec), profile)
        except (KeyError, IndexError, ValueError):
            continue
        if not link or link in seen:
            continue
        seen.add(link)
        field = lambda name: str(json_path(rec, cfg.get(name, "")) or "")  # noqa: E731
        items.append(new_item(link, title=html.unescape(field("title")).strip(),
                              pub_date=field("date").strip(),
                              description=html_to_text(field("description"))))
    return items


# --------------------------------------------------------------------------- #
# One source URL, any mode
# --------------------------------------------------------------------------- #

def fetch_source(get, url, profile):
    """Fetch one source URL with `get(url) -> bytes` and parse it with the
    profile's discovery mode. A sitemap index is followed to its newest
    matching child sitemaps."""
    content = get(url)
    if profile.discovery == "feed":
        return parse_feed(content, profile)
    if profile.discovery == "listing":
        return parse_listing(content, url, profile)
    if profile.discovery == "json":
        return parse_json(content, profile)
    kind, entries = parse_sitemap(content, profile)
    if kind == "urlset":
        return entries
    # Sitemap index: read the newest matching child sitemaps.
    cfg = profile.discovery_config
    child_re = cfg.get("child_re")
    children = [(loc, mod) for loc, mod in entries
                if loc and (not child_re or re.search(child_re, loc))]
    if cfg.get("child_order") == "lastmod":
        children.sort(key=lambda c: parse_date(c[1]) or "", reverse=True)
    else:   # numbered children (post-sitemap1..N): the last ones are newest
        children.reverse()
    items = []
    for loc, _mod in children[:cfg.get("children", 1)]:
        kind, child_items = parse_sitemap(get(loc), profile)
        if kind == "urlset":
            items.extend(child_items)
    items.sort(key=_newest_key, reverse=True)
    return items[:cfg.get("max_items", 200)]


def follow_redirects(session, link, profile, log):
    """Resolve a redirector link to the article URL, or None.

    One HEAD per hop (no body, Location read, at most 5 hops) while the URL
    stays on a redirector host. The target must be canonical and on an
    allowed host, otherwise the link is dropped.
    """
    url = link
    try:
        for _ in range(5):
            if (urlparse(url).hostname or "") not in profile.resolve_redirect_hosts:
                break
            resp = session.head(url, timeout=30, allow_redirects=False)
            location = resp.headers.get("Location")
            if not location:
                return None
            url = urljoin(url, location)
    except Exception as exc:
        log.log_warning(f"Could not resolve redirect {link}: {exc}")
        return None
    target = canonical_link(url, profile)
    if not target or (urlparse(target).hostname or "") not in profile.allowed_hosts:
        return None
    return target
