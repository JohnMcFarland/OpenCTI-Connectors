"""
The Record OpenCTI connector.

Purpose
-------
External-import connector that creates one container-only OpenCTI Report per
The Record article, with the live article page attached as one rendered PDF.
Part of the Feedly replacement program: The Record was previously
ingested through the (now deprecated) Feedly connector.

Collection model
----------------
Feed only, new posts only. The connector polls https://therecord.media/feed/ and never
backfills older articles; history before cut-over stays with the
Feedly-ingested Reports.

Next.js site. The feed holds only the latest 5 stories (about 7 hours), so
the default poll is 15 minutes; the scroll-off warning flags any gap.

Data model conformance
----------------------
- Container-only: a Report (external assertion, "what the world says") with an
  author Organization, a TLP marking, one External Reference to the article,
  and the rendered PDF attached. No SDOs, Observables,
  Relationships, Sightings or Labels are created (feed categories are not
  collection requirements, so they are never applied as Labels).
- published = the article's own publication date from the feed. An item with
  no parseable date is skipped, never stamped with ingestion time.
- Author: one "The Record" Organization, resolved once at startup.

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
  render_retries times with backoff, then the item is a transient failure and
  no Report is written (retried on a later poll);
- ContentUnavailable (page reached but no usable article, or URL blocked):
  the Report is created without a PDF and a WARNING is logged.

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
Report create does not block a retry, and articles already ingested by the
Feedly connector under the same URL are not duplicated). Anything ingested is
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
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse, urlunparse
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

SOURCE_NAME = "The Record"
FILE_PREFIX = "the_record"

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

# Only https article links on these hosts are accepted from the feed, so a
# malformed or hijacked item cannot make the renderer fetch arbitrary URLs.
ALLOWED_HOSTS = {"therecord.media", "www.therecord.media"}

# Article container on the live site (verified against article markup,
# Nov 2026). It wraps the headline, byline and body.
CONTENT_SELECTOR = "article.article"

# Selectors tried in order, first match wins (renderer and text extraction).
# Fallbacks cover article layouts seen live that lack the primary container.
CONTENT_SELECTORS = [CONTENT_SELECTOR]

# Chrome inside (or around) the container that is not part of the story.
HIDE_SELECTORS = [
    ".social-share-icons",               # share buttons
    ".article__pagination",              # previous/next links
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


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _report_id(link):
    """Return a deterministic STIX Report id derived from the article URL."""
    return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))


def _slug_from_url(url):
    """Return a filesystem-safe slug from the URL path ('report' for root)."""
    segments = [s for s in urlparse(url).path.split("/") if s]
    # Prefer the last non-numeric segment (some sites end with a numeric id).
    for seg in reversed(segments):
        if not seg.isdigit():
            seg = re.sub(r"\.html?$", "", seg)
            return re.sub(r"[^A-Za-z0-9._-]", "_", seg)[:120] or "report"
    return segments[-1] if segments else "report"


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
    text = _WS_RE.sub(" ", text).strip()
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
    """Simple hide selectors (id/class compounds) usable by the text parser.

    Sibling (~), descendant and attribute selectors are left to the renderer.
    """
    parts = []
    for sel in HIDE_SELECTORS:
        if any(ch in sel for ch in "~[ >"):
            continue
        p = _selector_parts(sel)
        if p[1] or p[2]:
            parts.append(p)
    return parts


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
    """Return the https link without fragment, or None if not allowed."""
    try:
        parsed = urlparse((link or "").strip())
    except ValueError:
        return None
    if parsed.scheme != "https" or (parsed.hostname or "") not in ALLOWED_HOSTS:
        return None
    return urlunparse(parsed._replace(fragment=""))


def _parse_feed(xml_bytes):
    """Parse RSS bytes into item dicts (deduplicated, allowed hosts only).

    Raises ElementTree.ParseError on malformed XML.
    """
    root = ElementTree.fromstring(xml_bytes)
    items = []
    seen = set()
    for item_el in root.iter("item"):
        link = _canonical_link(item_el.findtext("link"))
        if not link or link in seen:
            continue
        seen.add(link)
        items.append({
            "title": html.unescape((item_el.findtext("title") or "").strip()),
            "link": link,
            "description": _html_to_text(item_el.findtext("description")),
            "pub_date": (item_el.findtext("pubDate") or "").strip(),
            # Byline author for the PDF header (dc:creator, when present).
            "creator": html.unescape((item_el.findtext(DC_CREATOR_NS) or "").strip()),
            # Full text when the feed carries it; used only for classification.
            "full_text": _html_to_text(item_el.findtext(RSS_CONTENT_NS), None),
        })
    return items


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

class TheRecordConnector:
    """External-import connector that mirrors The Record articles into Reports."""

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
                f"THE_RECORD_{name.upper()}", ["the_record", name], config,
                isNumber=number, default=default,
            )
            if value in (None, ""):
                value = default
            return int(value) if number else value

        self.feed_url = setting("feed_url", "https://therecord.media/feed/")
        self.poll_interval = setting("poll_interval", 900, number=True)
        self.request_delay = setting("request_delay", 3, number=True)
        self.max_reports = setting("max_reports", 0, number=True)
        self.render_retries = setting("render_retries", 3, number=True)
        self.confidence = setting("confidence", 50, number=True)
        self.report_type = setting("report_type", "open-source-reporting")
        self.tlp_name = setting("tlp", "TLP:CLEAR")
        self.author_name = setting("author_name", "The Record")

        # The renderer address comes from PDF_RENDERER_URL inside the shared
        # client (default http://pdf-renderer:8000); only the timeout is set here.
        self.render_timeout = setting("pdf_render_timeout", 120, number=True)

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA})

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
            description="The Record from Recorded Future News - cybersecurity news.",
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
        """Fetch and parse the feed. Returns a list of items, or None on error."""
        try:
            resp = self.session.get(self.feed_url, timeout=60)
            resp.raise_for_status()
        except Exception as exc:
            self.helper.log_error(f"Failed to fetch feed: {exc}")
            return None
        try:
            return _parse_feed(resp.content)
        except ElementTree.ParseError as exc:
            self.helper.log_error(f"Failed to parse feed XML: {exc}")
            return None

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
        if item.get("creator"):
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
        delay = max(self.request_delay, 1)
        for attempt in range(1, self.render_retries + 1):
            try:
                pdf_bytes = self._render_live(item, published)
                if not pdf_bytes.startswith(b"%PDF"):
                    raise RendererUnavailable("pdf-renderer returned a non-PDF payload")
            except ContentUnavailable as exc:
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

    def _page_text(self, url):
        """Article text for the classifier when the feed has no full text.

        One plain GET of the article page, made only when the Collector is
        configured. Any failure returns "" (the summary is used instead).
        """
        if not os.environ.get("CRUCIBLE_COLLECTOR_URL"):
            return ""
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            return _article_text(resp.content)
        except Exception as exc:
            self.helper.log_warning(f"Article text fetch failed for {url}: {exc}")
            return ""

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
            article_text = (item.get("full_text") or self._page_text(url)
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

        Returns 'created', 'skipped-permanent' or 'failed' (transient).
        """
        url = item["link"]

        # Cheap validation before any network or render work.
        published = _parse_rfc2822(item["pub_date"])
        if not published:
            return self._skip_permanently(url, "no usable publication date")

        reason = self._precheck(item)
        if reason:
            return self._skip_permanently(url, reason)

        try:
            pdf_bytes = self._render_with_retry(item, published)
        except RendererUnavailable:
            return "failed"   # house policy: renderer down -> skip, retry later

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

        # Graph-driven dedup by External Reference URL. If the lookup fails,
        # skip this poll entirely rather than risk duplicates.
        candidates = [i for i in items if i["link"] not in self.permanent_skips]
        try:
            existing = self._ingested_links(candidates)
        except Exception as exc:
            self.helper.log_error(f"Dedup lookup failed ({exc}); skipping this poll.")
            return
        new_items = [i for i in candidates if i["link"] not in existing]

        # Prune in-memory bookkeeping to links still in the feed.
        live = {i["link"] for i in items}
        self.permanent_skips = {k: v for k, v in self.permanent_skips.items() if k in live}
        self.transient_failures = {k: v for k, v in self.transient_failures.items() if k in live}

        if not new_items:
            self.prev_poll_clean = True
            self.helper.log_debug(f"Feed returned {len(items)} items; nothing new.")
            return

        # A previous poll whose items all failed leaves no ingested overlap, so
        # only warn when the previous poll actually ingested what it saw.
        if candidates and not existing and self.poll_count > 1 and self.prev_poll_clean:
            self.helper.log_warning(
                f"None of the {len(candidates)} feed items were already ingested; "
                f"posts may have scrolled off the feed between polls. Consider "
                f"lowering poll_interval (now {self.poll_interval}s)."
            )

        # Work records are only opened when there is something to write.
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, f"{SOURCE_NAME} feed poll"
        )
        created = permanent = failed = 0
        for item in new_items:
            if self.max_reports and created >= self.max_reports:
                self.helper.log_info(f"Reached max_reports={self.max_reports}; stopping run.")
                break
            try:
                outcome = self._ingest_item(item)
            except Exception as exc:
                self.helper.log_error(f"Failed to ingest {item['link']}: {exc}")
                outcome = "failed"

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
            f"created, {permanent} skipped permanently, {failed} failed (will retry)."
        )
        self.prev_poll_clean = failed == 0
        self.helper.api.work.to_processed(work_id, message, in_error=failed > 0)
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
        TheRecordConnector().run()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
