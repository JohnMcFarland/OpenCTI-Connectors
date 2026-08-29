"""
Trellix blog OpenCTI connector.

Purpose
-------
External-import connector that ingests posts from the Trellix blog
(https://www.trellix.com/blogs/) as container-only OpenCTI Reports, one per post,
with the live source page attached as a full-fidelity Playwright-rendered PDF.
Scoped by default to the "research" and "platform" categories.

See CONNECTOR_SCOPE.md for the full decision log and verification details.
"""

import os
import re
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside the renderer so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Browser User-Agent for BOTH the sitemap client and the Playwright context. The
# origin's edge WAF gates non-browser clients (a plain fetch of /blogs/ is answered
# HTTP 403; a browser client gets 200). Deliberately NOT ClaudeBot: the connector
# performs reference-use ingestion of a public vendor blog.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Recycle the Chromium browser after this many renders to cap memory growth on a
# host that co-locates Elasticsearch.
BROWSER_RECYCLE_EVERY = 50

# Substrings indicating a Cloudflare/Akamai interstitial rather than article content.
CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")

# Earliest plausible real publication year; guards against a malformed date. The
# oldest post observed on this origin is from 2016 (migrated McAfee Labs content).
MIN_VALID_YEAR = 2000

# Article URL shape: https://www.trellix.com/blogs/{category}/{slug}/
_POST_URL_RE = re.compile(
    r"^https?://[^/]+/blogs/(?P<category>[a-z0-9][a-z0-9-]*)/(?P<slug>[^/]+)/?$",
    re.IGNORECASE,
)

# "Month D, YYYY" inside a dateline. Month names appear in full and abbreviated form
# and in mixed case ("February", "Aug", "NOV", "Nov."), so the month is matched as a
# bare word and validated against _MONTHS below. The year deliberately uses a
# negative lookahead rather than \b: WordPress-era markup runs the year straight into
# the following sentence ("August 30, 2022This blog was written by ..."), where a
# trailing \b would fail to match.
_DATELINE_DATE_RE = re.compile(r"\b([A-Za-z]{3,9})\.?\s+(\d{1,2}),\s*(\d{4})(?!\d)")

# A date immediately preceded by "Updated:" is a revision stamp, not the publication
# date; the connector skips it and falls through to <meta name="releaseDate">.
_UPDATED_PREFIX_RE = re.compile(r"updated\W*$", re.IGNORECASE)

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Read in the page context of an article. Everything article-specific is scoped to
# `.stories-category`, the article container: the page also renders a related-posts
# carousel whose cards carry their own `p.dateline`, and an unbounded selector would
# stamp a neighbouring article's date onto this report.
_METADATA_JS = """
() => {
  const q = (sel) => document.querySelector(sel);
  const metaContent = (sel) => {
    const el = q(sel);
    return el && el.content ? el.content.trim() : null;
  };
  const article = q('.stories-category');
  const dateline = article ? article.querySelector('p.dateline') : null;
  const heading = article ? article.querySelector('h1') : null;
  const canonical = q('link[rel="canonical"]');
  return {
    article_present: !!article,
    canonical: canonical ? canonical.href : null,
    title: metaContent('meta[property="og:title"]'),
    heading: heading ? heading.textContent.trim() : null,
    description: metaContent('meta[name="description"]')
              || metaContent('meta[property="og:description"]'),
    release_date: metaContent('meta[name="releaseDate"]'),
    dateline: dateline ? dateline.textContent.replace(/\\s+/g, ' ').trim() : null
  };
}
"""

# Fetch a URL same-origin from inside an already-loaded trellix.com page. Used as the
# WAF-proof fallback for the sitemap.
_SAME_ORIGIN_FETCH_JS = """
(url) => fetch(url, {credentials: 'same-origin'})
    .then((r) => (r.ok ? r.text() : null))
    .catch(() => null)
"""


def _escape_html(value):
    """Minimal HTML escaping for the PDF footer template."""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _local_name(tag):
    """Strip the XML namespace from an ElementTree tag.

    Sitemap elements are namespaced
    (`{http://www.sitemaps.org/schemas/sitemap/0.9}loc`); matching on the local name
    keeps the parser independent of the namespace URI.
    """
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _date_from_dateline(dateline):
    """Extract the publication date from an article byline.

    Returns the first `Month D, YYYY` in the dateline that is not tagged "Updated:",
    which is the original publication date even where the CMS `releaseDate` has been
    overwritten by the January 2022 rebrand migration.

    Args:
        dateline: byline text from the article container, or None.

    Returns:
        datetime: midnight UTC on the publication date, or None if the dateline holds
        no usable date (missing, or carrying only an "Updated:" revision stamp).
    """
    if not dateline:
        return None
    for match in _DATELINE_DATE_RE.finditer(dateline):
        month = _MONTHS.get(match.group(1)[:3].lower())
        if month is None:
            continue  # an ordinary word ("written", "blog"), not a month name
        preceding = dateline[max(0, match.start() - 14):match.start()]
        if _UPDATED_PREFIX_RE.search(preceding):
            continue  # revision stamp; fall through to releaseDate
        day, year = int(match.group(2)), int(match.group(3))
        if not MIN_VALID_YEAR <= year <= datetime.now(timezone.utc).year + 1:
            continue
        try:
            return datetime(year, month, day, tzinfo=timezone.utc)
        except ValueError:
            continue  # e.g. "February 30" in hand-written markup
    return None


def _date_from_release_meta(raw):
    """Parse `<meta name="releaseDate">` (ISO 8601, e.g. 2026-04-20T07:09:00.000Z).

    Returns:
        datetime in UTC, or None if absent/unparseable/out of range.
    """
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed.year < MIN_VALID_YEAR:
        return None
    return parsed.astimezone(timezone.utc)


class TrellixBlogConnector:
    """External-import connector that mirrors Trellix blog posts into Reports."""

    def __init__(self):
        """Load configuration, build the OpenCTI helper, and prepare the HTTP
        client. Fixed graph references are resolved later in run() via
        _resolve_graph_references().
        """
        config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        # --- Source configuration ------------------------------------------ #
        # `or` guard: get_config_variable returns an empty override verbatim rather
        # than falling back to `default`, and an empty base URL would silently
        # produce a relative sitemap URL.
        self.base_url = (get_config_variable(
            "TRELLIX_BASE_URL", ["trellix_blog", "base_url"], config,
            default="https://www.trellix.com",
        ) or "https://www.trellix.com").rstrip("/")

        # The complete en-US sitemap, as declared in robots.txt. This is the sole
        # enumeration surface: the origin publishes no RSS feed.
        self.sitemap_url = get_config_variable(
            "TRELLIX_SITEMAP_URL", ["trellix_blog", "sitemap_url"], config,
            default="",
        ) or f"{self.base_url}/en-us.sitemap.xml"

        # Comma-separated blog category slugs to ingest. Default = the two
        # threat-intelligence-bearing categories; "perspectives" (corporate and
        # thought-leadership content) is excluded by default.
        categories_raw = get_config_variable(
            "TRELLIX_CATEGORIES", ["trellix_blog", "categories"], config,
            default="research,platform",
        )
        self.categories = [
            slug.strip().strip("/").lower()
            for slug in str(categories_raw).split(",")
            if slug.strip().strip("/")
        ]
        if not self.categories:
            raise ValueError(
                "TRELLIX_CATEGORIES resolved to an empty list; refusing to start with "
                "no category in scope."
            )

        # Poll interval (seconds) between enumeration runs. Daily is ample: the
        # sitemap re-walk is cheap and Trellix publishes a handful of posts a month.
        self.poll_interval = get_config_variable(
            "TRELLIX_POLL_INTERVAL", ["trellix_blog", "poll_interval"], config,
            isNumber=True, default=86400,  # 24 hours
        )

        # Politeness delay (seconds) between successive article page loads.
        # robots.txt sets no Crawl-Delay; a small default is courteous.
        self.request_delay = get_config_variable(
            "TRELLIX_REQUEST_DELAY", ["trellix_blog", "request_delay"], config,
            isNumber=True, default=3,
        )

        # Per-run cap on new Reports. 0 == unlimited. Set small (e.g. 3) for a
        # bounded test before the full backfill.
        self.max_reports = get_config_variable(
            "TRELLIX_MAX_REPORTS", ["trellix_blog", "max_reports"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ------------------------------------------ #
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["trellix_blog", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "TRELLIX_RENDER_RETRIES", ["trellix_blog", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        # OpenCTI confidence 0-100. Medium band, matching the OSINT-publisher
        # connectors; Trellix is a primary source but we keep cross-connector parity.
        self.confidence = get_config_variable(
            "TRELLIX_CONFIDENCE", ["trellix_blog", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "TRELLIX_REPORT_TYPE", ["trellix_blog", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "TRELLIX_TLP", ["trellix_blog", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "TRELLIX_AUTHOR_NAME", ["trellix_blog", "author_name"], config,
            default="Trellix",
        )

        # HTTP session for the sitemap fetch: browser UA + XML accept.
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "application/xml, text/xml, */*",
        })

        # Resolved at startup.
        self.author_id = None          # author Organization internal UUID
        self.marking_id = None         # TLP marking internal UUID

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Resolve fixed graph objects and register the report_type vocabulary.

        Resolves internal OpenCTI UUIDs for the author identity and the TLP marking
        and registers the report_type vocabulary value. The marking resolution is
        fail-closed (raises), since Reports must not be created without a resolved
        marking UUID.

        Raises:
            RuntimeError: if the TLP marking cannot be resolved.
        """
        # Author: identity.create is upsert-safe (returns existing if present).
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Trellix threat intelligence and research (Advanced Research "
                        "Center). Source organization for ingested reports.",
        )
        self.author_id = author["id"]
        self.helper.log_info(f"Resolved author identity '{self.author_name}': {self.author_id}")

        # Marking: read to an internal UUID (TLP markings ship with the platform).
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

        # report_type open-vocabulary registration. Idempotent; harmless failure if
        # the vocabulary is locked (operator adds it via Settings).
        try:
            self.helper.api.vocabulary.create(
                name=self.report_type,
                category="report_types_ov",
                description="Open-source reporting ingested from public OSINT publishers.",
            )
            self.helper.log_info(f"Ensured report_type vocabulary value: {self.report_type}")
        except Exception as exc:  # noqa: BLE001 - non-fatal, operator-actionable
            self.helper.log_warning(
                f"Could not register report_type '{self.report_type}' ({exc}). "
                f"Add it under Settings -> Taxonomies -> Report types if missing."
            )

    # ------------------------------------------------------------------ #
    # Sitemap enumeration
    # ------------------------------------------------------------------ #

    def _fetch_sitemap(self, page):
        """Fetch the sitemap XML, preferring plain HTTP and falling back to the browser.

        The sitemap is a static XML asset, so the cheap `requests` path is tried
        first. The origin's edge WAF gates non-browser clients, however, so on any
        failure the connector retries via a same-origin `fetch()` evaluated inside
        the supplied Chromium page (which is already parked on trellix.com).

        Args:
            page: a Playwright page already navigated to a trellix.com URL, used for
                the same-origin fallback fetch.

        Returns:
            str: sitemap XML, or None if both paths failed.
        """
        try:
            resp = self.session.get(self.sitemap_url, timeout=90)
            if resp.status_code == 200 and resp.content.strip():
                return resp.text
            self.helper.log_warning(
                f"Direct sitemap fetch returned HTTP {resp.status_code} "
                f"({len(resp.content)} bytes); falling back to the browser."
            )
        except Exception as exc:  # noqa: BLE001 - falls back to the browser path
            self.helper.log_warning(
                f"Direct sitemap fetch failed ({exc}); falling back to the browser."
            )

        try:
            xml = page.evaluate(_SAME_ORIGIN_FETCH_JS, self.sitemap_url)
        except Exception as exc:  # noqa: BLE001 - cycle retries next poll
            self.helper.log_error(f"Browser sitemap fetch raised: {exc}")
            return None
        if not xml:
            self.helper.log_error(
                f"Browser sitemap fetch returned no body for {self.sitemap_url}."
            )
            return None
        self.helper.log_info("Sitemap retrieved via the browser fallback path.")
        return xml

    def _enumerate_posts(self, page):
        """Enumerate in-scope blog post URLs from the sitemap.

        Filters the sitemap to `/blogs/{category}/{slug}/` URLs whose category is in
        scope, and orders them by `<lastmod>` descending (freshest first) with the
        URL as a stable tie-break. `lastmod` is a CMS modification date, not a
        publication date; it orders the walk and is never written to the graph.

        Args:
            page: Playwright page used for the sitemap fallback fetch.

        Returns:
            list[str]: in-scope article URLs, freshest-modified first. None on a
            fetch/parse failure (caller ends the cycle and retries next poll).
        """
        xml = self._fetch_sitemap(page)
        if xml is None:
            return None
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            self.helper.log_error(f"Sitemap returned unparseable XML: {exc}")
            return None

        entries = []
        seen = set()
        for url_el in root.iter():
            if _local_name(url_el.tag) != "url":
                continue
            loc = lastmod = ""
            for child in url_el:
                name = _local_name(child.tag)
                if name == "loc":
                    loc = (child.text or "").strip()
                elif name == "lastmod":
                    lastmod = (child.text or "").strip()
            if not loc or loc in seen:
                continue
            match = _POST_URL_RE.match(loc)
            if not match or match.group("category").lower() not in self.categories:
                continue
            seen.add(loc)
            entries.append((lastmod, loc))

        # Freshest lastmod first; URL as a deterministic tie-break. Entries with no
        # lastmod sort last, which is the conservative placement for a backfill.
        entries.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
        return [loc for _lastmod, loc in entries]

    @staticmethod
    def _report_id(url):
        """Deterministic Report STIX id derived from an article URL.

        The same URL always maps to the same Report id, which makes the existence
        check and every write idempotent.
        """
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))

    @staticmethod
    def _canonical_url(metadata, fallback_url):
        """Pick the URL a Report should be keyed and referenced on.

        Prefers the page's own `rel=canonical` when it is a Trellix blog post URL:
        the CMS publishes a few articles under two category paths, one canonicalising
        to the other, and keying on the canonical collapses those aliases onto one
        Report. Falls back to the sitemap URL otherwise.
        """
        canonical = (metadata.get("canonical") or "").strip()
        if canonical and _POST_URL_RE.match(canonical):
            return canonical
        return fallback_url

    # ------------------------------------------------------------------ #
    # Page load: metadata + PDF render (Playwright)
    # ------------------------------------------------------------------ #

    def _auto_scroll(self, page):
        """Scroll to the page bottom to trigger lazy-loaded media before render."""
        page.evaluate(
            """
            async () => {
              await new Promise((resolve) => {
                let total = 0;
                const step = 400;
                const maxScroll = 100000;
                const timer = setInterval(() => {
                  window.scrollBy(0, step);
                  total += step;
                  if (total >= document.body.scrollHeight || total >= maxScroll) {
                    clearInterval(timer);
                    window.scrollTo(0, 0);
                    resolve();
                  }
                }, 100);
              });
            }
            """
        )

    def _load_article(self, browser, url):
        """Load an article once, reading both its metadata and its PDF.

        Metadata is read from the DOM of the same page that is rendered to PDF, so a
        post costs exactly one page load and the metadata path inherits the browser's
        standing with the origin's edge WAF.

        Args:
            browser: active Playwright Chromium browser.
            url: article URL from the sitemap.

        Returns:
            tuple[dict, bytes]: (metadata, PDF bytes).

        Raises:
            RuntimeError: on an edge-challenge interstitial or a page that is not an
                article (the 404 page, or a shell that failed to render).
            playwright errors: navigation timeouts propagate for retry handling.
        """
        context = browser.new_context(
            viewport={"width": 1280, "height": 1696},
            user_agent=BROWSER_UA,
        )
        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=self.nav_timeout_ms)

            title = (page.title() or "").lower()
            if any(marker in title for marker in CHALLENGE_MARKERS):
                raise RuntimeError("Edge challenge interstitial detected")

            metadata = page.evaluate(_METADATA_JS)
            if not metadata.get("article_present"):
                # No `.stories-category` container: the site 404 page, or a shell
                # that never hydrated. Either way this is not an article.
                raise RuntimeError("Article container absent (404 page or failed render)")
            if not (metadata.get("title") or metadata.get("heading")):
                raise RuntimeError("Article carries no title")

            self._auto_scroll(page)
            page.wait_for_timeout(1500)  # final settle for post-scroll loads

            ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            footer = (
                "<div style='font-size:8px; width:100%; padding:0 12px; "
                "color:#444; display:flex; justify-content:space-between;'>"
                f"<span>{_escape_html(url)}</span>"
                f"<span>OpenCTI Trellix blog connector &middot; ingested "
                f"{ingested_at} &middot; page <span class='pageNumber'></span>/"
                "<span class='totalPages'></span></span></div>"
            )
            pdf_bytes = page.pdf(
                print_background=True,
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=footer,
                margin={"top": "10mm", "bottom": "16mm", "left": "8mm", "right": "8mm"},
                format="A4",
            )
            return metadata, pdf_bytes
        finally:
            page.close()
            context.close()

    def _load_with_retry(self, browser, url):
        """Load an article with bounded exponential backoff.

        Returns:
            tuple[dict, bytes, int]: (metadata, PDF, attempts) on success, or
            (None, None, attempts) if all retries are exhausted.
        """
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                metadata, pdf_bytes = self._load_article(browser, url)
                return metadata, pdf_bytes, attempt
            except Exception as exc:  # noqa: BLE001 - retried, then skipped
                self.helper.log_warning(
                    f"Load attempt {attempt}/{self.render_retries} failed for {url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
        return None, None, self.render_retries

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _resolve_published(self, metadata, url):
        """Resolve a post's publication timestamp.

        Prefers the article's own dateline over `<meta name="releaseDate">`: the
        January 2022 rebrand migration overwrote releaseDate with the migration date
        on posts inherited from the McAfee Enterprise and FireEye blogs, while the
        dateline kept the original publication date.

        Returns:
            str: ISO 8601 UTC timestamp. Falls back to ingestion time (with a
            warning) if the page carries no usable date at all.
        """
        published = _date_from_dateline(metadata.get("dateline"))
        if published is None:
            published = _date_from_release_meta(metadata.get("release_date"))
        if published is None:
            self.helper.log_warning(
                f"No usable publication date for {url} "
                f"(dateline={metadata.get('dateline')!r}, "
                f"releaseDate={metadata.get('release_date')!r}); using ingestion time."
            )
            published = datetime.now(timezone.utc)
        return published.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def _create_report(self, url, metadata, pdf_bytes):
        """Create one Report container for a post and attach its PDF.

        Container-only: no object_refs. The Report carries a deterministic stix_id
        derived from the canonical article URL so the write is idempotent.

        Args:
            url: canonical article URL (also the Report's External Reference).
            metadata: page metadata read by _load_article().
            pdf_bytes: rendered article PDF.
        """
        name = metadata.get("title") or metadata.get("heading") or url
        description = metadata.get("description") or ""
        published = self._resolve_published(metadata, url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on www.trellix.com",
        )

        report = self.helper.api.report.create(
            stix_id=self._report_id(url),
            name=name,
            description=description,
            published=published,
            report_types=[self.report_type],
            confidence=self.confidence,
            createdBy=self.author_id,
            objectMarking=[self.marking_id],
            externalReferences=[external_reference["id"]],
            update=True,
        )

        match = _POST_URL_RE.match(url)
        category = match.group("category").lower() if match else "blog"
        slug = match.group("slug") if match else "report"
        self.helper.api.stix_domain_object.add_file(
            id=report["id"],
            file_name=f"trellix-{category}-{slug}.pdf",
            data=pdf_bytes,
            mime_type="application/pdf",
        )
        self.helper.log_info(
            f"Created Report for {url} ({name[:80]}) published {published[:10]}"
        )

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        """Execute one enumeration-and-ingest pass over the sitemap.

        Enumerates in-scope posts from the sitemap and loads each not-yet-ingested
        one into a Report + PDF. Deduplication is graph-driven and runs twice per
        post: once on the sitemap URL before the page load, and once on the page's
        canonical URL after it. There is no cursor; new posts appear in the sitemap
        and are picked up on the next poll.
        """
        from playwright.sync_api import sync_playwright  # lazy import

        self._work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Trellix blog enumeration run"
        )

        processed = 0   # new Reports created
        skipped = 0     # already present in the graph
        failed = 0      # page load / render failed
        urls = None

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                # Park a page on the origin so the sitemap fallback can fetch it
                # same-origin, then enumerate.
                bootstrap_ctx = browser.new_context(user_agent=BROWSER_UA)
                try:
                    bootstrap_page = bootstrap_ctx.new_page()
                    try:
                        bootstrap_page.goto(
                            f"{self.base_url}/blogs/",
                            wait_until="domcontentloaded",
                            timeout=self.nav_timeout_ms,
                        )
                    except Exception as exc:  # noqa: BLE001 - the direct path may still work
                        self.helper.log_warning(
                            f"Could not park a page on {self.base_url}/blogs/ ({exc}); "
                            f"the same-origin sitemap fallback will be unavailable this cycle."
                        )
                    urls = self._enumerate_posts(bootstrap_page)
                finally:
                    bootstrap_ctx.close()

                if urls is None:
                    message = "Run aborted: sitemap unavailable; retrying next poll."
                    self.helper.log_error(message)
                    self.helper.api.work.to_processed(self._work_id, message)
                    return

                self.helper.log_info(
                    f"Sitemap yielded {len(urls)} in-scope posts "
                    f"(categories={','.join(self.categories)}, "
                    f"request_delay={self.request_delay}s, "
                    f"max_reports={self.max_reports or 'unlimited'})."
                )

                for url in urls:
                    if self.max_reports and processed >= self.max_reports:
                        self.helper.log_info(
                            f"Reached TRELLIX_MAX_REPORTS={self.max_reports}; stopping run."
                        )
                        break

                    # Cheap dedup: skip already-ingested posts without a page load.
                    if self.helper.api.report.read(id=self._report_id(url)) is not None:
                        skipped += 1
                        continue

                    if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                        browser.close()
                        browser = pw.chromium.launch(
                            args=["--no-sandbox", "--disable-dev-shm-usage"]
                        )
                        renders_since_recycle = 0

                    metadata, pdf_bytes, attempts = self._load_with_retry(browser, url)
                    renders_since_recycle += attempts

                    if metadata is None:
                        failed += 1
                        self.helper.log_warning(f"Skipping {url}: load failed after retries.")
                        continue

                    # The CMS aliases a few articles across two category paths. Key on
                    # the canonical URL, and re-check the graph when it differs from
                    # the sitemap URL already checked above.
                    canonical = self._canonical_url(metadata, url)
                    if canonical != url and self.helper.api.report.read(
                        id=self._report_id(canonical)
                    ) is not None:
                        skipped += 1
                        self.helper.log_info(
                            f"Skipping {url}: already ingested under its canonical "
                            f"URL {canonical}."
                        )
                        time.sleep(self.request_delay)
                        continue

                    self._create_report(canonical, metadata, pdf_bytes)
                    processed += 1
                    time.sleep(self.request_delay)
            finally:
                browser.close()

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (load/render), out of {len(urls or [])} in-scope posts."
        )
        self.helper.api.work.to_processed(self._work_id, message)
        self.helper.log_info(message)

    def run(self):
        """Connector entrypoint: resolve references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info(
            f"Trellix blog connector started (categories={','.join(self.categories)})."
        )
        while True:
            self._work_id = None
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001 - keep the connector alive
                self.helper.log_error(
                    f"Unhandled error during run: {exc}\n{traceback.format_exc()}"
                )
                if self._work_id:
                    try:
                        self.helper.api.work.to_processed(
                            self._work_id,
                            f"Run failed with unhandled error: {exc}",
                        )
                    except Exception:  # noqa: BLE001 - best-effort finalization
                        pass
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        TrellixBlogConnector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
