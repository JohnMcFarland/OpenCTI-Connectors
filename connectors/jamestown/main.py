"""
The Jamestown Foundation OpenCTI connector.

Purpose
-------
External-import connector that ingests the entire Jamestown Foundation corpus
(https://jamestown.org) — every analytical article across all publication series
(Eurasia Daily Monitor, China Brief, Terrorism Monitor, Militant Leadership
Monitor, North Caucasus Weekly, Terrorism Focus, Prism, Spotlight on Terror,
Jamestown Perspectives, and the rest) plus the Briefs, Reports, Interviews, and
Books custom post types — and creates one OpenCTI Report container per item, with
the source page attached as a full-fidelity PDF.

Collection model
----------------
Jamestown runs WordPress and exposes a live WordPress REST API, so collection
enumerates each post type directly through the API rather than scraping front-end
archives (mirrors The DFIR Report's API-first approach, at ~550x the scale):

  - GET /wp-json/wp/v2/<rest_base>?per_page=100&page=N&order=asc&orderby=date
    paginated to the X-WP-TotalPages boundary, for each configured post type
    (posts, brief, report, interview, book). The API returns a stable post id,
    canonical link, slug, date_gmt, rendered title/excerpt, and the term
    class_list (which encodes the publication series, topics, and regions) in a
    single pass.

Enumeration is ASCENDING (oldest -> newest) behind a persisted, *positional*
cursor {<post_type>: {page, index}} held in OpenCTI connector state. A positional
(page/index) cursor is required rather than a date cursor because ~2,300 legacy
articles share an identical 1970-01-01 placeholder date (lost in a CMS migration),
which a date-valued cursor cannot disambiguate. The cursor advances one article at
a time, so an interrupted multi-day backfill resumes within the current page rather
than restarting. The same cursor drives steady state: once a type's newest page is
exhausted the cursor rests at its tail, and each subsequent poll re-fetches that
page to pick up freshly-appended articles, rolling onto a new page when one fills.
One uniform code path covers both backfill and steady state, per post type.

Per-article publication date comes from the API field date_gmt (naive UTC, marked
+00:00 on use); title and description come from the rendered title/excerpt fields;
the publication series, topics, and regions come from the post's class_list and are
recorded on the article's External Reference. Playwright is used purely to render
the live page to PDF — there is no on-page metadata scraping, because the API
already supplies everything.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects, no
Observables, no Relationships. Jamestown analysis is narrative geopolitical and
counterterrorism reporting; named-entity / IOC extraction is a separate, explicitly
out-of-scope downstream phase. Keeping this connector container-only makes it purely
additive and prevents it from acting as a graph-contamination vector, even across
the full ~51k-item corpus.

Key decisions (see CONNECTOR_SCOPE.md)
--------------------------------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published think-tank source).
- Author: the "The Jamestown Foundation" Organization identity (single author for
  every series — series identity is carried on the External Reference, not as a
  fan-out of Organization identities). Never the connector account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (Medium band — expert secondary analysis built
  on primary sources; above press aggregators, below first-party incident forensics).
- Scope levers (no code edits): JAMESTOWN_POST_TYPES selects which post types to
  ingest; JAMESTOWN_PUBLICATIONS (comma slugs, posts type only) restricts to chosen
  series server-side. Empty == entire corpus.
- Deduplication: graph-driven via External Reference URL lookup, backed by the
  persisted positional cursor. The graph lookup is the correctness backstop
  (idempotent even if state is lost); the cursor is the efficiency layer that avoids
  re-reading the whole corpus from the graph every poll.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import time
import html

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside the renderer so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Browser User-Agent for BOTH the API HTTP client and the Playwright context. A
# realistic UA keeps enumeration and rendering consistent and avoids UA gating
# (Jamestown is Cloudflare-fronted).
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# WordPress REST API page size. The API caps per_page at 100.
API_PER_PAGE = 100

# Hard ceiling on API pages walked PER post type, a safety stop against a
# pagination bug that never returns a terminating (empty/short) page. The largest
# type (posts) is ~516 pages at 100/page; this leaves ample headroom.
MAX_API_PAGES = 5000

# Recycle the Chromium browser after this many renders to cap memory growth on a
# host that co-locates Elasticsearch.
BROWSER_RECYCLE_EVERY = 50

# Substrings indicating a Cloudflare interstitial rather than article content.
CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")

# Post types ingested by default: the main article stream plus the four
# content-bearing custom post types. (analyst/event/career/press-releases and the
# volume-* index types are deliberately excluded — they are people/calendar/index
# objects, not analytical articles.)
DEFAULT_POST_TYPES = "posts,brief,report,interview,book"

# class_list term prefixes that carry the metadata we record on the External
# Reference: publication series, topic, and region.
CLASS_PREFIXES = {
    "publications-": "series",
    "topic-": "topic",
    "region-": "region",
}


def _strip_html(value: str) -> str:
    """Strip tags and decode HTML entities from a text fragment.

    Args:
        value: raw string that may contain tags/entities (may be empty/None).

    Returns:
        Plain text, tags removed and entities decoded.
    """
    if not value:
        return ""
    no_tags = re.sub(r"<[^>]+>", "", value)
    return html.unescape(no_tags).strip()


def _humanize(slug: str) -> str:
    """Turn a taxonomy slug into a readable label ('military-security' -> 'Military
    Security'). Used as a fallback when a slug is not in a resolved name map.
    """
    return " ".join(part for part in slug.replace("_", "-").split("-") if part).title()


class JamestownConnector:
    """External-import connector that mirrors Jamestown articles into Reports."""

    def __init__(self):
        """Load configuration, build the OpenCTI helper, and prepare the HTTP
        client. Fixed graph references and the publication-series name map are
        resolved later in run() via _resolve_graph_references().
        """
        config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        # --- Source configuration ------------------------------------------ #
        self.base_url = get_config_variable(
            "JAMESTOWN_BASE_URL", ["jamestown", "base_url"], config,
            default="https://jamestown.org",
        ).rstrip("/")

        # Post types to enumerate (WP rest_base values), comma-separated.
        post_types_raw = get_config_variable(
            "JAMESTOWN_POST_TYPES", ["jamestown", "post_types"], config,
            default=DEFAULT_POST_TYPES,
        ) or DEFAULT_POST_TYPES
        self.post_types = [t.strip() for t in post_types_raw.split(",") if t.strip()]

        # Optional publication-series restriction (comma slugs, e.g. "tm,mlm,cb").
        # Applied server-side to the 'posts' type only (the publications taxonomy is
        # registered on posts). Empty == every series.
        publications_raw = get_config_variable(
            "JAMESTOWN_PUBLICATIONS", ["jamestown", "publications"], config,
            default="",
        ) or ""
        self.publication_slugs = [s.strip() for s in publications_raw.split(",") if s.strip()]

        # Poll interval (seconds) between full enumeration runs.
        self.poll_interval = get_config_variable(
            "JAMESTOWN_POLL_INTERVAL", ["jamestown", "poll_interval"], config,
            isNumber=True, default=86400,  # 24 hours
        )

        # Politeness delay (seconds) between successive HTTP/render operations.
        self.request_delay = get_config_variable(
            "JAMESTOWN_REQUEST_DELAY", ["jamestown", "request_delay"], config,
            isNumber=True, default=2,
        )

        # Per-run cap on new Reports across all post types. 0 == unlimited. Set
        # small (e.g. 3) for a bounded test before the full backfill.
        self.max_reports = get_config_variable(
            "JAMESTOWN_MAX_REPORTS", ["jamestown", "max_reports"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ------------------------------------------ #
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["jamestown", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "JAMESTOWN_RENDER_RETRIES", ["jamestown", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        # OpenCTI confidence 0-100. Medium band: expert secondary analysis on
        # primary sources (above press aggregators, below incident forensics).
        self.confidence = get_config_variable(
            "JAMESTOWN_CONFIDENCE", ["jamestown", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "JAMESTOWN_REPORT_TYPE", ["jamestown", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "JAMESTOWN_TLP", ["jamestown", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "JAMESTOWN_AUTHOR_NAME", ["jamestown", "author_name"], config,
            default="The Jamestown Foundation",
        )

        # WP REST API base, derived from the configured base_url.
        self.api_base = f"{self.base_url}/wp-json/wp/v2"

        # HTTP session for API enumeration, browser UA + JSON accept.
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA, "Accept": "application/json"})

        # Resolved at startup.
        self.author_id = None          # author Organization internal UUID
        self.marking_id = None         # TLP marking internal UUID
        self.series_names = {}         # publications slug -> display name
        self.series_ids = {}           # publications slug -> term id (for filtering)

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Resolve fixed graph objects, load the series name map, and verify the
        API is reachable.

        Raises:
            RuntimeError: if the marking cannot be resolved or the API is not
                reachable, since neither can be silently tolerated.
        """
        # Author: identity.create is upsert-safe (returns existing if present).
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Washington, D.C. think tank providing primary-source intelligence "
                        "and analysis on Eurasia, China, and global terrorism. Source "
                        "organization for ingested reports.",
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

        # Publication-series name/id map (the 'publications' taxonomy). Best-effort:
        # used only to label External References and to translate configured series
        # slugs into term ids for server-side filtering. A failure degrades to
        # humanized slugs and (if filtering was requested) an aborted run.
        self._load_series_map()
        if self.publication_slugs:
            missing = [s for s in self.publication_slugs if s not in self.series_ids]
            if missing:
                raise RuntimeError(
                    f"JAMESTOWN_PUBLICATIONS names unknown series slug(s) {missing}; "
                    f"known slugs: {sorted(self.series_ids)}."
                )
            self.helper.log_info(
                f"Series filter active (posts only): {self.publication_slugs}"
            )

        # API reachability: confirm the collection surface is up and exposes the
        # backlog count header on the primary post type.
        probe_url = f"{self.api_base}/{self.post_types[0]}"
        try:
            resp = self.session.get(probe_url, params={"per_page": 1}, timeout=30)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"WordPress REST API unreachable at {probe_url} ({exc}).")
        if resp.status_code != 200 or "X-WP-Total" not in resp.headers:
            raise RuntimeError(
                f"WordPress REST API at {probe_url} returned HTTP {resp.status_code} "
                f"without an X-WP-Total header; refusing to run."
            )
        self.helper.log_info(
            f"WP REST API reachable: {resp.headers.get('X-WP-Total')} items in "
            f"'{self.post_types[0]}'. Enumerating types: {self.post_types}."
        )

    def _load_series_map(self):
        """Populate self.series_names / self.series_ids from the publications
        taxonomy. Best-effort; logs and continues on failure.
        """
        try:
            resp = self.session.get(
                f"{self.api_base}/publications",
                params={"per_page": 100, "_fields": "id,name,slug"},
                timeout=30,
            )
            resp.raise_for_status()
            for term in resp.json():
                slug = term.get("slug")
                if not slug:
                    continue
                self.series_names[slug] = _strip_html(term.get("name") or "") or _humanize(slug)
                self.series_ids[slug] = term.get("id")
            self.helper.log_info(f"Loaded {len(self.series_names)} publication-series terms.")
        except Exception as exc:  # noqa: BLE001 - non-fatal
            self.helper.log_warning(
                f"Could not load publications taxonomy ({exc}); series labels will be "
                f"derived from slugs and series filtering is unavailable."
            )

    # ------------------------------------------------------------------ #
    # Post enumeration (WordPress REST API)
    # ------------------------------------------------------------------ #

    def _fetch_page(self, post_type, page):
        """Fetch one page of a post type, ascending by date.

        Args:
            post_type: WP rest_base (e.g. "posts", "brief").
            page: 1-based page number.

        Returns:
            list[dict]: enumerated posts (possibly empty past the last page). Each
            dict has keys: link, slug, date_gmt, title, excerpt, class_list.

        Raises:
            requests.HTTPError: on a non-200, non-400-past-end response.
        """
        params = {
            "per_page": API_PER_PAGE,
            "page": page,
            "order": "asc",
            "orderby": "date",
            "_fields": "id,link,slug,date_gmt,title,excerpt,class_list",
        }
        # Server-side series filter applies to the main post stream only.
        if post_type == "posts" and self.publication_slugs:
            params["publications"] = ",".join(
                str(self.series_ids[s]) for s in self.publication_slugs
            )

        resp = self.session.get(f"{self.api_base}/{post_type}", params=params, timeout=60)
        # Past the last page WP returns 400 (rest_post_invalid_page_number).
        if resp.status_code == 400 and page > 1:
            return []
        resp.raise_for_status()
        posts = resp.json()
        if not isinstance(posts, list):
            return []
        return [
            {
                "post_type": post_type,
                "link": p.get("link"),
                "slug": p.get("slug"),
                "date_gmt": p.get("date_gmt"),
                "title": (p.get("title") or {}).get("rendered", ""),
                "excerpt": (p.get("excerpt") or {}).get("rendered", ""),
                "class_list": p.get("class_list") or [],
            }
            for p in posts
        ]

    def _already_ingested(self, url):
        """Return True if this article URL already has an External Reference.

        Deduplication is graph-driven and keys off the External Reference this
        connector creates for each article. external_reference creation is the
        first write in _create_report and is keyed on url, so the presence of an
        external reference for a url is the connector's idempotency marker. The
        positional cursor is only an efficiency layer; this graph check is the
        correctness backstop, idempotent even if cursor state is lost.

        Args:
            url: canonical article URL.

        Returns:
            bool: True if an External Reference with this url already exists.
        """
        existing_ref = self.helper.api.external_reference.read(
            filters={
                "mode": "and",
                "filters": [{"key": "url", "values": [url]}],
                "filterGroups": [],
            }
        )
        return existing_ref is not None

    def _parse_class_list(self, class_list):
        """Extract publication series / topics / regions from a post's class_list.

        Args:
            class_list: list of WP body-class strings (e.g. "publications-cb",
                "topic-foreign-policy", "region-china").

        Returns:
            dict with keys 'series', 'topic', 'region', each a list of display
            labels (series via the resolved name map, others humanized from slug).
        """
        out = {"series": [], "topic": [], "region": []}
        for cls in class_list or []:
            for prefix, kind in CLASS_PREFIXES.items():
                if cls.startswith(prefix):
                    slug = cls[len(prefix):]
                    if not slug:
                        break
                    if kind == "series":
                        out["series"].append(self.series_names.get(slug) or _humanize(slug))
                    else:
                        out[kind].append(_humanize(slug))
                    break
        return out

    # ------------------------------------------------------------------ #
    # PDF rendering (Playwright)
    # ------------------------------------------------------------------ #

    def _auto_scroll(self, page):
        """Scroll to the page bottom to trigger lazy-loaded media before render."""
        page.evaluate(
            """
            async () => {
              await new Promise((resolve) => {
                let total = 0;
                const step = 400;
                const timer = setInterval(() => {
                  window.scrollBy(0, step);
                  total += step;
                  if (total >= document.body.scrollHeight) {
                    clearInterval(timer);
                    window.scrollTo(0, 0);
                    resolve();
                  }
                }, 100);
              });
            }
            """
        )

    def _render_pdf(self, browser, url):
        """Render an article to PDF.

        Args:
            browser: active Playwright Chromium browser.
            url: canonical article URL.

        Returns:
            bytes: rendered article PDF.

        Raises:
            RuntimeError: on a Cloudflare challenge interstitial.
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
                raise RuntimeError("Cloudflare challenge interstitial detected")

            self._auto_scroll(page)
            page.wait_for_timeout(1500)  # final settle for post-scroll loads

            from datetime import datetime, timezone
            ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            footer = (
                "<div style='font-size:8px; width:100%; padding:0 12px; "
                "color:#444; display:flex; justify-content:space-between;'>"
                f"<span>{html.escape(url)}</span>"
                f"<span>OpenCTI Jamestown connector &middot; ingested {ingested_at} "
                "&middot; page <span class='pageNumber'></span>/"
                "<span class='totalPages'></span></span></div>"
            )
            return page.pdf(
                print_background=True,
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=footer,
                margin={"top": "10mm", "bottom": "16mm", "left": "8mm", "right": "8mm"},
                format="A4",
            )
        finally:
            page.close()
            context.close()

    def _render_with_retry(self, browser, url):
        """Render with bounded exponential backoff.

        Returns:
            bytes: PDF on success, or None if all retries are exhausted.
        """
        delay = self.request_delay
        for attempt in range(1, self.render_retries + 1):
            try:
                return self._render_pdf(browser, url)
            except Exception as exc:  # noqa: BLE001 - retried, then skipped
                self.helper.log_warning(
                    f"Render attempt {attempt}/{self.render_retries} failed for {url}: {exc}"
                )
                if attempt < self.render_retries:
                    time.sleep(delay)
                    delay *= 2
        return None

    # ------------------------------------------------------------------ #
    # Report creation
    # ------------------------------------------------------------------ #

    def _create_report(self, post, pdf_bytes):
        """Create one Report container for an article and attach its PDF.

        Container-only: no object_refs, so the single-step report.create path is
        used. The publication series, topics, and regions parsed from the post's
        class_list are recorded in the External Reference description so the
        series provenance is preserved without fanning out Organization identities
        or applying Labels.

        Args:
            post: enumerated post dict.
            pdf_bytes: rendered article PDF.
        """
        url = post["link"]
        name = _strip_html(post.get("title") or "") or (post.get("slug") or "report")
        description = _strip_html(post.get("excerpt") or "")

        # date_gmt is naive UTC (e.g. "2025-12-17T14:00:00"); mark it explicitly.
        # Note: ~2,300 legacy posts carry a 1970-01-01 placeholder date from a CMS
        # migration; we ingest that faithfully rather than fabricating a date.
        date_gmt = post.get("date_gmt")
        published = f"{date_gmt}+00:00" if date_gmt else None

        meta = self._parse_class_list(post.get("class_list"))
        ref_bits = []
        if meta["series"]:
            ref_bits.append(", ".join(dict.fromkeys(meta["series"])))
        if meta["topic"]:
            ref_bits.append("Topics: " + ", ".join(dict.fromkeys(meta["topic"])))
        if meta["region"]:
            ref_bits.append("Regions: " + ", ".join(dict.fromkeys(meta["region"])))
        ref_description = " · ".join(ref_bits) if ref_bits else "Source article on jamestown.org"

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description=ref_description,
        )

        report = self.helper.api.report.create(
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

        file_name = f"jamestown-{post.get('post_type', 'post')}-{post.get('slug') or 'report'}.pdf"
        self.helper.api.stix_domain_object.add_file(
            id=report["id"],
            file_name=file_name,
            data=pdf_bytes,
            mime_type="application/pdf",
        )
        self.helper.log_info(f"Created Report for {url} ({name[:80]})")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def _process(self):
        """Execute one enumeration-and-ingest pass across all configured post types.

        Each post type is walked ascending from its persisted {page, index} cursor.
        The cursor advances one article at a time; when a type's last (partial) page
        is reached the cursor rests there so the next poll re-checks it for appended
        articles. Render failures advance the cursor (the article is logged and not
        revisited). Returns when every type is exhausted or max_reports is hit.
        """
        from playwright.sync_api import sync_playwright  # lazy import

        state = self.helper.get_state() or {}
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "The Jamestown Foundation enumeration run"
        )

        processed = 0   # new Reports created
        skipped = 0     # already present in the graph
        failed = 0      # render failed
        stop = False

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                for post_type in self.post_types:
                    if stop:
                        break
                    tstate = state.get(post_type) or {}
                    page = max(1, int(tstate.get("page", 1)))
                    index = max(0, int(tstate.get("index", 0)))
                    self.helper.log_info(
                        f"[{post_type}] resuming at page={page}, index={index}."
                    )

                    for _ in range(MAX_API_PAGES):
                        posts = self._fetch_page(post_type, page)
                        if not posts:
                            # Past the end. Rest the cursor at this empty page so the
                            # next poll re-checks here for newly-appended articles.
                            state[post_type] = {"page": page, "index": 0}
                            self.helper.set_state(state)
                            break

                        for idx in range(index, len(posts)):
                            post = posts[idx]
                            url = post.get("link")

                            if self.max_reports and processed >= self.max_reports:
                                self.helper.log_info(
                                    f"Reached JAMESTOWN_MAX_REPORTS={self.max_reports}; stopping run."
                                )
                                stop = True
                                break

                            if not url:
                                state[post_type] = {"page": page, "index": idx + 1}
                                self.helper.set_state(state)
                                continue

                            if self._already_ingested(url):
                                skipped += 1
                                state[post_type] = {"page": page, "index": idx + 1}
                                self.helper.set_state(state)
                                continue

                            if renders_since_recycle >= BROWSER_RECYCLE_EVERY:
                                browser.close()
                                browser = pw.chromium.launch(
                                    args=["--no-sandbox", "--disable-dev-shm-usage"]
                                )
                                renders_since_recycle = 0

                            pdf_bytes = self._render_with_retry(browser, url)
                            renders_since_recycle += 1

                            if pdf_bytes is None:
                                failed += 1
                                self.helper.log_warning(
                                    f"Skipping {url}: render failed after retries."
                                )
                                state[post_type] = {"page": page, "index": idx + 1}
                                self.helper.set_state(state)
                                continue

                            self._create_report(post, pdf_bytes)
                            processed += 1
                            state[post_type] = {"page": page, "index": idx + 1}
                            self.helper.set_state(state)
                            time.sleep(self.request_delay)

                        if stop:
                            break

                        if len(posts) < API_PER_PAGE:
                            # Partial last page: rest here (cursor at the tail) so the
                            # next poll picks up articles appended to this page.
                            state[post_type] = {"page": page, "index": len(posts)}
                            self.helper.set_state(state)
                            break

                        # Full page consumed: advance to the next page.
                        page += 1
                        index = 0
                        state[post_type] = {"page": page, "index": 0}
                        self.helper.set_state(state)
                        time.sleep(self.request_delay)  # politeness between API pages
                    else:
                        self.helper.log_warning(
                            f"[{post_type}] hit MAX_API_PAGES={MAX_API_PAGES} without a "
                            f"terminating page; the list may be incomplete."
                        )
            finally:
                browser.close()

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        """Connector entrypoint: resolve references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info("The Jamestown Foundation connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001 - keep the connector alive
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        JamestownConnector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
