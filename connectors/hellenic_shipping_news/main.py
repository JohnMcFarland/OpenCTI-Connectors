"""
Hellenic Shipping News OpenCTI connector.

Purpose
-------
External-import connector that ingests articles from
https://www.hellenicshippingnews.com as container-only OpenCTI Reports, one per
post, with the live source page attached as a full-fidelity PDF.

Collection model (category-filtered WordPress REST backfill + steady state)
---------------------------------------------------------------------------
Hellenic Shipping News is a WordPress site (single post type `post`). Unlike the
Jamestown origin, this origin leaves the structured surfaces open to a browser-UA
client: the WordPress REST API (/wp-json/wp/v2/posts), the RSS feed, and the XML
sitemap all return HTTP 200. The REST API is therefore the enumeration surface,
because it supports server-side category filtering and stable ordering.

The full corpus is ~94k posts, the bulk of which are routine daily/weekly
market-data tickers (currency ratings, bunker prices, index quotes) with no
intelligence value. Collection is deliberately SCOPED to a fixed category
allowlist (HSN_CATEGORIES), server-side filtered via the REST `categories`
parameter. The default allowlist is the security/legal/risk and
geopolitics/energy/economy tiers (~30k posts); the high-volume shipping-operations
and Greek-market tiers and all pure market-data ticker categories are excluded.

Enumeration walks the filtered posts in ascending post-id order
(orderby=id&order=asc) behind a persisted positional {page, index} cursor held in
OpenCTI connector state. Ascending id is used, not date: ~thousands of legacy posts
carry a broken placeholder publication date (year -0001) that a date cursor cannot
disambiguate, whereas post ids are monotonic and stable. New posts always receive
the highest ids and land on the last page, so a positional cursor walked from page 1
is stable for the historical backfill and, once it reaches the tail, naturally picks
up freshly-appended posts on each subsequent poll. One uniform code path covers both
backfill and steady state (mirrors the ScienceDaily connector).

How far back the backfill reaches is bounded by HSN_BACKFILL_START_DATE: when set,
it is passed as the WordPress `after` filter so the origin returns only posts
published on/after that date (which also excludes the -0001 placeholder posts). It
must be an absolute date (e.g. 2023-07-19 for a two-year backfill at deployment),
NOT a relative window: the positional id cursor is only stable if the filtered set
is stable across restarts, so a drifting floor would silently mis-position it. Empty
means the full filtered corpus. The scope (category allowlist + floor) is fingerprinted
into connector state; changing it resets the cursor to page 1 rather than
mis-positioning it, and graph dedup makes the re-scan safe.

Per-post title, excerpt (description), publication date, link, and category ids are
read directly from the REST payload. Playwright is used purely to render the article
page to PDF: enumeration never goes through Playwright.

Publication date comes from the post's date_gmt (falling back to modified_gmt),
parsed as UTC. A post whose only available dates are the broken -0001 placeholder is
dated to ingestion time with a warning rather than dropped, because these are real
in-scope articles with a CMS date defect and no other date signal.

Deduplication and crash-safety
------------------------------
Dedup keys on a deterministic Report STIX id derived from the article URL
(uuid5 over the URL). Before rendering, the connector checks report.read(id) and
skips if the Report already exists. For a new post it creates the External Reference
(upsert-safe), then the Report (with the deterministic stix_id), then attaches the
PDF. Because the existence check keys on the Report id (not on the External
Reference), every sub-write is idempotent and a crash anywhere leaves the post still
"not done"; the next poll re-enters and completes it. The graph lookup is the
correctness backstop (idempotent even if the cursor state is lost); the {page, index}
cursor is the efficiency layer that avoids re-reading the whole corpus every poll.

Design philosophy
-----------------
Container-only. Creates Report containers and nothing else: no Domain Objects, no
Observables, no Relationships, no Labels. Named-entity / IOC extraction is a
separate, out-of-scope downstream phase. Keeping this connector container-only makes
it purely additive and prevents it from acting as a graph-contamination vector.

Politeness: the site's robots.txt requests Crawl-Delay: 30 and signals reference use
as permitted. The connector runs under a plain browser User-Agent for reference-use
ingestion and defaults HSN_REQUEST_DELAY to 30 seconds to honor the crawl delay.

Key decisions (see CONNECTOR_SCOPE.md)
--------------------------------------
- Container type: Report (external intelligence). Never Incident Response.
- TLP: CLEAR (free, publicly published source).
- Author: the single "Hellenic Shipping News" Organization identity. Never the
  connector account.
- report_type: "open-source-reporting" (custom open-vocabulary value).
- Confidence: a single blanket value (Medium band: secondary trade-news aggregation).
- Category ids drive server-side filtering only; they are NOT bound to Reports,
  Labels, or the External Reference.

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import re
import sys
import time
import html
import uuid
from datetime import datetime, timezone

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Playwright is imported lazily inside the renderer so a syntax/import check of
# this module does not require the browser stack to be present.


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Browser User-Agent for BOTH the REST client and the Playwright context. A
# realistic UA keeps enumeration and rendering consistent and avoids UA gating
# (the origin is Cloudflare-fronted). This is deliberately NOT ClaudeBot: the
# connector performs reference-use ingestion, the one use the site's robots.txt
# content-signal permits.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# WordPress REST caps per_page at 100.
MAX_PER_PAGE = 100

# Recycle the Chromium browser after this many renders to cap memory growth on a
# host that co-locates Elasticsearch.
BROWSER_RECYCLE_EVERY = 50

# Substrings indicating a Cloudflare interstitial rather than article content.
CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-browser-verification")

# Earliest plausible real publication year. Anything below this (notably the
# WordPress -0001 placeholder date defect) is treated as "no usable date".
MIN_VALID_YEAR = 1990


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


class HellenicShippingNewsConnector:
    """External-import connector that mirrors Hellenic Shipping News posts into Reports."""

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
        self.base_url = get_config_variable(
            "HSN_BASE_URL", ["hsn", "base_url"], config,
            default="https://www.hellenicshippingnews.com",
        ).rstrip("/")
        self.api_url = f"{self.base_url}/wp-json/wp/v2/posts"

        # Comma-separated WordPress category ids to ingest (server-side OR filter).
        # Default: security/legal/risk + geopolitics/energy/economy + shipping-ops.
        # (120 Report/Analysis dropped: verified 100% recurring charter-estimate
        # tables, no analysis. 122 Dry Bulk Market kept: ~56% Baltic Dry Index
        # tickers but ~44% substantive dry-bulk/commodity-flow reporting.)
        #   27  International Shipping News  101 Commodity News
        #   103 Oil & Companies News        105 Shipbuilding News
        #   107 World Economy News          108 General Energy News
        #   109 Piracy and Security News    112 Port News
        #   113 Freight News                115 Marine Insurance P&I Club News
        #   118 Shipping Law News           122 Dry Bulk Market
        #   124 Shipping: Emission Possible 125 IMF/OECD News
        self.categories = get_config_variable(
            "HSN_CATEGORIES", ["hsn", "categories"], config,
            default="27,101,103,105,107,108,109,112,113,115,118,122,124,125",
        ).strip()

        self.per_page = get_config_variable(
            "HSN_PER_PAGE", ["hsn", "per_page"], config,
            isNumber=True, default=MAX_PER_PAGE,
        )
        if self.per_page > MAX_PER_PAGE or self.per_page < 1:
            self.per_page = MAX_PER_PAGE

        # Optional backfill floor: only ingest posts published on/after this date
        # (server-side WordPress `after` filter). Empty = full corpus. For a
        # two-year backfill, set this to the date two years before deployment
        # (e.g. 2023-07-19). An ABSOLUTE date is required, not a relative window:
        # the positional id cursor is only stable if the filtered set is stable
        # across restarts, so the floor must not drift. Fail-closed on a bad value.
        self.backfill_after = self._parse_start_date(
            get_config_variable(
                "HSN_BACKFILL_START_DATE", ["hsn", "backfill_start_date"], config,
                default="",
            )
        )

        # Optional title-exclusion filter: a single case-insensitive regex matched
        # against each post's title; matches are skipped before render. Empty = off.
        # This is a CLIENT-SIDE refinement of the category-filtered stream, used to
        # drop recurring machine-generated "sub reports" that share a category with
        # substantive posts and so cannot be separated server-side (e.g. the "Baltic
        # Dry Index ..." daily tickers inside Dry Bulk Market, which carry no
        # distinguishing tag or sub-category). Because it does not change the set or
        # ordering of posts the API returns, it does NOT affect the positional cursor
        # and is deliberately excluded from the scope signature: editing it takes
        # effect going forward without a cursor reset. Fail-closed on a bad regex.
        # Default drops the recurring machine-generated data/listing series that
        # share categories with substantive posts (~2.7/day, ~1k/yr, ~4-5% of
        # inflow): Baltic Dry Index tickers, GAC port bulletins, Drewry/Intra-Asia
        # container indices and weekly Container Reports, ENGINE bunker-availability
        # outlooks, vessel auction (Bidding Announcement) listings, and Fujairah
        # inventory reports. Editorial recurring series (ING "The Commodities Feed",
        # "The Week in Alt Fuels", GTT newbuild-order PRs) are intentionally kept.
        self.title_exclude_re = self._compile_title_exclude(
            get_config_variable(
                "HSN_TITLE_EXCLUDE", ["hsn", "title_exclude"], config,
                default=(
                    "Baltic Dry Index|HOT PORT NEWS from GAC|World Container Index|"
                    "Intra-Asia Container Index|Container Report|^ENGINE:|"
                    "Bidding Announcement|Fujairah.*Inventor"
                ),
            )
        )

        # Poll interval (seconds) between enumeration runs. Daily is ample: the
        # backfill resumes from its cursor, and the site adds tens of new in-scope
        # posts per day.
        self.poll_interval = get_config_variable(
            "HSN_POLL_INTERVAL", ["hsn", "poll_interval"], config,
            isNumber=True, default=86400,  # 24 hours
        )

        # Politeness delay (seconds) between successive renders. Defaults to 30 to
        # honor the site's robots.txt Crawl-Delay: 30.
        self.request_delay = get_config_variable(
            "HSN_REQUEST_DELAY", ["hsn", "request_delay"], config,
            isNumber=True, default=30,
        )

        # Per-run cap on new Reports. 0 == unlimited. Set small (e.g. 3) for a
        # bounded test before the full backfill.
        self.max_reports = get_config_variable(
            "HSN_MAX_REPORTS", ["hsn", "max_reports"], config,
            isNumber=True, default=0,
        )

        # --- Render configuration ------------------------------------------ #
        self.nav_timeout_ms = get_config_variable(
            "PLAYWRIGHT_NAV_TIMEOUT", ["hsn", "playwright_nav_timeout"], config,
            isNumber=True, default=60000,
        )
        self.render_retries = get_config_variable(
            "HSN_RENDER_RETRIES", ["hsn", "render_retries"], config,
            isNumber=True, default=3,
        )

        # --- Report field configuration ------------------------------------ #
        # OpenCTI confidence 0-100. Medium band: secondary trade-news aggregation.
        self.confidence = get_config_variable(
            "HSN_CONFIDENCE", ["hsn", "confidence"], config,
            isNumber=True, default=50,
        )
        self.report_type = get_config_variable(
            "HSN_REPORT_TYPE", ["hsn", "report_type"], config,
            default="open-source-reporting",
        )
        self.tlp_name = get_config_variable(
            "HSN_TLP", ["hsn", "tlp"], config,
            default="TLP:CLEAR",
        )
        self.author_name = get_config_variable(
            "HSN_AUTHOR_NAME", ["hsn", "author_name"], config,
            default="Hellenic Shipping News",
        )

        # HTTP session for REST enumeration: browser UA + JSON accept.
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": "application/json, */*",
        })

        # Resolved at startup.
        self.author_id = None          # author Organization internal UUID
        self.marking_id = None         # TLP marking internal UUID

    @staticmethod
    def _parse_start_date(raw):
        """Validate HSN_BACKFILL_START_DATE and return a WordPress `after` string.

        Accepts an empty value (no floor -> None) or an ISO 8601 date / datetime.
        A date-only value is anchored to midnight. Fail-closed: a set-but-unparseable
        value raises, so a typo can never silently widen the backfill to the whole
        corpus.

        Returns:
            str: "YYYY-MM-DDTHH:MM:SS" for the WordPress `after` query, or None.

        Raises:
            RuntimeError: if a non-empty value is not ISO 8601.
        """
        raw = (raw or "").strip()
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"HSN_BACKFILL_START_DATE={raw!r} is not an ISO 8601 date/datetime "
                f"(e.g. 2023-07-19): {exc}. Refusing to start."
            )
        return dt.strftime("%Y-%m-%dT%H:%M:%S")

    @staticmethod
    def _compile_title_exclude(raw):
        """Compile HSN_TITLE_EXCLUDE into a case-insensitive regex, or None.

        Empty value -> None (filter off). Fail-closed: an invalid regex raises so a
        malformed pattern can never silently pass all titles through unfiltered.

        Returns:
            re.Pattern or None.

        Raises:
            RuntimeError: if a non-empty value is not a valid regex.
        """
        raw = (raw or "").strip()
        if not raw:
            return None
        try:
            return re.compile(raw, re.IGNORECASE)
        except re.error as exc:
            raise RuntimeError(
                f"HSN_TITLE_EXCLUDE is not a valid regex ({exc}): {raw!r}. "
                f"Refusing to start."
            )

    def _scope_sig(self):
        """Signature of the collection scope (category allowlist + backfill floor).

        Persisted alongside the cursor so a scope change invalidates the positional
        cursor instead of silently mis-positioning it.
        """
        return f"{self.categories}|{self.backfill_after or ''}"

    def _save_cursor(self, page, index):
        """Persist the positional cursor plus the current scope signature."""
        self.helper.set_state(
            {"page": page, "index": index, "scope_sig": self._scope_sig()}
        )

    # ------------------------------------------------------------------ #
    # Initialisation
    # ------------------------------------------------------------------ #

    def _resolve_graph_references(self):
        """Resolve fixed graph objects, register the vocabulary, and probe the API.

        Resolves internal OpenCTI UUIDs for the author identity and the TLP
        marking, registers the report_type vocabulary value, logs the resolved
        category allowlist, and probes the REST endpoint once. The marking
        resolution is fail-closed (raises); the API probe is NOT fail-closed (a
        transient blip logs and the connector enters the poll loop anyway).

        Raises:
            RuntimeError: if the marking cannot be resolved, since Reports must not
                be created without a resolved marking UUID.
        """
        # Author: identity.create is upsert-safe (returns existing if present).
        author = self.helper.api.identity.create(
            type="Organization",
            name=self.author_name,
            description="Greece-based maritime and shipping trade-news publisher. "
                        "Source organization for ingested reports.",
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

        # Log the resolved category allowlist (names) for operator visibility. The
        # filter is applied server-side; names are informational only.
        self._log_category_allowlist()

        # API probe (non-fatal). Logs reachability and the in-scope post count.
        total = self._probe_total()
        if total is None:
            self.helper.log_error(
                f"REST endpoint {self.api_url} unreachable at startup; entering poll "
                f"loop anyway and retrying next cycle."
            )
        else:
            floor = self.backfill_after or "none (full corpus)"
            self.helper.log_info(
                f"REST endpoint reachable: {total} in-scope posts "
                f"(categories={self.categories}, backfill floor={floor})."
            )

    def _log_category_allowlist(self):
        """Best-effort: resolve configured category ids to names and log them."""
        try:
            resp = self.session.get(
                f"{self.base_url}/wp-json/wp/v2/categories",
                params={"include": self.categories, "per_page": MAX_PER_PAGE,
                        "_fields": "id,name,count"},
                timeout=30,
            )
            resp.raise_for_status()
            names = [f"{c.get('name')} (id={c.get('id')}, count={c.get('count')})"
                     for c in resp.json()]
            self.helper.log_info(f"Category allowlist: {names}")
        except Exception as exc:  # noqa: BLE001 - purely informational
            self.helper.log_warning(
                f"Could not resolve category names for {self.categories}: {exc}"
            )

    def _probe_total(self):
        """Return the total in-scope post count (X-WP-Total), or None on failure."""
        params = {"categories": self.categories, "per_page": 1,
                  "orderby": "id", "order": "asc", "_fields": "id"}
        if self.backfill_after:
            params["after"] = self.backfill_after
        try:
            resp = self.session.get(self.api_url, params=params, timeout=60)
            resp.raise_for_status()
        except Exception:  # noqa: BLE001
            return None
        try:
            return int(resp.headers.get("X-WP-Total", "0"))
        except (TypeError, ValueError):
            return None

    # ------------------------------------------------------------------ #
    # REST enumeration and helpers
    # ------------------------------------------------------------------ #

    def _fetch_page(self, page):
        """Fetch one page of in-scope posts in ascending id order.

        Args:
            page: 1-based page number.

        Returns:
            list[dict]: posts on this page (possibly empty if past the last page),
            or None on a transient/HTTP error (caller retries next cycle from the
            same cursor). A WordPress HTTP 400 (rest_post_invalid_page_number) is
            treated as a legitimate end-of-list and returns [].
        """
        params = {
            "categories": self.categories,
            "per_page": self.per_page,
            "page": page,
            "orderby": "id",
            "order": "asc",
            "_fields": "id,date_gmt,modified_gmt,link,title,excerpt,categories",
        }
        if self.backfill_after:
            # Server-side floor: exclude posts published before the backfill date
            # (also excludes the ancient -0001 placeholder-date posts).
            params["after"] = self.backfill_after
        try:
            resp = self.session.get(self.api_url, params=params, timeout=90)
        except Exception as exc:  # noqa: BLE001 - cycle retries next poll
            self.helper.log_error(f"Failed to fetch page {page}: {exc}")
            return None
        if resp.status_code == 400:
            # Past the last page: WordPress returns rest_post_invalid_page_number.
            return []
        if resp.status_code != 200:
            self.helper.log_error(
                f"Page {page} returned HTTP {resp.status_code}; skipping this cycle."
            )
            return None
        try:
            data = resp.json()
        except ValueError as exc:
            self.helper.log_error(f"Page {page} returned non-JSON body: {exc}")
            return None
        return data if isinstance(data, list) else None

    @staticmethod
    def _report_id(link):
        """Deterministic Report STIX id derived from the article URL.

        Same URL always maps to the same Report id, which makes the existence check
        and every write idempotent.
        """
        return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))

    @staticmethod
    def _published_iso(post):
        """Parse a post's publication timestamp to ISO 8601 UTC.

        Prefers date_gmt, falling back to modified_gmt. Both WordPress GMT fields
        are naive UTC. Returns None if neither yields a plausible year (the -0001
        placeholder-date defect raises on fromisoformat and is thus skipped), so the
        caller can decide the fallback.

        Returns:
            str ISO 8601 timestamp with +00:00 offset, or None.
        """
        for key in ("date_gmt", "modified_gmt"):
            raw = post.get(key)
            if not raw:
                continue
            try:
                dt = datetime.fromisoformat(raw)
            except (TypeError, ValueError):
                continue
            if dt.year >= MIN_VALID_YEAR:
                return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        return None

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

            ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            footer = (
                "<div style='font-size:8px; width:100%; padding:0 12px; "
                "color:#444; display:flex; justify-content:space-between;'>"
                f"<span>{html.escape(url)}</span>"
                f"<span>OpenCTI Hellenic Shipping News connector &middot; ingested "
                f"{ingested_at} &middot; page <span class='pageNumber'></span>/"
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

    def _create_report(self, post, published, pdf_bytes):
        """Create one Report container for a post and attach its PDF.

        Container-only: no object_refs. The Report carries a deterministic stix_id
        derived from the article URL so the write is idempotent. Category ids are
        deliberately NOT written to the Report or the External Reference.

        Args:
            post: REST post dict.
            published: ISO 8601 published timestamp (already validated non-None).
            pdf_bytes: rendered article PDF.
        """
        url = post.get("link")
        name = _strip_html((post.get("title") or {}).get("rendered", "")) or url
        description = _strip_html((post.get("excerpt") or {}).get("rendered", ""))
        report_id = self._report_id(url)

        external_reference = self.helper.api.external_reference.create(
            source_name=self.author_name,
            url=url,
            description="Source article on hellenicshippingnews.com",
        )

        report = self.helper.api.report.create(
            stix_id=report_id,
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

        slug = url.rstrip("/").rsplit("/", 1)[-1] or "report"
        file_name = f"hellenic-{slug}.pdf"
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
        """Execute one enumeration-and-ingest pass from the persisted cursor.

        Walks the category-filtered posts in ascending id order starting at the
        persisted {page, index} cursor, rendering each not-yet-ingested post to a
        Report+PDF and advancing the cursor one post at a time. A full page
        (per_page items) advances to the next page; a partial page is the current
        tail, so the cursor rests on it and the next poll re-reads it to pick up
        freshly-appended posts. One uniform path covers backfill and steady state.
        """
        from playwright.sync_api import sync_playwright  # lazy import

        state = self.helper.get_state() or {}
        # A scope change (category allowlist or backfill floor) invalidates the
        # positional id cursor, which is only meaningful relative to a fixed
        # filtered set. Reset to page 1 rather than silently mis-positioning it;
        # graph dedup makes the re-scan safe (already-ingested posts are skipped).
        current_sig = self._scope_sig()
        stored_sig = state.get("scope_sig")
        if stored_sig is not None and stored_sig != current_sig:
            self.helper.log_warning(
                f"Collection scope changed; resetting cursor to page 1. "
                f"old={stored_sig!r} new={current_sig!r}. Graph dedup prevents "
                f"duplicates; already-ingested posts are skipped on the re-scan."
            )
            state = {}
        cursor_page = max(1, int(state.get("page", 1)))
        cursor_index = max(0, int(state.get("index", 0)))

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Hellenic Shipping News enumeration run"
        )
        self.helper.log_info(
            f"Resuming at page={cursor_page}, index={cursor_index} "
            f"(per_page={self.per_page}, categories={self.categories}, "
            f"backfill floor={self.backfill_after or 'none'}, "
            f"title_exclude={self.title_exclude_re.pattern if self.title_exclude_re else 'none'})."
        )

        processed = 0   # new Reports created
        skipped = 0     # already present in the graph
        excluded = 0    # dropped by the title-exclusion filter
        failed = 0      # render failed
        stop = False

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            renders_since_recycle = 0
            try:
                page_num = cursor_page
                while not stop:
                    posts = self._fetch_page(page_num)
                    if posts is None:
                        # Transient error: stop this cycle, keep the cursor, retry
                        # next poll from the same page.
                        self.helper.log_warning(
                            f"Page {page_num} fetch failed; ending cycle, cursor preserved."
                        )
                        break
                    if not posts:
                        # Past the tail: caught up. Rest here; do not advance the
                        # page, so the next poll re-checks this page for new posts.
                        self._save_cursor(page_num, 0)
                        self.helper.log_info(f"Caught up at page {page_num}; nothing new.")
                        break

                    start = cursor_index if page_num == cursor_page else 0
                    self.helper.log_info(
                        f"Page {page_num}: {len(posts)} posts; starting at index {start}."
                    )

                    for idx in range(start, len(posts)):
                        post = posts[idx]
                        url = post.get("link")
                        if not url:
                            self._save_cursor(page_num, idx + 1)
                            continue

                        # Client-side title-exclusion filter (e.g. Baltic Dry Index
                        # tickers). Applied before dedup/render so excluded posts
                        # cost nothing; the cursor still advances past them.
                        if self.title_exclude_re is not None:
                            title = _strip_html((post.get("title") or {}).get("rendered", ""))
                            if title and self.title_exclude_re.search(title):
                                excluded += 1
                                self._save_cursor(page_num, idx + 1)
                                continue

                        if self.max_reports and processed >= self.max_reports:
                            self.helper.log_info(
                                f"Reached HSN_MAX_REPORTS={self.max_reports}; stopping run."
                            )
                            stop = True
                            break

                        # Dedup BEFORE rendering, keyed on the deterministic Report id.
                        if self.helper.api.report.read(id=self._report_id(url)) is not None:
                            skipped += 1
                            self._save_cursor(page_num, idx + 1)
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
                            self.helper.log_warning(f"Skipping {url}: render failed after retries.")
                            # Advance past a persistently-failing post so it does not
                            # block the backfill; it is logged for operator review.
                            self._save_cursor(page_num, idx + 1)
                            continue

                        published = self._published_iso(post)
                        if not published:
                            # In-scope article with only the -0001 placeholder date:
                            # date it to ingestion time rather than dropping it.
                            published = datetime.now(timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%S+00:00"
                            )
                            self.helper.log_warning(
                                f"No usable date_gmt/modified_gmt for {url} "
                                f"(placeholder-date defect); using ingestion time."
                            )

                        self._create_report(post, published, pdf_bytes)
                        processed += 1
                        self._save_cursor(page_num, idx + 1)
                        time.sleep(self.request_delay)

                    if stop:
                        break

                    if len(posts) < self.per_page:
                        # Partial page == current tail. Rest on it (cursor already at
                        # its end); next poll re-reads it for freshly-appended posts.
                        self._save_cursor(page_num, len(posts))
                        break

                    # Full page consumed: advance to the next page.
                    page_num += 1
                    cursor_index = 0
                    self._save_cursor(page_num, 0)
                    time.sleep(self.request_delay)  # politeness between page fetches
            finally:
                browser.close()

        message = (
            f"Run complete: {processed} created, {skipped} already present, "
            f"{excluded} title-excluded, {failed} failed (render)."
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    def run(self):
        """Connector entrypoint: resolve references once, then poll forever."""
        self._resolve_graph_references()
        self.helper.log_info("Hellenic Shipping News connector started.")
        while True:
            try:
                self._process()
            except Exception as exc:  # noqa: BLE001 - keep the connector alive
                self.helper.log_error(f"Unhandled error during run: {exc}")
            time.sleep(self.poll_interval)


if __name__ == "__main__":
    try:
        HellenicShippingNewsConnector().run()
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
