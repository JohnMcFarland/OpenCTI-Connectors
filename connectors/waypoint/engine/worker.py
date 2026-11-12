"""One source: its HTTP session, in-memory failure bookkeeping, and the poll
stages the scheduler runs.

A poll is split into stages so the scheduler can apply global limits:

    discover()       fetch and parse every source URL         (worker thread)
    select_new()     scope filters, graph dedup, probe cap     (main thread)
    prepare(item)    page probe, skip_if, render, classify     (render thread)
    write(draft)     External Reference + report.create        (main thread)
    finish_item()    created / permanent / transient bookkeeping

process() runs the same stages back to back for one source; it is what a
generated connector's _process did, and the ported tests drive it.

State is in memory only, as in the generated connectors: permanent skips
(never retried for the life of the process) and transient failure counts
(given up after MAX_TRANSIENT_ATTEMPTS polls), both pruned to links still in
the feed. Dedup itself is always the graph's.
"""

from dataclasses import dataclass, field
from xml.etree import ElementTree

import requests

from . import dedup, discovery, render, report, scope, text, timing
from .dates import parse_date
from .settings import BROWSER_UA


class SourceLog:
    """The connector helper's log methods, prefixed with the source slug."""

    def __init__(self, helper, slug):
        self._helper = helper
        self._prefix = f"[{slug}] "

    def log_debug(self, msg):
        self._helper.log_debug(self._prefix + msg)

    def log_info(self, msg):
        self._helper.log_info(self._prefix + msg)

    def log_warning(self, msg):
        self._helper.log_warning(self._prefix + msg)

    def log_error(self, msg):
        self._helper.log_error(self._prefix + msg)


@dataclass
class PollState:
    """One poll of one source, from discovery to its summary line."""

    worker: object
    started: float
    outcome: str = "ok"             # ok | idle | feed-failed | dedup-failed | error
    discovered: int = 0
    in_scope: int = 0
    already: int = 0
    pending: list = field(default_factory=list)   # new items waiting to render
    created: int = 0
    created_no_pdf: int = 0
    transient: int = 0
    permanent: int = 0
    renderer_down: bool = False
    work_id: object = None

    @property
    def slug(self):
        return self.worker.profile.slug


class SourceWorker:
    """Everything one source needs between polls."""

    def __init__(self, profile, settings, api, log, session=None):
        self.profile = profile
        self.settings = settings
        self.api = api
        self.log = log
        self.feed_urls = list(profile.feed_urls)
        if session is None:
            session = requests.Session()
            session.headers.update({"User-Agent": BROWSER_UA,
                                    "Accept-Language": "en-US,en;q=0.9"})
        self.session = session
        self.resolved = {}             # redirector link -> article link (or None)
        self.author_id = None
        self.marking_id = None
        self.connect_id = None
        self.poll_count = 0
        self.prev_poll_clean = True    # False after a poll with transient failures
        self.permanent_skips = {}      # link -> reason
        self.transient_failures = {}   # link -> consecutive failed polls
        self.fetch_complete = True
        # Scheduling state (owned by the scheduler).
        self.next_due = 0.0
        self.crashes = 0

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #

    def _get(self, url):
        resp = self.session.get(url, timeout=60)
        resp.raise_for_status()
        return resp.content

    def fetch_source(self, url):
        """Fetch one source URL and parse it with the profile's discovery mode."""
        return discovery.fetch_source(self._get, url, self.profile)

    def discover(self):
        """Fetch and parse every source URL.

        Returns the merged items (feed order, deduplicated by link), or None
        when every URL failed. Sets fetch_complete to False when any failed,
        so per-link bookkeeping is not pruned for items it may hold.
        """
        items = []
        seen = set()
        failures = 0
        for url in self.feed_urls:
            try:
                parsed = self.fetch_source(url)
            except (ElementTree.ParseError, ValueError) as exc:
                self.log.log_error(f"Failed to parse source {url}: {exc}")
                failures += 1
                continue
            except Exception as exc:
                self.log.log_error(f"Failed to fetch source {url}: {exc}")
                failures += 1
                continue
            for item in parsed:
                if item["link"] not in seen:
                    seen.add(item["link"])
                    items.append(item)
        self.fetch_complete = failures == 0
        if failures == len(self.feed_urls):
            return None
        return self.resolve_redirects(items)

    def resolve_redirects(self, items):
        """Replace redirector links (resolve_redirect_hosts) by the article URL.

        One HEAD per new link, cached for the life of the process. Links that
        do not resolve to an allowed host are dropped.
        """
        hosts = self.profile.resolve_redirect_hosts
        if not hosts:
            return items
        out, seen = [], set()
        for item in items:
            link = item["link"]
            if (discovery.urlparse(link).hostname or "") in hosts:
                if link not in self.resolved:
                    self.resolved[link] = discovery.follow_redirects(
                        self.session, link, self.profile, self.log)
                target = self.resolved[link]
                if not target:
                    continue
                item = dict(item, link=target)
            if item["link"] not in seen:
                seen.add(item["link"])
                out.append(item)
        return out

    # ------------------------------------------------------------------ #
    # Selection: scope, dedup, page-probe cap
    # ------------------------------------------------------------------ #

    def ingested_links(self, items):
        return dedup.ingested_links(self.api, items, self.log)

    def select_new(self, items, started=None):
        """Turn discovered items into a PollState holding the new items.

        Scope filters first (out-of-scope items never reach dedup or render),
        then graph dedup; if the dedup lookup fails the poll writes nothing.
        """
        self.poll_count += 1
        poll = PollState(worker=self, started=timing.now() if started is None else started)
        if items is None:
            poll.outcome = "feed-failed"
            return poll
        poll.discovered = len(items)
        reasons = [scope.out_of_scope(i, self.profile) for i in items]
        # When the feed reaches back past max_age_days, nothing can have
        # scrolled off it unseen (used by the gap warning below).
        reaches_back = "older than max_age_days" in reasons
        items = [i for i, why in zip(items, reasons) if not why]
        poll.in_scope = len(items)
        if poll.in_scope != poll.discovered:
            self.log.log_debug(f"{poll.discovered - poll.in_scope} items out of scope.")

        # Graph-driven dedup by External Reference URL.
        candidates = [i for i in items if i["link"] not in self.permanent_skips]
        try:
            existing = self.ingested_links(candidates)
        except Exception as exc:
            self.log.log_error(f"Dedup lookup failed ({exc}); skipping this poll.")
            poll.outcome = "dedup-failed"
            return poll
        new_items = [i for i in candidates if i["link"] not in existing]
        poll.already = len(candidates) - len(new_items)

        # Prune in-memory bookkeeping to links still in the source; skipped
        # when a source URL failed, since its items are missing this poll.
        if self.fetch_complete:
            live = {i["link"] for i in items}
            self.permanent_skips = {k: v for k, v in self.permanent_skips.items() if k in live}
            self.transient_failures = {
                k: v for k, v in self.transient_failures.items() if k in live}

        if not new_items:
            self.prev_poll_clean = True
            poll.outcome = "idle"
            self.log.log_debug(f"Source returned {len(items)} items; nothing new.")
            return poll

        # A previous poll whose items all failed leaves no ingested overlap,
        # so only warn when the previous poll actually ingested what it saw.
        if (candidates and not existing and not reaches_back
                and self.poll_count > 1 and self.prev_poll_clean):
            self.log.log_warning(
                f"None of the {len(candidates)} items were already ingested; "
                f"posts may have scrolled off the source between polls. Consider "
                f"lowering poll_interval (now {self.profile.poll_interval}s)."
            )

        # Items that need their article page just to learn a date or title
        # are capped per poll; the rest wait for the next poll.
        probes = [i for i in new_items if not parse_date(i["pub_date"]) or not i["title"]]
        if len(probes) > self.settings.max_page_probes:
            later = {i["link"] for i in probes[self.settings.max_page_probes:]}
            new_items = [i for i in new_items if i["link"] not in later]
            self.log.log_info(f"{len(later)} undated items wait for the next poll.")
        poll.pending = new_items
        return poll

    # ------------------------------------------------------------------ #
    # Per-item: prepare (no writes) and write
    # ------------------------------------------------------------------ #

    def fetch_page(self, url):
        """One plain GET of the article page; None on any failure."""
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            return resp.content or b""
        except Exception as exc:
            self.log.log_warning(f"Article page fetch failed for {url}: {exc}")
            return None

    def page_for(self, item):
        """The item's article page, fetched at most once per ingest (None on failure)."""
        if "_page" not in item:
            item["_page"] = self.fetch_page(item["link"])
        return item["_page"]

    def skip_permanently(self, link, reason):
        self.permanent_skips[link] = reason
        self.transient_failures.pop(link, None)
        self.log.log_warning(f"Skipping {link} permanently: {reason}")
        return "skipped-permanent"

    def prepare(self, item):
        """Everything up to the write, for one new item.

        Returns (outcome, draft): ("ready", draft) when a Report should be
        written; otherwise ("skipped-permanent" | "failed" | "renderer-down",
        None). Writes nothing to OpenCTI.
        """
        url = item["link"]

        # Cheap validation before any network or render work.
        published = parse_date(item["pub_date"])
        if not published or not item["title"]:
            # Source without a date or title: read them from the article
            # page, then re-apply the scope rules.
            fetched = "_page" not in item
            page = self.page_for(item)
            if fetched:
                timing.sleep(self.profile.request_delay)   # politeness between page probes
            if page is None:
                return "failed", None     # page fetch failed: retry next poll
            published = published or text.page_date(page, self.profile.date_text_selector)
            item["title"] = item["title"] or text.page_title(page, self.profile.name)
            if published:
                reason = scope.out_of_scope(dict(item, pub_date=published), self.profile)
                if reason:
                    return self.skip_permanently(url, f"{reason} (from the article page)"), None
        if not published:
            return self.skip_permanently(url, "no usable publication date"), None

        # skip_if (e.g. members-only paywall). A fetch error raises: transient.
        reason = scope.skip_reason(self.session, item, self.profile)
        if reason:
            return self.skip_permanently(url, reason), None

        try:
            pdf_bytes = render.render_with_retry(item, published, self.profile,
                                                 self.settings, self.log)
        except render.SiteUnavailable as exc:
            self.log.log_warning(f"Site unavailable for {url}: {exc}")
            return "failed", None
        except render.RendererUnavailable:
            return "renderer-down", None   # house policy: renderer down -> retry later

        draft = report.build_draft(item, published, pdf_bytes, self.profile,
                                   self.page_for, self.log)
        return "ready", draft

    def write(self, draft):
        """Write one prepared Report (the only OpenCTI write per article)."""
        report.write_report(self.api, draft, self.profile, self.author_id,
                            self.marking_id, self.log)

    def ingest_item(self, item):
        """Prepare and write one item.

        Returns 'created', 'skipped-permanent', 'failed' (transient for this
        item) or 'renderer-down' (the pdf-renderer service is unavailable).
        """
        outcome, draft = self.prepare(item)
        if outcome != "ready":
            return outcome
        self.write(draft)
        return "created"

    def record_transient(self, link):
        attempts = self.transient_failures.get(link, 0) + 1
        self.transient_failures[link] = attempts
        cap = self.settings.max_transient_attempts
        if attempts >= cap:
            self.skip_permanently(link, f"failed on {attempts} consecutive polls; giving up")
        else:
            self.log.log_warning(
                f"Transient failure for {link} (poll {attempts}/{cap}); "
                f"will retry while it stays in the source."
            )

    def finish_item(self, poll, item, outcome, had_pdf=True):
        """Count one item's outcome on its poll and update bookkeeping."""
        if outcome == "created":
            poll.created += 1
            if not had_pdf:
                poll.created_no_pdf += 1
            self.transient_failures.pop(item["link"], None)
        elif outcome == "skipped-permanent":
            poll.permanent += 1
        else:
            poll.transient += 1
            self.record_transient(item["link"])

    # ------------------------------------------------------------------ #
    # Work record and summary
    # ------------------------------------------------------------------ #

    def open_work(self, poll):
        """Open this poll's OpenCTI work, named "<Source> poll"."""
        poll.work_id = self.api.work.initiate_work(self.connect_id, f"{self.profile.name} poll")

    def close_poll(self, poll):
        """Close the work (if any), log the per-poll summary line, and
        update the gap-warning state."""
        left = len(poll.pending)
        message = (
            f"{self.profile.name} poll ({poll.outcome}): discovered {poll.discovered}, in scope "
            f"{poll.in_scope}, already ingested {poll.already}, created {poll.created} "
            f"({poll.created_no_pdf} without PDF), transient {poll.transient}, "
            f"skipped permanently {poll.permanent}"
            + (f", {left} waiting for the next cycle" if left else "")
            + ("; pdf-renderer unavailable" if poll.renderer_down else "")
            + f"; {timing.now() - poll.started:.1f}s"
        )
        if poll.outcome in ("ok",):
            self.prev_poll_clean = poll.transient == 0 and not poll.renderer_down
        if poll.work_id is not None:
            self.api.work.to_processed(
                poll.work_id, message, in_error=poll.transient > 0 or poll.renderer_down)
        self.log.log_info(message)
        return message

    # ------------------------------------------------------------------ #
    # Sequential poll (one source alone; what the generated _process did)
    # ------------------------------------------------------------------ #

    def process(self, max_reports=None):
        """Run one complete poll of this source, sequentially.

        max_reports caps Reports created in this poll (default: the engine's
        AGG_MAX_REPORTS_PER_SOURCE_POLL; 0 = no cap).
        """
        cap = self.settings.max_reports_per_source_poll if max_reports is None else max_reports
        poll = self.select_new(self.discover())
        if not poll.pending:
            return poll
        self.open_work(poll)
        while poll.pending:
            if cap and poll.created >= cap:
                self.log.log_info(f"Reached {cap} Reports this poll; the rest wait.")
                break
            item = poll.pending.pop(0)
            try:
                outcome, draft = self.prepare(item)
                if outcome == "ready":
                    self.write(draft)
                    outcome = "created"
            except Exception as exc:
                self.log.log_error(f"Failed to ingest {item['link']}: {exc}")
                outcome, draft = "failed", None
            if outcome == "renderer-down":
                # Not the item's fault: stop here, retry everything next poll,
                # and do not count it towards giving up on the item.
                poll.renderer_down = True
                poll.pending.insert(0, item)
                self.log.log_warning(
                    "pdf-renderer unavailable; stopping this poll. Remaining items "
                    "are retried next poll.")
                break
            self.finish_item(poll, item, outcome, had_pdf=bool(draft and draft["pdf_bytes"]))
            if outcome == "created":
                timing.sleep(self.profile.request_delay)
        self.close_poll(poll)
        return poll
