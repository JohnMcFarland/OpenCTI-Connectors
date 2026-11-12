"""The scheduler: which sources run, and every global limit.

One tick:
  1. Due sources (oldest next_due first) are discovered in parallel
     (AGG_SOURCE_WORKERS threads; HTTP only).
  2. On the main thread, each poll applies scope filters and graph dedup.
     In dry run, new items are logged ("would create") and nothing else
     happens.
  3. New items enter the render queue, served round-robin across sources so
     one source's backlog cannot starve the others. AGG_RENDER_CONCURRENCY
     items are prepared at once (page probe, skip_if, render, classify), at
     most one per source, with the source's request_delay between its items.
     Prepared Reports are written on the main thread (one writer).
  4. Budgets: AGG_REPORTS_PER_CYCLE Reports per cycle window across all
     sources, AGG_MAX_REPORTS_PER_SOURCE_POLL per source poll. Items that do
     not fit are not dropped: the source is polled again at the next window
     and they are rediscovered (dedup is the graph's).
  5. A pdf-renderer outage seen by any item pauses all rendering for
     AGG_RENDERER_PAUSE_SECONDS; the item is not counted against.
  6. Every source poll runs inside its own exception boundary. An unexpected
     error ends that poll with a traceback logged, and the source backs off
     (poll_interval doubling per consecutive crash, capped at 6 hours).
"""

import traceback
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from . import report, timing
from .status import iso
from .worker import PollState


class Budget:
    """Reports written per cycle window, across all sources (0 = no cap)."""

    def __init__(self, limit, window_seconds, now):
        self.limit = limit
        self.window = window_seconds
        self.window_end = now + window_seconds
        self.used = 0

    def roll(self, now):
        """Start a new window when the current one has ended."""
        if now >= self.window_end:
            # Windows stay aligned to the first one, even after idle gaps.
            missed = int((now - self.window_end) // self.window) + 1
            self.window_end += missed * self.window
            self.used = 0

    def take(self):
        if self.limit and self.used >= self.limit:
            return False
        self.used += 1
        return True

    def give_back(self):
        self.used = max(0, self.used - 1)

    @property
    def spent(self):
        return bool(self.limit) and self.used >= self.limit


class Scheduler:
    """Runs every enabled source under shared budgets."""

    def __init__(self, workers, settings, log, status, connect_id=None):
        self.workers = workers                  # slug -> SourceWorker
        self.settings = settings
        self.log = log                          # engine-level log (helper)
        self.status = status
        self.connect_id = connect_id
        self.budget = Budget(settings.reports_per_cycle, settings.cycle_seconds, timing.now())
        self.renderer_paused_until = 0.0
        self.dry_run_logged = set()             # URLs already reported in dry run
        self.started = timing.now()
        self.stale_warned = {}                  # slug -> last stale WARNING time
        report.set_classify_concurrency(settings.classify_concurrency)
        for w in workers.values():
            w.connect_id = connect_id

    # ------------------------------------------------------------------ #
    # Startup: graph references, per source
    # ------------------------------------------------------------------ #

    def start(self, api):
        """Resolve each source's author and marking once.

        A source whose references cannot be resolved does not start; the
        others do. In dry run nothing is created: authors are not resolved
        and the report-type vocabulary is not registered.
        """
        markings, vocab_done = {}, set()
        for slug, w in list(self.workers.items()):
            try:
                if w.profile.tlp not in markings:
                    markings[w.profile.tlp] = report.resolve_marking(api, w.profile.tlp)
                w.marking_id = markings[w.profile.tlp]
                if not self.settings.dry_run:
                    w.author_id = report.resolve_author(api, w.profile)
                    if w.profile.report_type not in vocab_done:
                        report.ensure_vocabulary(api, w.profile.report_type, w.log)
                        vocab_done.add(w.profile.report_type)
                self.status.set_state(slug, "running")
            except Exception as exc:
                w.log.log_error(f"Source not started: {exc}")
                self.status.set_state(slug, "failed-start", str(exc))
                del self.workers[slug]

    # ------------------------------------------------------------------ #
    # One tick
    # ------------------------------------------------------------------ #

    def due(self, now):
        """Sources due now, oldest next_due first."""
        return sorted((w for w in self.workers.values() if w.next_due <= now),
                      key=lambda w: (w.next_due, w.profile.slug))

    def tick(self):
        """Poll every due source once, render under the budgets, write.

        Returns the polls handled (empty when nothing was due).
        """
        now = timing.now()
        self.budget.roll(now)
        due = self.due(now)
        if not due:
            self._stale_check(now)
            return []

        # Stage 1: discovery in parallel (HTTP only, no graph calls).
        discovered = {}
        with ThreadPoolExecutor(max_workers=self.settings.source_workers) as pool:
            futures = {w.profile.slug: pool.submit(w.discover) for w in due}
        for w in due:
            try:
                discovered[w.profile.slug] = ("ok", futures[w.profile.slug].result())
            except Exception as exc:
                discovered[w.profile.slug] = ("error", exc)

        # Stage 2: scope + dedup on the main thread, one boundary per source.
        # Works are opened only when this tick will render (renderer not
        # paused, cycle budget not spent).
        can_render = self.renderer_paused_until <= now and not self.budget.spent
        polls = []
        for w in due:
            kind, value = discovered[w.profile.slug]
            try:
                if kind == "error":
                    raise value
                poll = w.select_new(value, started=now)
            except Exception as exc:
                self._crashed(w, now, exc)
                continue
            if self.settings.dry_run:
                self._dry_run_log(poll)
            elif poll.pending and can_render:
                try:
                    w.open_work(poll)
                except Exception as exc:
                    self._crashed(w, now, exc)
                    continue
            polls.append(poll)

        # Stage 3: the render queue (skipped in dry run, while paused, or
        # when the cycle budget is already spent).
        if not self.settings.dry_run and can_render:
            self.render_queue([p for p in polls if p.pending and p.work_id is not None])

        # Stage 4: close each poll, schedule its next run, record status.
        written = 0
        end = timing.now()
        for poll in polls:
            w = poll.worker
            try:
                w.close_poll(poll)       # the per-poll summary line (and work close)
            except Exception as exc:
                self._crashed(w, end, exc)
                continue
            written += poll.created
            w.crashes = 0
            w.next_due = self._next_due(w, poll, end)
            failed = poll.outcome in ("feed-failed", "dedup-failed")
            self.status.record_poll(w.profile.slug, end, poll.outcome, w.next_due,
                                    poll.created, failed)

        self.log.log_info(
            f"Cycle: {len(due)} sources polled, {written} Reports written "
            f"({self.budget.used}/{self.budget.limit or 'unlimited'} this window), "
            f"render queue depth {sum(len(p.pending) for p in polls)}"
            + (" [DRY RUN]" if self.settings.dry_run else ""))
        self._stale_check(end)
        self.status.save(end)
        return polls

    # ------------------------------------------------------------------ #
    # Render queue
    # ------------------------------------------------------------------ #

    def render_queue(self, polls):
        """Prepare and write pending items round-robin across sources.

        At most render_concurrency items in flight, at most one per source,
        request_delay between one source's items. Stops dispatching when the
        cycle budget is spent or the renderer is down; in-flight items still
        finish. Items left in poll.pending wait for the next cycle.
        """
        if not polls:
            return
        cap = self.settings.max_reports_per_source_poll
        lanes = deque(polls)
        busy, ready_at, inflight = set(), {}, {}
        stop = False
        with ThreadPoolExecutor(max_workers=self.settings.render_concurrency) as pool:
            while True:
                # Dispatch: one pass round the lanes, filling free slots.
                if not stop:
                    for _ in range(len(lanes)):
                        if len(inflight) >= self.settings.render_concurrency:
                            break
                        poll = lanes[0]
                        lanes.rotate(-1)
                        slug = poll.slug
                        if (slug in busy or not poll.pending
                                or ready_at.get(slug, 0) > timing.now()
                                or (cap and poll.created >= cap)):
                            continue
                        if not self.budget.take():
                            stop = True
                            break
                        item = poll.pending.pop(0)
                        fut = pool.submit(poll.worker.prepare, item)
                        inflight[fut] = (poll, item)
                        busy.add(slug)

                if not inflight:
                    waiting = [p for p in lanes
                               if p.pending and not (cap and p.created >= cap)]
                    if stop or not waiting:
                        break
                    # Only cooldowns block dispatch: wait for the earliest.
                    timing.sleep(min(ready_at.get(p.slug, 0) for p in waiting) - timing.now())
                    continue

                # Wait for a job, or (when a slot is free) for a source's
                # cooldown to end, whichever comes first.
                now = timing.now()
                cooling = [ready_at[p.slug] for p in lanes
                           if p.pending and p.slug not in busy
                           and ready_at.get(p.slug, 0) > now]
                if cooling and not stop and len(inflight) < self.settings.render_concurrency:
                    timeout = max(0.0, min(cooling) - now)
                else:
                    timeout = None
                done, _ = wait(list(inflight), timeout=timeout, return_when=FIRST_COMPLETED)
                for fut in done:
                    poll, item = inflight.pop(fut)
                    busy.discard(poll.slug)
                    outcome, had_pdf = self._complete(poll, item, fut)
                    if outcome != "created":
                        self.budget.give_back()
                    if outcome == "renderer-down":
                        # Shared signal: no source renders until the pause ends.
                        stop = True
                        poll.renderer_down = True
                        poll.pending.insert(0, item)
                        self.renderer_paused_until = (
                            timing.now() + self.settings.renderer_pause_seconds)
                        self.log.log_warning(
                            "pdf-renderer unavailable; rendering paused for all sources "
                            f"for {self.settings.renderer_pause_seconds}s.")
                        continue
                    poll.worker.finish_item(poll, item, outcome, had_pdf)
                    if outcome == "created":
                        ready_at[poll.slug] = timing.now() + poll.worker.profile.request_delay

    def _complete(self, poll, item, fut):
        """Finish one dispatched item on the main thread: write it if ready."""
        w = poll.worker
        try:
            outcome, draft = fut.result()
            if outcome == "ready":
                w.write(draft)
                return "created", bool(draft["pdf_bytes"])
            return outcome, False
        except Exception as exc:
            w.log.log_error(f"Failed to ingest {item['link']}: {exc}")
            return "failed", False

    # ------------------------------------------------------------------ #
    # Scheduling, failure isolation, dry run, staleness
    # ------------------------------------------------------------------ #

    def _next_due(self, w, poll, now):
        """Normally now + poll_interval; sooner when items are still waiting."""
        due = now + w.profile.poll_interval
        if poll.pending and not self.settings.dry_run:
            retry = (self.renderer_paused_until if poll.renderer_down
                     or self.renderer_paused_until > now else self.budget.window_end)
            due = min(due, max(retry, now))
        return due

    def _crashed(self, w, now, exc):
        """An unexpected error ended this source's poll: log, back off."""
        w.crashes += 1
        delay = min(w.profile.poll_interval * (2 ** w.crashes), self.settings.backoff_cap_seconds)
        w.next_due = now + delay
        w.log.log_error(
            f"Poll failed ({exc}); backing off {delay}s.\n"
            + "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
        self.status.record_poll(w.profile.slug, now, "error", w.next_due, 0, True)

    def _dry_run_log(self, poll):
        """Dry run: say what would be created, once per URL, and drop it."""
        for item in poll.pending:
            if item["link"] not in self.dry_run_logged:
                self.dry_run_logged.add(item["link"])
                poll.worker.log.log_info(
                    f"DRY-RUN would create Report for {item['link']} ({item['title'][:80]})")
        poll.pending = []

    def _stale_check(self, now):
        """WARNING once a day per source with no new Report for too long."""
        for slug, w in self.workers.items():
            days = w.profile.stale_after_days or self.settings.stale_after_days
            last = self.status.last_report(slug) or self.started
            if now - last <= days * 86400:
                continue
            if now - self.stale_warned.get(slug, 0) < 86400:
                continue
            self.stale_warned[slug] = now
            w.log.log_warning(
                f"No new Report for more than {days} days (last: "
                f"{iso(self.status.last_report(slug)) or 'none since start'}); "
                f"check the source.")

    # ------------------------------------------------------------------ #
    # Run loop
    # ------------------------------------------------------------------ #

    def run_forever(self):
        """Tick until stopped; one scheduler-level boundary around each tick."""
        while True:
            try:
                self.tick()
            except Exception as exc:
                self.log.log_error(
                    f"Scheduler tick failed ({exc}).\n" + traceback.format_exc())
            nxt = min((w.next_due for w in self.workers.values()), default=None)
            pause = self.settings.tick_seconds if nxt is None else nxt - timing.now()
            timing.sleep(min(max(pause, 1), self.settings.tick_seconds))


__all__ = ["Budget", "Scheduler", "PollState"]
