"""Orchestration: scheduled run -> each configured search -> cases -> STIX -> send.

EXTERNAL_IMPORT. Uses helper scheduling + work lifecycle + platform state (no
hand-rolled while/sleep loop). State is kept per search name:

    {"searches": {"<name>": {"cursor": "<epoch>", "span": <seconds, see _learn_span>,
                             "clean_runs": <rolling: clean runs since span last changed>,
                             "cases": {"<group key>": [see cases.RollingCases]}}}}

Cursor mode (default): each run searches [cursor, now - ingest_lag). Windows do not
overlap, so no per-case state is needed, and a group gets one case per window. The
cursor only moves forward. A search that fails keeps its cursor, so the
same window is retried next run; other searches are unaffected.

Rolling mode (`lookback` set on the search): each run re-searches the same relative
window, for data that changes after it is indexed (e.g. ES notables dispositioned
days later). `cases` (see cases.RollingCases) pins each group's title and created
time (its OpenCTI identity) to what was first sent, so a group whose rows change
updates the same case instead of minting a new one; unchanged groups are skipped.

A window whose job hits `max_results` or the job timeout is split in half and re-run
until every part fits, so rows are never silently dropped. Parts finish oldest first,
so when a cursor search runs out of its job or timeout budget it imports what is
complete and moves the cursor to that boundary. A rolling search has no cursor to
resume from, and a window with no complete part cannot progress, so both fail (cursor
kept) instead. Either way `span` records the size that worked for the next run, so a
backlog drains over several runs instead of stalling.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from .cases import Case, RollingCases, build_cases
from .config import Settings
from .opencti_lookup import OpenCTILookup
from .searches import SearchDef, parse_relative
from .splunk_client import SplunkClient, SplunkJobTimeout, SplunkSearchError
from .stix_builder import SplunkStixBuilder

_CASES_CAP = 5000
_MAX_JOBS_PER_SEARCH = 32
_MAX_TIMEOUTS_PER_SEARCH = 3  # per run; each costs a full SPLUNK_JOB_TIMEOUT
_ROLLING_PROBE_RUNS = 16  # clean runs before a rolling search tries a larger span


class SplunkConnector:
    def __init__(self, helper, settings: Settings, searches: list[SearchDef]) -> None:
        self.helper = helper
        self.settings = settings
        self.known_names = {s.name for s in searches}  # disabled ones keep their state
        self.searches = [s for s in searches if s.enabled]
        self.client = SplunkClient(settings, helper.connector_logger)
        self.lookup = OpenCTILookup(helper)
        self.builder = SplunkStixBuilder(helper, settings, self.lookup)

    # -- scheduling --------------------------------------------------------

    def run(self) -> None:
        version = self.client.check()  # fail fast on bad URL / creds / TLS
        self.helper.connector_logger.info(
            "Connected to Splunk", {"version": version, "searches": [s.name for s in self.searches]})
        self.builder.prepare()
        self.helper.schedule_iso(
            message_callback=self.process,
            duration_period=self.settings.connector_duration_period,
        )

    def process(self) -> None:
        state = self.helper.get_state() or {}
        per_search = state.setdefault("searches", {})
        # Drop state only for searches removed from the file, so it does not grow forever.
        for name in list(per_search):
            if name not in self.known_names:
                del per_search[name]
        self.lookup.begin_run()
        now = int(time.time())
        latest = now - self.settings.splunk_ingest_lag_seconds
        initial = latest - parse_relative(self.settings.splunk_initial_lookback)
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"Splunk run @ {datetime.fromtimestamp(now, tz=timezone.utc).isoformat()}")
        failed: list[str] = []
        for search in self.searches:
            sstate = per_search.setdefault(search.name, {})
            if search.lookback:
                earliest = latest - parse_relative(search.lookback)
            else:
                # Stored before the first attempt, so a failed first run retries the
                # same window instead of one recomputed from the clock.
                earliest = int(sstate.setdefault("cursor", str(initial)))
                sstate.pop("cases", None)  # left over if lookback was removed
            try:
                done_until = self._run_search(search, earliest, latest, sstate, work_id)
            except Exception as exc:  # noqa: BLE001 - isolate per search, retry window next run
                failed.append(search.name)
                self.helper.connector_logger.error(
                    "Search failed; cursor not advanced",
                    {"search": search.name, "error": str(exc)})
                continue
            sstate["cursor"] = str(done_until)
            # Hand each search's progress to the helper as it completes; pycti pushes
            # state to the platform on its own schedule.
            self.helper.set_state(state)
        self.helper.set_state(state)
        msg = "Splunk run complete" + (f"; failed: {', '.join(failed)}" if failed else "")
        self.helper.api.work.to_processed(work_id, msg, in_error=bool(failed))

    # -- one search --------------------------------------------------------

    def _run_search(self, search: SearchDef, earliest: int, latest: int, sstate: dict,
                    work_id: str) -> int:
        """Import [earliest, latest); returns the end of what was actually covered."""
        # Ingest lag raised, or the clock stepped back. Returning `earliest` keeps the
        # cursor from moving backwards and re-importing a span as new cases.
        if earliest >= latest:
            return earliest
        rows, jobs, done_until = self._collect(search, earliest, latest, sstate)
        # Fallback for rows with no usable time. The window start stays the same when a
        # failed run retries, so a case that was already sent keeps its id.
        fallback = datetime.fromtimestamp(earliest, tz=timezone.utc)
        cases = build_cases(search, rows, fallback)
        rolling = (RollingCases(sstate.get("cases", {}), _CASES_CAP, latest, earliest)
                   if search.lookback else None)
        sent = 0
        try:
            for case in cases:
                if rolling:
                    linked = [t for t in case.techniques if self.lookup.attack_pattern(t)]
                    if not rolling.needs_send(case, linked):
                        continue
                self._send(search, case, work_id)
                if rolling:
                    rolling.mark_sent(case)
                sent += 1
        finally:
            if rolling:  # also on failure: what was sent must stay pinned to its id
                sstate["cases"] = rolling.commit(c.key for c in cases)
                if len(sstate["cases"]) > _CASES_CAP:
                    self.helper.connector_logger.warning(
                        "Rolling search tracks more groups than expected; connector state "
                        "is growing, consider a shorter lookback",
                        {"search": search.name, "groups": len(sstate["cases"])})
        self.helper.connector_logger.info(
            "Search complete",
            {"search": search.name, "earliest": earliest, "done_until": done_until,
             "jobs": jobs, "rows": len(rows), "cases": len(cases), "sent": sent})
        return done_until

    def _send(self, search: SearchDef, case: Case, work_id: str) -> None:
        # One bundle per case keeps every object_ref resolvable together.
        bundle = json.dumps({
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": self.builder.build(search, case),
        })
        self.helper.send_stix2_bundle(bundle, work_id=work_id, update=True)

    def _collect(self, search: SearchDef, earliest: int, latest: int,
                 sstate: dict) -> tuple[list[dict], int, int]:
        """Rows in [earliest, latest), halving windows that are too big (hit max_results)
        or too slow (hit the job timeout). Returns (rows, jobs run, end of covered span).

        Rows from every part are returned together, so grouping still sees a group
        whole even when its rows land in different parts."""
        span = sstate.get("span")
        if span and search.lookback:
            # A rolling window must fit in one run, so a smaller span could never finish.
            span = max(span, -(-(latest - earliest) // _MAX_JOBS_PER_SEARCH))
        pending = _windows(earliest, latest, span)  # a stack: the oldest part pops first
        rows: list[dict] = []
        jobs = timeouts = failed = 0  # failed: the smallest window that was too big or slow
        errored = False
        fields = search.referenced_fields()
        try:
            while pending:
                lo, hi = pending.pop()
                if jobs >= _MAX_JOBS_PER_SEARCH:
                    problem = (f"Window needs more than {jobs} jobs; raise max_results or "
                               "narrow the SPL (time bounds may not apply to it, e.g. "
                               "inputlookup)")
                else:
                    jobs += 1
                    try:
                        result = self.client.run_search(
                            search.spl, search.app, lo, hi, search.time_mode,
                            search.max_results, fields)
                        if not result.truncated:
                            rows.extend(result.rows)
                            continue
                        problem = (f"More than {search.max_results} rows in {hi - lo} "
                                   "second(s); raise max_results")
                        too_big = True
                    except SplunkJobTimeout as exc:
                        timeouts += 1
                        problem = f"{exc}; raise SPLUNK_JOB_TIMEOUT or narrow the SPL"
                        too_big = True
                    except Exception as exc:  # noqa: BLE001 - keep finished parts, see below
                        problem = str(exc)
                        too_big = False
                        errored = True
                    if too_big:
                        failed = min(failed or hi - lo, hi - lo)
                        if hi - lo > 1 and timeouts < _MAX_TIMEOUTS_PER_SEARCH:
                            mid = (lo + hi) // 2
                            pending += [(mid, hi), (lo, mid)]
                            continue
                # Everything before `lo` is complete. Keep it if the cursor can resume there.
                if search.lookback or lo == earliest:
                    raise SplunkSearchError(problem)
                self.helper.connector_logger.warning(
                    "Search window only partly imported; the next run resumes from here",
                    {"search": search.name, "done_until": lo, "latest": latest,
                     "reason": problem})
                return rows, jobs, lo
            return rows, jobs, latest
        finally:
            _learn_span(sstate, span, failed, errored, latest - earliest,
                        bool(search.lookback))


def _windows(earliest: int, latest: int, span: int | None) -> list[tuple[int, int]]:
    """[earliest, latest) cut into `span`-second parts, oldest last (it is a stack).
    A run cannot use more than _MAX_JOBS_PER_SEARCH parts, so the rest stay one part."""
    if not span:
        return [(earliest, latest)]
    starts = range(earliest, latest, span)[:_MAX_JOBS_PER_SEARCH + 1]
    bounds = [*starts, latest]
    return list(zip(bounds, bounds[1:]))[::-1]


def _learn_span(sstate: dict, span: int | None, failed: int, errored: bool,
                window: int, rolling: bool = False) -> None:
    """Remember what size of window works, so the next run starts there. Without this a
    backlog re-tries the same too-big windows every run and never gets further; even a
    run that achieved nothing narrows the next one.

    Doubles after any run where every job worked, including one that merely ran out of
    job budget: that is the run that must grow, or a span shrunk by an outage would stay
    too small to ever catch up. A run that hit other errors (Splunk down) proves nothing,
    so it leaves the span alone. Forgotten when a whole window fits again.

    A rolling window never shrinks, so growing every run would walk straight back into
    the size that failed. It tries a larger size only every _ROLLING_PROBE_RUNS clean
    runs, so an oversized try is rare but an outage is still recovered from."""
    if failed:
        sstate["span"] = max(1, failed // 2)
        sstate.pop("clean_runs", None)
    elif span and not errored:
        if rolling:
            sstate["clean_runs"] = sstate.get("clean_runs", 0) + 1
            if sstate["clean_runs"] < _ROLLING_PROBE_RUNS:
                return
            del sstate["clean_runs"]
        if span * 2 >= window:
            del sstate["span"]
        else:
            sstate["span"] = span * 2
