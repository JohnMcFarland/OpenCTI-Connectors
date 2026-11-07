"""Thin Splunk REST client (management port, default 8089).

Flow per job: create under servicesNS/<owner>/<app> -> poll until DONE -> page the
results -> cancel the job so it does not hold dispatch disk until its TTL.
Auth is a Splunk auth token (Bearer) or, failing that, basic auth.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import Settings


class SplunkSearchError(RuntimeError):
    """A search job failed or timed out. The cursor for that search is NOT advanced."""


class SplunkJobTimeout(SplunkSearchError):
    """A job outran SPLUNK_JOB_TIMEOUT. A smaller window may still finish."""


@dataclass
class JobResult:
    rows: list[dict]  # empty when truncated: the caller splits the window instead
    truncated: bool = False


class SplunkClient:
    def __init__(self, settings: Settings, logger) -> None:
        self.base = settings.splunk_base_url.rstrip("/")
        self.owner = settings.splunk_owner
        self.results_path = "search/v2/jobs" if settings.splunk_results_api == "v2" else "search/jobs"
        self.timeout = settings.splunk_request_timeout
        self.job_timeout = settings.splunk_job_timeout
        self.page_size = settings.splunk_page_size
        self.time_skew = settings.splunk_index_time_skew_seconds
        self.log = logger

        self.session = requests.Session()
        self.session.verify = settings.verify
        if settings.verify is False:
            # Logged once here instead of a urllib3 warning on every request.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SPLUNK_VERIFY_SSL=false: Splunk TLS certificate is NOT verified")
        if settings.splunk_token:
            self.session.headers["Authorization"] = f"Bearer {settings.splunk_token}"
        elif settings.splunk_username:
            self.session.auth = (settings.splunk_username, settings.splunk_password)
        else:
            raise ValueError("Set SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD")
        # GET only: retrying a job-creating POST after a gateway error can leave a
        # duplicate job running in Splunk that nothing cancels.
        retry = Retry(total=3, backoff_factor=2, status_forcelist=(429, 502, 503, 504),
                      allowed_methods=frozenset({"GET"}))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

    # -- public ------------------------------------------------------------

    def check(self) -> str:
        """Cheap startup probe: confirms reachability + credentials. Returns server version."""
        r = self._get("services/server/info")
        return r["entry"][0]["content"].get("version", "unknown")

    def run_search(self, spl: str, app: str, earliest: int, latest: int, time_mode: str,
                   max_results: int, fields: list[str] | None = None) -> JobResult:
        """Run one job over [earliest, latest) (epoch seconds) and return its rows.

        time_mode "index" bounds by _indextime, so events that arrive late are picked up
        by the next window. _time is still bounded (window +/- SPLUNK_INDEX_TIME_SKEW_SECONDS)
        because Splunk selects buckets by _time: an unbounded _time scans every bucket in
        the index on every run. "event" bounds by _time only.

        A job over max_results is reported as truncated WITHOUT downloading its rows,
        since the caller discards them and re-runs smaller windows.
        """
        # max_count: Splunk keeps only 10,000 results per job by default. One past the
        # cap is enough to tell "exactly max_results" from "more than max_results".
        data = {"search": spl, "exec_mode": "normal", "max_count": str(max_results + 1)}
        if time_mode == "index":
            data.update({"index_earliest": str(earliest), "index_latest": str(latest),
                         "earliest_time": str(earliest - self.time_skew),
                         "latest_time": str(latest + self.time_skew)})
        else:
            data.update({"earliest_time": str(earliest), "latest_time": str(latest)})

        sid = self._post(f"servicesNS/{self.owner}/{app}/search/jobs", data)["sid"]
        try:
            total = self._wait(sid)
            if total > max_results:
                return JobResult([], truncated=True)
            return JobResult(self._results(sid, total, fields))
        finally:
            self._cancel(sid)

    # -- job lifecycle -----------------------------------------------------

    def _wait(self, sid: str) -> int:
        """Poll until the job finishes; return its resultCount."""
        deadline = time.monotonic() + self.job_timeout
        delay = 1.0
        while True:
            # A just-created job can answer 204 with no body: not ready yet, keep polling.
            entries = self._get(f"services/search/jobs/{sid}").get("entry") or [{}]
            content = entries[0].get("content", {})
            if (content.get("isFailed") or content.get("isZombie")
                    or content.get("dispatchState") == "FAILED"):
                raise SplunkSearchError(f"Job {sid} failed: {self._messages(content)}")
            if content.get("isDone") or content.get("dispatchState") == "DONE":
                # A job stopped early, or one that lost a peer, still reports DONE with
                # the rows it got. Taking those would move the cursor past the rest.
                messages = self._messages(content)
                if content.get("isFinalized") or "incomplete" in messages.lower():
                    raise SplunkSearchError(f"Job {sid} results are incomplete: {messages}")
                return int(content.get("resultCount", 0))
            if time.monotonic() > deadline:
                raise SplunkJobTimeout(f"Job {sid} exceeded {self.job_timeout}s")
            time.sleep(delay)
            delay = min(delay * 1.5, 10.0)

    def _results(self, sid: str, wanted: int, fields: list[str] | None) -> list[dict]:
        rows: list[dict] = []
        while len(rows) < wanted:
            params: dict = {"count": min(self.page_size, wanted - len(rows)), "offset": len(rows)}
            if fields:
                params["f"] = fields
            batch = self._get(f"services/{self.results_path}/{sid}/results", params).get("results", [])
            if not batch:
                # Fewer rows retrievable than the job produced (e.g. limits.conf
                # maxresultrows below max_results): fail rather than drop the rest.
                raise SplunkSearchError(
                    f"Job {sid} returned {len(rows)} of {wanted} rows; lower max_results "
                    "or raise maxresultrows in Splunk limits.conf")
            rows.extend(batch)
        return rows

    def _cancel(self, sid: str) -> None:
        try:
            self._post(f"services/search/jobs/{sid}/control", {"action": "cancel"})
        except Exception as exc:  # noqa: BLE001 - best effort; job expires on its TTL anyway
            self.log.debug("Job cancel failed", {"sid": sid, "error": str(exc)})

    # -- http --------------------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> dict:
        p = {"output_mode": "json", **(params or {})}
        r = self.session.get(f"{self.base}/{path}", params=p, timeout=self.timeout)
        return self._json(r)

    def _post(self, path: str, data: dict) -> dict:
        r = self.session.post(f"{self.base}/{path}", data={"output_mode": "json", **data},
                              timeout=self.timeout)
        return self._json(r)

    @staticmethod
    def _json(r: requests.Response) -> dict:
        if r.status_code >= 400:
            # Splunk returns {"messages":[{"type":"ERROR","text":...}]} on failures.
            try:
                detail = "; ".join(m.get("text", "") for m in r.json().get("messages", []))
            except ValueError:
                detail = r.text[:300]
            raise SplunkSearchError(f"HTTP {r.status_code} {r.request.method} "
                                    f"{r.url.split('?')[0]}: {detail}")
        return r.json() if r.content else {}

    @staticmethod
    def _messages(content: dict) -> str:
        msgs = content.get("messages") or []
        return "; ".join(m.get("text", "") for m in msgs if isinstance(m, dict)) or "no detail"
