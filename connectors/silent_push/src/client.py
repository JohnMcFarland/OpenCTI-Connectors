"""
Silent Push API client.

These calls back the connector, all confirmed live in November 2026:

    GET  api.silentpush.com/api/v1/export/iofa-exports/<file>/   302 to signed S3
    GET  app.silentpush.com/api/v1/feeds/                        feed catalogue
    POST app.silentpush.com/api/v1/enrich/{domain,ipv4}/bulk/    context per value
    POST app.silentpush.com/app/v1/feed-scan/query-{count,data}/ Feed Scan (OSINT)

The documented /api/v2/iocs/threat-ranking/ route returns 404 for API keys, and
/api/v1/feeds/{uuid}/indicators/ refuses global feeds. The two export files are
the only bulk route to IOFA, and they hold bare values, so enrichment supplies
the score, dates and feed attribution.

Open-source feeds have no export file at all. Feed Scan is the only route to
them, and its rows arrive already enriched. Each data page costs one quota
request. Behaviour found live, November 2026:

- `page` pages; `skip` and `offset` are silently ignored.
- `sorting: ["first_seen_on/desc"]` is honoured (and is the default).
- Relative windows work only in whole days (`now-1d`); hours are ignored, and
  absolute timestamps are ignored. So the connector narrows by days server
  side and cuts at the exact time itself.
- Each page takes about 25 seconds, whatever its size.
"""

import time
from datetime import datetime, timezone
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import requests

APP_URL = "https://app.silentpush.com"
API_URL = "https://api.silentpush.com"
EXPORT_PATH = "/api/v1/export/iofa-exports"
DOMAIN_EXPORT = "all_iofas_domains.txt"
IP_EXPORT = "all_iofas_ips.txt"
S3_HOST = "silentpush-feeds.s3.amazonaws.com"

# Past these sizes the API silently drops the excess.
ENRICH_ROUTES = {
    "domain": ("/api/v1/enrich/domain/bulk/", "domains", 100),
    "ipv4": ("/api/v1/enrich/ipv4/bulk/", "ipv4s", 200),
}

# The real files hold hundreds of thousands of lines. Anything this small is a
# failed export, and saving it as the baseline would make the whole corpus look
# new on the following run.
MIN_EXPORT_LINES = 1000

REQUEST_TIMEOUT_SECONDS = 120
DOWNLOAD_TIMEOUT_SECONDS = 300
MAX_RETRIES = 3
BASE_RETRY_DELAY_SECONDS = 2
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
EMPTY_ENRICH_ATTEMPTS = 3

FEED_SCAN_PATH = "/app/v1/feed-scan"
FEED_SCAN_PAGE_SIZE = 1000  # the API refuses anything larger
FEED_SCAN_MAX_PAGES = 500
FEED_SCAN_SORTING = ["first_seen_on/desc"]


class SilentPushAPIError(Exception):
    """The API refused the request or returned something unusable."""


def batch_size(kind: str) -> int:
    return ENRICH_ROUTES[kind][2]


class SilentPushClient:
    def __init__(self, api_key: str) -> None:
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": "OpenCTI-SilentPush-Connector/2.0.0",
                "x-api-key": api_key,
            }
        )

    def _with_retries(
        self, send: Callable[[], requests.Response]
    ) -> requests.Response:
        """Run a request, retrying transient failures only."""
        last_error: Exception | None = None
        wait: int | None = None

        for attempt in range(MAX_RETRIES + 1):
            if attempt:
                backoff = BASE_RETRY_DELAY_SECONDS * (2 ** (attempt - 1))
                time.sleep(backoff if wait is None else wait)
                wait = None

            try:
                response = send()
            except (requests.ConnectionError, requests.Timeout) as exc:
                # Not the exception text: for S3 it would quote the signed URL.
                last_error = SilentPushAPIError(type(exc).__name__)
                continue

            if response.status_code in RETRYABLE_STATUS_CODES:
                last_error = SilentPushAPIError(f"HTTP {response.status_code}")
                wait = _retry_after(response)
                continue

            if response.status_code >= 400:
                # A bad key or exhausted quota will not fix itself on retry.
                raise SilentPushAPIError(
                    f"HTTP {response.status_code} from Silent Push: "
                    f"{response.text[:200]}"
                )
            return response

        raise SilentPushAPIError(
            f"Silent Push request failed after {MAX_RETRIES + 1} attempts: "
            f"{last_error}"
        )

    def download_export(self, file_name: str) -> list[str]:
        """Return the lines of an IOFA export file."""
        url = f"{API_URL}{EXPORT_PATH}/{file_name}/"
        redirect = self._with_retries(
            lambda: self._session.get(
                url, timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=False
            )
        )
        location = redirect.headers.get("Location", "")
        parsed = urlparse(location)
        if parsed.scheme != "https" or parsed.hostname != S3_HOST:
            raise SilentPushAPIError(
                f"Export {file_name} did not redirect to {S3_HOST} "
                f"(HTTP {redirect.status_code}, host {parsed.hostname})"
            )

        # Bare requests.get, not the session: the key must never reach S3.
        body = self._with_retries(
            lambda: requests.get(location, timeout=DOWNLOAD_TIMEOUT_SECONDS)
        )
        expected = body.headers.get("Content-Length")
        if expected and expected.isdigit() and int(expected) != len(body.content):
            raise SilentPushAPIError(f"Export {file_name} download was truncated")

        lines = [
            line.strip()
            for line in body.content.decode("utf-8", "replace").splitlines()
        ]
        lines = [line for line in lines if line]
        if len(lines) < MIN_EXPORT_LINES:
            raise SilentPushAPIError(
                f"Export {file_name} has only {len(lines)} lines"
            )
        return lines

    def list_feeds(self) -> list[dict]:
        """Return the whole feed catalogue."""
        feeds: list[dict] = []
        page = 1
        while True:
            response = self._with_retries(
                lambda: self._session.get(
                    f"{APP_URL}/api/v1/feeds/",
                    params={"page": page},
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
            )
            payload = _json(response)
            rows = payload.get("data") if isinstance(payload, dict) else None
            metadata = payload.get("metadata") if isinstance(payload, dict) else None
            if not isinstance(rows, list) or not isinstance(metadata, dict):
                raise SilentPushAPIError("Unexpected feed catalogue response")
            feeds += [row for row in rows if isinstance(row, dict)]
            if not rows or page >= int(metadata.get("pages") or 0):
                return feeds
            page += 1

    def enrich(self, kind: str, values: list[str]) -> list[dict]:
        """
        Return enrichment rows, or [] if the API keeps answering with none.

        A 200 with no rows has happened live and cleared on retry, so it is
        retried here. The caller decides what a persistent [] means.
        """
        path, field, limit = ENRICH_ROUTES[kind]
        if len(values) > limit:
            raise ValueError(f"{len(values)} values exceeds the {kind} cap of {limit}")

        for attempt in range(EMPTY_ENRICH_ATTEMPTS):
            if attempt:
                time.sleep(BASE_RETRY_DELAY_SECONDS * attempt)
            response = self._with_retries(
                lambda: self._session.post(
                    f"{APP_URL}{path}",
                    json={field: values},
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
            )
            rows = _enrichment_rows(_json(response))
            if rows:
                return rows
        return []


    def feed_scan_since(self, query: str, cutoff: datetime) -> list[dict]:
        """
        Every row added at or after `cutoff`, newest first.

        Pages newest-first and stops at the first page that reaches back past
        the cutoff. Rows that arrive mid-pull push older rows down a page, so
        paging can repeat a row but never skip one.
        """
        rows: list[dict] = []
        previous: datetime | None = None
        for page in range(1, FEED_SCAN_MAX_PAGES + 1):
            body = self._feed_scan_post(
                "data",
                {
                    "query": query,
                    "limit": FEED_SCAN_PAGE_SIZE,
                    "page": page,
                    "sorting": FEED_SCAN_SORTING,
                },
            )
            data = body.get("data")
            if not isinstance(data, list):
                raise SilentPushAPIError("Unexpected Feed Scan data response")

            reached_cutoff = False
            for row in data:
                if not isinstance(row, dict):
                    continue
                added = _seen_time(row.get("first_seen_on"))
                if added is None:
                    raise SilentPushAPIError("Feed Scan row has no first_seen_on")
                # Stopping early is only safe if the order really is newest
                # first; otherwise rows past the cutoff could still follow.
                if previous is not None and added > previous:
                    raise SilentPushAPIError("Feed Scan rows are not newest first")
                previous = added
                if added < cutoff:
                    reached_cutoff = True
                    break
                rows.append(row)
            if reached_cutoff or len(data) < FEED_SCAN_PAGE_SIZE:
                return rows
        raise SilentPushAPIError(f"Feed Scan ran past {FEED_SCAN_MAX_PAGES} pages")

    def _feed_scan_post(self, kind: str, body: dict) -> dict:
        response = self._with_retries(
            lambda: self._session.post(
                f"{APP_URL}{FEED_SCAN_PATH}/query-{kind}/",
                json=body,
                timeout=DOWNLOAD_TIMEOUT_SECONDS,
            )
        )
        payload = _json(response)
        inner = payload.get("response") if isinstance(payload, dict) else None
        if not isinstance(inner, dict) or payload.get("error"):
            raise SilentPushAPIError(
                f"Feed Scan {kind} failed: {str(payload.get('error') if isinstance(payload, dict) else payload)[:200]}"
            )
        return inner


def _seen_time(raw) -> datetime | None:
    """Feed Scan timestamps look like 2026-11-07T01:47:47, in UTC."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        moment = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _retry_after(response: requests.Response) -> int | None:
    try:
        return max(0, int(response.headers.get("Retry-After", "")))
    except ValueError:
        return None


def _json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError as exc:
        raise SilentPushAPIError("Silent Push returned a non-JSON response") from exc


def _enrichment_rows(payload: Any) -> list[dict]:
    """Domains answer {"response": [...]}, IPv4 {"response": {"ip2asn": [...]}}."""
    body = payload.get("response") if isinstance(payload, dict) else None
    if isinstance(body, dict):
        body = body.get("ip2asn")
    if not isinstance(body, list):
        return []
    return [row for row in body if isinstance(row, dict)]
