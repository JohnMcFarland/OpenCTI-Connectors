"""
URLHaus API client.

Wraps the abuse.ch URLHaus API v1. Two endpoints are consumed:
  - /urls/recent/     → recent URLs (filtered to online only)
  - /payloads/recent/ → recent payloads

Authentication: Auth-Key sent as HTTP header on all requests.
Method: GET (POST returns 405 on current API version).

Retry behaviour:
  All requests are wrapped in an exponential backoff retry loop. Transient
  network errors and 5xx server errors are retried up to MAX_RETRIES times.
  4xx client errors (e.g., 401 Unauthorized) are not retried since they
  indicate a configuration problem that retrying will not resolve.

API reference: https://urlhaus-api.abuse.ch/
"""

import time
import logging

import requests


# ── Constants ─────────────────────────────────────────────────────────────────

URLHAUS_BASE_URL = "https://urlhaus-api.abuse.ch/v1"

# Wall-clock timeout for a single HTTP request in seconds.
REQUEST_TIMEOUT_SECONDS = 60

# Maximum number of retry attempts on transient failures before giving up.
# Total attempts = 1 initial + MAX_RETRIES retries.
MAX_RETRIES = 3

# Base delay in seconds for exponential backoff. Delay on attempt N is:
#   BASE_RETRY_DELAY_SECONDS * (2 ** N)
# So: 2s, 4s, 8s for retries 0, 1, 2.
BASE_RETRY_DELAY_SECONDS = 2

# HTTP status codes that warrant a retry. 5xx = server-side transient errors.
# 429 = rate limited. 4xx other than 429 are configuration errors — not retried.
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

logger = logging.getLogger(__name__)


# ── Exceptions ────────────────────────────────────────────────────────────────

class URLHausAPIError(Exception):
    """Raised when the URLHaus API returns a non-OK query status."""


# ── Client ────────────────────────────────────────────────────────────────────

class URLHausClient:
    """Thin HTTP client for the URLHaus API v1 with exponential backoff retry."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._session = requests.Session()
        # Auth-Key is set at session level so all requests carry it automatically.
        self._session.headers.update({
            "User-Agent": "OpenCTI-URLHaus-Connector/1.0.0",
            "Auth-Key": self.api_key,
        })

    def _get(self, endpoint: str) -> dict:
        """
        Execute an authenticated GET request with exponential backoff retry.

        Retry policy:
          - Retries on connection errors, timeouts, and RETRYABLE_STATUS_CODES.
          - Does NOT retry on 4xx client errors (except 429) — these indicate
            a configuration problem (bad API key, wrong endpoint) that will
            not be resolved by retrying.
          - Raises the last exception after MAX_RETRIES retries are exhausted.

        Returns the parsed JSON response body.
        """
        url = f"{URLHAUS_BASE_URL}{endpoint}"
        last_exception: Exception | None = None

        for attempt in range(MAX_RETRIES + 1):
            # On retry attempts, sleep with exponential backoff before sending.
            if attempt > 0:
                delay = BASE_RETRY_DELAY_SECONDS * (2 ** (attempt - 1))
                logger.warning(
                    "URLHaus request failed, retrying",
                    extra={
                        "endpoint": endpoint,
                        "attempt": attempt,
                        "delay_seconds": delay,
                        "error": str(last_exception),
                    },
                )
                time.sleep(delay)

            try:
                response = self._session.get(url, timeout=REQUEST_TIMEOUT_SECONDS)

                # Raise immediately on non-retryable 4xx errors. These indicate
                # a configuration problem — retrying will not help.
                if (
                    response.status_code >= 400
                    and response.status_code < 500
                    and response.status_code not in RETRYABLE_STATUS_CODES
                ):
                    response.raise_for_status()

                # On retryable status codes, store exception and retry.
                if response.status_code in RETRYABLE_STATUS_CODES:
                    last_exception = requests.HTTPError(
                        f"{response.status_code} retryable error",
                        response=response,
                    )
                    continue

                # Success — raise for any remaining unexpected errors then return.
                response.raise_for_status()
                return response.json()

            except requests.exceptions.ConnectionError as exc:
                # Network-level failure (DNS, TCP) — always retryable.
                last_exception = exc
                continue

            except requests.exceptions.Timeout as exc:
                # Request timed out — retryable.
                last_exception = exc
                continue

            except requests.HTTPError:
                # Non-retryable 4xx — re-raise immediately without further attempts.
                raise

        # All retry attempts exhausted — raise the last stored exception.
        raise last_exception

    def get_recent_urls(self) -> list[dict]:
        """
        Fetch recent URLs from URLHaus.

        Returns only entries with url_status == 'online'. URLHaus defines
        'online' as the URL actively serving malicious content at the time
        of last check. This is the tightest possible filter for active
        threat relevance.
        """
        result = self._get("/urls/recent/")
        status = result.get("query_status")
        if status != "ok":
            raise URLHausAPIError(f"URLs endpoint returned query_status={status!r}")
        entries = result.get("urls") or []
        return [e for e in entries if e.get("url_status") == "online"]

    def get_recent_payloads(self) -> list[dict]:
        """
        Fetch recent payload submissions from URLHaus.

        All payloads are returned regardless of associated URL status, as
        payload hashes remain analytically relevant for detection and
        retrospective analysis even after a hosting URL goes offline.
        """
        result = self._get("/payloads/recent/")
        status = result.get("query_status")
        if status != "ok":
            raise URLHausAPIError(
                f"Payloads endpoint returned query_status={status!r}"
            )
        return result.get("payloads") or []
