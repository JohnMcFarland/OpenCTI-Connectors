"""
http_client.py
Shared HTTP session with retry logic, rate limiting, jitter, and browser-like headers.
All plugins should use this rather than raw requests calls.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def build_session(
    retries: int = 3,
    backoff_factor: float = 1.5,
    timeout: int = 30,
) -> requests.Session:
    """
    Build a requests.Session with retry logic and consistent headers.
    """
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session._default_timeout = timeout

    return session


def safe_get(
    session: requests.Session,
    url: str,
    rate_limit_delay: float = 1.0,
    jitter: float = 2.0,
    **kwargs,
) -> Optional[requests.Response]:
    """
    GET with rate limiting, randomised jitter, and error handling.
    Total delay = rate_limit_delay + random(0, jitter) seconds.
    Returns None on any error rather than raising.
    """
    delay = rate_limit_delay + random.uniform(0, jitter)
    logger.debug("Sleeping %.2fs before request to %s", delay, url)
    time.sleep(delay)

    try:
        timeout = kwargs.pop("timeout", session._default_timeout)
        response = session.get(url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.HTTPError as e:
        logger.warning("HTTP error fetching %s: %s", url, e)
    except requests.exceptions.ConnectionError as e:
        logger.warning("Connection error fetching %s: %s", url, e)
    except requests.exceptions.Timeout:
        logger.warning("Timeout fetching %s", url)
    except requests.exceptions.RequestException as e:
        logger.warning("Request failed for %s: %s", url, e)
    return None


def fetch_pdf(session: requests.Session, url: str) -> Optional[bytes]:
    """
    Attempt to download a PDF from the given URL.
    Returns raw bytes or None if unavailable or not a PDF.
    """
    resp = safe_get(session, url)
    if resp is None:
        return None
    content_type = resp.headers.get("Content-Type", "")
    if "pdf" not in content_type.lower() and not url.lower().endswith(".pdf"):
        logger.debug("URL does not appear to be a PDF: %s (Content-Type: %s)", url, content_type)
        return None
    return resp.content


def is_pdf_response(response: requests.Response) -> bool:
    """Check if a response contains PDF content."""
    content_type = response.headers.get("Content-Type", "")
    return "pdf" in content_type.lower()
