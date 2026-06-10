import random
import time
from typing import List, Dict, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

def _sleep(min_seconds: int, jitter_seconds: int) -> None:
    if min_seconds <= 0:
        return
    j = random.randint(0, max(0, jitter_seconds))
    time.sleep(min_seconds + j)

def _session(user_agent: str) -> requests.Session:
    s = requests.Session()
    h = dict(DEFAULT_HEADERS)
    h["User-Agent"] = user_agent
    s.headers.update(h)
    return s

def fetch_listing(
    listing_url: str,
    timeout_s: int,
    user_agent: str,
    min_seconds_between_requests: int = 0,
    jitter_seconds: int = 0,
    max_retries: int = 4,
) -> str:
    """
    Returns HTML text. Implements:
      - browser-like headers
      - request pacing
      - retry/backoff
      - fallback URL variant (NSA sometimes treats /Research vs /research differently)
    """
    urls_to_try = [listing_url]

    # Fallback: lowercase path variant sometimes behaves differently behind CDNs/WAFs.
    if "/Research/" in listing_url:
        urls_to_try.append(listing_url.replace("/Research/", "/research/"))

    s = _session(user_agent)

    last_exc: Optional[Exception] = None
    for url in urls_to_try:
        for attempt in range(1, max_retries + 1):
            try:
                _sleep(min_seconds_between_requests, jitter_seconds)
                r = s.get(url, timeout=timeout_s, allow_redirects=True)

                # If we get blocked, back off harder.
                if r.status_code == 403:
                    backoff = (2 ** (attempt - 1)) + random.randint(0, 2)
                    time.sleep(backoff)
                    r.raise_for_status()

                r.raise_for_status()
                return r.text

            except Exception as e:
                last_exc = e
                # gentle backoff for transient CDN/WAF weirdness
                backoff = (2 ** (attempt - 1)) + random.randint(0, 2)
                time.sleep(backoff)

    raise last_exc if last_exc else RuntimeError("Failed to fetch listing (unknown error)")

def extract_govinfo_pdfs(listing_html: str) -> List[Dict[str, str]]:
    """
    Parse NSA TNW listing HTML and return govinfo PDF urls + basic identifiers.
    We intentionally prefer govinfo PDFs (stable) once discovered.
    """
    soup = BeautifulSoup(listing_html, "lxml")
    out: List[Dict[str, str]] = []

    # Look for govinfo PDF links in the page
    for a in soup.select('a[href*="govinfo.gov"][href$=".pdf"], a[href*="govinfo.gov/content/pkg/"][href$=".pdf"]'):
        href = a.get("href", "").strip()
        if not href:
            continue

        # normalize
        if href.startswith("/"):
            href = urljoin("https://www.govinfo.gov", href)

        external_id = ""
        # common pattern: .../content/pkg/GPO-TNW-24-1-2023/pdf/GPO-TNW-24-1-2023-1.pdf
        if "/pkg/" in href:
            try:
                external_id = href.split("/pkg/")[1].split("/")[0]
            except Exception:
                external_id = ""

        title = a.get_text(" ", strip=True) or external_id or "NSA The Next Wave"

        out.append(
            {
                "external_id": external_id or href,
                "title": title,
                "pdf_url": href,
            }
        )

    # de-dupe by pdf_url
    seen = set()
    deduped = []
    for item in out:
        u = item["pdf_url"]
        if u in seen:
            continue
        seen.add(u)
        deduped.append(item)

    return deduped
