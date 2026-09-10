import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


@dataclass
class DiscoveredEntry:
    url: str
    title: str = ""
    published: datetime | None = None
    summary: str = ""


# -- Page metadata extraction ------------------------------------------------


def extract_page_title(soup: BeautifulSoup) -> str:
    h1 = soup.find("h1")
    if h1:
        text = h1.get_text(strip=True)
        if text:
            return text
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
        for sep in (" | ", " — ", " - ", " :: "):
            if sep in title:
                title = title.split(sep)[0].strip()
        return title
    return "Untitled Advisory"


def extract_description(soup: BeautifulSoup) -> str:
    field = soup.select_one(".field--name-field-description")
    if field:
        return field.get_text(strip=True)[:500]
    for attr in ("description", "og:description"):
        tag = soup.find("meta", attrs={"name": attr}) or soup.find(
            "meta", attrs={"property": attr}
        )
        if tag and tag.get("content"):
            return tag["content"].strip()[:500]
    for p in soup.find_all("p"):
        text = p.get_text(strip=True)
        if len(text) > 80:
            return text[:500]
    return ""


def find_direct_pdf(soup: BeautifulSoup, base_url: str) -> str | None:
    for selector in (
        '.btn-download-file a[href$=".pdf"]',
        'a.btn-download[href$=".pdf"]',
    ):
        tag = soup.select_one(selector)
        if tag and tag.get("href"):
            return urljoin(base_url, tag["href"].strip())
    return None


def enrich_from_page(entry: DiscoveredEntry, html: str) -> str | None:
    """Enrich entry metadata from page HTML. Returns direct PDF URL if found."""
    soup = BeautifulSoup(html, "lxml")

    if not entry.title:
        entry.title = extract_page_title(soup)
    if not entry.summary:
        entry.summary = extract_description(soup)

    date_el = soup.select_one("p.publish-date span.date")
    if date_el and date_el.text:
        try:
            entry.published = datetime.strptime(
                date_el.text.strip(), "%B %d, %Y"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return find_direct_pdf(soup, entry.url)


# -- Pure utility functions ----------------------------------------------------

_FILENAME_UNSAFE_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def parse_published(entry) -> datetime:
    for attr in ("published_parsed", "updated_parsed"):
        val = getattr(entry, attr, None)
        if val:
            try:
                return datetime(*val[:6], tzinfo=timezone.utc)
            except (TypeError, ValueError):
                pass
    return datetime.now(tz=timezone.utc)


def make_pdf_filename(url: str) -> str:
    slug = urlparse(url).path.rstrip("/").split("/")[-1] or "advisory"
    slug = _FILENAME_UNSAFE_RE.sub("_", slug)
    if len(slug) > 200:
        slug = slug[:200]
    if not slug.endswith(".pdf"):
        slug = f"{slug}.pdf"
    return slug


def truncate_summary(text: str, limit: int = 500) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


# -- Scraper type alias -------------------------------------------------------

ScraperGet = Callable[[str], requests.Response | None]
ScraperLog = Callable[[str], None]


# -- ENISA sitemap scraper ----------------------------------------------------


def scrape_enisa(
    get: ScraperGet, request_delay: float, log_info: ScraperLog
) -> list[DiscoveredEntry]:
    resp = get("https://www.enisa.europa.eu/sitemap.xml")
    if not resp:
        return []

    soup = BeautifulSoup(resp.content, "lxml-xml")
    entries: list[DiscoveredEntry] = []

    for url_tag in soup.find_all("url"):
        loc = url_tag.find("loc")
        if not loc:
            continue
        url = loc.text.strip()
        if "/publications/" not in url:
            continue

        published = None
        lastmod = url_tag.find("lastmod")
        if lastmod and lastmod.text:
            try:
                text = lastmod.text.strip()
                if "T" in text:
                    published = datetime.fromisoformat(
                        text.replace("Z", "+00:00")
                    )
                else:
                    published = datetime.strptime(text, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
            except ValueError:
                pass

        entries.append(DiscoveredEntry(url=url, published=published))

    entries.sort(
        key=lambda e: e.published or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    log_info(f"[enisa] Sitemap: {len(entries)} publication URLs")
    return entries


# -- CERT-In servlet scraper --------------------------------------------------

_CERTIN_BASE = "https://www.cert-in.org.in"
_CERTIN_DATE_RE = re.compile(r"\((\w+ \d{1,2}, \d{4})\)")


def _scrape_certin_listing(
    get: ScraperGet,
    request_delay: float,
    page_id: str,
    year: int,
    page_size: int = 20,
) -> list[DiscoveredEntry]:
    entries: list[DiscoveredEntry] = []
    seen_urls: set[str] = set()
    offset = 0

    while True:
        url = f"{_CERTIN_BASE}/s2cMainServlet?pageid={page_id}&year={year}"
        if offset > 0:
            url += f"&next={offset}"

        resp = get(url)
        if not resp:
            break

        soup = BeautifulSoup(resp.text, "lxml")
        page_count = 0

        for li in soup.find_all("li"):
            link = li.find("a", href=True)
            if not link or "VLCODE=" not in link["href"]:
                continue

            full_url = urljoin(_CERTIN_BASE + "/", link["href"].strip())
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)
            page_count += 1

            full_text = li.get_text(separator=" ", strip=True)

            published = None
            date_match = _CERTIN_DATE_RE.search(full_text)
            if date_match:
                try:
                    published = datetime.strptime(
                        date_match.group(1), "%B %d, %Y"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            title = link.get_text(strip=True)
            if date_match:
                after = full_text[date_match.end() :].strip()
                if after:
                    title = after

            entries.append(
                DiscoveredEntry(url=full_url, title=title, published=published)
            )

        if page_count < page_size:
            break
        offset += page_size
        time.sleep(request_delay)

    return entries


def scrape_certin(
    get: ScraperGet, request_delay: float, log_info: ScraperLog
) -> list[DiscoveredEntry]:
    current_year = datetime.now(tz=timezone.utc).year
    all_entries: list[DiscoveredEntry] = []

    for year in range(current_year, current_year - 3, -1):
        advisories = _scrape_certin_listing(
            get, request_delay, "PUBADVLIST02", year, page_size=15
        )
        vuln_notes = _scrape_certin_listing(
            get, request_delay, "VLNLIST02", year, page_size=20
        )
        all_entries.extend(advisories)
        all_entries.extend(vuln_notes)
        log_info(
            f"[cert_in] {year}: {len(advisories)} advisories, "
            f"{len(vuln_notes)} vulnerability notes"
        )
        time.sleep(request_delay)

    return all_entries


# -- Registry -----------------------------------------------------------------

SCRAPER_REGISTRY: dict[str, Callable] = {
    "enisa": scrape_enisa,
    "certin": scrape_certin,
}
