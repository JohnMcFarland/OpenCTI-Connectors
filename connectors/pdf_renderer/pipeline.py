"""pdf-renderer pipeline.

Single implementation of the house PDF pattern (ProPublica pattern) used by
every connector through the pdf-renderer service:

  extract -> strip -> fix lazy images -> dedupe title -> defang links
  -> title + byline header -> PDF metadata -> WeasyPrint render

Two entry points, each run inside a killable worker process by app.py:

  render_html_job(req) -- caller supplies HTML (feed body, Feedly content,
                          or a page the connector fetched itself)
  render_url_job(req)  -- the service loads the URL in Playwright, takes the
                          rendered DOM, then runs the same pipeline

Security: every outbound fetch (page navigation, sub-requests, images) goes
through check_url(), which allows only http/https to hosts that resolve to
public (is_global) addresses. Docker service names, RFC1918, loopback,
link-local and metadata addresses are refused (SSRF block).

Markers: PDF-RENDERER-V1
"""

import datetime
import functools
import ipaddress
import re
import socket
import unicodedata
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup, Comment, NavigableString

VERSION = "1.0.0"

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Generic article-body selectors for multi-publisher sources (Feedly, url mode).
# Ordered most-specific first; the first match wins.
GENERIC_SELECTORS = [
    "[itemprop=articleBody]",
    "article .entry-content",
    ".entry-content",
    ".post-content",
    ".article-body",
    ".article-content",
    ".story-body",
    "article",
    "main",
]

# Noise removed from inside the extracted body. ProPublica's list plus the
# generic chrome that shows up across publishers.
DEFAULT_STRIP = [
    "script", "style", "noscript", "iframe", "form", "button", "svg",
    "nav", "header", "footer", "aside",
    ".newsletter-signup", ".newsletter", ".subscribe", ".donation-banner",
    ".ad-container", ".ad", ".advertisement", ".sidebar",
    ".related-stories", ".related-posts", ".related", ".share-tools",
    ".share", ".social-share", ".sharedaddy", ".comments", "#comments",
    ".author-bio", ".breadcrumb", ".breadcrumbs", ".cookie-banner",
]

CHALLENGE_MARKERS = ("just a moment", "checking your browser", "attention required")

MAX_RESOURCE_BYTES = 10 * 1024 * 1024  # per image/resource fetched by WeasyPrint
RESOURCE_TIMEOUT = 10                   # seconds per resource fetch
MAX_REDIRECTS = 3

PDF_STYLE = (
    "@page { size: A4; margin: 15mm 12mm 15mm 12mm; } "
    "body { font-family: 'Liberation Serif', 'DejaVu Serif', Georgia, serif; "
    "color: #222; line-height: 1.55; font-size: 11pt; } "
    "h1.doc-title { font-size: 20pt; line-height: 1.25; margin: 0 0 0.3em 0; } "
    "p.byline { font-size: 9pt; color: #555; margin: 0 0 1.4em 0; "
    "padding-bottom: 0.6em; border-bottom: 1px solid #ccc; } "
    "h1 { font-size: 17pt; } h2 { font-size: 14pt; } h3 { font-size: 12pt; } "
    "img { max-width: 100%; height: auto; } "
    "pre, code { font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace; "
    "background: #f4f4f4; font-size: 9pt; white-space: pre-wrap; "
    "word-break: break-all; } "
    "pre { padding: 6px; } "
    "table { border-collapse: collapse; width: 100%; } "
    "td, th { border: 1px solid #ccc; padding: 4px 6px; font-size: 9.5pt; } "
    "figure { margin: 1em 0; } "
    "figcaption { font-size: 8.5pt; color: #666; margin-top: 4px; } "
    "blockquote { border-left: 3px solid #ccc; margin: 1em 0; "
    "padding: 0.4em 1em; color: #555; } "
)


class BlockedURL(Exception):
    """Raised when a URL fails the SSRF policy."""


class ExtractError(Exception):
    """Raised when no usable article body can be extracted."""


# --------------------------------------------------------------------------- #
# SSRF guard
# --------------------------------------------------------------------------- #

@functools.lru_cache(maxsize=2048)
def _host_is_public(host):
    """True only if every address the host resolves to is globally routable.

    Single-label names (Docker service names such as opencti, minio,
    elasticsearch) are refused before DNS is consulted.
    """
    if not host or "." not in host:
        return False
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


def check_url(url):
    """Raise BlockedURL unless url is http(s) to a public host."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BlockedURL(f"scheme not allowed: {parts.scheme or '(none)'}")
    host = (parts.hostname or "").lower()
    if not _host_is_public(host):
        raise BlockedURL(f"host not public: {host or '(none)'}")


def safe_get(url, headers, max_bytes=MAX_RESOURCE_BYTES):
    """GET with the SSRF check re-applied on every redirect hop and a size cap.

    Returns (bytes, mime_type).
    """
    for _ in range(MAX_REDIRECTS + 1):
        check_url(url)
        resp = requests.get(
            url, headers=headers, timeout=RESOURCE_TIMEOUT,
            allow_redirects=False, stream=True,
        )
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location")
            resp.close()
            if not location:
                raise BlockedURL("redirect without location")
            url = urljoin(url, location)
            continue
        resp.raise_for_status()
        chunks = []
        size = 0
        for chunk in resp.iter_content(65536):
            size += len(chunk)
            if size > max_bytes:
                resp.close()
                raise BlockedURL(f"resource exceeds {max_bytes} bytes")
            chunks.append(chunk)
        mime = resp.headers.get("content-type", "application/octet-stream")
        return b"".join(chunks), mime.split(";")[0].strip()
    raise BlockedURL("too many redirects")


def make_url_fetcher(headers):
    """WeasyPrint url_fetcher bound to the request headers.

    data: URIs use WeasyPrint's own fetcher; everything else goes through
    safe_get. A raised exception makes WeasyPrint skip that resource.
    """
    def fetcher(url, *args, **kwargs):
        if url.startswith("data:"):
            import weasyprint
            return weasyprint.default_url_fetcher(url)
        data, mime = safe_get(url, headers)
        return {"string": data, "mime_type": mime, "redirected_url": url}
    return fetcher


# --------------------------------------------------------------------------- #
# HTML transforms
# --------------------------------------------------------------------------- #

_QUOTES_RE = re.compile("[\"'\u2018\u2019\u201a\u201b\u201c\u201d\u201e\u201f\u00ab\u00bb]")
_WS_RE = re.compile(r"\s+")


def _norm(text):
    """Normalize a heading or title for equality comparison."""
    t = unicodedata.normalize("NFKC", text or "")
    t = _QUOTES_RE.sub("", t)
    return _WS_RE.sub(" ", t).strip().casefold()


_URL_RE = re.compile(r"\b(https?)://([^\s/<>\"'?#]+)([^\s<>\"']*)", re.IGNORECASE)


def defang_text(text):
    """Defang URLs in plain text: http->hxxp, dots in the host -> [.].

    Bare domains without a scheme are left alone (too many false positives
    in prose: version numbers, abbreviations).
    """
    def _rep(m):
        scheme = "hxxps" if m.group(1).lower() == "https" else "hxxp"
        host = m.group(2).replace("[.]", "\x00").replace(".", "[.]").replace("\x00", "[.]")
        return f"{scheme}://{host}{m.group(3)}"
    return _URL_RE.sub(_rep, text)


def extract_content(soup, selectors, raw_html=""):
    """Return the article-body element.

    selectors None  -> the input is already body content; use <body> or root.
    selectors "generic" -> readability extraction of raw_html.
    selectors list  -> first matching selector wins; none matching is an error.
    """
    if selectors is None:
        return soup.body or soup
    if selectors == "generic":
        # PDF-RENDERER-READABILITY-V1: multi-publisher sources use a
        # readability (Firefox Reader View port) extraction instead of a
        # guessed selector list, which matched page chrome in testing.
        from readability import Document
        summary = Document(raw_html).summary(html_partial=True)
        content = BeautifulSoup(summary, "lxml").body
        if content is None or not content.get_text(strip=True):
            raise ExtractError("readability found no article body")
        return content
    if isinstance(selectors, str):
        selectors = [selectors]
    for sel in selectors:
        found = soup.select_one(sel)
        if found is not None:
            return found
    raise ExtractError("no article container matched selectors")


def clean_content(content, title, extra_strip):
    """Strip noise, fix lazy images, dedupe the title, defang links in place."""
    # Comments carry tracking and template junk
    for c in content.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()

    # Noise elements
    for sel in DEFAULT_STRIP + list(extra_strip or []):
        for el in content.select(sel):
            el.decompose()

    # Lazy-loaded images: promote data-* sources; WeasyPrint ignores srcset
    for img in content.find_all("img"):
        src = img.get("src") or ""
        if not src or src.startswith("data:image/svg") or src.startswith("data:image/gif"):
            for attr in ("data-src", "data-lazy-src", "data-original", "data-orig-file"):
                if img.get(attr):
                    img["src"] = img[attr]
                    break
        for attr in ("srcset", "sizes", "loading"):
            if attr in img.attrs:
                del img[attr]

    # Title dedupe: drop body headings identical to the document title
    want = _norm(title)
    if want:
        for h in content.find_all(["h1", "h2"]):
            if _norm(h.get_text(" ")) == want:
                h.decompose()

    # Links: unwrap anchors (text kept, href gone) so nothing is clickable
    for a in content.find_all("a"):
        a.unwrap()

    # Defang URL text everywhere in the body
    for node in content.find_all(string=True):
        if isinstance(node, NavigableString) and not isinstance(node, Comment):
            new = defang_text(str(node))
            if new != str(node):
                node.replace_with(new)


def _esc(text):
    import html as html_mod
    return html_mod.escape(text or "", quote=True)


def build_document(title, body_html, source_url, byline, connector):
    """Wrap the cleaned body with title, byline and PDF metadata.

    Byline line: By <author> | <publisher> | <published> | <defanged source>.
    Connector name and ingestion timestamp go into PDF metadata only.
    """
    byline = byline or {}
    parts = []
    if byline.get("author"):
        parts.append("By " + byline["author"])
    if byline.get("publisher"):
        parts.append(byline["publisher"])
    if byline.get("published"):
        parts.append(byline["published"])
    if source_url:
        parts.append(defang_text(source_url))
    byline_html = ""
    if parts:
        byline_html = "<p class='byline'>" + _esc(" | ".join(parts)) + "</p>"

    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    generator = f"pdf-renderer {VERSION}" + (f"; connector={connector}" if connector else "")
    author_meta = byline.get("publisher") or byline.get("author") or ""
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{_esc(title)}</title>"
        f"<meta name='author' content='{_esc(author_meta)}'>"
        f"<meta name='generator' content='{_esc(generator)}'>"
        f"<meta name='dcterms.created' content='{created}'>"
        f"<meta name='description' content='{_esc(defang_text(source_url or ''))}'>"
        f"<style>{PDF_STYLE}</style></head><body>"
        f"<h1 class='doc-title'>{_esc(title)}</h1>"
        f"{byline_html}{body_html}</body></html>"
    )


def prepare_html(req):
    """Run extract + clean and return the full document HTML (no rendering).

    Separated from rendering so the transform can be unit-tested without
    WeasyPrint.
    """
    title = (req.get("title") or "").strip()
    if not title:
        raise ExtractError("title is required")
    soup = BeautifulSoup(req.get("html") or "", "lxml")
    content = extract_content(soup, req.get("selectors"), req.get("html") or "")
    clean_content(content, title, req.get("strip"))
    min_chars = int(req.get("min_chars") or 0)
    text_len = len(content.get_text(" ", strip=True))
    if text_len < min_chars:
        raise ExtractError(f"extracted text too short ({text_len} < {min_chars} chars)")
    if content.name in ("body", "[document]"):
        body_html = content.decode_contents()
    else:
        body_html = str(content)
    return build_document(
        title, body_html, req.get("source_url") or "",
        req.get("byline"), req.get("connector") or "",
    )


# --------------------------------------------------------------------------- #
# Job entry points (run in worker processes)
# --------------------------------------------------------------------------- #

def render_html_job(req):
    """HTML in -> PDF bytes out."""
    import weasyprint
    doc = prepare_html(req)
    headers = {"User-Agent": BROWSER_UA}
    if req.get("source_url"):
        headers["Referer"] = req["source_url"]
    headers.update(req.get("headers") or {})
    base = req.get("source_url") or None
    return weasyprint.HTML(
        string=doc, base_url=base, url_fetcher=make_url_fetcher(headers),
    ).write_pdf()


_SCROLL_JS = """
async () => {
  await new Promise((resolve) => {
    let steps = 0;
    const timer = setInterval(() => {
      window.scrollBy(0, 600);
      steps += 1;
      if (steps >= 40 || window.scrollY + window.innerHeight >= document.body.scrollHeight) {
        clearInterval(timer);
        window.scrollTo(0, 0);
        resolve();
      }
    }, 100);
  });
}
"""


def render_url_job(req):
    """URL in -> Playwright DOM -> same pipeline -> PDF bytes out.

    Images, media and fonts are aborted in the browser (only the DOM is
    needed; WeasyPrint fetches images itself through the SSRF guard). Every
    other sub-request is checked against the SSRF policy.
    """
    from playwright.sync_api import sync_playwright

    url = req["url"]
    check_url(url)
    ua = (req.get("headers") or {}).get("User-Agent", BROWSER_UA)
    nav_ms = int(req.get("nav_timeout_ms") or 60000)

    def _route(route):
        r = route.request
        if r.resource_type in ("image", "media", "font"):
            return route.abort()
        try:
            check_url(r.url)
        except BlockedURL:
            return route.abort()
        return route.continue_()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            ctx = browser.new_context(user_agent=ua, viewport={"width": 1280, "height": 1600})
            ctx.route("**/*", _route)
            page = ctx.new_page()
            # PDF-RENDERER-NAVFAIL-V1: a site that fails to load is a content
            # problem (422), not a renderer outage (500)
            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=nav_ms)
            except Exception as exc:
                raise ExtractError(f"navigation failed: {str(exc).splitlines()[0][:200]}")
            # PDF-RENDERER-HTTPSTATUS-V1: an error page is not the article
            if resp is not None and resp.status >= 400:
                raise ExtractError(f"HTTP {resp.status} from {url}")
            # A redirect chain can land somewhere the first check never saw
            check_url(page.url)
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            if any(m in (page.title() or "").lower() for m in CHALLENGE_MARKERS):
                raise ExtractError("bot challenge interstitial detected")
            page.evaluate(_SCROLL_JS)
            page.wait_for_timeout(500)
            html = page.content()
            final_url = page.url
        finally:
            browser.close()

    job = dict(req)
    job["html"] = html
    job["source_url"] = req.get("source_url") or final_url
    if job.get("selectors") is None:
        job["selectors"] = "generic"
    if job.get("min_chars") is None:
        job["min_chars"] = 200
    return render_html_job(job)


def child_entry(fn_name, req, conn):
    """Worker-process body: run one job and send (status, payload) back.

    Lives in this module (not app.py) so forkserver children only import the
    preloaded pipeline, never the web app.
    """
    try:
        conn.send(("ok", globals()[fn_name](req)))
    except BlockedURL as exc:
        conn.send(("blocked", str(exc)))
    except ExtractError as exc:
        conn.send(("extract", str(exc)))
    except Exception as exc:  # noqa: BLE001 - reported to caller as 500
        conn.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        conn.close()
