"""PDF rendering.

Shared module that provides two rendering paths for generating PDFs
from article content:

  - render_html_to_pdf: WeasyPrint-based rendering from an HTML string.
    Used by connectors that fetch and parse article HTML themselves
    (requests + BeautifulSoup, or Playwright for JS-rendered pages).

  - render_page_to_pdf: Playwright-based rendering from a live page URL.
    Used by connectors that need the full browser-rendered page captured
    as-is (JS-heavy sites, lazy-loaded images, interactive content).

Both return raw PDF bytes on success, or None on timeout/failure.
"""

import html as html_mod
import logging
import threading
from datetime import datetime, timezone

logging.getLogger("weasyprint").setLevel(logging.ERROR)
logging.getLogger("fontTools").setLevel(logging.WARNING)

# -- Shared constants ----------------------------------------------------- #

PDF_STYLE = (
    "body { font-family: Georgia, serif; max-width: 800px; "
    "margin: 0 auto; padding: 20px; color: #222; line-height: 1.6; } "
    "h1 { font-size: 24px; margin-bottom: 0.5em; } "
    "h2 { font-size: 20px; } "
    "img { max-width: 100%; height: auto; } "
    "pre, code { background: #f4f4f4; padding: 2px 6px; "
    "font-size: 13px; white-space: pre-wrap; word-break: break-all; } "
    "table { border-collapse: collapse; width: 100%; } "
    "td, th { border: 1px solid #ccc; padding: 8px; } "
    "figure { margin: 1em 0; } "
    "figcaption { font-size: 0.85em; color: #666; margin-top: 4px; } "
    "blockquote { border-left: 3px solid #ccc; margin: 1em 0; "
    "padding: 0.5em 1em; color: #555; } "
)

CHALLENGE_MARKERS = ("just a moment", "checking your browser", "attention required")

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


# -- Internal helpers ------------------------------------------------------ #

def _escape_html(text):
    """Escape HTML special characters.

    Input:  text -- raw string (may be None).
    Process: delegates to html.escape; returns "" for falsy input.
    Output: escaped string safe for embedding in HTML.
    """
    return html_mod.escape(text) if text else ""


def _build_pdf_html(title, content_html, source_url):
    """Assemble a full HTML document for WeasyPrint.

    Input:
        title: document title (will be escaped).
        content_html: raw HTML body content.
        source_url: unused in the template but kept for parity.

    Process: wraps content in a DOCTYPE document with PDF_STYLE
        and @page margin rules.

    Output: complete HTML document string.
    """
    safe_title = _escape_html(title)
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><style>"
        + PDF_STYLE
        + "@page { margin: 15mm 12mm 15mm 12mm; } "
        + "</style></head><body>"
        + "<h1>" + safe_title + "</h1>"
        + content_html
        + "</body></html>"
    )


def _default_url_fetcher(url, session=None):
    """WeasyPrint URL fetcher that uses an optional requests.Session.

    Input:
        url: resource URL requested by WeasyPrint.
        session: optional requests.Session with auth/cookies.

    Process: data: URIs go to WeasyPrint's built-in fetcher.
        Everything else is fetched via the session (or bare requests).

    Output: dict with 'string' (bytes) and 'mime_type' keys.
    """
    import weasyprint

    if url.startswith("data:"):
        return weasyprint.default_url_fetcher(url)
    try:
        import requests as _requests
        getter = session if session else _requests
        resp = getter.get(url, timeout=15)
        return {
            "string": resp.content,
            "mime_type": resp.headers.get(
                "content-type", "application/octet-stream"
            ).split(";")[0],
        }
    except Exception:
        return {"string": b"", "mime_type": "text/plain"}


def _auto_scroll(page):
    """Scroll a Playwright page to the bottom to trigger lazy loading.

    Input:  page -- active Playwright page object.
    Process: scrolls 400px at a time, then resets to top.
    Output: None (side-effect: all lazy content triggered).
    """
    page.evaluate(
        """
        async () => {
          await new Promise((resolve) => {
            let total = 0;
            const step = 400;
            const timer = setInterval(() => {
              window.scrollBy(0, step);
              total += step;
              if (total >= document.body.scrollHeight) {
                clearInterval(timer);
                window.scrollTo(0, 0);
                resolve();
              }
            }, 100);
          });
        }
        """
    )


# -- Public API ------------------------------------------------------------ #

def render_html_to_pdf(title, content_html, source_url,
                       session=None, timeout=120):
    """Render HTML content to PDF bytes via WeasyPrint.

    Input:
        title: document title for the PDF heading.
        content_html: HTML body content (article text).
        source_url: base URL for resolving relative resources
            (images, stylesheets).
        session: optional requests.Session for authenticated
            resource fetching (cookies, headers).
        timeout: wall-clock timeout in seconds (default 120).

    Process:
        Builds a full HTML document with PDF_STYLE, then renders
        via WeasyPrint in a daemon thread with a wall-clock timeout
        guard. The daemon thread prevents WeasyPrint hangs from
        blocking the connector indefinitely.

    Output:
        bytes: raw PDF on success.
        Raises TimeoutError on timeout.
        Raises on WeasyPrint rendering errors.
    """
    doc_html = _build_pdf_html(title, str(content_html), source_url)

    def _fetcher(u):
        return _default_url_fetcher(u, session=session)

    result = [None]
    exc_holder = [None]

    def target():
        try:
            import weasyprint
            result[0] = weasyprint.HTML(
                string=doc_html, base_url=source_url, url_fetcher=_fetcher
            ).write_pdf()
        except Exception as e:
            exc_holder[0] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        raise TimeoutError(
            f"WeasyPrint render exceeded {timeout}s timeout"
        )
    if exc_holder[0]:
        raise exc_holder[0]
    return result[0]


def render_page_to_pdf(browser, url, connector_name="",
                       nav_timeout_ms=60000, settle_ms=1500):
    """Render a live web page to PDF via Playwright.

    Input:
        browser: active Playwright Chromium browser instance.
        url: page URL to navigate and render.
        connector_name: human-readable connector name for the
            PDF footer (e.g. "DFIR Report").
        nav_timeout_ms: Playwright navigation timeout in ms.
        settle_ms: post-scroll settle delay in ms (default 1500).

    Process:
        Opens a fresh browser context (1280x1696 viewport),
        navigates to the URL, checks for Cloudflare challenge
        pages, auto-scrolls to trigger lazy-loaded media, waits
        for the page to settle, then calls page.pdf() with A4
        format and a branded footer.

    Output:
        bytes: rendered PDF.
        Raises RuntimeError on Cloudflare challenge detection.
        Raises playwright errors on navigation/timeout failures.
    """
    context = browser.new_context(
        viewport={"width": 1280, "height": 1696},
        user_agent=BROWSER_UA,
    )
    page = context.new_page()
    try:
        page.goto(url, wait_until="networkidle", timeout=nav_timeout_ms)

        title = (page.title() or "").lower()
        if any(marker in title for marker in CHALLENGE_MARKERS):
            raise RuntimeError("Cloudflare challenge interstitial detected")

        _auto_scroll(page)
        page.wait_for_timeout(settle_ms)

        ingested_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        footer = (
            "<div style='font-size:8px; width:100%; padding:0 12px; "
            "color:#444; display:flex; justify-content:space-between;'>"
            "<span>" + _escape_html(url) + "</span>"
            "<span>OpenCTI " + _escape_html(connector_name) + " connector"
            " &middot; ingested " + ingested_at
            + " &middot; page <span class='pageNumber'></span>/"
            "<span class='totalPages'></span></span></div>"
        )
        return page.pdf(
            print_background=True,
            display_header_footer=True,
            header_template="<span></span>",
            footer_template=footer,
            margin={"top": "10mm", "bottom": "16mm",
                    "left": "8mm", "right": "8mm"},
            format="A4",
        )
    finally:
        page.close()
        context.close()
