"""pdf-renderer calls with retry and failure classification.

Uses the shared house client microservices/make_pdf.render_live_pdf
(PDF-RENDERER-CLIENT-V1), never a copy. Failure policy, as in the generated
connectors:
- RendererUnavailable (service down, busy, timed out, 5xx, non-PDF reply):
  retried render_retries times with backoff, then re-raised. The caller
  pauses all rendering; the item is not counted against.
- The site failing (navigation failure, HTTP 408/425/429/5xx from the site,
  bot challenge), or "no content" for a no_content_is_transient profile:
  SiteUnavailable, retried on a later poll.
- Any other ContentUnavailable, or a PDF over the size cap: None, and the
  Report is created without a PDF.
"""

import re

from microservices.make_pdf import (  # noqa: F401  (re-exported for callers/tests)
    ContentUnavailable,
    RendererUnavailable,
    render_live_pdf,
)

from . import timing

# The renderer reports some SITE problems as "no usable article" (HTTP 422):
# the page failed to load, the site answered 429/5xx, or a bot challenge.
# Those are transient for the item. A 422 whose detail is a validation-error
# list means the request itself was rejected (client/service mismatch), which
# is a renderer problem, not a content one.
_SITE_FAILURE_RE = re.compile(
    r"navigation failed|HTTP (?:408|425|429|5\d\d) from|bot challenge", re.IGNORECASE)
_VALIDATION_ERROR_RE = re.compile(r'"detail"\s*:\s*\[')


class SiteUnavailable(Exception):
    """The article's site failed for this poll; retry the item later."""


def render_live(item, published, profile, timeout):
    """Render the live article to PDF bytes via the pdf-renderer service.

    Raises RendererUnavailable or ContentUnavailable.
    """
    byline = {"publisher": profile.author_name, "published": published[:10]}
    if profile.byline_author and item.get("creator"):
        byline["author"] = item["creator"]
    kwargs = {}
    # Site-specific request headers (e.g. BleepingComputer's User-Agent,
    # BLEEPING-RENDER-UA-V1); sources without them call the client as before.
    if profile.render_headers:
        kwargs["headers"] = dict(profile.render_headers)
    selectors = profile.content_selectors
    return render_live_pdf(
        item["link"],
        item["title"] or item["link"],   # verbatim feed title
        profile.name,
        byline=byline,
        selectors=list(selectors) if isinstance(selectors, list) else selectors,
        strip=list(profile.hide_selectors),
        timeout=timeout,
        **kwargs,
    )


def render_with_retry(item, published, profile, settings, log):
    """Return PDF bytes, or None when there is no usable article.

    RendererUnavailable is retried with exponential backoff and re-raised
    after the last attempt (no Report is written). A ContentUnavailable or
    oversized PDF returns None: the Report is still created, without a PDF,
    and a WARNING says why.
    """
    url = item["link"]
    # Backoff starts at request_delay (a site's crawl delay) but is capped:
    # these retries wait for the renderer, not the site.
    delay = min(max(profile.request_delay, 1), 30)
    retries = settings.render_retries
    for attempt in range(1, retries + 1):
        try:
            pdf_bytes = render_live(item, published, profile, settings.render_timeout)
            if not pdf_bytes.startswith(b"%PDF"):
                raise RendererUnavailable("pdf-renderer returned a non-PDF payload")
        except ContentUnavailable as exc:
            detail = str(exc)
            if _VALIDATION_ERROR_RE.search(detail):
                raise RendererUnavailable(f"renderer rejected the request: {detail}")
            if profile.no_content_is_transient or _SITE_FAILURE_RE.search(detail):
                # The site (or its bot challenge) failed: retry on a later poll.
                raise SiteUnavailable(detail)
            log.log_warning(f"No PDF for {url}: {exc}")
            return None
        except RendererUnavailable as exc:
            log.log_warning(f"Render attempt {attempt}/{retries} failed for {url}: {exc}")
            if attempt >= retries:
                raise
            timing.sleep(delay)
            delay *= 2
            continue
        if len(pdf_bytes) > settings.max_pdf_bytes:
            log.log_warning(
                f"No PDF for {url}: rendered PDF is {len(pdf_bytes)} bytes "
                f"(cap {settings.max_pdf_bytes})"
            )
            return None
        return pdf_bytes
    raise RendererUnavailable("render_retries is 0")
