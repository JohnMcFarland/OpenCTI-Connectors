"""pdf-renderer HTTP service.

Internal-only service on the OpenCTI compose network (no published port).
Connectors POST content or a URL and receive application/pdf.

  GET  /health        -> {"status": "ok", ...}
  POST /render/html   -> PDF from caller-supplied HTML
  POST /render/url    -> PDF from a URL loaded in Playwright

Each render runs in its own worker process (forkserver, pipeline preloaded)
and is killed outright when it exceeds its timeout, so a hung WeasyPrint or
Chromium can never leak. Concurrency is capped by PDF_RENDERER_WORKERS.

Status codes: 200 pdf | 403 URL blocked by SSRF policy | 422 no usable
content | 503 renderer busy | 504 render timeout | 500 other failure.

Markers: PDF-RENDERER-V1
"""

import logging
import multiprocessing as mp
import os
import threading
import time
from typing import Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

import pipeline

WORKERS = int(os.environ.get("PDF_RENDERER_WORKERS", "2"))
DEFAULT_TIMEOUT = int(os.environ.get("PDF_RENDERER_TIMEOUT", "120"))
MAX_HTML_BYTES = 5 * 1024 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pdf-renderer")

# forkserver: children fork from a clean server process with pipeline (bs4,
# lxml, requests) already imported, so per-job startup stays cheap
_mp = mp.get_context("forkserver")
_mp.set_forkserver_preload(["pipeline"])
_slots = threading.BoundedSemaphore(WORKERS)

app = FastAPI(title="pdf-renderer", version=pipeline.VERSION)


class Byline(BaseModel):
    author: Optional[str] = None
    publisher: Optional[str] = None
    published: Optional[str] = None


class HtmlRequest(BaseModel):
    title: str
    html: str
    source_url: str = ""
    byline: Optional[Byline] = None
    selectors: Optional[Union[str, List[str]]] = None
    strip: List[str] = []
    headers: Dict[str, str] = {}
    connector: str = ""
    min_chars: int = 0
    timeout: Optional[int] = None


class UrlRequest(BaseModel):
    url: str
    title: str
    source_url: str = ""
    byline: Optional[Byline] = None
    selectors: Optional[Union[str, List[str]]] = "generic"
    strip: List[str] = []
    headers: Dict[str, str] = {}
    connector: str = ""
    min_chars: int = 200
    nav_timeout_ms: int = 60000
    timeout: Optional[int] = None


def _run(fn_name, req, timeout, label):
    """Run a job in a killable worker under the concurrency cap."""
    started = time.monotonic()
    if not _slots.acquire(timeout=timeout):
        log.warning("busy %s", label)
        raise HTTPException(503, "renderer busy")
    try:
        parent, child = _mp.Pipe(duplex=False)
        proc = _mp.Process(target=pipeline.child_entry, args=(fn_name, req, child), daemon=True)
        proc.start()
        child.close()
        if not parent.poll(timeout):
            proc.kill()
            proc.join(5)
            log.warning("timeout %s after %ss", label, timeout)
            raise HTTPException(504, f"render exceeded {timeout}s")
        try:
            status, payload = parent.recv()
        except EOFError:
            status, payload = "error", "worker exited without result"
        proc.join(5)
    finally:
        _slots.release()

    ms = int((time.monotonic() - started) * 1000)
    if status == "ok":
        log.info("ok %s %dms %d bytes", label, ms, len(payload))
        return payload
    log.warning("%s %s %dms: %s", status, label, ms, payload)
    code = {"blocked": 403, "extract": 422}.get(status, 500)
    raise HTTPException(code, payload)


@app.get("/health")
def health():
    return {"status": "ok", "version": pipeline.VERSION, "workers": WORKERS}


@app.post("/render/html")
def render_html(body: HtmlRequest):
    if len(body.html.encode("utf-8", "ignore")) > MAX_HTML_BYTES:
        raise HTTPException(413, "html exceeds 5MB")
    req = body.model_dump()
    label = f"html connector={body.connector or '-'} src={body.source_url[:120]}"
    pdf = _run("render_html_job", req, body.timeout or DEFAULT_TIMEOUT, label)
    return Response(content=pdf, media_type="application/pdf")


@app.post("/render/url")
def render_url(body: UrlRequest):
    req = body.model_dump()
    label = f"url connector={body.connector or '-'} url={body.url[:120]}"
    pdf = _run("render_url_job", req, body.timeout or DEFAULT_TIMEOUT, label)
    return Response(content=pdf, media_type="application/pdf")
