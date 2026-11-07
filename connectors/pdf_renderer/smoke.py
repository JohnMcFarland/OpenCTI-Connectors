"""pdf-renderer smoke test. Run inside the container:

    docker exec opencti-pdf-renderer python smoke.py

Read-only against the outside world except one public page fetch. Writes the
rendered PDFs to /tmp/smoke/ for inspection.
"""
import io
import json
import os
import urllib.error
import urllib.request

from pypdf import PdfReader

BASE = "http://127.0.0.1:8000"
OUT = "/tmp/smoke"
os.makedirs(OUT, exist_ok=True)
results = []


def post(path, payload):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def check(name, cond, detail=""):
    results.append(cond)
    print(("PASS " if cond else "FAIL ") + name + (" -- " + detail if detail else ""))


def pdf_info(data):
    reader = PdfReader(io.BytesIO(data))
    text = "\n".join((p.extract_text() or "") for p in reader.pages)
    uris = 0
    for page in reader.pages:
        for annot in page.get("/Annots") or []:
            obj = annot.get_object()
            if "/URI" in str(obj.get("/A", "")):
                uris += 1
    return reader, text, uris


# 1. health
with urllib.request.urlopen(BASE + "/health", timeout=10) as r:
    check("health", r.status == 200, r.read().decode())

# 2. html render: defang, title dedupe, strip, SSRF-blocked image skipped
TITLE = "\u201cNext Exploit Opportunities\u201d: Smoke Test"
html = (
    "<html><body><nav>NAVMENU</nav><article>"
    "<h1>\u201cNext Exploit Opportunities\u201d: Smoke Test</h1>"
    "<p>See <a href='https://evil.example.com/path'>https://evil.example.com/path</a> now.</p>"
    "<img src='http://opencti:8080/static/logo.png'>"
    "<div class='share'>SHAREBLOCK</div><script>alert(1)</script>"
    "</article><footer>FOOTERTEXT</footer></body></html>"
)
code, body = post("/render/html", {
    "title": TITLE, "html": html, "selectors": "generic",
    "source_url": "https://unit42.paloaltonetworks.com/smoke/",
    "byline": {"author": "Smoke Author", "publisher": "Unit 42", "published": "2026-10-24"},
    "connector": "smoke",
})
check("html status 200", code == 200, str(code) + " " + body[:200].decode("utf-8", "ignore") if code != 200 else "")
if code == 200:
    open(OUT + "/html.pdf", "wb").write(body)
    reader, text, uris = pdf_info(body)
    flat = " ".join(text.split())
    check("html defanged", "hxxps://" in flat and "https://" not in flat)
    check("html no link annotations", uris == 0, str(uris))
    check("html title once", flat.count("Next Exploit Opportunities") == 1, str(flat.count("Next Exploit Opportunities")))
    check("html noise stripped", not any(x in flat for x in ("NAVMENU", "SHAREBLOCK", "FOOTERTEXT", "alert(1)")))
    check("html byline", "Smoke Author" in flat and "unit42[.]paloaltonetworks[.]com" in flat)
    print("     metadata:", dict(reader.metadata or {}))

# 3. extract failure -> 422
code, body = post("/render/html", {"title": "T", "html": "<div>x</div>", "selectors": ["article"]})
check("no-match selectors -> 422", code == 422, str(code))

# 4. SSRF: internal URL -> 403
code, body = post("/render/url", {"url": "http://opencti:8080/", "title": "T"})
check("internal url -> 403", code == 403, str(code))
code, body = post("/render/url", {"url": "http://169.254.169.254/latest/meta-data/", "title": "T"})
check("metadata ip -> 403", code == 403, str(code))

# 5. live url render through Playwright
code, body = post("/render/url", {
    "url": "https://unit42.paloaltonetworks.com/ai-assisted-cybercrime-analysis/",
    "title": "\u201cNext Exploit Opportunities\u201d: How a Threat Actor Used AI to Help Plan and Execute Multiple Types of Cybercrime Activities",
    "byline": {"publisher": "Unit 42"}, "connector": "smoke",
})
check("url status 200", code == 200, str(code) + " " + body[:300].decode("utf-8", "ignore") if code != 200 else "")
if code == 200:
    open(OUT + "/url.pdf", "wb").write(body)
    reader, text, uris = pdf_info(body)
    flat = " ".join(text.split())
    check("url no link annotations", uris == 0, str(uris))
    check("url no live https text", "https://" not in flat)
    print("     pages=%d bytes=%d" % (len(reader.pages), len(body)))
    print("     text head:", flat[:400])

print("SUMMARY %d/%d passed" % (sum(results), len(results)))
