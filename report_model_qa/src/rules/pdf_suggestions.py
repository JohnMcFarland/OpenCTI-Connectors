from __future__ import annotations

import io
import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from util.graph import safe_get

try:
    import PyPDF2  # type: ignore
except Exception:
    PyPDF2 = None  # type: ignore

try:
    import pytesseract  # type: ignore
except Exception:
    pytesseract = None  # type: ignore

try:
    from pdf2image import convert_from_bytes  # type: ignore
except Exception:
    convert_from_bytes = None  # type: ignore


SUPPORTED_TYPES = ["pdf", "md", "txt"]

# ---------------------------------------------------------------------------
# Smart-parse false positive filters
# ---------------------------------------------------------------------------

# Patterns that are never valid actor/cluster names regardless of cue phrase.
# These catch common smart-parse extraction errors where the cue phrase fires
# on a CVE ID, conjunction phrase, or other non-entity token.
_INVALID_CANDIDATE_PATTERNS = [
    re.compile(r"^CVE-\d{4}-\d{4,7}", re.IGNORECASE),          # CVE IDs
    re.compile(r"^CVSSv?\d", re.IGNORECASE),                     # CVSS scores
    re.compile(r"\b(and|or|with|a|an|the)\b", re.IGNORECASE),   # conjunctions
    re.compile(r"deployment\s+and", re.IGNORECASE),              # prose fragments
    re.compile(r"^\d"),                                           # starts with digit
    re.compile(r"^[a-z]{1,2}\d"),                                 # short version strings
]

# Minimum word count for a multi-word candidate to be valid.
# Single-word candidates must pass name length requirements instead.
_MIN_SINGLE_WORD_LEN = 5


def _is_invalid_candidate(name: str) -> bool:
    """Return True if the candidate name should be rejected before KB lookup."""
    if not name or not name.strip():
        return True
    stripped = name.strip()
    for pattern in _INVALID_CANDIDATE_PATTERNS:
        if pattern.search(stripped):
            return True
    words = stripped.split()
    if len(words) == 1 and len(stripped) < _MIN_SINGLE_WORD_LEN:
        return True
    return False


# -------------------------
# File selection helpers
# -------------------------

def _is_pdf(f: Dict[str, Any]) -> bool:
    name = (f.get("name") or f.get("file_name") or f.get("filename") or "").lower()
    mime = (f.get("mime_type") or f.get("mimeType") or "").lower()
    return name.endswith(".pdf") or "pdf" in mime


def _is_md(f: Dict[str, Any]) -> bool:
    name = (f.get("name") or f.get("file_name") or f.get("filename") or "").lower()
    mime = (f.get("mime_type") or f.get("mimeType") or "").lower()
    return name.endswith(".md") or "markdown" in mime or mime in ("text/markdown", "text/x-markdown")


def _is_txt(f: Dict[str, Any]) -> bool:
    name = (f.get("name") or f.get("file_name") or f.get("filename") or "").lower()
    mime = (f.get("mime_type") or f.get("mimeType") or "").lower()
    return name.endswith(".txt") or mime == "text/plain"


def _select_supported_files(report: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    files = safe_get(report, "files") or safe_get(report, "importFiles") or []
    out: Dict[str, List[Dict[str, Any]]] = {"pdf": [], "md": [], "txt": []}
    if not isinstance(files, list):
        return out
    for f in files:
        if not isinstance(f, dict):
            continue
        if _is_pdf(f):
            out["pdf"].append(f)
        elif _is_md(f):
            out["md"].append(f)
        elif _is_txt(f):
            out["txt"].append(f)
    return out


# -------------------------
# Download + extraction
# -------------------------

def _download_file_bytes(helper: Any, file_id: str) -> Optional[bytes]:
    try:
        if hasattr(helper.api, "opencti_file") and hasattr(helper.api.opencti_file, "download"):
            data = helper.api.opencti_file.download(file_id)
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
    except Exception:
        pass
    try:
        if hasattr(helper.api, "opencti_file") and hasattr(helper.api.opencti_file, "download_file"):
            data = helper.api.opencti_file.download_file(file_id)
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
    except Exception:
        pass
    try:
        import requests
        base = os.environ.get("OPENCTI_URL", "") or ""
        token = os.environ.get("OPENCTI_TOKEN", "") or ""
        if not base:
            return None
        url = base.rstrip("/") + f"/storage/get/{file_id}"
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 200 and r.content:
            return r.content
    except Exception:
        pass
    return None


def _extract_text_bytes(blob: bytes) -> str:
    if not blob:
        return ""
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return blob.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def _extract_pdf_text_pdftotext(pdf_bytes: bytes) -> str:
    if not pdf_bytes:
        return ""
    try:
        with tempfile.NamedTemporaryFile(prefix="qa_", suffix=".pdf", delete=False) as f:
            f.write(pdf_bytes)
            pdf_path = f.name
        try:
            p = subprocess.run(
                ["pdftotext", "-layout", pdf_path, "-"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=45,
            )
            if p.stdout:
                return p.stdout.decode("utf-8", errors="ignore") or ""
            return ""
        finally:
            try:
                os.unlink(pdf_path)
            except Exception:
                pass
    except Exception:
        return ""


def _extract_pdf_text_pypdf2(pdf_bytes: bytes) -> str:
    if not pdf_bytes or PyPDF2 is None:
        return ""
    try:
        reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
        chunks: List[str] = []
        for page in reader.pages[:50]:
            try:
                t = page.extract_text() or ""
                if t:
                    chunks.append(t)
            except Exception:
                continue
        return "\n".join(chunks)
    except Exception:
        return ""


def _extract_pdf_text_ocr(pdf_bytes: bytes, max_pages: int = 6) -> str:
    if not pdf_bytes or convert_from_bytes is None or pytesseract is None:
        return ""
    try:
        images = convert_from_bytes(pdf_bytes, first_page=1, last_page=max_pages)
        chunks: List[str] = []
        for img in images:
            try:
                txt = pytesseract.image_to_string(img) or ""
                if txt.strip():
                    chunks.append(txt)
            except Exception:
                continue
        return "\n".join(chunks)
    except Exception:
        return ""


# -------------------------
# Text sources inside OpenCTI
# -------------------------

def _report_raw_text(report: Dict[str, Any]) -> str:
    """
    Read description and content fields from the report container.
    Both fields are collected — content is the primary intelligence body,
    description is typically a summary.
    """
    parts: List[str] = []
    for key in ("description", "content", "x_opencti_description", "x_opencti_content"):
        v = safe_get(report, key)
        if v and isinstance(v, str) and v.strip():
            parts.append(v.strip())
    return "\n\n".join(parts)


def _report_attached_notes_text(
    helper: Any, report_internal_id: str,
    limit: int = 5, max_chars: int = 40000,
) -> str:
    """Pull non-QA note contents. QA notes excluded to prevent feedback loop."""
    try:
        query = """
        query NotesForReport($id: String!, $first: Int!) {
          notes(
            filters: [{key: "objects", values: [$id]}]
            first: $first
          ) {
            edges { node { id content created_at note_types } }
          }
        }
        """
        res = helper.api.query(query, {"id": report_internal_id, "first": limit})
        edges = (((res or {}).get("data") or {}).get("notes") or {}).get("edges") or []
        texts: List[str] = []
        for e in edges:
            node = (e or {}).get("node") or {}
            note_types = node.get("note_types") or []
            if isinstance(note_types, list) and "QA" in note_types:
                continue
            c = node.get("content")
            if c and isinstance(c, str) and c.strip():
                texts.append(c.strip())
        return "\n\n".join(texts)[:max_chars]
    except Exception:
        return ""


# -------------------------
# Additive text assembly
# -------------------------

def _assemble_text(
    helper: Any,
    report: Dict[str, Any],
    file_sets: Dict[str, List[Dict[str, Any]]],
    attempts: List[str],
) -> Tuple[str, Dict[str, Any]]:
    parts: List[str] = []
    pdf_meta: Dict[str, Any] = {}

    # 1) PDF — always attempted first
    for f in file_sets.get("pdf", []):
        fid = f.get("id")
        fname = f.get("name") or f.get("file_name") or f.get("filename")
        if not fid:
            continue
        blob = _download_file_bytes(helper, str(fid))
        if not blob:
            pdf_meta = {"file_id": str(fid), "file_name": fname, "downloaded": False}
            continue
        pdf_meta = {"file_id": str(fid), "file_name": fname, "downloaded": True}

        t = _extract_pdf_text_pdftotext(blob)
        attempts.append("pdf_pdftotext")
        if t.strip():
            parts.append(t)
            break

        t = _extract_pdf_text_pypdf2(blob)
        attempts.append("pdf_pypdf2")
        if t.strip():
            parts.append(t)
            break

        t = _extract_pdf_text_ocr(
            blob, max_pages=int(os.environ.get("QA_DOC_OCR_MAX_PAGES", "6"))
        )
        attempts.append("pdf_ocr")
        if t.strip():
            pdf_meta["ocr_used"] = True
            parts.append(t)

    # 2) MD/TXT attachments
    for kind in ("md", "txt"):
        for f in file_sets.get(kind, []):
            fid = f.get("id")
            if not fid:
                continue
            blob = _download_file_bytes(helper, str(fid))
            if not blob:
                continue
            t = _extract_text_bytes(blob)
            attempts.append(f"attachment_{kind}")
            if t.strip():
                parts.append(t)

    # 3) Report raw text (description + content)
    raw = _report_raw_text(report)
    if raw.strip():
        attempts.append("report_fields")
        parts.append(raw)

    # 4) Non-QA notes
    report_internal_id = safe_get(report, "id") or ""
    if report_internal_id:
        note_txt = _report_attached_notes_text(helper, str(report_internal_id))
        if note_txt.strip():
            attempts.append("report_notes")
            parts.append(note_txt)

    return "\n\n".join(parts), pdf_meta


# -------------------------
# Deterministic token extraction
# -------------------------

def _suggest_from_text_deterministic(
    text: str,
) -> Tuple[List[Tuple[str, str, str, str]], int, int]:
    rows: List[Tuple[str, str, str, str]] = []

    attack      = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)))
    mitigations = sorted(set(re.findall(r"\bM\d{4}\b", text)))
    capec       = sorted(set(re.findall(r"\bCAPEC-\d+\b", text, flags=re.IGNORECASE)))
    cves        = sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)))
    ipv4        = sorted(set(re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", text)))
    ipv6        = sorted(set(re.findall(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", text)))
    domains     = sorted(set(re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.(?:[a-zA-Z]{2,63})\b", text)))
    emails      = sorted(set(re.findall(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", text)))
    urls        = sorted(set(re.findall(r"https?://[^\s\"'<>]{4,}", text)))
    md5         = sorted(set(re.findall(r"\b[a-fA-F0-9]{32}\b", text)))
    sha1        = sorted(set(re.findall(r"\b[a-fA-F0-9]{40}\b", text)))
    sha256      = sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text)))
    asns        = sorted(set(re.findall(r"\bAS\d{1,10}\b", text, flags=re.IGNORECASE)))
    unc         = sorted(set(re.findall(r"\bUNC\d{3,5}\b", text, flags=re.IGNORECASE)))
    reg_keys    = sorted(set(re.findall(r"\bHK(?:LM|CU|CR|U|CC)\\[^\s\"'<>]{4,}", text, flags=re.IGNORECASE)))
    mutexes     = sorted(set(re.findall(r"\bGlobal\\[^\s\"'<>,;]{3,}\b", text)))

    email_domains = {e.split("@")[-1].lower() for e in emails}

    obj_count = 0
    rel_count = 0

    for t in unc[:50]:
        rows.append(("document", "suggests", f"Intrusion-Set:{t.upper()}", "UNC pattern found in extracted text."))
        obj_count += 1
    for t in attack[:100]:
        rows.append(("document", "suggests", f"Attack-Pattern:{t}", "ATT&CK technique ID found in extracted text."))
        obj_count += 1
    for m in mitigations[:100]:
        rows.append(("document", "suggests", f"Course-Of-Action:{m}", "ATT&CK mitigation ID found in extracted text."))
        obj_count += 1
    for c in capec[:50]:
        rows.append(("document", "suggests", f"Attack-Pattern:{c.upper()}", "CAPEC identifier found in extracted text."))
        obj_count += 1
    for c in cves[:100]:
        rows.append(("document", "suggests", f"Vulnerability:{c.upper()}", "CVE identifier found in extracted text."))
        obj_count += 1
    for ip in ipv4[:200]:
        rows.append(("document", "suggests", f"IPv4-Addr:{ip}", "IPv4 address found in extracted text."))
        obj_count += 1
    for ip in ipv6[:50]:
        rows.append(("document", "suggests", f"IPv6-Addr:{ip}", "IPv6 address found in extracted text."))
        obj_count += 1
    for e in emails[:100]:
        rows.append(("document", "suggests", f"Email-Addr:{e.lower()}", "Email address found in extracted text."))
        obj_count += 1
    for u in urls[:100]:
        rows.append(("document", "suggests", f"Url:{u}", "URL found in extracted text."))
        obj_count += 1
    for d in domains[:200]:
        if len(d) >= 4 and d.lower() not in email_domains:
            rows.append(("document", "suggests", f"Domain-Name:{d.lower()}", "Domain-like token found in extracted text."))
            obj_count += 1
    for h in sha256[:100]:
        rows.append(("document", "suggests", f"StixFile:{h.lower()}", "SHA256 hash found in extracted text."))
        obj_count += 1
    for h in sha1[:100]:
        rows.append(("document", "suggests", f"StixFile:{h.lower()}", "SHA1 hash found in extracted text."))
        obj_count += 1
    for h in md5[:100]:
        rows.append(("document", "suggests", f"StixFile:{h.lower()}", "MD5 hash found in extracted text."))
        obj_count += 1
    for a in asns[:50]:
        rows.append(("document", "suggests", f"Autonomous-System:{a.upper()}", "ASN found in extracted text."))
        obj_count += 1
    for r in reg_keys[:50]:
        rows.append(("document", "suggests", f"Windows-Registry-Key:{r}", "Windows registry key found in extracted text."))
        obj_count += 1
    for m in mutexes[:50]:
        rows.append(("document", "suggests", f"Mutex:{m}", "Mutex string found in extracted text."))
        obj_count += 1

    if unc and attack:
        src = f"Intrusion-Set:{unc[0].upper()}"
        for t in attack[:25]:
            rows.append((src, "uses", f"Attack-Pattern:{t}", "Co-occurrence: UNC + ATT&CK token (requires analyst validation)."))
            rel_count += 1
    if unc and cves:
        src = f"Intrusion-Set:{unc[0].upper()}"
        for c in cves[:25]:
            rows.append((src, "targets", f"Vulnerability:{c.upper()}", "Co-occurrence: UNC + CVE token (requires analyst validation)."))
            rel_count += 1

    return rows, obj_count, rel_count


# -------------------------
# KB-based named entity scan
# -------------------------

def _kb_scan_rows(
    text: str, kb: Any,
) -> Tuple[List[Tuple[str, str, str, str]], List[Dict[str, Any]]]:
    if kb is None:
        return [], []
    try:
        matches = kb.scan_text(text)
    except Exception:
        return [], []
    rows: List[Tuple[str, str, str, str]] = []
    for m in matches:
        et = m.get("entity_type") or ""
        name = m.get("name") or ""
        mitre_id = m.get("mitre_id")
        snippet = m.get("snippet") or ""
        label = f"{et}:{name}"
        if mitre_id:
            label += f" ({mitre_id})"
        reason = f"KB match: '{m.get('matched_term')}' found in text."
        if snippet:
            reason += f" Context: \"{snippet[:120]}\""
        rows.append(("document", "suggests", f"{et}:{name}", reason))
    return rows, matches


# -------------------------
# Smart parsing with KB reclassification
# -------------------------

_CLUSTER_ID_RE = re.compile(
    r"^(UNC\d{3,5}|APT\d{1,3}|FIN\d{1,4}|TA\d{1,4}|G\d{4}|TEMP\.[A-Z0-9]+)$",
    re.IGNORECASE,
)
_INTRUSIONSET_CUE_RE = re.compile(
    r"\b(tracked as|tracked by|known as|also known as|aka|a\.k\.a\.|referred to as|dubbed|designated as)\b",
    re.IGNORECASE,
)
_THREATACTOR_CUE_RE = re.compile(
    r"\b(attributed to|linked to|associated with|acting on behalf of|sponsored by|directed by)\b",
    re.IGNORECASE,
)
_ORG_KEYWORDS_RE = re.compile(
    r"\b(ministry|department|directorate|intelligence|security service|guard corps|revolutionary guard|army|navy|air force|unit|brigade|bureau|office|agency|command|company|corporation|ltd|llc|inc|gmbh)\b",
    re.IGNORECASE,
)
_STOP_TOKENS = {"the", "a", "an", "and", "or", "of", "to", "in", "for", "with", "by", "from"}


def _clean_candidate(raw: str) -> str:
    s = (raw or "").strip()
    s = s.strip(" \t\r\n\"'\u201c\u201d\u2018\u2019()[]{}.,;:!?\u2013\u2014")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _extract_candidate_after(match_end: int, text: str, max_words: int = 8) -> str:
    tail = text[match_end: match_end + 260]
    tail = tail.split("\n", 1)[0]
    for sep in [".", "\u2014", "\u2013", ":", ";"]:
        if sep in tail:
            tail = tail.split(sep, 1)[0]
    words = tail.strip().split()
    out_words = [w.strip() for w in words[:max_words] if w.strip()]
    return _clean_candidate(" ".join(out_words))


def _evidence_snippet(text: str, start: int, end: int, window: int = 140) -> str:
    a = max(0, start - window)
    b = min(len(text), end + window)
    return re.sub(r"\s+", " ", text[a:b]).strip()[:320]


def _count_occurrences(text: str, phrase: str) -> int:
    if not phrase:
        return 0
    try:
        return len(re.findall(re.escape(phrase), text, flags=re.IGNORECASE))
    except Exception:
        return 0


def _classify_actor(candidate: str, cue_phrase: str) -> Tuple[str, str]:
    c = candidate.strip()
    if _CLUSTER_ID_RE.match(c):
        return "Intrusion-Set", "cluster-id pattern"
    if _INTRUSIONSET_CUE_RE.search(cue_phrase or ""):
        if _ORG_KEYWORDS_RE.search(c) and len(c.split()) >= 2:
            return "Threat-Actor", "org-keywords + vendor-style cue"
        return "Intrusion-Set", "vendor-style naming cue"
    if _THREATACTOR_CUE_RE.search(cue_phrase or ""):
        if _ORG_KEYWORDS_RE.search(c) and len(c.split()) >= 2:
            return "Threat-Actor", "attribution cue + org-like string"
        return "Intrusion-Set", "attribution cue, not org-like"
    return "Intrusion-Set", "default"


def _kb_reclassify(
    name: str,
    smart_parse_type: str,
    kb: Optional[Any],
) -> Tuple[str, str]:
    """
    Look up the candidate name in the KB. If the KB has an authoritative
    entity type that differs from the smart-parse classification, use the
    KB type. This prevents smart-parse from misclassifying known malware/tools
    as Intrusion-Sets when cue phrases fire on their names.

    Returns (authoritative_type, reclassification_note).
    """
    if kb is None:
        return smart_parse_type, ""
    try:
        entries = kb.lookup(name)
    except Exception:
        return smart_parse_type, ""
    if not entries:
        return smart_parse_type, ""

    # If there's exactly one KB match, use it
    if len(entries) == 1:
        kb_type = entries[0].entity_type
        if kb_type != smart_parse_type:
            return kb_type, (
                f"KB reclassified from {smart_parse_type} to {kb_type} "
                f"(KB authoritative: '{entries[0].name}')"
            )
        return smart_parse_type, ""

    # Multiple matches: prefer the most specific non-generic type
    # Priority: Malware > Tool > Intrusion-Set > Threat-Actor > Campaign > others
    priority = {
        "Malware": 0, "Tool": 1, "Intrusion-Set": 2, "Threat-Actor": 3,
        "Campaign": 4, "Attack-Pattern": 5,
    }
    best = min(entries, key=lambda e: priority.get(e.entity_type, 99))
    if best.entity_type != smart_parse_type:
        return best.entity_type, (
            f"KB reclassified from {smart_parse_type} to {best.entity_type} "
            f"({len(entries)} KB matches; using highest-priority type)"
        )
    return smart_parse_type, ""


def _smart_parse_actor_candidates(
    text: str,
    min_conf: float,
    max_candidates: int,
    kb: Optional[Any],
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    cue_patterns = [
        ("CTX.ACTOR.TRACKED_AS",     re.compile(r"\b(tracked as)\b", re.IGNORECASE), 0.90),
        ("CTX.ACTOR.KNOWN_AS",       re.compile(r"\b(known as|also known as)\b", re.IGNORECASE), 0.85),
        ("CTX.ACTOR.AKA",            re.compile(r"\b(aka|a\.k\.a\.)\b", re.IGNORECASE), 0.80),
        ("CTX.ACTOR.REFERRED_TO_AS", re.compile(r"\b(referred to as|dubbed|designated as)\b", re.IGNORECASE), 0.75),
        ("CTX.ACTOR.ATTRIBUTED_TO",  re.compile(r"\b(attributed to|linked to|associated with|acting on behalf of|sponsored by|directed by)\b", re.IGNORECASE), 0.70),
    ]
    for rule_id, rx, base_conf in cue_patterns:
        for m in rx.finditer(text):
            cue = m.group(0)
            cand = _extract_candidate_after(m.end(), text, max_words=8)

            # Pre-extraction filter: reject known-bad patterns before KB lookup
            if not cand or cand.lower() in _STOP_TOKENS or len(cand) < 3:
                continue
            if cand.split()[0].lower() in _STOP_TOKENS:
                continue
            if _is_invalid_candidate(cand):
                continue

            occ = _count_occurrences(text, cand)
            conf = min(0.95, base_conf + (0.05 if occ >= 3 else 0) + (0.05 if occ >= 6 else 0))
            if conf < min_conf:
                continue

            evidence = _evidence_snippet(text, m.start(), m.end())
            etype, rationale = _classify_actor(cand, cue)

            # KB reclassification: authoritative type wins over smart-parse classification
            kb_type, reclass_note = _kb_reclassify(cand, etype, kb)
            if kb_type != etype:
                etype = kb_type
                rationale = reclass_note

            candidates.append({
                "name": cand, "entity_type": etype, "confidence": conf,
                "rule": rule_id, "rationale": rationale,
                "evidence": evidence, "occurrences": occ,
            })
            if len(candidates) >= max_candidates:
                return candidates
    return candidates


def _smart_parse_rows(
    text: str, kb: Optional[Any] = None,
) -> Tuple[List[Tuple[str, str, str, str]], int, List[Dict[str, Any]]]:
    """Returns (rows, count, raw_candidates)."""
    if os.environ.get("QA_DOC_SMART_PARSE", "true").lower() not in ("1", "true", "yes"):
        return [], 0, []
    try:
        min_conf = float(os.environ.get("QA_DOC_SMART_PARSE_MIN_CONFIDENCE", "0.70"))
    except Exception:
        min_conf = 0.70
    try:
        max_cand = int(os.environ.get("QA_DOC_SMART_PARSE_MAX_CANDIDATES", "80"))
    except Exception:
        max_cand = 80

    cands = _smart_parse_actor_candidates(text, min_conf=min_conf, max_candidates=max_cand, kb=kb)
    rows: List[Tuple[str, str, str, str]] = []
    for c in cands:
        reason = (
            f"smart-parse confidence={c['confidence']:.2f}; rule={c['rule']}; "
            f"classification={c['rationale']}; occurrences={c['occurrences']}; "
            f"evidence=\"{c['evidence']}\""
        )
        rows.append(("document", "suggests", f"{c['entity_type']}:{c['name']}", reason))
    return rows, len(rows), cands


# -------------------------
# Main entry point
# -------------------------

def qa_document_suggestions(
    helper: Any,
    report: Dict[str, Any],
    kb: Optional[Any] = None,
) -> Tuple[Dict[str, Any], List[Tuple[str, str, str, str]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Returns:
        (finding_dict, suggestion_rows, kb_matches, smart_parse_candidates)
    """
    file_sets = _select_supported_files(report)
    attempts: List[str] = []

    extracted_text, pdf_meta = _assemble_text(helper, report, file_sets, attempts)

    has_pdf_attachment = bool(file_sets.get("pdf"))
    pdf_downloaded = pdf_meta.get("downloaded", None)

    base_evidence = {
        "supported_types": SUPPORTED_TYPES,
        "attempts": attempts,
        "qa_notes_excluded": True,
        "attachments_present": {k: len(v) for k, v in file_sets.items()},
        "pdf_meta": pdf_meta,
        "kb_available": kb is not None,
        "text_len": len(extracted_text),
    }

    if not extracted_text.strip():
        if has_pdf_attachment and pdf_downloaded is False:
            title = "PDF attachment detected but download failed"
            msg = (
                "A PDF attachment was found but could not be downloaded. "
                "Verify the connector token has file read permissions in OpenCTI "
                "and that the /storage/get/ endpoint is accessible."
            )
        elif has_pdf_attachment and pdf_downloaded is True:
            title = "PDF downloaded but text extraction failed"
            if convert_from_bytes is None or pytesseract is None:
                msg = (
                    "PDF was downloaded but all extraction methods failed. "
                    "OCR libraries (pdf2image/pytesseract) are unavailable. "
                    "The PDF may be image-based and cannot be processed without OCR."
                )
            else:
                msg = (
                    "PDF was downloaded. pdftotext, PyPDF2, and OCR all yielded no text. "
                    "The PDF may be corrupted, encrypted, or contain only unreadable images."
                )
        elif not has_pdf_attachment and not any(attempts):
            title = "No attachments and no report text fields present"
            msg = (
                "This report has no attached files and no text in the description or content fields. "
                "Upload the source document as a PDF attachment or populate the content field "
                "with the full intelligence text."
            )
        else:
            title = "No extractable text recovered from any source"
            msg = (
                f"Attempted sources: {', '.join(attempts) if attempts else 'none'}. "
                "No text could be extracted. Ensure the report has a PDF attachment or "
                "populated description/content fields."
            )
        return (
            {
                "section": "Document Extraction",
                "severity": "INFO",
                "code": "QA.DOC.020",
                "title": title,
                "norm": "Supporting documents SHOULD yield extractable text.",
                "rows": [("document", "extraction_failed", "text", msg)],
                "evidence": base_evidence,
                "metrics": {"doc_suggestions_objects": 0, "doc_suggestions_relationships": 0},
            },
            [], [], [],
        )

    det_rows, det_obj_count, det_rel_count = _suggest_from_text_deterministic(extracted_text)
    kb_rows, kb_matches = _kb_scan_rows(extracted_text, kb)
    # Pass KB to smart-parse for reclassification
    smart_rows, smart_count, smart_candidates = _smart_parse_rows(extracted_text, kb=kb)

    merged_rows = det_rows + kb_rows + smart_rows
    obj_count = det_obj_count + len(kb_rows) + smart_count

    if not merged_rows:
        return (
            {
                "section": "Document Extraction",
                "severity": "INFO",
                "code": "QA.DOC.010",
                "title": "Text recovered; no candidate tokens detected",
                "norm": "Document text MAY be used to propose candidate entities. This connector does not create or modify objects.",
                "rows": [("document", "parsed", "text",
                           "Extraction succeeded, but heuristics found no candidate tokens.")],
                "evidence": base_evidence,
                "metrics": {"doc_suggestions_objects": 0, "doc_suggestions_relationships": 0},
            },
            [], [], [],
        )

    return (
        {
            "section": "Document Extraction",
            "severity": "INFO",
            "code": "QA.DOC.010",
            "title": "Document-derived suggestions (deterministic + KB + contextual)",
            "norm": "Document text MAY be used to propose candidate entities. This connector does not create or modify objects.",
            "rows": merged_rows,
            "evidence": {
                **base_evidence,
                "smart_parse_enabled": os.environ.get("QA_DOC_SMART_PARSE", "true"),
                "kb_entries": kb.entry_count if kb is not None else 0,
                "kb_built_at": kb.built_at.isoformat() if kb is not None and kb.built_at else None,
                "kb_matches": len(kb_matches),
                "det_candidates": det_obj_count,
                "smart_candidates": smart_count,
            },
            "metrics": {
                "doc_suggestions_objects": obj_count,
                "doc_suggestions_relationships": det_rel_count,
            },
        },
        det_rows + smart_rows,
        kb_matches,
        smart_candidates,
    )
