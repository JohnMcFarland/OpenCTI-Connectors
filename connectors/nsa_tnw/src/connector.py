import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from pycti import OpenCTIConnectorHelper

from tnw_fetch import fetch_listing, extract_govinfo_pdfs
from opencti_publish import create_report_from_item


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_state(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"known_external_ids": [], "last_run": None, "heartbeat_count": 0}
    except Exception:
        return {"known_external_ids": [], "last_run": None, "heartbeat_count": 0}


def _write_state(path: str, state: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _log(msg: str, level: str = "INFO") -> None:
    print(f"[{_utc_now_iso()}] [{level}] {msg}", flush=True)


def run_once() -> None:
    _log("NSA Published Reports (Step 4) starting")

    opencti_url = os.getenv("OPENCTI_URL", "").strip()
    opencti_token = os.getenv("OPENCTI_TOKEN", "").strip()
    connector_id = os.getenv("CONNECTOR_ID", "").strip()
    interval_min = int(os.getenv("CONNECTOR_RUN_INTERVAL", "60"))

    state_path = os.getenv("NSA_STATE_PATH", "/opt/connector/state/state.json")
    listing_url = os.getenv("TNW_LISTING_URL", "").strip()

    timeout_s = int(os.getenv("TNW_PDF_TIMEOUT", "30"))
    user_agent = os.getenv("TNW_USER_AGENT", "Mozilla/5.0 (compatible; OpenCTI-NSA-TNW/1.0)")
    min_between = int(os.getenv("TNW_MIN_SECONDS_BETWEEN_REQUESTS", "10"))
    jitter = int(os.getenv("TNW_JITTER_SECONDS", "5"))

    max_ingest = int(os.getenv("TNW_MAX_INGEST_PER_CYCLE", "30"))

    _log(f"CONNECTOR_ID={connector_id}")
    _log(f"CONNECTOR_RUN_INTERVAL(min)={interval_min}")
    _log(f"NSA_STATE_PATH={state_path}")
    _log(f"TNW_LISTING_URL={listing_url}")
    _log(f"OPENCTI_URL set? {'yes' if opencti_url else 'no'}")
    _log(f"OPENCTI_TOKEN present? {'yes' if opencti_token else 'no'}")

    state = _read_state(state_path)
    known = set(state.get("known_external_ids", []))

    helper = OpenCTIConnectorHelper({
        "opencti": {"url": opencti_url, "token": opencti_token},
        "connector": {"id": connector_id, "type": "EXTERNAL_IMPORT", "name": "NSA Published Reports", "scope": ["report"]},
    })

    html = fetch_listing(
        listing_url=listing_url,
        timeout_s=timeout_s,
        user_agent=user_agent,
        min_seconds_between_requests=min_between,
        jitter_seconds=jitter,
    )
    items = extract_govinfo_pdfs(html)

    new_items: List[Dict[str, str]] = []
    for it in items:
        ext = it.get("external_id") or it.get("pdf_url")
        if not ext:
            continue
        if ext in known:
            continue
        new_items.append(it)

    new_items = new_items[:max_ingest]

    _log(f"TNW discovered={len(items)} new={len(new_items)} (Step 4: create reports)")

    now_iso = _utc_now_iso()
    for it in new_items:
        ext = it.get("external_id") or it.get("pdf_url")
        pdf = it.get("pdf_url")
        _log(f"Creating Report external_id={ext} pdf={pdf}")
        report_id = create_report_from_item(helper, it, now_iso=now_iso)
        _log(f"Created Report id={report_id}")

        known.add(ext)

    state["known_external_ids"] = sorted(list(known))
    state["last_run"] = now_iso
    state["heartbeat_count"] = int(state.get("heartbeat_count", 0)) + 1
    _write_state(state_path, state)

    _log(f"Cycle complete. Sleeping {interval_min} minute(s)...")


def main() -> None:
    while True:
        try:
            run_once()
        except Exception as e:
            _log(f"Unhandled error: {e}", level="ERROR")
            interval_min = int(os.getenv("CONNECTOR_RUN_INTERVAL", "60"))
            _log(f"Sleeping {interval_min} minute(s)...")
        time.sleep(int(os.getenv("CONNECTOR_RUN_INTERVAL", "60")) * 60)


if __name__ == "__main__":
    main()
