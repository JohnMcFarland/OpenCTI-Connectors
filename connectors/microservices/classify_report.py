"""Crucible report classification.

Shared function that calls the Crucible Collector /classify endpoint
to determine the report type for an ingested article. Gated behind the
CRUCIBLE_COLLECTOR_URL env var; when absent the caller's default_types
pass through unchanged.

The Collector's response also carries collection_requirements. Those are
deliberately ignored here: OpenCTI Labels are reserved for collection
requirements and are not set from classifier output (user ruling,
2026-11-11).
"""

import os

import requests

# Default request timeout in seconds; override with CRUCIBLE_CLASSIFY_TIMEOUT.
DEFAULT_TIMEOUT = 30


def _timeout():
    """Return the request timeout from CRUCIBLE_CLASSIFY_TIMEOUT (seconds)."""
    raw = os.environ.get("CRUCIBLE_CLASSIFY_TIMEOUT", "")
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT
    return value if value > 0 else DEFAULT_TIMEOUT


def classify_report(title, description="", content="", source="",
                    source_url="", default_types=None, logger=None):
    """Call the Crucible Collector /classify endpoint.

    Input:
        title: report title.
        description: report description or summary.
        content: report body text (may duplicate description).
        source: human-readable source name (e.g. "404 Media").
        source_url: canonical URL of the source article.
        default_types: fallback report_types list when classification
            is unavailable or fails. Defaults to ["threat-report"].
        logger: optional callable taking one message string (for example
            a connector's helper.log_warning). When given, every failed
            classification is logged as a warning naming the source, the
            report title and the error. When omitted, failures stay silent
            (the original behaviour).

    Process:
        If CRUCIBLE_COLLECTOR_URL is set, POST the metadata to
        {CRUCIBLE_COLLECTOR_URL}/classify with a timeout of
        CRUCIBLE_CLASSIFY_TIMEOUT seconds (default 30). On success, return
        the classified report_type wrapped in a list. On any failure
        (network, timeout, HTTP error, JSON decode, missing or empty
        report_type) fall back to default_types.

    Output:
        list[str]: single-element list with the classified report_type
        on success, or default_types unchanged on failure/skip.
    """
    if default_types is None:
        default_types = ["threat-report"]

    # Standalone operation: no Collector configured, no call made.
    classify_url = os.environ.get("CRUCIBLE_COLLECTOR_URL")
    if not classify_url:
        return list(default_types)

    # Ask the Collector; any problem is turned into an error string.
    error = None
    try:
        resp = requests.post(
            f"{classify_url.rstrip('/')}/classify",
            json={
                "title": title,
                "description": description,
                "content": content,
                "source": source,
                "source_url": source_url,
            },
            timeout=_timeout(),
        )
        if resp.ok:
            report_type = resp.json().get("report_type")
            if isinstance(report_type, str) and report_type.strip():
                return [report_type.strip()]
            error = "response has no report_type"
        else:
            error = f"HTTP {resp.status_code}"
    except Exception as exc:  # network, timeout, JSON decode
        error = f"{type(exc).__name__}: {exc}"

    # Fallback path: log (if the caller asked) and return the defaults.
    if logger is not None:
        logger(
            f"[{source or 'unknown connector'}] Crucible classify failed for "
            f"'{title}': {error}; using report_types={list(default_types)}"
        )
    return list(default_types)
