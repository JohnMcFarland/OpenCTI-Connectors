"""Crucible report classification.

Shared function that calls the Crucible Collector /classify endpoint
to determine the report type and collection requirements for an
ingested article. Gated behind the CRUCIBLE_COLLECTOR_URL env var;
when absent the caller's default_types pass through unchanged.
"""

import os

import requests


def classify_report(title, description="", content="", source="",
                    source_url="", default_types=None):
    """Call the Crucible Collector /classify endpoint.

    Input:
        title: report title.
        description: report description or summary.
        content: report body text (may duplicate description).
        source: human-readable source name (e.g. "404 Media").
        source_url: canonical URL of the source article.
        default_types: fallback report_types list when classification
            is unavailable or fails. Defaults to ["threat-report"].

    Process:
        If CRUCIBLE_COLLECTOR_URL is set, POST the metadata to
        {CRUCIBLE_COLLECTOR_URL}/classify with a 30-second timeout.
        On success, return the classified report_type wrapped in a
        list. On any failure (network, HTTP error, JSON decode,
        missing key) silently fall back to default_types.

    Output:
        list[str]: single-element list with the classified report_type
        on success, or default_types unchanged on failure/skip.
    """
    if default_types is None:
        default_types = ["threat-report"]

    classify_url = os.environ.get("CRUCIBLE_COLLECTOR_URL")
    if not classify_url:
        return list(default_types)

    try:
        resp = requests.post(
            f"{classify_url}/classify",
            json={
                "title": title,
                "description": description,
                "content": content,
                "source": source,
                "source_url": source_url,
            },
            timeout=30,
        )
        if resp.ok:
            result = resp.json()
            return [result["report_type"]]
    except Exception:
        pass

    return list(default_types)
