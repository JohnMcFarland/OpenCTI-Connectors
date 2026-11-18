"""Shared freshness gate: forward-only ingestion for crawling connectors.

CRUCIBLE-FRESHNESS-V1. is_fresh(published) -> (ok, reason).
Max age from CONNECTOR_MAX_AGE_DAYS (default 7). Missing or unparseable dates
are rejected ("undated"); connectors must not stamp them with ingestion time.
"""
import os
from datetime import datetime, timedelta, timezone

DEFAULT_MAX_AGE_DAYS = 7


def _max_age_days():
    # Env override; a bad value falls back to the default, never disables the gate.
    try:
        v = int(os.environ.get("CONNECTOR_MAX_AGE_DAYS", DEFAULT_MAX_AGE_DAYS))
        return v if v > 0 else DEFAULT_MAX_AGE_DAYS
    except ValueError:
        return DEFAULT_MAX_AGE_DAYS


def is_fresh(published, now=None):
    """Return (True, "fresh") if published is within the max age, else (False, reason)."""
    # Accept datetime or ISO 8601 string; naive values are treated as UTC.
    dt = published if isinstance(published, datetime) else None
    if dt is None and isinstance(published, str) and published.strip():
        try:
            dt = datetime.fromisoformat(published.strip().replace("Z", "+00:00"))
        except ValueError:
            dt = None
    if dt is None:
        return False, "undated"
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    limit = timedelta(days=_max_age_days())
    if (now or datetime.now(timezone.utc)) - dt > limit:
        return False, "stale (published %s, older than %d days)" % (dt.date().isoformat(), limit.days)
    return True, "fresh"
