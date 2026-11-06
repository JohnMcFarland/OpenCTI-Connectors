"""Daily Groupings: "Indicator Export YYYY-MM-DD", dated in US Eastern time.

Indicators are queued in the local store and added here, so a failed add is
retried next cycle and an Indicator already added today is not added again.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Tuple
from zoneinfo import ZoneInfo

# America/New_York rather than a fixed UTC-5, so the day changes at local
# midnight all year, including during daylight saving time.
EASTERN = ZoneInfo("America/New_York")


def grouping_day(moment: datetime) -> str:
    return moment.astimezone(EASTERN).strftime("%Y-%m-%d")


def grouping_name(day: str) -> str:
    return f"Indicator Export {day}"


def flush_groupings(
    client: Any,
    store: Any,
    logger: Any,
    author_id: str,
    marking_id: str,
    today: str,
) -> Tuple[int, int]:
    """Add queued Indicators to their Groupings. Returns (added, errors)."""
    added = 0
    errors = 0
    grouping_ids: Dict[str, str] = {}
    for day, indicator_id in store.pending_grouping():
        try:
            if day not in grouping_ids:
                grouping_ids[day] = client.ensure_grouping(
                    grouping_name(day), author_id, [marking_id]
                )
            client.add_to_grouping(grouping_ids[day], indicator_id)
            store.mark_grouped(day, indicator_id)
            added += 1
        except Exception as exc:  # noqa: BLE001 - retried next cycle
            errors += 1
            logger.error(f"Could not add {indicator_id} to Grouping {day}: {exc}")
    store.prune_grouped(today)
    return added, errors
