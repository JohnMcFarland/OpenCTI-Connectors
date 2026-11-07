"""Connector state, kept on the OpenCTI platform (helper.get_state/set_state).

Same convention as the rest of the repository: no local state file. The state
is one JSON document on the connector record, so it survives a rebuilt or
moved container and is visible in the platform's connector view.

Holds three things the graph cannot answer for us:

* decay: which Indicators this connector put into decay. valid_until cannot
  mark this, because the platform may set it on every Indicator.
* sent: a short fingerprint of what the stream destination last confirmed.
* grouped: which Indicators still need adding to which day's Grouping.

Writes are buffered in memory and pushed with save(), once per cycle, because
serialising the whole document on every change would be quadratic. pycti then
syncs it to the platform on its next ping. Losing unsaved changes is safe:
decay windows restart, the stream re-sends objects that keep their STIX ids,
and Grouping adds are repeated harmlessly.

Layout of the document:

    {"last_run": "<iso>",
     "decay":   {"<indicator id>": {"deadline", "prior_valid_until", "reason"}},
     "sent":    {"<stix id>": "<fingerprint>"},
     "grouped": {"<day>": {"<indicator id>": <0 pending | 1 added>}}}
"""

from __future__ import annotations

import copy
import threading
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

_SECTIONS = ("decay", "sent", "grouped")


@dataclass(frozen=True)
class DecayEntry:
    deadline: str
    prior_valid_until: Optional[str]
    reason: str


class StateStore:
    def __init__(self, helper: Any) -> None:
        self._helper = helper
        # Cycles never overlap, but the scheduler may run them on its own thread.
        self._lock = threading.Lock()
        loaded = helper.get_state() or {}
        self._state: Dict[str, Any] = copy.deepcopy(loaded) if isinstance(loaded, dict) else {}
        for section in _SECTIONS:
            if not isinstance(self._state.get(section), dict):
                self._state[section] = {}

    # -- persistence -------------------------------------------------------

    def save(self, **extra: Any) -> None:
        """Push the whole document to the platform. extra sets top-level keys
        such as last_run."""
        with self._lock:
            self._state.update(extra)
            self._helper.set_state(copy.deepcopy(self._state))

    # -- decay -------------------------------------------------------------

    def get_decay(self, indicator_id: str) -> Optional[DecayEntry]:
        entry = self._state["decay"].get(indicator_id)
        if not isinstance(entry, dict):
            return None
        try:
            return DecayEntry(
                entry["deadline"], entry.get("prior_valid_until"), entry["reason"]
            )
        except KeyError:
            return None

    def put_decay(self, indicator_id: str, entry: DecayEntry) -> None:
        with self._lock:
            self._state["decay"][indicator_id] = asdict(entry)

    def clear_decay(self, indicator_id: str) -> None:
        with self._lock:
            self._state["decay"].pop(indicator_id, None)

    # -- stream confirmations ----------------------------------------------

    def sent_fingerprints(self) -> Dict[str, str]:
        return dict(self._state["sent"])

    def mark_sent(self, items: Iterable[Tuple[str, str]]) -> None:
        with self._lock:
            self._state["sent"].update(items)

    # -- daily Grouping queue ----------------------------------------------

    def queue_grouping(self, day: str, indicator_ids: Iterable[str]) -> None:
        with self._lock:
            pending = self._state["grouped"].setdefault(day, {})
            for indicator_id in indicator_ids:
                pending.setdefault(indicator_id, 0)

    def pending_grouping(self) -> List[Tuple[str, str]]:
        return sorted(
            (day, indicator_id)
            for day, members in self._state["grouped"].items()
            for indicator_id, added in members.items()
            if not added
        )

    def mark_grouped(self, day: str, indicator_id: str) -> None:
        with self._lock:
            members = self._state["grouped"].get(day)
            if members is not None and indicator_id in members:
                members[indicator_id] = 1

    def prune_grouped(self, today: str) -> None:
        """Forget finished days. Unfinished rows stay until they succeed."""
        with self._lock:
            grouped = self._state["grouped"]
            for day in list(grouped):
                if day >= today:
                    continue
                members = grouped[day]
                for indicator_id in [k for k, added in members.items() if added]:
                    del members[indicator_id]
                if not members:
                    del grouped[day]
