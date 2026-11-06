"""Local state, kept in SQLite on the mounted volume.

Holds three things OpenCTI cannot answer for us:

* decay: which Indicators this connector put into decay. valid_until cannot
  mark this, because the platform may set it on every Indicator.
* sent: a fingerprint of what the stream destination last confirmed.
* grouped: which Indicators still need adding to which day's Grouping.

Losing the file is safe. Decay windows restart, the stream re-sends objects
that keep their STIX ids, and Grouping adds are repeated harmlessly.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class DecayEntry:
    deadline: str
    prior_valid_until: Optional[str]
    reason: str


class StateStore:
    def __init__(self, data_dir: str) -> None:
        os.makedirs(data_dir, exist_ok=True)
        # Cycles never overlap, but the scheduler may run them on its own thread.
        self._db = sqlite3.connect(
            os.path.join(data_dir, "state.sqlite3"), check_same_thread=False
        )
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS decay (
                indicator_id TEXT PRIMARY KEY,
                deadline TEXT NOT NULL,
                prior_valid_until TEXT,
                reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sent (
                stix_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS grouped (
                day TEXT NOT NULL,
                indicator_id TEXT NOT NULL,
                added INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (day, indicator_id)
            );
            """
        )
        self._db.commit()

    def get_decay(self, indicator_id: str) -> Optional[DecayEntry]:
        row = self._db.execute(
            "SELECT deadline, prior_valid_until, reason FROM decay "
            "WHERE indicator_id = ?",
            (indicator_id,),
        ).fetchone()
        return DecayEntry(*row) if row else None

    def put_decay(self, indicator_id: str, entry: DecayEntry) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO decay VALUES (?, ?, ?, ?)",
            (indicator_id, entry.deadline, entry.prior_valid_until, entry.reason),
        )
        self._db.commit()

    def clear_decay(self, indicator_id: str) -> None:
        self._db.execute("DELETE FROM decay WHERE indicator_id = ?", (indicator_id,))
        self._db.commit()

    def sent_fingerprints(self) -> Dict[str, str]:
        return dict(self._db.execute("SELECT stix_id, fingerprint FROM sent"))

    def mark_sent(self, items: Iterable[Tuple[str, str]]) -> None:
        self._db.executemany("INSERT OR REPLACE INTO sent VALUES (?, ?)", items)
        self._db.commit()

    def queue_grouping(self, day: str, indicator_ids: Iterable[str]) -> None:
        self._db.executemany(
            "INSERT OR IGNORE INTO grouped (day, indicator_id) VALUES (?, ?)",
            ((day, indicator_id) for indicator_id in indicator_ids),
        )
        self._db.commit()

    def pending_grouping(self) -> List[Tuple[str, str]]:
        return list(
            self._db.execute(
                "SELECT day, indicator_id FROM grouped WHERE added = 0 "
                "ORDER BY day, indicator_id"
            )
        )

    def mark_grouped(self, day: str, indicator_id: str) -> None:
        self._db.execute(
            "UPDATE grouped SET added = 1 WHERE day = ? AND indicator_id = ?",
            (day, indicator_id),
        )
        self._db.commit()

    def prune_grouped(self, today: str) -> None:
        """Forget finished days. Unfinished rows stay until they succeed."""
        self._db.execute("DELETE FROM grouped WHERE added = 1 AND day < ?", (today,))
        self._db.commit()

    def close(self) -> None:
        self._db.close()
