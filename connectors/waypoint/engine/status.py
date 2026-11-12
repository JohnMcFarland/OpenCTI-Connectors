"""Per-source health in /data/status.json.

One entry per source: last poll time and outcome, last Report time,
consecutive failures, next due, and why a source is not running (disabled
or invalid). Written atomically after each scheduler tick; read back at
startup so "last Report" survives restarts (it drives the stale-source
warning). Nothing in Crucible depends on the file yet; the HMI can read it.
"""

import json
import os
import tempfile
from datetime import datetime, timezone


def iso(ts):
    """Epoch seconds -> ISO-8601 UTC, or None."""
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def from_iso(value):
    """ISO-8601 -> epoch seconds, or None."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


class StatusStore:
    """In-memory status, persisted as JSON."""

    def __init__(self, path, log=None):
        self.path = path
        self.log = log
        self.sources = {}
        self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.sources = data.get("sources", {}) if isinstance(data, dict) else {}
        except FileNotFoundError:
            self.sources = {}
        except Exception as exc:  # unreadable status is not fatal
            self.sources = {}
            if self.log:
                self.log.log_warning(f"Ignoring unreadable status file {self.path}: {exc}")

    def entry(self, slug):
        return self.sources.setdefault(slug, {})

    def set_state(self, slug, state, reason=None):
        """Record why a source is or is not running (running/disabled/invalid/failed-start)."""
        e = self.entry(slug)
        e["state"] = state
        if reason:
            e["reason"] = reason
        else:
            e.pop("reason", None)

    def record_poll(self, slug, now, outcome, next_due, created, failed):
        """Update one source after a poll."""
        e = self.entry(slug)
        e["last_poll"] = iso(now)
        e["last_outcome"] = outcome
        e["next_due"] = iso(next_due)
        e["consecutive_failures"] = (e.get("consecutive_failures", 0) + 1) if failed else 0
        if created:
            e["last_report"] = iso(now)

    def last_report(self, slug):
        return from_iso(self.entry(slug).get("last_report"))

    def save(self, now):
        """Write the file atomically (temp file + rename). Failure is a warning."""
        payload = {"updated": iso(now), "sources": self.sources}
        try:
            directory = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".status-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except Exception as exc:
            if self.log:
                self.log.log_warning(f"Could not write status file {self.path}: {exc}")
