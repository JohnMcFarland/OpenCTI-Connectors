"""
The set of values a stream has already handled, on a persistent volume.

One file per stream: seen_iofa.txt and seen_osint.txt. Neither source has a
usable date cursor (the IOFA exports carry no dates, and Feed Scan ignores
absolute date filters), so "new" can only mean "not handled before". Two million
values is far too large for connector state, hence a plain file.

It only ever grows. A value that leaves the export and returns is not new, and
does not cost another enrichment call. Values are appended after they are sent,
so anything unfinished is simply new again on the next run.
"""

import os
from datetime import datetime, timezone


class SeenStore:
    def __init__(self, state_dir: str, file_name: str = "seen_iofa.txt") -> None:
        self.path = os.path.join(state_dir, file_name)

    def exists(self) -> bool:
        return os.path.isfile(self.path)

    def load(self) -> set[str]:
        with open(self.path, encoding="utf-8") as handle:
            return {line.strip() for line in handle if line.strip()}

    def write_baseline(self, values: list[str]) -> None:
        """Replace atomically, so a crash cannot leave a half baseline."""
        temporary = f"{self.path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write("\n".join(values) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    def append(self, values: list[str]) -> None:
        if not values:
            return
        with open(self.path, "a", encoding="utf-8") as handle:
            # The leading newline isolates any partial line from a past crash.
            handle.write("\n" + "\n".join(values) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


class Cursor:
    """A single UTC timestamp on the state volume, replaced atomically."""

    def __init__(self, state_dir: str, file_name: str) -> None:
        self.path = os.path.join(state_dir, file_name)

    def read(self) -> datetime | None:
        try:
            with open(self.path, encoding="utf-8") as handle:
                text = handle.read().strip()
        except FileNotFoundError:
            return None
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)

    def write(self, moment: datetime) -> None:
        temporary = f"{self.path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(moment.astimezone(timezone.utc).isoformat())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)
