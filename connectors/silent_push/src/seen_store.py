"""
The set of values a stream has already handled, on a persistent volume,
plus the OSINT cursor, which lives in platform connector state.

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


class StateCursor:
    """A single UTC timestamp kept in the connector's platform state.

    SP-STATE-CURSOR-V1: the OSINT cursor lives in OpenCTI connector state
    (helper.get_state/set_state), the repository convention, so it survives a
    rebuilt container and is visible in the platform. Only the seen-value sets
    stay on the volume, because about two million values do not fit in
    connector state.
    """

    def __init__(self, helper, key: str) -> None:
        self.helper = helper
        self.key = key
        self.path = f"connector state: {key}"

    def _state(self) -> dict:
        state = self.helper.get_state()
        return dict(state) if isinstance(state, dict) else {}

    def read(self) -> datetime | None:
        text = self._state().get(self.key)
        if not isinstance(text, str):
            return None
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)

    def write(self, moment: datetime) -> None:
        # Merge, so any other key in the connector state is kept.
        state = self._state()
        state[self.key] = moment.astimezone(timezone.utc).isoformat()
        self.helper.set_state(state)
