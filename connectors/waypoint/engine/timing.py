"""The clock and sleep used by every engine module.

Kept in one place so tests can patch them once (engine.timing.sleep /
engine.timing.now) instead of hunting for time.sleep in each module.
"""

import time


def now():
    """Seconds since the epoch."""
    return time.time()


def sleep(seconds):
    """Block for `seconds` (no-op for zero or negative values)."""
    if seconds and seconds > 0:
        time.sleep(seconds)
