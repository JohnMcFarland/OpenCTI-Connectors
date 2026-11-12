"""Engine-wide settings.

Two kinds, both from environment variables (never from sources.yml):

- Constants that were identical in all 78 generated connectors (PDF size
  cap, transient attempts, page probes, description length, browser UA).
  They are module constants, read once at import, so pure helpers can use
  them as defaults exactly as the generated code did.
- The global load controls (AGG_*), held in EngineSettings and passed to
  the scheduler and workers.
"""

import os
from dataclasses import dataclass, fields


def _env_int(name, default, env=None):
    """Integer from the environment; blank or unset gives the default."""
    raw = (env if env is not None else os.environ).get(name, "")
    return int(raw) if str(raw).strip() else default


def _env_bool(name, default, env=None):
    raw = str((env if env is not None else os.environ).get(name, "")).strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------- #
# Constants shared by every source (the generated connectors' values)
# --------------------------------------------------------------------------- #

MAX_PDF_BYTES = _env_int("AGG_MAX_PDF_BYTES", 25 * 1024 * 1024)
MAX_TRANSIENT_ATTEMPTS = _env_int("AGG_MAX_TRANSIENT_ATTEMPTS", 5)
MAX_PAGE_PROBES = _env_int("AGG_MAX_PAGE_PROBES", 50)
MAX_DESCRIPTION_CHARS = _env_int("AGG_MAX_DESCRIPTION_CHARS", 2000)
# Feed dates earlier than this are treated as unusable.
MIN_VALID_YEAR = 1990
BROWSER_UA = os.environ.get("AGG_BROWSER_UA") or (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)


# --------------------------------------------------------------------------- #
# Global load controls and runtime switches
# --------------------------------------------------------------------------- #

@dataclass
class EngineSettings:
    """Scheduler budgets and engine switches. Defaults per docs/WAYPOINT_SCOPE.md."""

    # Sources polled at the same time (discovery only; graph calls stay on
    # the main thread).
    source_workers: int = 4
    # Renders in flight to pdf-renderer at once, across all sources.
    render_concurrency: int = 2
    # Reports written per cycle window, across all sources (0 = no cap).
    reports_per_cycle: int = 120
    # New Reports one source may write in one poll (0 = no cap).
    max_reports_per_source_poll: int = 10
    # Collector /classify calls in flight (only when CRUCIBLE_COLLECTOR_URL is set).
    classify_concurrency: int = 2
    # Length of the budget window ("cycle") and the scheduler's idle tick.
    cycle_seconds: int = 1800
    tick_seconds: int = 60
    # After a pdf-renderer outage, rendering pauses for this long (all sources).
    renderer_pause_seconds: int = 300
    # Failing-source backoff cap (doubling from poll_interval).
    backoff_cap_seconds: int = 6 * 3600
    # Stale-source warning threshold when a profile sets none.
    stale_after_days: int = 7
    # Discover, filter and dedup, log what would be created, write nothing.
    dry_run: bool = False
    # pdf-renderer call policy (same in all 78 generated connectors).
    render_retries: int = 3
    render_timeout: int = 120
    # Per-item and per-poll limits (module constants above, overridable per run).
    max_transient_attempts: int = MAX_TRANSIENT_ATTEMPTS
    max_page_probes: int = MAX_PAGE_PROBES
    max_pdf_bytes: int = MAX_PDF_BYTES
    # Files.
    sources_file: str = "/app/sources.yml"
    status_file: str = "/data/status.json"

    # Environment variable for each field.
    ENV = {
        "source_workers": "AGG_SOURCE_WORKERS",
        "render_concurrency": "AGG_RENDER_CONCURRENCY",
        "reports_per_cycle": "AGG_REPORTS_PER_CYCLE",
        "max_reports_per_source_poll": "AGG_MAX_REPORTS_PER_SOURCE_POLL",
        "classify_concurrency": "AGG_CLASSIFY_CONCURRENCY",
        "cycle_seconds": "AGG_CYCLE_SECONDS",
        "tick_seconds": "AGG_TICK_SECONDS",
        "renderer_pause_seconds": "AGG_RENDERER_PAUSE_SECONDS",
        "backoff_cap_seconds": "AGG_BACKOFF_CAP_SECONDS",
        "stale_after_days": "AGG_STALE_AFTER_DAYS",
        "dry_run": "AGG_DRY_RUN",
        "render_retries": "AGG_RENDER_RETRIES",
        "render_timeout": "AGG_RENDER_TIMEOUT",
        "max_transient_attempts": "AGG_MAX_TRANSIENT_ATTEMPTS",
        "max_page_probes": "AGG_MAX_PAGE_PROBES",
        "max_pdf_bytes": "AGG_MAX_PDF_BYTES",
        "sources_file": "AGG_SOURCES_FILE",
        "status_file": "AGG_STATUS_FILE",
    }

    @classmethod
    def from_env(cls, env=None):
        """Settings from the environment; anything unset keeps its default."""
        env = env if env is not None else os.environ
        values = {}
        for f in fields(cls):
            name = cls.ENV[f.name]
            if f.type is bool or isinstance(f.default, bool):
                values[f.name] = _env_bool(name, f.default, env)
            elif isinstance(f.default, int):
                values[f.name] = _env_int(name, f.default, env)
            else:
                values[f.name] = env.get(name) or f.default
        settings = cls(**values)
        settings.validate()
        return settings

    def validate(self):
        """Refuse settings that would stall or flood the engine."""
        for name in ("source_workers", "render_concurrency", "classify_concurrency",
                     "cycle_seconds", "tick_seconds", "render_retries"):
            if getattr(self, name) < 1:
                raise ValueError(f"{self.ENV[name]} must be at least 1")
        for name in ("reports_per_cycle", "max_reports_per_source_poll",
                     "renderer_pause_seconds", "backoff_cap_seconds"):
            if getattr(self, name) < 0:
                raise ValueError(f"{self.ENV[name]} must not be negative")
