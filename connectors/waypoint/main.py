"""
Waypoint OpenCTI connector (WAYPOINT-V1).

Purpose
-------
One EXTERNAL_IMPORT connector for every article source in sources.yml. Each
publisher is a profile (data); the engine (engine/) is shared. It replaces
the 78 per-publisher connectors generated from the shared feed template,
writing exactly what they wrote: one container-only Report per article, the
publisher Organization as author, TLP:CLEAR on the Report and its file, one
External Reference, and one PDF of the live article from pdf-renderer.

See docs/WAYPOINT_SCOPE.md for the scope, schema, budgets and migration plan,
and README.md for operating it (adding or disabling a source, budgets, the
status file).

Configuration
-------------
- config.yml / environment: OpenCTI connection and connector identity
  (OPENCTI_URL, OPENCTI_TOKEN, CONNECTOR_ID, ...). Real values come only from
  docker-compose.override.yml, never from the repo.
- sources.yml (AGG_SOURCES_FILE, mounted read-only): the source profiles.
  An invalid entry disables that source only.
- AGG_* environment variables: global budgets and engine settings
  (engine/settings.py).

Targets pycti==6.9.13 and the classic OpenCTIConnectorHelper stack.
"""

import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper

# Deployment proof: grep the running image for this marker.
WAYPOINT_MARKER = "WAYPOINT-V1"

# The engine package sits next to this file; importing it also puts the
# shared microservices/ package (mounted at /microservices) on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine import report  # noqa: E402
from engine.profile import load_sources  # noqa: E402
from engine.scheduler import Scheduler  # noqa: E402
from engine.settings import EngineSettings  # noqa: E402
from engine.status import StatusStore  # noqa: E402
from engine.worker import SourceLog, SourceWorker  # noqa: E402


def load_config():
    """config.yml next to this file (structure-only defaults; env wins)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def build(helper, settings):
    """Load sources.yml and build one worker per enabled, valid source.

    Invalid entries are logged with the failing field and skipped; every
    other source still starts. Disabled entries are recorded in the status
    file only.
    """
    status = StatusStore(settings.status_file, helper)
    profiles, errors = load_sources(settings.sources_file)
    for slug, err in sorted(errors.items()):
        helper.log_error(f"Source '{slug}' not started: invalid sources.yml entry ({err}).")
        status.set_state(slug, "invalid", err)
    workers = {}
    for slug, profile in sorted(profiles.items()):
        if not profile.enabled:
            status.set_state(slug, "disabled")
            continue
        workers[slug] = SourceWorker(profile, settings, helper.api, SourceLog(helper, slug))
    return workers, status


def main():
    """Configure, resolve graph references per source, then run forever."""
    helper = OpenCTIConnectorHelper(load_config())
    settings = EngineSettings.from_env()
    workers, status = build(helper, settings)

    collector = os.environ.get("CRUCIBLE_COLLECTOR_URL")
    if report.classify_report is None or not collector:
        helper.log_info("Report types: standalone mode (each profile's report_type).")
    else:
        helper.log_info(f"Report types from the Crucible Collector at {collector}/classify.")

    scheduler = Scheduler(workers, settings, helper, status, connect_id=helper.connect_id)
    scheduler.start(helper.api)
    helper.log_info(
        f"{WAYPOINT_MARKER} started: {len(scheduler.workers)} sources running "
        f"({', '.join(sorted(scheduler.workers)) or 'none'}); "
        f"render concurrency {settings.render_concurrency}, "
        f"{settings.reports_per_cycle or 'unlimited'} Reports per {settings.cycle_seconds}s cycle, "
        f"{settings.max_reports_per_source_poll or 'unlimited'} per source poll"
        + ("; DRY RUN: nothing is written" if settings.dry_run else "."))
    scheduler.run_forever()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
