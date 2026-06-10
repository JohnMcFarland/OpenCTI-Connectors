"""
connector.py
Core connector class for the IC Reports OpenCTI connector.

Architecture:
- Registers with OpenCTI via pycti's OpenCTIConnectorHelper
- Runs a blocking cycle loop with configurable sleep interval
- Delegates source discovery and enrichment to plugin instances
- Delegates all OpenCTI API calls to ReportBuilder
- No local dedup state — deduplication is handled by ReportBuilder via
  External Reference URL lookups against the live graph

Logging uses pycti's AppLogger (self.log) which has the signature:
    self.log.info("message", {"key": value})   # NOT printf-style %s args
    self.log.error("message", {"key": value})  # NO exc_info= kwarg
Standard Python logging (_pylog) is used for internal/startup messages only.
"""

from __future__ import annotations

import logging
import os
import sys
import time
import traceback
from datetime import datetime, timezone

import yaml
from pycti import OpenCTIConnectorHelper

from plugins import load_plugins
from report_builder import ReportBuilder

# Standard Python logger for pre-helper startup messages
_pylog = logging.getLogger(__name__)


class ICReportsConnector:

    def __init__(self):
        # --- Load config from mounted file ---------------------------------
        config_path = "/opt/opencti-connector/config.yml"
        try:
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            print(f"FATAL: Config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)

        # --- Ensure required config sections exist -------------------------
        if not self.config.get("opencti"):
            self.config["opencti"] = {}
        if not self.config.get("connector"):
            self.config["connector"] = {}

        # --- Inject environment variables into config for pycti ------------
        # pycti reads these from the config dict, not from os.environ directly
        self.config["opencti"]["url"] = os.environ.get(
            "OPENCTI_URL", self.config["opencti"].get("url", "http://opencti:8080")
        )
        self.config["opencti"]["token"] = os.environ.get(
            "OPENCTI_TOKEN", self.config["opencti"].get("token", "")
        )
        self.config["connector"]["id"] = os.environ.get(
            "CONNECTOR_ID", self.config["connector"].get("id", "")
        )
        self.config["connector"]["type"] = os.environ.get(
            "CONNECTOR_TYPE", self.config["connector"].get("type", "EXTERNAL_IMPORT")
        )
        self.config["connector"]["name"] = os.environ.get(
            "CONNECTOR_NAME", self.config["connector"].get("name", "IC Reports")
        )
        self.config["connector"]["scope"] = os.environ.get(
            "CONNECTOR_SCOPE", self.config["connector"].get("scope", "application/pdf")
        )
        self.config["connector"]["log_level"] = os.environ.get(
            "CONNECTOR_LOG_LEVEL", self.config["connector"].get("log_level", "info")
        )
        self.config["connector"]["duration_period"] = os.environ.get(
            "CONNECTOR_DURATION_PERIOD",
            self.config["connector"].get("duration_period", "P1D")
        )

        # --- Initialise pycti helper — registers connector with OpenCTI ----
        self.helper = OpenCTIConnectorHelper(self.config)

        # Use pycti's AppLogger for all runtime logging
        self.log = self.helper.connector_logger

        # --- Run interval in seconds (default 24h) -------------------------
        self.interval = int(
            os.environ.get(
                "CONNECTOR_RUN_INTERVAL",
                self.config.get("connector", {}).get("run_interval", 86400),
            )
        )

        # --- ReportBuilder wraps all OpenCTI API write operations ----------
        self.builder = ReportBuilder(
            opencti_api=self.helper.api,
            helper=self.helper,
        )

    def run(self) -> None:
        """
        Main entry point. Runs one ingestion cycle then sleeps, in a loop.
        Exceptions inside a cycle are caught and logged — the connector
        continues to the next cycle rather than crashing.
        """
        self.log.info(
            "IC Reports connector starting.",
            {"run_interval_seconds": self.interval},
        )

        while True:
            try:
                self._run_cycle()
            except KeyboardInterrupt:
                self.log.info("Connector interrupted, exiting.")
                sys.exit(0)
            except Exception as e:
                # Log the full traceback as a structured attribute so it's
                # captured by OpenCTI's logging infrastructure
                self.log.error(
                    "Unhandled exception in run cycle.",
                    {"error": str(e), "traceback": traceback.format_exc()},
                )

            self.log.info(
                "Cycle complete. Sleeping until next run.",
                {"sleep_seconds": self.interval},
            )
            time.sleep(self.interval)

    def _run_cycle(self) -> None:
        """
        Execute one full ingestion cycle across all enabled plugins.
        Each plugin runs independently — an error in one does not affect others.
        """
        run_start = datetime.now(timezone.utc)
        self.log.info("Starting ingestion cycle.", {"started_at": run_start.isoformat()})

        # Load enabled plugins — no state passed, dedup is graph-driven
        plugins = load_plugins(
            config=self.config,
            log=logging.getLogger("ic_reports.plugins"),
        )

        if not plugins:
            self.log.warning("No plugins loaded — check config.yml plugin settings.")
            return

        total_ingested = 0
        total_skipped = 0
        total_errors = 0

        for plugin in plugins:
            p_ingested, p_skipped, p_errors = self._run_plugin(plugin)
            total_ingested += p_ingested
            total_skipped += p_skipped
            total_errors += p_errors

        duration = (datetime.now(timezone.utc) - run_start).total_seconds()
        self.log.info(
            "Ingestion cycle complete.",
            {
                "duration_seconds": round(duration, 1),
                "ingested": total_ingested,
                "skipped": total_skipped,
                "errors": total_errors,
            },
        )

    def _run_plugin(self, plugin) -> tuple[int, int, int]:
        """
        Run a single plugin's full discovery → enrich → ingest pipeline.
        Errors in fetch or individual report processing are isolated so one
        bad report doesn't abort the rest of the plugin's run.

        Returns:
            Tuple of (ingested_count, skipped_count, error_count)
        """
        self.log.info("Running plugin.", {"plugin": plugin.name})
        ingested = 0
        skipped = 0
        errors = 0

        # --- Discovery phase -----------------------------------------------
        # Plugin returns all reports it finds — dedup happens in ingest()
        try:
            raw_reports = plugin.fetch_new_reports()
        except Exception as e:
            self.log.error(
                "Plugin fetch_new_reports() failed.",
                {"plugin": plugin.name, "error": str(e), "traceback": traceback.format_exc()},
            )
            return 0, 0, 1

        self.log.info(
            "Plugin discovered reports.",
            {"plugin": plugin.name, "count": len(raw_reports)},
        )

        # --- Enrich and ingest phase ---------------------------------------
        for raw in raw_reports:
            try:
                # Enrich: fetch full content, resolve dates, download PDF
                enriched = plugin.enrich_report(raw)
                if enriched is None:
                    # Plugin explicitly rejected this report (e.g. 404, bad content)
                    self.log.info(
                        "Report skipped by plugin.",
                        {"plugin": plugin.name, "url": raw.url},
                    )
                    skipped += 1
                    continue

                # Ingest: create Report container in OpenCTI (dedup check inside)
                report_id = self.builder.ingest(enriched, plugin)
                if report_id:
                    ingested += 1
                    self.log.info(
                        "Report ingested.",
                        {"plugin": plugin.name, "report_id": report_id, "title": raw.title},
                    )
                else:
                    # ingest() returned None — report already exists (dedup hit)
                    skipped += 1

            except Exception as e:
                self.log.error(
                    "Error processing report.",
                    {
                        "plugin": plugin.name,
                        "title": raw.title,
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                    },
                )
                errors += 1

        return ingested, skipped, errors
