"""OpenCTI connector class for ThreatFox."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper

from . import config
from .mitre_lookup import MitreLookup
from .stix_converter import StixConverter
from .threatfox_client import ThreatFoxClient
from .bundler import chunk_bundles, report_description, report_name

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from microservices.classify_report import classify_report

logger = logging.getLogger(__name__)


class ThreatFoxConnector:

    def __init__(self):
        connector_config = {
            "opencti": {
                "url": os.environ.get("OPENCTI_URL", config.OPENCTI_URL),
                "token": os.environ.get("OPENCTI_TOKEN", config.OPENCTI_TOKEN),
            },
            "connector": {
                "id": os.environ.get("CONNECTOR_ID", config.CONNECTOR_ID),
                "type": "EXTERNAL_IMPORT",
                "name": os.environ.get("CONNECTOR_NAME", config.CONNECTOR_NAME),
                "scope": os.environ.get("CONNECTOR_SCOPE", config.CONNECTOR_SCOPE),
                "log_level": os.environ.get("CONNECTOR_LOG_LEVEL", config.CONNECTOR_LOG_LEVEL),
            },
        }
        self.helper = OpenCTIConnectorHelper(connector_config)
        self._interval = int(os.environ.get("CONNECTOR_INTERVAL", config.CONNECTOR_INTERVAL))
        self._default_days = int(os.environ.get("THREATFOX_DAYS", config.THREATFOX_DEFAULT_DAYS))
        self._mitre = MitreLookup()
        self._converter = StixConverter(self._mitre)
        self._client = ThreatFoxClient()

    def run(self) -> None:
        self.helper.log_info("ThreatFox connector starting...")
        while True:
            try:
                now = datetime.now(timezone.utc)
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, f"ThreatFox run @ {now.isoformat()}"
                )
                self._process_data(work_id, now)
                self.helper.api.work.to_processed(
                    work_id, f"ThreatFox connector run completed at {now.isoformat()}"
                )
                self.helper.log_info("Run completed at %s", now.isoformat())
            except Exception as e:
                self.helper.log_error(f"ThreatFox connector error: {str(e)}\n{traceback.format_exc()}")

            if self._interval > 0:
                self.helper.log_info(f"Sleeping {self._interval} minutes until next run...")
                time.sleep(self._interval * 60)
            else:
                break

    def _compute_fetch_days(self, now: datetime) -> int:
        state = self.helper.get_state()
        last_run_str = state.get("last_run") if state else None
        if last_run_str:
            try:
                last_run_dt = datetime.fromisoformat(last_run_str)
                delta_days = (now - last_run_dt).days + 1
                return max(1, min(delta_days, config.THREATFOX_MAX_DAYS))
            except (ValueError, TypeError):
                logger.warning("Invalid last_run state '%s'; using default", last_run_str)
        return self._default_days

    def _process_data(self, work_id: str, now: datetime) -> None:
        fetch_days = self._compute_fetch_days(now)
        self.helper.log_info(f"Fetching ThreatFox IOCs for the last {fetch_days} day(s)...")

        ioc_data = self._client.get_iocs(days=fetch_days)
        if not ioc_data:
            self.helper.log_info("No IOCs returned from ThreatFox")
            self.helper.set_state({"last_run": now.isoformat()})
            return

        self.helper.log_info(f"Processing {len(ioc_data)} ThreatFox IOC entries...")
        stix_objects = self._converter.convert(ioc_data)
        self.helper.log_info(f"Generated {len(stix_objects)} STIX objects")

        # THREATFOX-REPORT-IN-BUNDLE-V1: each chunk carries its own copy of the
        # day's Report with that chunk's refs; no per-object API calls after
        # the send, and no race with the workers.
        date_str = now.strftime("%Y-%m-%d")
        published = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        report_types = classify_report(
            title=report_name(date_str),
            description=report_description(date_str),
            content=report_description(date_str),
            source="ThreatFox", source_url="",
            default_types=["observable-feed"],
        )
        chunks = chunk_bundles(stix_objects, date_str, published, report_types)
        for chunk in chunks:
            bundle = {
                "type": "bundle",
                "id": f"bundle--{str(uuid.uuid4())}",
                "objects": chunk,
            }
            self.helper.send_stix2_bundle(json.dumps(bundle), update=True, work_id=work_id)
        self.helper.log_info(
            f"Sent {len(stix_objects)} objects in {len(chunks)} chunk(s) "
            f"with Report {report_name(date_str)}"
        )

        self.helper.set_state({"last_run": now.isoformat()})

