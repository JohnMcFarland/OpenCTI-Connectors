"""OpenCTI connector class for ThreatFox."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper

from . import config
from .mitre_lookup import MitreLookup
from .stix_converter import StixConverter, CTHREATFOX_IDENTITY
from .threatfox_client import ThreatFoxClient
from .uuid_generator import report_id

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
                self.helper.log_error(f"ThreatFox connector error: {str(e)}")

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

        # Push all content objects via bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{self.helper.connect_id}",
            "objects": stix_objects,
        }
        self.helper.log_info("Sending STIX bundle to OpenCTI...")
        self.helper.send_stix2_bundle(json.dumps(bundle), update=True, work_id=work_id)
        self.helper.log_info("STIX bundle sent successfully")

        # Create Report container via direct API call
        date_str = now.strftime("%Y-%m-%d")
        self.helper.log_info(f"Creating report container: Threat Fox Feed {date_str}")
        self._create_report(date_str, now, stix_objects)

        self.helper.set_state({"last_run": now.isoformat()})

    def _create_report(
        self, date_str: str, now: datetime, stix_objects: list[dict]
    ) -> None:
        ts = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        name = f"Threat Fox Feed {date_str}"

        content_ids = [
            obj["id"] for obj in stix_objects
            if obj.get("type") not in ("marking-definition",)
            and obj.get("id") != config.CTHREATFOX_IDENTITY_ID
        ]

        # Resolve the internal OpenCTI ID for the [C]ThreatFox identity.
        # pycti report.create() createdBy requires the internal UUID, not the STIX ID.
        created_by_internal_id = None
        try:
            identity = self.helper.api.identity.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "standard_id", "values": [config.CTHREATFOX_IDENTITY_ID]}],
                    "filterGroups": [],
                }
            )
            if identity:
                created_by_internal_id = identity["id"]
        except Exception as e:
            logger.warning("Could not resolve [C]ThreatFox identity ID: %s", e)

        # Resolve the internal OpenCTI ID for TLP:CLEAR marking definition.
        marking_internal_id = None
        try:
            markings = self.helper.api.marking_definition.read_all()
            for m in (markings or []):
                if m.get("standard_id") == config.TLP_CLEAR_ID:
                    marking_internal_id = m["id"]
                    break
        except Exception as e:
            logger.warning("Could not resolve TLP:CLEAR marking ID: %s", e)

        try:
            create_kwargs = {
                "name": name,
                "description": (
                    f"Automated ThreatFox IOC ingestion for {date_str}. "
                    "Contains observables, malware family references, and reporter identities "
                    "sourced from the ThreatFox abuse.ch feed."
                ),
                "published": ts,
                "report_types": ["threat-report"],
                "stix_id": report_id(date_str),
                "update": True,
            }
            if created_by_internal_id:
                create_kwargs["createdBy"] = created_by_internal_id
            if marking_internal_id:
                create_kwargs["objectMarking"] = [marking_internal_id]

            report = self.helper.api.report.create(**create_kwargs)

            if report and report.get("id"):
                self.helper.log_info(
                    f"Report created/updated: {report['id']} — adding {len(content_ids)} object refs"
                )
                for stix_id in content_ids:
                    try:
                        self.helper.api.report.add_stix_object_or_stix_relationship(
                            id=report["id"],
                            stixObjectOrStixRelationshipId=stix_id,
                        )
                    except Exception as e:
                        logger.debug("Could not add %s to report: %s", stix_id, e)
            else:
                self.helper.log_error("Report creation returned no ID")

        except Exception as e:
            self.helper.log_error(f"Failed to create report container: {str(e)}")
