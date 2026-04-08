"""
CrowdStrike Intel Reports connector for OpenCTI.

CONNECTOR TYPE:  EXTERNAL_IMPORT (scheduled polling)
TRIGGER:         Time interval (CROWDSTRIKE_INTERVAL_HOURS)
SOURCE:          CrowdStrike Falcon Intel Reports API
OUTPUT:          OpenCTI Report containers with PDF attachments
"""

import base64
import datetime
import time

import stix2
import yaml
import os

from pycti import (
    OpenCTIConnectorHelper,
    Report,
    get_config_variable,
)

from .client import FalconIntelClient


DEFAULT_REPORT_TYPE_MAP = {
    "alert":                          "threat-report",
    "adversary intelligence report":  "threat-report",
    "intelligence summary":           "threat-report",
    "monthly report":                 "threat-report",
    "weekly report":                  "threat-report",
    "threat intelligence report":     "threat-report",
    "vulnerability report":           "vulnerability-advisory",
    "malware analysis":               "malware-analysis",
    "malware report":                 "malware-analysis",
    "indicator report":               "threat-report",
    "technical analysis":             "malware-analysis",
    "hunting report":                 "threat-report",
}

FALLBACK_REPORT_TYPE = "threat-report"


class CrowdStrikeIntelReportsConnector:

    def __init__(self):
        # ------------------------------------------------------------------ #
        # Config                                                              #
        # ------------------------------------------------------------------ #
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "config.yml"
        )
        config = (
            yaml.safe_load(open(config_file_path, encoding="utf-8"))
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.cs_client_id = get_config_variable(
            "CROWDSTRIKE_CLIENT_ID", ["crowdstrike", "client_id"], config,
        )
        self.cs_client_secret = get_config_variable(
            "CROWDSTRIKE_CLIENT_SECRET", ["crowdstrike", "client_secret"], config,
        )
        self.cs_base_url = get_config_variable(
            "CROWDSTRIKE_BASE_URL", ["crowdstrike", "base_url"], config,
            False, "https://api.crowdstrike.com",
        )
        self.lookback_days = int(get_config_variable(
            "CROWDSTRIKE_LOOKBACK_DAYS", ["crowdstrike", "lookback_days"],
            config, False, 7,
        ))
        self.interval_hours = int(get_config_variable(
            "CROWDSTRIKE_INTERVAL_HOURS", ["crowdstrike", "interval_hours"],
            config, False, 24,
        ))
        report_types_raw = get_config_variable(
            "CROWDSTRIKE_REPORT_TYPES", ["crowdstrike", "report_types"],
            config, False, "",
        )
        self.cs_report_type_filter = (
            {t.strip().lower() for t in report_types_raw.split(",") if t.strip()}
            if report_types_raw else set()
        )
        self.api_timeout = int(get_config_variable(
            "CROWDSTRIKE_API_TIMEOUT", ["crowdstrike", "api_timeout"],
            config, False, 60,
        ))

        # ------------------------------------------------------------------ #
        # Resolve author identity                                             #
        #                                                                     #
        # identity.list() is broken on this instance regardless of filters.  #
        # Use stix_domain_object.read() with a name filter instead.          #
        # ------------------------------------------------------------------ #
        self.author = self.helper.api.stix_domain_object.read(
            filters={
                "mode": "and",
                "filters": [
                    {"key": "name", "values": ["CrowdStrike"]},
                    {"key": "entity_type", "values": ["Organization"]},
                ],
                "filterGroups": [],
            }
        )
        if self.author is None:
            raise ValueError(
                "[CrowdStrikeIntelReports] Initialization failed: no Organization "
                "identity named 'CrowdStrike' found. Create this identity in the "
                "platform before starting the connector."
            )

        # ------------------------------------------------------------------ #
        # Resolve TLP:AMBER+STRICT marking (client-side match)               #
        # ------------------------------------------------------------------ #
        all_markings = self.helper.api.marking_definition.list()
        self.marking = next(
            (m for m in (all_markings or []) if m.get("definition") == "TLP:AMBER+STRICT"),
            None,
        )
        if self.marking is None:
            raise ValueError(
                "[CrowdStrikeIntelReports] Initialization failed: marking "
                "definition 'TLP:AMBER+STRICT' not found in the platform."
            )

        # ------------------------------------------------------------------ #
        # Falcon API client                                                   #
        # ------------------------------------------------------------------ #
        self.falcon = FalconIntelClient(
            client_id=self.cs_client_id,
            client_secret=self.cs_client_secret,
            base_url=self.cs_base_url,
            timeout=self.api_timeout,
        )

        self.helper.log_info(
            "[CrowdStrikeIntelReports] Connector initialized. "
            f"Author: '{self.author['name']}', "
            f"Marking: '{self.marking['definition']}', "
            f"Lookback: {self.lookback_days}d, Interval: {self.interval_hours}h."
        )

    # ---------------------------------------------------------------------- #
    # High-water mark                                                         #
    # ---------------------------------------------------------------------- #

    def _get_high_water_mark(self) -> datetime.datetime:
        all_cs_reports = None
        try:
            all_cs_reports = self.helper.api.report.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "createdBy", "values": [self.author["id"]]}
                    ],
                    "filterGroups": [],
                }
            )
        except Exception as exc:
            self.helper.log_warning(
                f"[CrowdStrikeIntelReports] High-water mark query failed "
                f"({exc}); falling back to lookback window."
            )

        recent = None
        if all_cs_reports:
            try:
                sorted_reports = sorted(
                    [r for r in all_cs_reports if r.get("published")],
                    key=lambda r: r["published"],
                    reverse=True,
                )
                if sorted_reports:
                    recent = [sorted_reports[0]]
            except Exception as exc:
                self.helper.log_warning(
                    f"[CrowdStrikeIntelReports] Could not sort reports for "
                    f"high-water mark ({exc}); falling back to lookback window."
                )

        if recent:
            last_published = recent[0].get("published")
            if last_published:
                try:
                    hwm = datetime.datetime.fromisoformat(
                        last_published.replace("Z", "+00:00")
                    )
                    hwm += datetime.timedelta(seconds=1)
                    self.helper.log_info(
                        f"[CrowdStrikeIntelReports] High-water mark: {hwm.isoformat()}"
                    )
                    return hwm
                except (ValueError, AttributeError) as exc:
                    self.helper.log_warning(
                        f"[CrowdStrikeIntelReports] Could not parse published "
                        f"date '{last_published}': {exc}. Falling back."
                    )

        fallback = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            days=self.lookback_days
        )
        self.helper.log_info(
            f"[CrowdStrikeIntelReports] Using {self.lookback_days}-day "
            f"lookback: {fallback.isoformat()}"
        )
        return fallback

    # ---------------------------------------------------------------------- #
    # Deduplication                                                           #
    # ---------------------------------------------------------------------- #

    def _report_exists(self, report_name: str) -> bool:
        try:
            results = self.helper.api.report.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [report_name]}],
                    "filterGroups": [],
                }
            )
        except Exception as exc:
            self.helper.log_warning(
                f"[CrowdStrikeIntelReports] Dedup query failed for "
                f"'{report_name}': {exc}. Proceeding."
            )
            return False
        for r in (results or []):
            if r.get("name") == report_name:
                return True
        return False

    # ---------------------------------------------------------------------- #
    # Report type mapping                                                     #
    # ---------------------------------------------------------------------- #

    def _map_report_type(self, cs_type_name: str) -> str:
        if not cs_type_name:
            return FALLBACK_REPORT_TYPE
        mapped = DEFAULT_REPORT_TYPE_MAP.get(cs_type_name.lower())
        if mapped is None:
            self.helper.log_info(
                f"[CrowdStrikeIntelReports] Unmapped type '{cs_type_name}'; "
                f"defaulting to '{FALLBACK_REPORT_TYPE}'."
            )
            return FALLBACK_REPORT_TYPE
        return mapped

    # ---------------------------------------------------------------------- #
    # Bundle construction                                                     #
    # ---------------------------------------------------------------------- #

    def _build_bundle(self, report: dict, pdf_bytes: bytes) -> str:
        name = report.get("name") or f"CrowdStrike Report {report['id']}"

        created_ts = report.get("created_date")
        if created_ts:
            published = datetime.datetime.fromtimestamp(
                int(created_ts), tz=datetime.timezone.utc
            )
        else:
            published = datetime.datetime.now(datetime.timezone.utc)
            self.helper.log_warning(
                f"[CrowdStrikeIntelReports] No created_date on '{name}'; "
                f"using current time."
            )

        description = report.get("short_description") or ""
        report_url = report.get("url") or ""
        cs_type = report.get("type") or {}
        cs_type_name = cs_type.get("name", "") if isinstance(cs_type, dict) else ""
        opencti_report_type = self._map_report_type(cs_type_name)

        stix_author = stix2.Identity(
            id=self.author["standard_id"],
            name=self.author["name"],
            identity_class="organization",
            allow_custom=True,
        )

        external_refs = []
        if report_url:
            external_refs.append(
                stix2.ExternalReference(
                    source_name="CrowdStrike Falcon Intelligence",
                    url=report_url,
                    description=(
                        f"CrowdStrike Falcon Intelligence report. "
                        f"Internal ID: {report['id']}. Type: {cs_type_name}."
                    ),
                )
            )

        pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")
        file_name = f"crowdstrike_{report['id']}.pdf"

        stix_report = stix2.Report(
            id=Report.generate_id(name, published.strftime("%Y-%m-%dT%H:%M:%S")),
            name=name,
            description=description,
            published=published,
            report_types=[opencti_report_type],
            created_by_ref=self.author["standard_id"],
            object_marking_refs=[self.marking["standard_id"]],
            external_references=external_refs,
            object_refs=[self.author["standard_id"]],
            custom_properties={
                "x_opencti_files": [
                    {
                        "name": file_name,
                        "data": pdf_b64,
                        "mime_type": "application/pdf",
                        "version": "1",
                    }
                ],
            },
            allow_custom=True,
        )

        return stix2.Bundle(
            objects=[stix_author, stix_report],
            allow_custom=True,
        ).serialize()

    # ---------------------------------------------------------------------- #
    # Per-report processing                                                   #
    # ---------------------------------------------------------------------- #

    def _process_report(self, report: dict) -> bool:
        report_id = report.get("id", "unknown")
        report_name = report.get("name") or f"CrowdStrike Report {report_id}"

        if self.cs_report_type_filter:
            cs_type = report.get("type") or {}
            cs_type_name = cs_type.get("name", "") if isinstance(cs_type, dict) else ""
            if cs_type_name.lower() not in self.cs_report_type_filter:
                self.helper.log_info(
                    f"[CrowdStrikeIntelReports] Skipping '{report_name}' "
                    f"(type '{cs_type_name}' not in filter)."
                )
                return False

        if self._report_exists(report_name):
            self.helper.log_info(
                f"[CrowdStrikeIntelReports] Already ingested: '{report_name}'"
            )
            return False

        try:
            pdf_bytes = self.falcon.get_report_pdf(report_id)
        except RuntimeError as exc:
            self.helper.log_warning(
                f"[CrowdStrikeIntelReports] PDF download failed for "
                f"'{report_name}': {exc}. Skipping."
            )
            return False

        if not pdf_bytes:
            self.helper.log_warning(
                f"[CrowdStrikeIntelReports] Empty PDF for '{report_name}'. Skipping."
            )
            return False

        self.helper.send_stix2_bundle(
            bundle=self._build_bundle(report, pdf_bytes),
            update=False,
            bypass_validation=False,
        )

        self.helper.log_info(f"[CrowdStrikeIntelReports] Ingested: '{report_name}'")
        return True

    # ---------------------------------------------------------------------- #
    # Poll cycle                                                              #
    # ---------------------------------------------------------------------- #

    def _run_cycle(self):
        self.helper.log_info("[CrowdStrikeIntelReports] Starting poll cycle.")

        since = self._get_high_water_mark()
        ingested = 0
        skipped = 0
        errors = 0

        try:
            for report in self.falcon.get_reports_since(since):
                try:
                    if self._process_report(report):
                        ingested += 1
                    else:
                        skipped += 1
                except Exception as exc:
                    name = report.get("name", report.get("id", "unknown"))
                    self.helper.log_error(
                        f"[CrowdStrikeIntelReports] Error on '{name}': {exc}"
                    )
                    errors += 1

        except RuntimeError as exc:
            self.helper.log_error(
                f"[CrowdStrikeIntelReports] Falcon API error: {exc}"
            )
            return f"Cycle aborted: {exc}"

        summary = (
            f"Cycle complete — ingested: {ingested}, "
            f"skipped: {skipped}, errors: {errors}."
        )
        self.helper.log_info(f"[CrowdStrikeIntelReports] {summary}")
        return summary

    # ---------------------------------------------------------------------- #
    # Entry point                                                             #
    # ---------------------------------------------------------------------- #

    def start(self):
        self.helper.log_info("[CrowdStrikeIntelReports] Connector starting.")

        while True:
            work_id = None
            result = "Cycle did not complete."

            try:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id,
                    f"CrowdStrike Intel Reports — "
                    f"{datetime.datetime.now(datetime.timezone.utc).isoformat()}",
                )
                result = self._run_cycle()

            except Exception as exc:
                self.helper.log_error(
                    f"[CrowdStrikeIntelReports] Critical error: {exc}"
                )
                result = f"Cycle failed: {exc}"

            finally:
                if work_id is not None:
                    try:
                        self.helper.api.work.to_processed(work_id, result)
                    except Exception as exc:
                        self.helper.log_error(
                            f"[CrowdStrikeIntelReports] Failed to close "
                            f"work item '{work_id}': {exc}"
                        )

            sleep_seconds = self.interval_hours * 3600
            self.helper.log_info(
                f"[CrowdStrikeIntelReports] Next cycle in "
                f"{self.interval_hours}h ({sleep_seconds}s)."
            )
            time.sleep(sleep_seconds)
