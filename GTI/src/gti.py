"""Google Threat Intelligence (GTI) Report Importer Connector.

Polls the GTI /api/v3/collections endpoint for GTI-authored report objects
and ingests them into OpenCTI as Report containers with the official Mandiant
PDF and a markdown attachment.

PDF download uses the GTI /api/v3/collections/{id}/download_report endpoint
which returns a signed GCS URL pointing to the official Mandiant-formatted PDF.
This requires only the GTI API key — no separate Mandiant credentials needed.
"""

import os
import sys
import time
import datetime

import yaml
import requests
import markdown as md_lib
from pycti import OpenCTIConnectorHelper, get_config_variable


class GTIReportConnector:

    GTI_API_BASE = "https://www.virustotal.com/api/v3"
    GTI_GUI_BASE = "https://www.virustotal.com/gui/collection"

    def __init__(self):
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = {}
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}

        self.helper = OpenCTIConnectorHelper(config)
        self.api_key = get_config_variable("GTI_API_KEY", ["gti", "api_key"], config)
        self.interval = int(get_config_variable("GTI_INTERVAL", ["gti", "interval"], config, True, 60))
        self.import_limit = int(get_config_variable("GTI_IMPORT_LIMIT", ["gti", "import_limit"], config, True, 40))
        self.report_filter = get_config_variable(
            "GTI_REPORT_FILTER",
            ["gti", "report_filter"],
            config,
            False,
            'collection_type:report origin:"Google Threat Intelligence"',
        )
        self.confidence = int(get_config_variable("GTI_CONFIDENCE", ["gti", "confidence"], config, True, 85))
        self.identity = self._resolve_or_create_identity("Google Threat Intelligence")
        marking_str = get_config_variable("GTI_MARKING_DEFINITION", ["gti", "marking_definition"], config, False, "TLP:AMBER+STRICT")
        self.marking_ids = self._resolve_markings(marking_str)

    def _resolve_or_create_identity(self, name):
        identity = self.helper.api.identity.read(
            filters={"mode": "and", "filters": [{"key": "name", "values": name}], "filterGroups": []}
        )
        if identity:
            self.helper.log_info(f"[GTI] Resolved identity: {name}")
            return identity
        self.helper.log_info(f"[GTI] Creating identity: {name}")
        return self.helper.api.identity.create(
            type="Organization", name=name,
            description="Google Threat Intelligence provides curated threat intelligence reports.",
        )

    def _resolve_markings(self, marking_str):
        ids = []
        for raw in marking_str.split(","):
            name = raw.strip()
            if not name:
                continue
            md = self.helper.api.marking_definition.read(
                filters={"mode": "and", "filters": [{"key": "definition", "values": name}], "filterGroups": []}
            )
            if md is None:
                raise ValueError(f"[GTI] Marking definition '{name}' not found in OpenCTI.")
            ids.append(md["id"])
            self.helper.log_info(f"[GTI] Marking '{name}' -> {md['id']}")
        return ids

    def _headers(self, accept="application/json"):
        return {"x-apikey": self.api_key, "x-tool": "opencti-gti-report-connector", "Accept": accept}

    def _map_report_type(self, gti_report_type):
        """Map GTI report_type to the correct OpenCTI report_types value."""
        activity_roundup_types = {
            "Weekly Vulnerability Exploitation Report",
            "Actor Profile",
            "Trends and Forecasting",
        }
        if gti_report_type in activity_roundup_types:
            return "Activity Roundup"
        return "threat-report"

    def list_reports(self):
        """Fetch GTI-authored reports ordered by relevance."""
        url = f"{self.GTI_API_BASE}/collections"
        params = {
            "filter": self.report_filter,
            "limit": min(self.import_limit, 40),
            "order": "relevance-",
        }
        reports = []
        cursor = None

        while True:
            if cursor:
                params["cursor"] = cursor
            try:
                resp = requests.get(url, headers=self._headers(), params=params, timeout=30)
            except requests.exceptions.RequestException as exc:
                self.helper.log_error(f"[GTI] list_reports failed: {exc}")
                break

            if resp.status_code == 200:
                body = resp.json()
                batch = body.get("data", [])
                reports.extend(batch)
                self.helper.log_info(f"[GTI] Page: {len(batch)} objects (total: {len(reports)})")
                if len(reports) >= self.import_limit:
                    reports = reports[:self.import_limit]
                    break
                cursor = body.get("meta", {}).get("cursor")
                if not cursor:
                    break
            elif resp.status_code == 204:
                self.helper.log_info("[GTI] 204 No Content.")
                break
            else:
                self.helper.log_error(f"[GTI] HTTP {resp.status_code}: {resp.text[:400]}")
                break

        return reports

    def _report_exists(self, external_url):
        try:
            ext_refs = self.helper.api.external_reference.list(
                filters={"mode": "and", "filters": [{"key": "url", "values": external_url}], "filterGroups": []}
            )
            return bool(ext_refs)
        except Exception as exc:
            self.helper.log_warning(f"[GTI] Dedup check failed for {external_url}: {exc}. Treating as new.")
            return False

    def _download_pdf(self, collection_id):
        """Download the official Mandiant PDF via the GTI download_report endpoint.

        The endpoint returns a signed GCS URL. We fetch that URL to get the
        actual PDF bytes. Only the GTI API key is required — no separate
        Mandiant credentials needed.

        Args:
            collection_id: Full collection ID e.g. 'report--26-10017422'.

        Returns:
            PDF bytes if successful, None otherwise.
        """
        try:
            resp = requests.get(
                f"{self.GTI_API_BASE}/collections/{collection_id}/download_report",
                headers=self._headers(),
                timeout=30,
            )
            if resp.status_code != 200:
                self.helper.log_warning(f"[GTI] download_report HTTP {resp.status_code} for {collection_id}")
                return None
            signed_url = resp.json().get("data")
            if not signed_url:
                self.helper.log_warning(f"[GTI] No signed URL returned for {collection_id}")
                return None
            pdf_resp = requests.get(signed_url, timeout=60)
            if pdf_resp.status_code == 200 and pdf_resp.content[:4] == b"%PDF":
                self.helper.log_info(f"[GTI] PDF downloaded: {collection_id} ({len(pdf_resp.content)} bytes)")
                return pdf_resp.content
            self.helper.log_warning(f"[GTI] PDF fetch failed: HTTP {pdf_resp.status_code} for {collection_id}")
            return None
        except Exception as exc:
            self.helper.log_warning(f"[GTI] PDF download error for {collection_id}: {exc}")
            return None

    def _build_markdown(self, attrs, name):
        """Assemble the full report markdown from GTI attributes."""
        lines = [f"# {name}", "", "## Metadata", ""]
        if attrs.get("report_id"):
            lines.append(f"- **Report ID:** {attrs['report_id']}")
        if attrs.get("version"):
            lines.append(f"- **Version:** {attrs['version']}")
        if attrs.get("report_type"):
            lines.append(f"- **Report Type:** {attrs['report_type']}")
        if attrs.get("publisher"):
            lines.append(f"- **Publisher:** {attrs['publisher']}")
        if attrs.get("origin"):
            lines.append(f"- **Origin:** {attrs['origin']}")
        if attrs.get("author"):
            lines.append(f"- **Author:** {attrs['author']}")
        if attrs.get("creation_date"):
            dt = datetime.datetime.utcfromtimestamp(int(attrs["creation_date"])).strftime("%Y-%m-%d %H:%M UTC")
            lines.append(f"- **Published:** {dt}")
        if attrs.get("last_modification_date"):
            dt = datetime.datetime.utcfromtimestamp(int(attrs["last_modification_date"])).strftime("%Y-%m-%d %H:%M UTC")
            lines.append(f"- **Last Modified:** {dt}")
        if attrs.get("link"):
            lines.append(f"- **Source URL:** {attrs['link']}")
        if attrs.get("threat_scape"):
            lines.append(f"- **Threat Scape:** {', '.join(attrs['threat_scape'])}")
        if attrs.get("targeted_industries"):
            lines.append(f"- **Targeted Industries:** {', '.join(attrs['targeted_industries'])}")
        if attrs.get("targeted_regions"):
            lines.append(f"- **Targeted Regions:** {', '.join(attrs['targeted_regions'])}")
        if attrs.get("affected_systems"):
            lines.append(f"- **Affected Systems:** {', '.join(attrs['affected_systems'])}")
        if attrs.get("motivations"):
            motives = [m.get("value", "") for m in attrs["motivations"] if m.get("value")]
            if motives:
                lines.append(f"- **Motivations:** {', '.join(motives)}")
        lines.append("")
        if attrs.get("executive_summary"):
            lines += ["## Executive Summary", "", attrs["executive_summary"], ""]
        if attrs.get("autogenerated_summary"):
            lines += ["## AI Summary", "", attrs["autogenerated_summary"], ""]
        if attrs.get("analyst_comment"):
            lines += ["## Analyst Comment", "", attrs["analyst_comment"], ""]
        if attrs.get("content"):
            lines += ["## Content", "", attrs["content"], ""]
        return "\n".join(lines)

    def _attach_files(self, report_standard_id, report_id, attrs, name):
        """Attach the official Mandiant PDF and markdown to the report container.

        PDF is downloaded from the GTI download_report endpoint. Markdown is
        always attached regardless of PDF outcome, providing a fallback that
        contains the full report content.
        """
        safe_stem = report_id.replace("--", "-").replace("/", "_")

        # Download and attach the official Mandiant PDF
        pdf_bytes = self._download_pdf(report_id)
        if pdf_bytes:
            mandiant_id = attrs.get("report_id", safe_stem)
            pdf_path = f"/tmp/gti-{mandiant_id}.pdf"
            try:
                with open(pdf_path, "wb") as fh:
                    fh.write(pdf_bytes)
                self.helper.api.stix_domain_object.add_file(
                    id=report_standard_id,
                    file_name=pdf_path,
                )
                self.helper.log_info(f"[GTI] PDF attached: '{name}'")
            except Exception as exc:
                self.helper.log_warning(f"[GTI] PDF attachment failed for '{name}': {exc}")
            finally:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
        else:
            self.helper.log_info(f"[GTI] PDF unavailable for '{name}' — markdown only.")

        # Always attach markdown
        md_text = self._build_markdown(attrs, name)
        md_path = f"/tmp/gti-{safe_stem}.md"
        try:
            with open(md_path, "w", encoding="utf-8") as fh:
                fh.write(md_text)
            self.helper.api.stix_domain_object.add_file(
                id=report_standard_id,
                file_name=md_path,
            )
            self.helper.log_info(f"[GTI] Markdown attached: '{name}'")
        except Exception as exc:
            self.helper.log_warning(f"[GTI] Markdown attachment failed for '{name}': {exc}")
        finally:
            if os.path.exists(md_path):
                os.remove(md_path)

    def ingest_report(self, report_data):
        report_id = report_data.get("id", "")
        attrs = report_data.get("attributes", {})

        name = (attrs.get("name") or "").strip()
        if not name:
            self.helper.log_warning(f"[GTI] Skipping {report_id}: no name.")
            return False

        creation_ts = attrs.get("creation_date")
        if not creation_ts:
            self.helper.log_warning(f"[GTI] Skipping {report_id}: no creation_date.")
            return False

        published = datetime.datetime.utcfromtimestamp(int(creation_ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
        description = attrs.get("autogenerated_summary") or attrs.get("executive_summary") or ""
        external_url = f"{self.GTI_GUI_BASE}/{report_id}"
        mandiant_report_id = attrs.get("report_id", "")

        if self._report_exists(external_url):
            self.helper.log_info(f"[GTI] Duplicate — skipping: '{name}'")
            return False

        ext_ref = self.helper.api.external_reference.create(
            source_name="Google Threat Intelligence",
            url=external_url,
            description=f"GTI Report ID: {mandiant_report_id}" if mandiant_report_id else f"GTI collection ID: {report_id}",
        )

        report = self.helper.api.report.create(
            name=name,
            description=description,
            published=published,
            report_types=[self._map_report_type(attrs.get("report_type", ""))],
            createdBy=self.identity["standard_id"],
            objectMarking=self.marking_ids,
            confidence=self.confidence,
            externalReferences=[ext_ref["id"]],
        )

        if report is None:
            self.helper.log_error(f"[GTI] Report creation failed: '{name}'")
            return False

        self.helper.log_info(
            f"[GTI] Created report: '{name}' "
            f"(ID: {mandiant_report_id or report_id}, published: {published})"
        )

        self._attach_files(report["standard_id"], report_id, attrs, name)

        return True

    def import_reports(self, work_id):
        reports = self.list_reports()
        self.helper.log_info(f"[GTI] {len(reports)} report(s) from API.")
        created = 0
        for report_data in reports:
            if report_data.get("type") != "collection":
                continue
            try:
                if self.ingest_report(report_data):
                    created += 1
            except Exception as exc:
                self.helper.log_error(f"[GTI] Error on {report_data.get('id', 'unknown')}: {exc}")
        return created

    def run(self):
        self.helper.log_info("[GTI] Connector starting.")
        while True:
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            last_run = current_state.get("last_run") if current_state else None

            if last_run:
                self.helper.log_info(
                    "[GTI] Last run: "
                    + datetime.datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                    + " UTC."
                )
            else:
                self.helper.log_info("[GTI] Cold start.")

            interval_seconds = self.interval * 60
            if last_run is None or (timestamp - last_run) >= (interval_seconds - 60):
                now_str = datetime.datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(self.helper.connect_id, f"GTI Reports @ {now_str} UTC")
                self.helper.log_info(f"[GTI] Work {work_id} initiated.")
                created = self.import_reports(work_id)
                self.helper.set_state({"last_run": timestamp})
                message = f"Done. {created} new report(s). Next run in {round(interval_seconds / 60, 1)} min."
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(f"[GTI] {message}")
                time.sleep(interval_seconds)
            else:
                remaining = interval_seconds - (timestamp - last_run)
                self.helper.log_info(f"[GTI] Next run in {round(remaining / 60, 1)} min.")
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = GTIReportConnector()
        connector.run()
    except Exception as exc:
        print(f"[GTI] Fatal: {exc}")
        time.sleep(10)
        sys.exit(1)
