# =============================================================================
# flashpoint_connector/connector.py
# =============================================================================
# Main connector orchestration: scheduling, state management, dataset
# dispatchers, and Incident Response container management.
#
# RESPONSIBILITIES:
#   - Schedule the connector run via helper.schedule_iso()
#   - Maintain per-dataset state cursors (reports, alerts, communities,
#     credentials — each independently tracked)
#   - Dispatch each enabled dataset to its import method
#   - Bifurcate alerts and credentials between Report and IR containers
#   - Create and manage Incident Response containers for org-domain hits
#   - Build daily batch Report containers from accumulated objects
#   - Log per-dataset statistics for operational monitoring
#
# STATE MANAGEMENT — KEY DESIGN DECISION:
# Each dataset tracks its own cursor independently in the connector state
# store. A failure in one dataset does not advance any other dataset's cursor.
#
# WHY: The Filigran connector used a single shared `last_run` key. If reports
# ingested successfully but alerts failed, the next run would skip all alerts
# from the failed window because last_run had already advanced. This caused
# silent data loss. Per-dataset cursors make failure recovery deterministic:
# a failed dataset re-fetches from its last successful position on the next run.
#
# STATE SCHEMA:
#   {
#     "reports_last_run":     "ISO8601",   # Updated after successful reports run
#     "alerts_last_run":      "ISO8601",   # Updated after successful alerts run
#     "communities_last_run": "ISO8601",   # Updated after successful communities run
#     "credentials_last_run": "ISO8601",   # Updated after successful credentials run
#   }
#
# ALERT BIFURCATION:
# Alerts split into two paths based on org domain matching:
#   Org-domain match → Incident Response container (one IR per alert)
#   No match         → Daily batch Report (accumulated by date, sent at end)
#
# DAILY BATCH REPORTS:
# Alerts and Communities results are accumulated in per-day buckets during
# the run. After all records for a dataset are processed, the buckets are
# flushed as Report containers via build_daily_report(). The Report ID is
# deterministic (name + date), so re-running on the same day upserts the
# existing container rather than creating a duplicate.
#
# IR CONTAINERS:
# Follow the UDM connector pattern exactly:
#   1. Lookup by name before create (prevents duplicates)
#   2. externalReferences passed as list of resolved IDs (inline dicts
#      are rejected by the OpenCTI GraphQL schema — BAD_USER_INPUT)
#   3. Objects added individually via add_stix_object_or_stix_relationship()
#
# CONNECTOR SUPERSEDES FILIGRAN:
# The Filigran upstream connector (external-import/flashpoint) must be
# stopped and removed from docker-compose.override.yml before deploying
# this connector. Running both simultaneously will produce duplicate
# Reports, duplicate Observables, and conflicting relationships.
# =============================================================================

import datetime
import mimetypes
import sys
from typing import Optional

import pytz
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix

# =============================================================================
# State key constants
# =============================================================================
# Using named constants rather than inline strings prevents typos in cursor
# key names from silently resetting dataset state.

_STATE_REPORTS = "reports_last_run"
_STATE_ALERTS = "alerts_last_run"
_STATE_COMMUNITIES = "communities_last_run"
_STATE_CREDENTIALS = "credentials_last_run"


# =============================================================================
# FlashpointConnector
# =============================================================================


class FlashpointConnector:
    """
    Main connector class. Instantiated once at startup and runs for the
    connector's lifetime via the schedule_iso loop.

    Sub-components:
      config   — ConfigConnector: all configuration values
      helper   — OpenCTIConnectorHelper: platform API and scheduling
      client   — ConnectorClient: Flashpoint Ignite API
      converter — ConverterToStix: STIX object construction
    """

    def __init__(self):
        """
        Initialise the connector.

        Instantiation order matters:
          1. ConfigConnector — must exist before helper (needs config.load)
          2. OpenCTIConnectorHelper — must exist before client/converter (needs helper)
          3. ConnectorClient — needs helper (logging) and config (api_key)
          4. ConverterToStix — needs helper (API) and config (confidence values)
             ConverterToStix.__init__ makes two API calls:
               - _resolve_author(): creates/retrieves Flashpoint identity
               - _ensure_activity_roundup_vocabulary(): registers report type
             Both are safe to call at startup; both are idempotent.
        """
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ConnectorClient(self.helper, self.config)
        self.converter = ConverterToStix(self.helper, self.config)

    # =========================================================================
    # State management helpers
    # =========================================================================

    def _get_cursor(self, key: str) -> str:
        """
        Retrieve the stored cursor for a specific dataset.

        If no cursor exists for this key (first run, or state was reset),
        falls back to FLASHPOINT_IMPORT_START_DATE normalised to UTC ISO8601.
        This ensures every dataset begins from the configured backfill start
        on its first run.

        Uses the full state dict to avoid overwriting other datasets' cursors
        when setting state — see _set_cursor().

        :param key: one of the _STATE_* constants
        :return: ISO8601 datetime string for use as API start_date parameter
        """
        state = self.helper.get_state() or {}
        if key in state and state[key]:
            return state[key]
        # First run for this dataset — use the configured import start date.
        return (
            parse(self.config.import_start_date)
            .astimezone(pytz.UTC)
            .isoformat()
        )

    def _set_cursor(self, key: str, value: str) -> None:
        """
        Update a single dataset cursor in the state store.

        Reads the full current state, updates only the specified key, and
        writes back. This prevents one dataset's cursor update from
        overwriting another dataset's cursor with an old or empty value.

        Only called after a dataset has been successfully fully processed.
        Never called on partial success or failure — the cursor advances
        only when the complete dataset fetch-and-ingest cycle completes
        without raising.

        :param key: one of the _STATE_* constants
        :param value: ISO8601 datetime string (current run start time)
        """
        state = self.helper.get_state() or {}
        state[key] = value
        self.helper.set_state(state)

    # =========================================================================
    # Bundle sending
    # =========================================================================

    def _send_bundle(self, work_id: str, stix_objects: list) -> None:
        """
        Serialise a list of STIX objects into a bundle and send to OpenCTI.

        stix2_create_bundle() handles deduplication of objects that appear
        in multiple bundles (e.g. the marking definition, which is included
        in every object list). The resulting bundle is sent to the connector
        work queue identified by work_id.

        Sending is asynchronous — this method returns immediately once the
        bundle is queued. Worker processing happens independently. This means
        relationship type rejections (e.g. 'publishes' not being supported)
        will only appear in worker logs, not as exceptions here.

        :param work_id: OpenCTI work item ID for tracking/grouping
        :param stix_objects: list of STIX objects to bundle and send
        """
        if not stix_objects:
            # Sending an empty bundle is a no-op waste of a network call.
            return
        try:
            bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(bundle, work_id=work_id)
        except Exception as exc:
            self.helper.connector_logger.error(
                f"[CONNECTOR] Bundle send failed: {exc}"
            )

    # =========================================================================
    # Incident Response container management
    # =========================================================================

    def _add_to_ir_container(self, container_id: str, object_id: str) -> None:
        """
        Add a single object to an Incident Response container.

        Uses add_stix_object_or_stix_relationship() rather than bulk add
because the OpenCTI API requires individual calls per object. This is
        the same pattern used by the UDM connector, confirmed working in
        production.

        Failures are logged as warnings, not errors — a single object
        failing to attach to a container is not a fatal error. The object
        still exists in the graph; only the container membership is missing,
        which can be corrected manually.

        :param container_id: OpenCTI internal ID of the case_incident container
        :param object_id: STIX ID of the object to add
        """
        if not container_id or not object_id:
            return
        try:
            self.helper.api.case_incident.add_stix_object_or_stix_relationship(
                id=container_id,
                stixObjectOrStixRelationshipId=object_id,
            )
        except Exception as exc:
            self.helper.connector_logger.warning(
                f"[CONNECTOR] add_to_ir_container "
                f"container={container_id} object={object_id}: {exc}"
            )

    def _get_or_create_ir_container(
        self,
        name: str,
        description: str,
        flashpoint_url: str = "",
    ) -> Optional[str]:
        """
        Look up an Incident Response container by name, creating if absent.

        LOOKUP-BEFORE-CREATE pattern (from UDM connector):
        Searching by exact name before creating prevents duplicate containers
        if the connector re-processes the same alert (e.g. after a restart
        mid-run or after a state reset). The IR container for a given alert
        is idempotent — the same alert always produces the same container name,
        so finding an existing one is the expected behaviour on re-ingestion.

        EXTERNAL REFERENCES — IMPORTANT:
        externalReferences must be passed as a list of resolved OpenCTI
        internal IDs, not as inline dict objects. Passing inline dicts
        causes a BAD_USER_INPUT GraphQL error. The ID is obtained by calling
        helper.api.external_reference.create() first (which is also an
        upsert — safe to call repeatedly for the same URL).

        MARKING:
        TLP:AMBER+STRICT is applied. The marking definition's STIX ID is
        resolved to an OpenCTI internal ID for the GraphQL call — the STIX
        ID format is not accepted by case_incident.create().

        :param name: container name (deterministic for a given alert)
        :param description: human-readable description of what the IR covers
        :param flashpoint_url: Flashpoint platform URL for the alert (optional)
        :return: OpenCTI internal ID of the container, or None on failure
        """
        # ── Lookup ────────────────────────────────────────────────────────────
        try:
            hits = self.helper.api.case_incident.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "name", "values": [name], "operator": "eq"}
                    ],
                    "filterGroups": [],
                }
            )
            if hits:
                self.helper.connector_logger.debug(
                    f"[CONNECTOR] Found existing IR container: {name}"
                )
                return hits[0]["id"]
        except Exception as exc:
            self.helper.connector_logger.warning(
                f"[CONNECTOR] IR container lookup '{name}': {exc}"
            )

        # ── Create ────────────────────────────────────────────────────────────
        try:
            # Resolve external reference to an OpenCTI ID first.
            # create() is upsert — safe to call for the same URL multiple times.
            ext_ref_id = None
            if flashpoint_url:
                ext_ref = self.helper.api.external_reference.create(
                    source_name="Flashpoint",
                    url=flashpoint_url,
                )
                ext_ref_id = ext_ref.get("id")

            kwargs = dict(
                name=name,
                description=description,
                # Medium severity for IR containers — the alert is directly
                # relevant to the org but not yet confirmed as a breach.
                severity="medium",
                objectMarking=[self.converter.marking.get("id")],
                createdBy=self.converter.author_id,
                confidence=self.config.alert_org_confidence,
            )
            # Only include externalReferences if we successfully resolved an ID.
            # Passing None or empty list causes a GraphQL validation error.
            if ext_ref_id:
                kwargs["externalReferences"] = [ext_ref_id]

            obj = self.helper.api.case_incident.create(**kwargs)
            self.helper.connector_logger.info(
                f"[CONNECTOR] Created IR container: {name}"
            )
            return obj["id"]

        except Exception as exc:
            self.helper.connector_logger.error(
                f"[CONNECTOR] Create IR container '{name}': {exc}"
            )
            return None

    # =========================================================================
    # Alert processing utilities
    # =========================================================================

    def _is_org_domain_alert(self, alert: dict) -> bool:
        """
        Determine whether an alert should route to an Incident Response
        container (org-domain match) or a keyword-match batch Report.

        MATCHING STRATEGY:
        The entire alert resource dict is serialised to a lowercase string
        and each configured org domain is checked for membership. This is
        intentionally broad — a domain match anywhere in the resource
        (repo owner, email address, URL path, display name) triggers IR routing.

        The breadth is deliberate: a credential exposure might reference
        the org domain in a URL rather than a direct email field, and a
        data_exposure alert might reference the domain in the repo owner
        field. Narrow field-level matching would miss these cases.

        If org_domains is not configured (empty list), all alerts route to
        batch Reports. This is the safe default — without knowing what the
        org's domains are, we cannot make the bifurcation decision.

        :param alert: raw Flashpoint alert dict from the API
        :return: True if alert should go to IR container, False for batch Report
        """
        if not self.config.org_domains:
            # No org domains configured — cannot bifurcate.
            # All alerts route to batch Reports.
            return False

        # Serialise the resource dict to a lowercase string for broad matching.
        resource_str = str(alert.get("resource", {})).lower()

        for domain in self.config.org_domains:
            if domain in resource_str:
                return True

        return False

    def _process_alert(self, alert: dict) -> Optional[dict]:
        """
        Extract and normalise fields from a raw Flashpoint alert API response.

        ALERT SOURCE TYPES:
        Flashpoint alerts have a `source` field indicating what kind of
        content triggered the alert:
          "communities"    — a dark web forum post matched the alert rule
          "media"          — an image or file matched the alert rule
          "data_exposure"  — content in a code repository matched the rule

        Each source type has a slightly different resource structure, so
        field extraction is handled per-source-type.

        For "communities" and "media" source types, an additional API call
        is made to fetch the source document. This enriches the alert with
        actor alias data and the original content URL:
          communities: fetches site_actor_alias and container_external_uri
          media: fetches storage_uri to enable binary content download

        RETURN VALUE:
        Returns a normalised dict with consistent field names regardless of
        source type. Returns None if the alert is malformed or the source
        type is unrecognised, signalling the dispatcher to skip this alert.

        :param alert: raw alert dict from get_alerts()
        :return: normalised processed alert dict, or None to skip
        """
        source = alert.get("source")
        if not source:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Alert missing 'source' field — skipping. "
                "This may indicate an API schema change."
            )
            return None

        resource = alert.get("resource") or {}
        alert_id = str(alert.get("id") or "unknown")

        # Build the base processed dict with fields common to all source types.
        processed = {
            "alert_id": alert_id,
            # channel_type: the platform (e.g. "Telegram", "GitHub", "XSS Forum")
            "channel_type": resource.get("site", {}).get("title") or "",
            # channel_name: the specific channel/repo/thread within the platform
            "channel_name": (
                resource.get("title")
                if "title" in resource
                else (resource.get("site", {}).get("title") or "")
            ),
            # author: the handle of the post/commit author
            "author": (
                resource.get("site_actor", {})
                .get("names", {})
                .get("handle") or ""
            ),
            "created_at": alert.get("created_at") or "",
            "alert_status": alert.get("status") or "None",
            "alert_source": source,
            "alert_reason": (alert.get("reason") or {}).get("name") or "",
            "highlight_text": alert.get("highlight_text") or "",
            "document_id": resource.get("id"),
            # Default Flashpoint platform URL — overridden for data_exposure.
            "flashpoint_url": (
                "https://app.flashpoint.io/search/context/"
                + source
                + "/"
                + str(resource.get("id") or "")
            ),
            # Populated for communities alerts after doc enrichment.
            "channel_aliases": [],
            "channel_ref": None,
            # Populated for media alerts after binary fetch.
            "media_content": None,
            "media_type": None,
            "media_name": None,
        }

        # ── Source-specific enrichment ────────────────────────────────────────

        if source == "communities":
            # Fetch the communities document to get actor alias data and the
            # original thread/channel URL. These are not available in the
            # alert notification itself.
            try:
                doc = self.client.get_communities_doc(resource.get("id"))
                results = doc.get("results") or {}
                processed["channel_aliases"] = (
                    results.get("site_actor_alias") or []
                )
                processed["channel_ref"] = results.get("container_external_uri")
            except Exception as exc:
                # Non-fatal — the alert can still be processed without
                # aliases and channel ref; they are enrichment data.
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Communities doc enrichment for alert "
                    f"{alert_id}: {exc}"
                )

        elif source == "media":
            # Fetch the media document metadata to get storage_uri, then
            # fetch the actual binary content. The binary is stored in
            # processed["media_content"] as base64 for attachment to the
            # Incident via x_opencti_files.
            try:
                media_doc = self.client.get_media_doc(resource.get("id"))
                storage_uri = media_doc.get("storage_uri")
                if storage_uri:
                    media_content, media_type = self.client.get_media(storage_uri)
                    if media_content:
                        # Guess the file extension from the MIME type for
                        # a human-readable attachment filename.
                        ext = mimetypes.guess_extension(media_type) or ""
                        processed["media_content"] = media_content
                        processed["media_type"] = media_type
                        processed["media_name"] = (
                            str(media_doc.get("media_id") or "attachment") + ext
                        )
            except Exception as exc:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Media fetch for alert {alert_id}: {exc}"
                )

        elif source.startswith("data_exposure"):
            # data_exposure alerts reference a code repository or paste site.
            # The resource structure differs from communities/media:
            #   resource.source = platform name (e.g. "GitHub")
            #   resource.repo   = repository name
            #   resource.owner  = repository owner
            #   resource.url    = direct URL to the exposed content
            processed["channel_type"] = resource.get("source") or ""
            processed["channel_name"] = resource.get("repo") or ""
            processed["author"] = resource.get("owner") or ""
            # For data_exposure, the flashpoint_url is the actual repository
            # URL, not a Flashpoint platform URL.
            processed["flashpoint_url"] = resource.get("url") or ""

        else:
            # Unrecognised source type — skip this alert.
            # This could indicate a new Flashpoint alert type not yet
            # supported by this connector. Log with enough context for
            # a developer to add support.
            self.helper.connector_logger.warning(
                f"[CONNECTOR] Unrecognised alert source type '{source}' "
                f"for alert {alert_id}. "
                f"Supported types: communities, media, data_exposure*. "
                f"Skipping this alert."
            )
            return None

        return processed

    @staticmethod
    def _alert_date_str(alert: dict) -> str:
        """
        Extract the YYYY-MM-DD date string from a processed alert dict.

        Used for bucketing alerts into daily batch Reports. The date is
        derived from created_at — the time the alert was fired, which
        corresponds to when the content was detected, not when it was ingested.

        Falls back to the current UTC date if created_at cannot be parsed.
        The fallback is logged implicitly — a date parse failure here is
        not worth a warning log since it results in the alert being correctly
        bucketed to "today" regardless.

        :param alert: processed alert dict (post _process_alert())
        :return: date string in YYYY-MM-DD format
        """
        created_at = alert.get("created_at") or ""
        try:
            return parse(created_at).strftime("%Y-%m-%d")
        except Exception:
            return datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%d"
            )

    # =========================================================================
    # Dataset dispatchers
    # =========================================================================

    def _import_reports(self) -> None:
        """
        Fetch and ingest Flashpoint finished intelligence reports.

        FLOW:
          1. Read reports cursor (reports_last_run or import_start_date)
          2. Fetch all reports updated since cursor
          3. For each report: convert to STIX objects, send as bundle
          4. On complete success: advance reports_last_run cursor

        ONE BUNDLE PER REPORT: Each report is sent as an independent bundle.
        This ensures that a conversion failure on one report does not prevent
        other reports from being ingested. The work_id groups all report
        bundles for this run for tracking in the OpenCTI work management view.

        CURSOR ADVANCEMENT: The cursor is set to now_iso (captured at the
        start of this method) only after all reports have been processed.
        Using now_iso rather than the latest report's updated_at ensures
        we don't miss reports created between the last report's timestamp
        and when this run started.

        FAILURE: If the entire fetch fails (API error), the cursor is not
        advanced and the exception is logged. The next run will retry from
        the same start_date.
        """
        # Capture the run start time before any API calls.
        # This becomes the new cursor value after a successful run.
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        start_date = self._get_cursor(_STATE_REPORTS)

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"Flashpoint Reports @ {now_iso}",
        )
        try:
            reports = self.client.get_reports(start_date)
            self.helper.connector_logger.info(
                f"[REPORTS] Fetched {len(reports)} reports since {start_date}"
            )

            success_count = 0
            for report in reports:
                report_id = report.get("id") or "unknown"
                report_title = report.get("title") or "untitled"
                try:
                    objects = self.converter.convert_flashpoint_report(report)
                    self._send_bundle(work_id, objects)
                    success_count += 1
                except Exception as exc:
                    # Per-report exception — log and continue to next report.
                    self.helper.connector_logger.error(
                        f"[REPORTS] Conversion failed for report "
                        f"id={report_id} title='{report_title}': {exc}"
                    )

            self.helper.connector_logger.info(
                f"[REPORTS] Complete: {success_count}/{len(reports)} ingested."
            )
            self.helper.api.work.to_processed(
                work_id,
                f"Reports complete: {success_count}/{len(reports)}",
            )
            # Advance cursor only after full successful run.
            self._set_cursor(_STATE_REPORTS, now_iso)

        except Exception as exc:
            # Entire dataset failure — cursor not advanced.
            self.helper.connector_logger.error(
                f"[REPORTS] Dataset fetch failed: {exc}"
            )
            self.helper.api.work.to_processed(
                work_id, f"Reports failed: {exc}"
            )

    def _import_alerts(self) -> None:
        """
        Fetch and ingest Flashpoint alert notifications.

        BIFURCATION:
        Each alert is evaluated against the org domain list:
          - Org-domain match → Incident Response container
          - No match → daily batch Report accumulator

        IR PATH (org-domain):
          1. Create or retrieve IR container by deterministic name
          2. Convert alert to Incident + Observable objects
          3. Send each object as a bundle (ensures platform processes before add)
          4. Add each object to IR container individually

        BATCH REPORT PATH (keyword match):
          1. Process alert into STIX member objects
          2. Accumulate in keyword_buckets[date_str]
          3. After all alerts processed: flush each date bucket as a Report

        FLUSH:
        Daily batch Reports are only constructed after all alerts have been
        processed and bucketed. This ensures each Report contains the complete
        set of objects for that day rather than being sent incrementally
        (which would create multiple Reports for the same day).

        The Report ID is deterministic (name + date), so if the connector
        is re-run on the same day, the existing Report is upserted.

        ALERT.md ATTACHMENT NOTE:
        For IR-path alerts, the alert.md markdown file is generated by the
        converter and attached to the Incident via x_opencti_files. This
        file provides analysts with a formatted summary of the alert without
        requiring them to navigate to Flashpoint Ignite.
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Alerts require a specific datetime format with microseconds.
        # dateutil.parse() → strftime() normalises whatever format the
        # cursor was stored in to the format Flashpoint's API requires.
        start_date = parse(self._get_cursor(_STATE_ALERTS)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"Flashpoint Alerts @ {now_iso}",
        )
        try:
            raw_alerts = self.client.get_alerts(start_date)
            self.helper.connector_logger.info(
                f"[ALERTS] Fetched {len(raw_alerts)} alerts since {start_date}"
            )

            # Bucket structure for keyword-match daily batch Reports.
            # {date_str: {"objects": [stix_objects], "ext_refs": [ExternalReference]}}
            # ext_refs accumulates per-alert Flashpoint URLs so the batch
            # Report has a complete list of contributing alert URLs.
            keyword_buckets: dict = {}

            ir_count = 0          # Count of alerts routed to IR
            keyword_count = 0     # Count of alerts routed to batch Report
            skip_count = 0        # Count of alerts skipped (malformed/unrecognised)

            for raw_alert in raw_alerts:
                # Normalise the raw alert into a consistent processed dict.
                processed = self._process_alert(raw_alert)
                if processed is None:
                    # Malformed or unrecognised source type — skip.
                    skip_count += 1
                    continue

                if self._is_org_domain_alert(raw_alert):
                    # ── Incident Response path ────────────────────────────────
                    try:
                        alert_id = processed["alert_id"]
                        ir_name = f"Flashpoint Alert — {alert_id}"
                        ir_description = (
                            f"Org-domain credential or data exposure alert "
                            f"from Flashpoint Ignite. "
                            f"Source: {processed['alert_source']}. "
                            f"Rule: {processed['alert_reason']}. "
                            f"Alert ID: {alert_id}. "
                            f"Captured: {processed['created_at']}."
                        )

                        # Get or create the IR container for this alert.
                        container_id = self._get_or_create_ir_container(
                            name=ir_name,
                            description=ir_description,
                            flashpoint_url=processed["flashpoint_url"],
                        )
                        if not container_id:
                            self.helper.connector_logger.error(
                                f"[ALERTS] Could not create IR container "
                                f"for alert {alert_id}. Skipping."
                            )
                            continue

                        # Convert alert to Incident + Observable objects.
                        objects = (
                            self.converter.credential_alert_to_incident_objects(
                                processed
                            )
                        )

                        # Send each object individually and add to container.
                        # Sending before adding ensures the object exists in
                        # the platform before the container membership call.
                        for obj in objects:
                            if hasattr(obj, "id"):
                                self._send_bundle(work_id, [obj])
                                self._add_to_ir_container(container_id, obj.id)

                        ir_count += 1

                    except Exception as exc:
                        self.helper.connector_logger.error(
                            f"[ALERTS] IR path failed for alert "
                            f"{processed.get('alert_id')}: {exc}"
                        )

                else:
                    # ── Daily batch Report path ───────────────────────────────
                    try:
                        date_str = self._alert_date_str(processed)

                        # Initialise bucket for this date if first alert.
                        if date_str not in keyword_buckets:
                            keyword_buckets[date_str] = {
                                "objects": [],
                                "ext_refs": [],
                            }

                        # Convert alert to member objects (no container).
                        objects = self.converter.alert_to_report_objects(
                            processed, create_related_entities=True
                        )
                        keyword_buckets[date_str]["objects"].extend(objects)

                        # Accumulate per-alert external reference for the batch
                        # Report. This allows analysts to navigate from the
                        # Report directly to individual alerts in Flashpoint.
                        if processed["flashpoint_url"]:
                            import stix2 as _stix2
                            keyword_buckets[date_str]["ext_refs"].append(
                                _stix2.ExternalReference(
                                    source_name="Flashpoint",
                                    url=processed["flashpoint_url"],
                                )
                            )
                        keyword_count += 1

                    except Exception as exc:
                        self.helper.connector_logger.error(
                            f"[ALERTS] Batch path failed for alert "
                            f"{processed.get('alert_id')}: {exc}"
                        )

            # ── Flush keyword batch Reports ───────────────────────────────────
            # Process date buckets in chronological order for predictable logs.
            for date_str, bucket in sorted(keyword_buckets.items()):
                try:
                    report_name = f"Flashpoint Alerts — {date_str}"
                    report_obj = self.converter.build_daily_report(
                        name=report_name,
                        date_str=date_str,
                        member_objects=bucket["objects"],
                        confidence=self.config.alert_confidence,
                        extra_external_refs=bucket["ext_refs"],
                    )
                    # Include marking + all member objects + Report in one bundle.
                    all_objects = (
                        [self.converter.marking]
                        + bucket["objects"]
                        + [report_obj]
                    )
                    self._send_bundle(work_id, all_objects)
                    self.helper.connector_logger.info(
                        f"[ALERTS] Sent keyword batch Report: {report_name}"
                    )
                except Exception as exc:
                    self.helper.connector_logger.error(
                        f"[ALERTS] Batch Report flush failed for "
                        f"date={date_str}: {exc}"
                    )

            self.helper.connector_logger.info(
                f"[ALERTS] Complete — IR: {ir_count}, "
                f"keyword batch: {keyword_count}, skipped: {skip_count}"
            )
            self.helper.api.work.to_processed(
                work_id,
                f"Alerts complete — IR: {ir_count}, "
                f"keyword: {keyword_count}, skipped: {skip_count}",
            )
            # Advance cursor only on full dataset success.
            self._set_cursor(_STATE_ALERTS, now_iso)

        except Exception as exc:
            self.helper.connector_logger.error(
                f"[ALERTS] Dataset fetch failed: {exc}"
            )
            self.helper.api.work.to_processed(
                work_id, f"Alerts failed: {exc}"
            )

    def _import_communities(self) -> None:
        """
        Search Flashpoint dark web community posts and ingest results.

        ONE QUERY PER DAILY BATCH REPORT:
        Each configured query term produces its own independent set of
        daily batch Reports. Results from different queries are not mixed —
        "cybersecurity" hits and "ransomware" hits go into separate Reports.
        This allows analysts to filter by query topic and maintains clear
        provenance (which query produced which content).

        QUERY SANITISATION:
        Query terms are sanitised for use in Report names by replacing
        forward and back slashes. This prevents unintended path separators
        in the deterministic Report name.

        CHANNEL → PUBLISHES → TEXT NOTE:
        The 'publishes' relationship type between Channel and Text is
        emitted by the converter. If the OpenCTI platform's worker does
        not support this relationship type for these entity types, it will
        reject only that edge — the rest of the bundle (Channel, Persona,
        Text, and other relationships) will still land. The rejection will
        appear in worker logs, not here. Check worker logs after the first
        communities run to confirm whether 'publishes' is accepted.

        PERSONA NOTE:
        CustomObservablePersona is imported inside the converter. If this
        custom observable type is not available in pycti==6.9.13, Persona
        creation will fail with a warning per-result, and the Text observable
        will receive a floor relationship to the Flashpoint identity instead.
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        start_date = parse(self._get_cursor(_STATE_COMMUNITIES)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"Flashpoint Communities @ {now_iso}",
        )
        try:
            total_results = 0

            for query in self.config.communities_queries:
                self.helper.connector_logger.info(
                    f"[COMMUNITIES] Processing query: '{query}' "
                    f"since {start_date}"
                )

                # Fetch all posts matching this query since the cursor.
                try:
                    results = self.client.communities_search(query, start_date)
                except Exception as exc:
                    self.helper.connector_logger.error(
                        f"[COMMUNITIES] Search API call failed for "
                        f"query '{query}': {exc}"
                    )
                    # Continue to next query — don't fail the entire dataset.
                    continue

                self.helper.connector_logger.info(
                    f"[COMMUNITIES] Query '{query}': {len(results)} results"
                )

                # Bucket results by post date for daily batch Reports.
                # {date_str: [stix_objects]}
                query_buckets: dict = {}

                for result in results:
                    # Extract post date for bucketing.
                    result_date = result.get("date") or ""
                    try:
                        date_str = parse(result_date).strftime("%Y-%m-%d")
                    except Exception:
                        # Fall back to today if date is unparseable.
                        date_str = datetime.datetime.now(
                            datetime.timezone.utc
                        ).strftime("%Y-%m-%d")

                    if date_str not in query_buckets:
                        query_buckets[date_str] = []

                    try:
                        objects = self.converter.convert_communities_result(
                            result, query
                        )
                        query_buckets[date_str].extend(objects)
                        total_results += 1
                    except Exception as exc:
                        self.helper.connector_logger.error(
                            f"[COMMUNITIES] Conversion failed for result "
                            f"id={result.get('id', '?')}: {exc}"
                        )

                # ── Flush daily batch Reports for this query ──────────────────
                for date_str, objects in sorted(query_buckets.items()):
                    try:
                        # Sanitise query for Report name — slashes would
                        # be interpreted as path separators in some contexts.
                        safe_query = query.replace("/", "-").replace("\\", "-")
                        report_name = (
                            f"Flashpoint Communities [{safe_query}] — {date_str}"
                        )
                        report_obj = self.converter.build_daily_report(
                            name=report_name,
                            date_str=date_str,
                            member_objects=objects,
                            confidence=self.config.communities_confidence,
                        )
                        all_objects = (
                            [self.converter.marking] + objects + [report_obj]
                        )
                        self._send_bundle(work_id, all_objects)
                        self.helper.connector_logger.info(
                            f"[COMMUNITIES] Sent batch Report: {report_name}"
                        )
                    except Exception as exc:
                        self.helper.connector_logger.error(
                            f"[COMMUNITIES] Batch Report flush failed "
                            f"query='{query}' date={date_str}: {exc}"
                        )

            self.helper.connector_logger.info(
                f"[COMMUNITIES] Complete — {total_results} results "
                f"across {len(self.config.communities_queries)} queries."
            )
            self.helper.api.work.to_processed(
                work_id,
                f"Communities complete — {total_results} results",
            )
            # Advance cursor only after all queries processed successfully.
            self._set_cursor(_STATE_COMMUNITIES, now_iso)

        except Exception as exc:
            self.helper.connector_logger.error(
                f"[COMMUNITIES] Dataset failed: {exc}"
            )
            self.helper.api.work.to_processed(
                work_id, f"Communities failed: {exc}"
            )

    def _import_credentials(self) -> None:
        """
        Import Flashpoint compromised credential records.

        !! NOT IMPLEMENTED — STUB ONLY !!

        This method exists as a stub so that:
          1. import_credentials=True in config does not crash the connector
          2. The intended behaviour is documented in code
          3. The missing implementation is clearly visible in logs

        The stub logs a warning and returns without advancing the cursor
        or making any API calls. The credentials_last_run cursor is never
        set, so when the implementation is complete, the connector will
        automatically backfill from import_start_date on its first real run.

        WHAT THIS METHOD WILL DO ONCE IMPLEMENTED:
          1. Read credentials_last_run cursor
          2. Fetch credential records from Flashpoint API since cursor
          3. For each record:
               - Check if email/domain matches org_domains
               - Org match → create IR container + Incident + Observables
               - No match → accumulate in daily batch Report
          4. Flush non-org daily batch Reports
          5. Advance credentials_last_run cursor

        WHAT IS BLOCKING IMPLEMENTATION:
          The Flashpoint Compromised Credentials API endpoint path, date
          filter parameter name, pagination style, and response field
          schema are not yet confirmed from docs.flashpoint.io.
          See CONNECTOR_SCOPE.md open items.
        """
        self.helper.connector_logger.warning(
            "[CREDENTIALS] _import_credentials() is not yet implemented. "
            "The Flashpoint Compromised Credentials endpoint path, "
            "date filter parameter, pagination style, and response schema "
            "are pending confirmation from docs.flashpoint.io. "
            "Skipping credentials import this run. "
            "The credentials cursor is NOT advanced — the connector will "
            "retry from import_start_date once the implementation is complete. "
            "To suppress this warning, set FLASHPOINT_IMPORT_CREDENTIALS=false."
        )
        # Intentionally no cursor advancement here.
        # When the implementation is complete, the cursor will be set to
        # now_iso after a successful full credentials run, just like the
        # other datasets.

    # =========================================================================
    # Main process
    # =========================================================================

    def process_data(self) -> None:
        """
        Main connector execution method — called by the scheduler on each run.

        EXECUTION ORDER:
          1. Reports     — finished intelligence reports
          2. Alerts      — rule-based alert notifications
          3. Communities — dark web forum search results
          4. Credentials — compromised credentials (stub)

        ISOLATION:
        Each dataset dispatcher is called inside its own try/except block.
        A failure in one dataset (API error, conversion error, send error)
        is logged and the next dataset proceeds. This ensures a transient
        API error for one endpoint does not prevent ingestion of other
        datasets in the same run.

        CURSOR ADVANCEMENT:
        Each dispatcher advances its own cursor only on successful completion.
        If a dispatcher raises an unhandled exception before reaching its
        _set_cursor() call, the cursor is not advanced and the next run
        will re-fetch from the same start position for that dataset.

        KEYBOARD INTERRUPT:
        Caught explicitly to allow graceful shutdown. The connector logs
        the stop event and exits cleanly rather than leaving the work item
        in an open state.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting run.",
            {"connector_name": self.helper.connect_name},
        )

        try:
            if self.config.import_reports:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Reports dataset enabled — starting."
                )
                self._import_reports()
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Reports dataset disabled — skipping."
                )

            if self.config.import_alerts:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Alerts dataset enabled — starting."
                )
                self._import_alerts()
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Alerts dataset disabled — skipping."
                )

            if self.config.import_communities:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Communities dataset enabled — starting."
                )
                self._import_communities()
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Communities dataset disabled — skipping."
                )

            if self.config.import_credentials:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Credentials dataset enabled — running stub."
                )
                self._import_credentials()
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Credentials dataset disabled — skipping."
                )

            self.helper.connector_logger.info(
                "[CONNECTOR] Run complete.",
                {"connector_name": self.helper.connect_name},
            )

        except (KeyboardInterrupt, SystemExit):
            # Graceful shutdown — log and exit cleanly.
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped by interrupt.",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)

        except Exception as exc:
            # Catch-all for unexpected errors in the orchestration layer.
            # Individual dataset dispatchers have their own try/except, so
            # this should only fire for errors in process_data itself.
            self.helper.connector_logger.error(
                f"[CONNECTOR] Unhandled error in process_data: {exc}"
            )

    def run(self) -> None:
        """
        Start the connector's scheduling loop.

        schedule_iso() calls process_data() on the configured interval
        (CONNECTOR_DURATION_PERIOD, ISO-8601 format, e.g. PT6H).
        The scheduler also monitors the connector's work queue depth — if
        the queue exceeds CONNECTOR_QUEUE_THRESHOLD (default 500MB), the
        scheduler skips the next run until the queue drains. This prevents
        the connector from overwhelming the OpenCTI worker under high load.

        This method blocks indefinitely — the connector runs until the
        container is stopped.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Flashpoint connector starting.",
            {"connector_name": self.helper.connect_name},
        )
        self.helper.schedule_iso(
            message_callback=self.process_data,
            duration_period=self.config.duration_period,
        )
