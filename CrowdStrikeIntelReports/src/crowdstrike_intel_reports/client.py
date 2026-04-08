"""
CrowdStrike Falcon Intel API client.

Wraps FalconPy's Intel service class to provide paginated report querying and
synchronous PDF download for CrowdStrike Falcon Intelligence reports.

Token management (OAuth2 client credentials, refresh) is handled entirely by
FalconPy — this module does not need to manage tokens manually.

Required Falcon API scope: Reports (Falcon Intelligence): READ
"""

import datetime
from typing import Generator, Optional

from falconpy import Intel


class FalconIntelClient:
    """
    Thin wrapper around FalconPy's Intel service class.

    Exposes two operations used by the connector:
      - Paginated query of report entities since a given datetime.
      - Synchronous PDF download for a single report ID.

    All other Intel operations (actors, indicators, malware) are out of scope
    for this connector.
    """

    # Number of report entities to request per API call.
    # The combined endpoint supports up to 5000, but smaller pages are
    # preferable for memory efficiency and faster failure detection.
    PAGE_SIZE = 100

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "https://api.crowdstrike.com",
        timeout: int = 60,
    ):
        """
        Initialize the Falcon Intel API client.

        Args:
            client_id: Falcon API client ID. Must carry Reports (Falcon
                       Intelligence): READ scope.
            client_secret: Falcon API client secret.
            base_url: CrowdStrike API base URL. Defaults to US-1.
                      EU-1: https://api.eu-1.crowdstrike.com
                      US-2: https://api.us-2.crowdstrike.com
            timeout: HTTP request timeout in seconds. Applied to all calls,
                     including PDF downloads which may be large. Default: 60.
        """
        # FalconPy handles OAuth2 token acquisition and refresh automatically.
        # The timeout is passed at construction and applied to every request.
        self.intel = Intel(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            timeout=timeout,
        )

    def get_reports_since(
        self, since: datetime.datetime
    ) -> Generator[dict, None, None]:
        """
        Yield all report entity objects created on or after the given datetime.

        Uses the QueryIntelReportEntities combined endpoint
        (GET /intel/combined/reports/v1), which returns full entity objects
        in a single call — no separate entity hydration step required.

        Pagination: iterates using offset until fewer than PAGE_SIZE results
        are returned, indicating the final page.

        FQL filter: created_date:>='<unix_timestamp>' — CrowdStrike stores
        created_date as Unix seconds (integer).

        Results are returned in ascending created_date order so the
        high-water mark advances correctly even on partial/interrupted runs.

        Args:
            since: Lower bound datetime (inclusive). Timezone-aware recommended;
                   converted to UTC Unix timestamp for the FQL filter.

        Yields:
            dict: Full report entity objects from the API response.
                  Key fields: id, name, created_date, short_description,
                  url, type (dict: name/id/slug), sub_type (dict: name/id/slug).

        Raises:
            RuntimeError: If the API returns a non-200 status code.
        """
        # Convert datetime to integer Unix timestamp for FQL.
        since_ts = int(since.timestamp())
        fql_filter = f"created_date:>='{since_ts}'"

        offset = 0

        while True:
            response = self.intel.query_report_entities(
                filter=fql_filter,
                sort="created_date|asc",
                limit=self.PAGE_SIZE,
                offset=offset,
                fields=["__full__"],  # request all available fields per report
            )

            status_code = response.get("status_code")
            if status_code != 200:
                errors = response.get("body", {}).get("errors", [])
                raise RuntimeError(
                    f"[FalconIntelClient] query_report_entities failed with "
                    f"HTTP {status_code}: {errors}"
                )

            resources = response.get("body", {}).get("resources") or []

            if not resources:
                # Empty page — pagination complete.
                break

            for report in resources:
                yield report

            if len(resources) < self.PAGE_SIZE:
                # Partial page — this is the last page.
                break

            # Advance offset for next page.
            offset += len(resources)

    def get_report_pdf(self, report_id: str) -> Optional[bytes]:
        """
        Download the PDF attachment for a given CrowdStrike report ID.

        Calls GetIntelReportPDF (GET /intel/entities/report-files/v1).
        This endpoint returns the pre-rendered PDF as raw application/octet-stream
        bytes in a single synchronous call — no async execution pipeline or
        polling required.

        This is distinct from the ReportExecutions service (ScheduledReports),
        which is for user-created scheduled dashboard exports, not Intel reports.

        Args:
            report_id: The CrowdStrike internal report ID (integer string,
                       from the id field on the report entity).

        Returns:
            bytes: Raw PDF content ready to be base64-encoded and attached.
                   Returns None only if the response is unexpectedly empty.

        Raises:
            RuntimeError: If the API returns an error response dict instead of
                          raw bytes (FalconPy returns a dict on HTTP errors).
        """
        response = self.intel.get_report_pdf(id=report_id)

        # FalconPy returns raw bytes for octet-stream endpoints on success.
        # On failure it returns a standard error dict.
        if isinstance(response, dict):
            status_code = response.get("status_code")
            errors = response.get("body", {}).get("errors", [])
            raise RuntimeError(
                f"[FalconIntelClient] get_report_pdf failed for report_id "
                f"'{report_id}' with HTTP {status_code}: {errors}"
            )

        # Guard against an unexpectedly empty bytes response.
        if not response:
            return None

        return response
