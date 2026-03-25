# =============================================================================
# flashpoint_connector/client_api.py
# =============================================================================
# Flashpoint Ignite REST API client.
#
# Responsibilities:
#   - Manage authentication (Bearer token via session header)
#   - Handle all pagination internally — callers receive complete result lists
#   - Raise requests.HTTPError on non-2xx responses (callers catch these)
#   - Log pagination progress at DEBUG level for operational visibility
#
# BASE URL: https://api.flashpoint.io
# AUTH:     Authorization: Bearer {api_key}
#
# ENDPOINTS IMPLEMENTED:
#   /finished-intelligence/v1/reports         — Finished Intel Reports
#   /alert-management/v1/notifications        — Alerts
#   /sources/v2/communities                   — Communities search (POST)
#   /sources/v2/communities/{id}              — Single community doc
#   /sources/v2/media/{id}                    — Media doc metadata
#   /sources/v1/media                         — Media binary content
#
# ENDPOINTS STUBBED (not yet implemented):
#   Compromised Credentials                   — path TBD (see CONNECTOR_SCOPE.md)
#
# PAGINATION PATTERNS:
#   Reports:     offset/skip. Stop when len(collected) == response["total"].
#   Alerts:      cursor-based via pagination.next URL. Follow verbatim.
#   Communities: page integer in POST body. Stop when len(collected) >= total.
#
# DEVIATION FROM FILIGRAN:
# This module retains the same endpoint paths and pagination logic from the
# Filigran upstream connector, which were correct. The only changes are:
#   - Added comprehensive docstrings and inline comments
#   - Added DEBUG-level pagination logging for operational visibility
#   - get_credentials() stub added (was absent in Filigran entirely)
#   - BASE_URL extracted to class constant rather than inline string
# =============================================================================

import base64

import requests


class ConnectorClient:
    """
    HTTP client for the Flashpoint Ignite API.

    All methods handle pagination internally and return complete result lists.
    Authentication is configured once at construction via a requests.Session
    with the Authorization header set globally — individual methods do not
    handle auth.

    Error handling: all methods call response.raise_for_status() which raises
    requests.HTTPError on 4xx/5xx. Callers (connector dispatchers) are
    responsible for catching these and deciding whether to skip, retry, or
    abort the run for that dataset.
    """

    # The base URL for all Flashpoint Ignite API endpoints.
    # Extracted as a class constant so it can be patched in tests and is
    # not scattered across individual method strings.
    BASE_URL = "https://api.flashpoint.io"

    def __init__(self, helper, config):
        """
        Initialise the client and configure the requests session.

        :param helper: OpenCTIConnectorHelper instance for logging
        :param config: ConfigConnector instance for api_key
        """
        self.helper = helper
        self.config = config

        # Use a requests.Session so the Authorization header and any
        # connection pooling are shared across all requests in a run.
        # This is more efficient than creating a new connection per request
        # and ensures the token is always present without explicit handling
        # in each method.
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                # Flashpoint uses Bearer token authentication for all endpoints.
                # The token is generated in Flashpoint Ignite under
                # Settings → APIs & Integrations.
                "Authorization": "Bearer " + self.config.api_key,
            }
        )

    # =========================================================================
    # Finished Intelligence Reports
    # =========================================================================

    def get_reports(self, start_date: str) -> list:
        """
        Fetch all finished intelligence reports updated since start_date.

        ENDPOINT: GET /finished-intelligence/v1/reports
        PAGINATION: offset/skip with limit=100 per page.
        STOP CONDITION: len(collected) == response["total"]

        The `since` parameter filters by updated_at, not created_at. This
        means reports that were edited after original publication will be
        re-fetched on the next run if their updated_at advances past the
        cursor. This is intentional — edited reports should be re-ingested
        to capture corrections. OpenCTI's upsert semantics handle this
        without creating duplicates; the existing Report is updated.

        sort=updated_at:asc ensures pages are stable during pagination —
        if new reports are published mid-page, they appear at the end rather
        than shifting earlier pages and causing missed records.

        embed=asset includes the report body content in the response,
        avoiding a second per-report API call to fetch full text.

        :param start_date: ISO8601 datetime string from reports_last_run cursor
        :return: list of report dicts, fully paginated
        """
        url = self.BASE_URL + "/finished-intelligence/v1/reports"

        # Page size of 100 is the maximum permitted by the Flashpoint API.
        # Using the maximum reduces the number of round trips for large backlogs.
        limit = 100
        params = {
            "since": start_date,
            "limit": limit,
            "skip": 0,                  # Will be incremented per page
            "sort": "updated_at:asc",   # Stable sort — new records at end
            "embed": "asset",           # Include body content in response
        }

        reports = []
        while True:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            total = data.get("total", 0)
            batch = data.get("data", [])
            reports.extend(batch)

            self.helper.connector_logger.debug(
                f"[API] Reports page skip={params['skip']}: "
                f"fetched={len(batch)}, collected={len(reports)}, total={total}"
            )

            # Stop when we have collected everything the API has for this window.
            # Using >= rather than == defensively — if the API returns more
            # items than total due to a race condition, we still stop correctly.
            if len(reports) >= total:
                break

            # Advance the offset for the next page.
            params["skip"] += limit

        return reports

    # =========================================================================
    # Alerts
    # =========================================================================

    def get_alerts(self, start_date: str) -> list:
        """
        Fetch all alert notifications created after start_date.

        ENDPOINT: GET /alert-management/v1/notifications
        PAGINATION: cursor-based via pagination.next URL.
        STOP CONDITION: pagination.next is absent or null.

        IMPORTANT: The next URL is followed verbatim — do not modify it or
        re-add params. The cursor is encoded into the URL by the Flashpoint
        API; adding params= to the follow-up request would corrupt the cursor
        and produce incorrect results or duplicate records.

        The created_after format requires microseconds (%Y-%m-%dT%H:%M:%S.%fZ)
        rather than the simpler ISO8601 used by other endpoints. Passing the
        wrong format results in a 400 error. The connector dispatcher formats
        the cursor appropriately before calling this method.

        :param start_date: datetime string formatted as %Y-%m-%dT%H:%M:%S.%fZ
        :return: list of alert notification dicts, fully paginated
        """
        url = self.BASE_URL + "/alert-management/v1/notifications"

        # Initial params — only used for the first request.
        # Subsequent requests use the next URL verbatim (params={}).
        params = {"created_after": start_date}

        alerts = []
        while True:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            batch = data.get("items", [])
            alerts.extend(batch)

            # The next URL is a fully-qualified URL with the cursor baked in.
            next_url = data.get("pagination", {}).get("next")

            self.helper.connector_logger.debug(
                f"[API] Alerts page: fetched={len(batch)}, "
                f"collected={len(alerts)}, has_next={bool(next_url)}"
            )

            if not next_url:
                # No next page — pagination complete.
                break

            # Follow the cursor URL verbatim for subsequent pages.
            # Clear params so the cursor encoded in next_url is not
            # overridden by re-applying the initial created_after filter.
            url = next_url
            params = {}

        return alerts

    # =========================================================================
    # Alert document enrichment
    # =========================================================================

    def get_communities_doc(self, doc_id: str) -> dict:
        """
        Fetch a single communities document by ID.

        Used during alert processing to enrich communities-source alerts
        with actor alias data and the container external URI (the URL of
        the forum thread or channel that triggered the alert). This data
        is not available in the alert notification itself — it requires
        a separate lookup against the source document.

        Called only for alerts where source == "communities".

        :param doc_id: Flashpoint document ID from alert["resource"]["id"]
        :return: document dict containing results.site_actor_alias and
                 results.container_external_uri
        """
        url = self.BASE_URL + "/sources/v2/communities/" + doc_id
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def get_media_doc(self, doc_id: str) -> dict:
        """
        Fetch metadata for a media document by ID.

        Used during alert processing to retrieve the storage_uri field,
        which is required to download the actual media binary via get_media().
        The media document metadata and the binary are separate API calls —
        this method fetches only the metadata.

        Called only for alerts where source == "media".

        :param doc_id: Flashpoint document ID from alert["resource"]["id"]
        :return: media document metadata dict (contains storage_uri)
        """
        url = self.BASE_URL + "/sources/v2/media/" + doc_id
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def get_media(self, media_id: str) -> tuple:
        """
        Fetch raw media binary content and return it base64-encoded.

        The media binary is base64-encoded here because OpenCTI's
        x_opencti_files custom property expects base64 data, and transmitting
        raw bytes through the STIX bundle serialisation layer is not reliable.

        cdn=False forces retrieval from Flashpoint's origin server rather
        than a CDN cache, ensuring the most current version of the asset
        is returned.

        :param media_id: storage_uri value from the media document metadata
        :return: tuple of (base64-encoded bytes, content-type string)
        """
        url = self.BASE_URL + "/sources/v1/media"
        response = self.session.get(
            url,
            params={
                "cdn": False,       # Fetch from origin, not CDN cache
                "asset_id": media_id,
            },
        )
        response.raise_for_status()
        return (
            base64.b64encode(response.content),
            # Fall back to a safe generic MIME type if Content-Type is absent.
            response.headers.get("Content-Type", "application/octet-stream"),
        )

    # =========================================================================
    # Communities search
    # =========================================================================

    def communities_search(self, query: str, start_date: str) -> list:
        """
        Search Flashpoint dark web community posts matching query since start_date.

        ENDPOINT: POST /sources/v2/communities
        PAGINATION: page integer in POST body. Size is fixed at 1000 (maximum).
        STOP CONDITION: len(collected) >= response["total"]["value"]

        This endpoint uses POST rather than GET because the query parameters
        are complex enough to require a JSON body. The page counter is part
        of the body, not a query parameter, which is why it must be incremented
        manually rather than using the next-URL cursor pattern.

        sort.date=asc ensures results are returned oldest-first. This is
        important for date bucketing in the connector — we want results grouped
        by the date they were posted, not the date they were ingested.

        The date filter uses include.date.start with an empty end, meaning
        "from start_date to now". Flashpoint accepts an empty string for the
        end boundary; do not pass null or omit the key.

        :param query: keyword search string (e.g. "ransomware", "CVE-2024-1234")
        :param start_date: ISO8601 datetime string from communities_last_run cursor
        :return: list of community post dicts, fully paginated
        """
        url = self.BASE_URL + "/sources/v2/communities"

        # Page starts at 0 (zero-indexed).
        page = 0
        results = []

        while True:
            body = {
                "query": query,
                "include": {
                    "date": {
                        "start": start_date,
                        "end": "",          # Empty string = no end bound (up to now)
                    }
                },
                "size": "1000",             # Maximum page size; sent as string per API spec
                "sort": {"date": "asc"},    # Oldest first for stable date bucketing
                "page": page,
            }

            response = self.session.post(url, json=body)
            response.raise_for_status()
            data = response.json()

            batch = data.get("items", [])
            results.extend(batch)

            # total is nested: {"value": int, "relation": "eq"/"gte"}
            total = data.get("total", {}).get("value", 0)

            self.helper.connector_logger.debug(
                f"[API] Communities page {page} query='{query}': "
                f"fetched={len(batch)}, collected={len(results)}, total={total}"
            )

            # >= rather than == defensively handles the case where total is
            # an estimate ("relation": "gte") rather than an exact count.
            if len(results) >= total:
                break

            page += 1

        return results

    # =========================================================================
    # Compromised Credentials — STUB
    # =========================================================================

    def get_credentials(self, start_date: str) -> list:  # noqa: ARG002
        """
        Fetch compromised credential records since start_date.

        !! NOT IMPLEMENTED !!

        This method is a stub. It raises NotImplementedError unconditionally.
        It must not be called in production until the implementation is
        complete.

        What is needed before this can be implemented:
          1. Endpoint path (e.g. /compromised-credentials/v1/...)
          2. Date filter parameter name and expected format
          3. Pagination style (offset/skip like Reports, or cursor like Alerts)
          4. Response schema — specifically:
               - Field name carrying the email/username of the credential
               - Field name carrying the domain (for org-domain bifurcation)
               - Field name for the source type (stealer log, forum, marketplace)
               - Field name for the discovery/exposure timestamp
               - Field name for the source URL (if present)

        All of the above must be confirmed from docs.flashpoint.io before
        writing this method. See CONNECTOR_SCOPE.md open items.

        :param start_date: ISO8601 datetime string (unused until implemented)
        :raises NotImplementedError: always
        """
        raise NotImplementedError(
            "get_credentials() is not yet implemented. "
            "The Flashpoint Compromised Credentials endpoint path, "
            "date filter parameter, pagination style, and response schema "
            "must be confirmed from docs.flashpoint.io before this method "
            "can be built. See CONNECTOR_SCOPE.md open items."
        )
