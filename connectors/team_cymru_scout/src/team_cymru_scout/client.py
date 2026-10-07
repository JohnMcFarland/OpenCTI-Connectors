import json
from urllib.parse import quote

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

_BASE_URL = "https://scout.cymru.com"


class TeamCymruScoutClient:

    def __init__(self, helper: OpenCTIConnectorHelper, api_key: str) -> None:
        self.helper = helper
        self.headers = {
            "Authorization": f"Token {api_key}",
            "Accept": "application/json",
        }

        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", adapter)

    def _get(self, url: str, params: dict = None) -> dict | None:
        try:
            response = self.session.get(
                url, headers=self.headers, params=params, timeout=60,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.helper.log_error(f"[TeamCymruScout] HTTP error: {e}")
            self.helper.metric.inc("client_error_count")
            return None
        except requests.exceptions.ConnectionError as e:
            self.helper.log_error(f"[TeamCymruScout] Connection error: {e}")
            self.helper.metric.inc("client_error_count")
            return None
        except requests.exceptions.Timeout as e:
            self.helper.log_error(f"[TeamCymruScout] Timeout: {e}")
            self.helper.metric.inc("client_error_count")
            return None
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"[TeamCymruScout] Request error: {e}")
            self.helper.metric.inc("client_error_count")
            return None

        try:
            return response.json()
        except json.JSONDecodeError as e:
            self.helper.log_error(
                f"[TeamCymruScout] JSON decode error: {e} — {response.text[:200]}"
            )
            self.helper.metric.inc("client_error_count")
            return None

    def get_ip_details(self, ip: str) -> dict | None:
        """Full IP enrichment via Details API (4 query credits)."""
        return self._get(f"{_BASE_URL}/api/scout/ip/{quote(ip, safe='')}/details")

    def get_ip_foundation(self, ip: str) -> dict | None:
        """Lightweight IP enrichment via Foundation API (1 foundation credit)."""
        data = self._get(f"{_BASE_URL}/api/scout/ip/foundation", params={"ips": ip})
        if data and data.get("data"):
            return data["data"][0]
        return None

    def search(self, query: str, size: int = 20) -> dict | None:
        """Search for IPs related to a domain or IP query."""
        return self._get(
            f"{_BASE_URL}/api/scout/search",
            params={"query": query, "size": size},
        )

    def get_usage(self) -> dict | None:
        """Return current query usage and limits."""
        return self._get(f"{_BASE_URL}/api/scout/usage")
