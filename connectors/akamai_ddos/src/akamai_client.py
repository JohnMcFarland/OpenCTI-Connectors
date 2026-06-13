"""Akamai EdgeGrid HTTP client.

A single requests.Session signed with EdgeGrid auth, shared by both pollers,
with retry/backoff on transient failures and 429 handling. Credentials come
either from an .edgerc file or from the four discrete settings values.
"""

from __future__ import annotations

import requests
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import Settings


class AkamaiClient:
    def __init__(self, settings: Settings, logger) -> None:
        self.logger = logger
        self.session = requests.Session()

        if settings.akamai_edgerc_path:
            rc = EdgeRc(settings.akamai_edgerc_path)
            section = "default"
            self.base_url = f"https://{rc.get(section, 'host')}"
            self.session.auth = EdgeGridAuth.from_edgerc(rc, section)
        else:
            host = settings.akamai_host.replace("https://", "").rstrip("/")
            self.base_url = f"https://{host}"
            self.session.auth = EdgeGridAuth(
                client_token=settings.akamai_client_token,
                client_secret=settings.akamai_client_secret,
                access_token=settings.akamai_access_token,
            )

        retry = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)

    def get(self, path: str, params: dict | None = None, stream: bool = False) -> requests.Response:
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, params=params, stream=stream, timeout=120)
        resp.raise_for_status()
        return resp

    def get_json(self, path: str, params: dict | None = None) -> dict:
        return self.get(path, params=params).json()

    def iter_ndjson(self, path: str, params: dict | None = None):
        """Yield parsed JSON objects from an NDJSON stream (SIEM)."""
        import json

        with self.get(path, params=params, stream=True) as resp:
            for line in resp.iter_lines():
                if line:
                    yield json.loads(line)
