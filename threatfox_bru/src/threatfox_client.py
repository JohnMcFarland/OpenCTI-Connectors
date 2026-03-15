"""ThreatFox API client."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List

import requests

from . import config

logger = logging.getLogger(__name__)


class ThreatFoxClient:

    def __init__(self, api_url: str = None, auth_key: str = None):
        self._api_url = api_url or config.THREATFOX_API_URL
        self._auth_key = auth_key or config.THREATFOX_AUTH_KEY

    def get_iocs(self, days: int = None) -> Dict[str, List[dict]]:
        days = min(days or config.THREATFOX_DEFAULT_DAYS, config.THREATFOX_MAX_DAYS)
        payload = {"query": "get_iocs", "days": days}
        headers = {}
        if self._auth_key:
            headers["Auth-Key"] = self._auth_key

        logger.info("Fetching ThreatFox IOCs for the last %d days...", days)
        resp = requests.post(self._api_url, json=payload, headers=headers, timeout=120)
        resp.raise_for_status()

        data = resp.json()
        query_status = data.get("query_status", "")

        if query_status == "no_result":
            logger.warning("ThreatFox returned no results for %d days", days)
            return {}

        if query_status != "ok":
            raise RuntimeError(f"ThreatFox API error: query_status={query_status}")

        raw_iocs = data.get("data", [])
        result: Dict[str, List[dict]] = {}
        for ioc in raw_iocs:
            ioc_id = str(ioc.get("id", ""))
            if not ioc_id:
                continue
            result.setdefault(ioc_id, []).append(ioc)

        logger.info("Fetched %d IOC entries (%d unique IDs)", len(raw_iocs), len(result))
        return result

    @staticmethod
    def load_from_file(file_path: str) -> Dict[str, List[dict]]:
        path = Path(file_path)
        logger.info("Loading ThreatFox data from %s", path)
        with open(path) as f:
            data = json.load(f)

        if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
            raw_iocs = data["data"]
            result: Dict[str, List[dict]] = {}
            for ioc in raw_iocs:
                ioc_id = str(ioc.get("id", ""))
                if not ioc_id:
                    continue
                result.setdefault(ioc_id, []).append(ioc)
            logger.info("Loaded %d IOC entries from API response format", len(raw_iocs))
            return result

        if isinstance(data, dict):
            logger.info("Loaded %d IOC IDs from structured format", len(data))
            return data

        raise ValueError(f"Unsupported JSON format in {file_path}")
