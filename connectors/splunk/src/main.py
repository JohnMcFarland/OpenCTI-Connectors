"""Entrypoint: load settings + searches, build the OpenCTI helper, start the connector."""

from __future__ import annotations

import sys
import traceback

from pycti import OpenCTIConnectorHelper

from .config import load_settings
from .connector import SplunkConnector
from .searches import load_searches


def main() -> None:
    settings = load_settings()
    searches = load_searches(settings.splunk_searches_file)  # validate before registering
    helper = OpenCTIConnectorHelper(
        {
            "opencti": {"url": settings.opencti_url, "token": settings.opencti_token},
            "connector": {
                "id": settings.connector_id,
                "type": "EXTERNAL_IMPORT",
                "name": settings.connector_name,
                "scope": settings.connector_scope,
                "duration_period": settings.connector_duration_period,
                "log_level": settings.connector_log_level,
            },
        }
    )
    SplunkConnector(helper, settings, searches).run()


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
