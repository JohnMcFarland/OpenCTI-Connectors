"""Entrypoint: load settings, build the OpenCTI helper, start the connector."""

from __future__ import annotations

import sys
import traceback

from pycti import OpenCTIConnectorHelper

from .config import load_settings
from .connector import AkamaiDdosConnector


def main() -> None:
    settings = load_settings()
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
    AkamaiDdosConnector(helper, settings).run()


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
