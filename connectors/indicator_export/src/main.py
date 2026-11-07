"""Entrypoint: validate settings, then start the connector."""

from __future__ import annotations

import sys
import traceback

from pycti import OpenCTIConnectorHelper

from .config import load_settings
from .connector import IndicatorExportConnector
from .opencti_client import OpenCTIClient
from .sinks import build_sink
from .store import StateStore


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
    store = StateStore(helper)
    client = OpenCTIClient(helper, settings.author_name, settings.dry_run)
    sink = build_sink(settings, store)
    IndicatorExportConnector(helper, settings, client, store, sink).run()


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
