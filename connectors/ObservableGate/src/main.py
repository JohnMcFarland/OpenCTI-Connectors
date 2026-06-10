"""
main.py — ObservableGate Entry Point

Initializes configuration and the pycti connector helper, then starts
the polling loop. Configuration errors surface before the helper is
initialized, preventing partial startup against the platform.
"""

from pycti import OpenCTIConnectorHelper

from config import ObservableGateConfig
from connector import ObservableGateConnector


def main() -> None:
    """
    Load configuration, initialize the OpenCTI connector helper, and start
    the ObservableGate polling loop.

    Uses the dict-based pycti config initialization to keep all configuration
    in environment variables, consistent with the connector delivery standard.
    No config.yml file is required or expected.

    The connector type is EXTERNAL_IMPORT: it runs on a self-managed schedule
    rather than responding to platform entity events. duration_period is set
    from GATE_POLL_INTERVAL for visibility in the platform UI, but the actual
    polling loop is managed internally by connector.run().
    """
    # Load and validate all configuration from environment variables.
    # Raises ValueError on any missing required variable before the helper
    # is initialized, ensuring the connector does not start with a broken config.
    config = ObservableGateConfig()

    opencti_config = {
        "opencti": {
            "url": config.opencti_base_url,
            "token": config.opencti_token,
        },
        "connector": {
            "id": config.connector_id,
            "type": "EXTERNAL_IMPORT",
            "name": config.connector_name,
            "scope": config.connector_scope,
            "log_level": config.connector_log_level,
            # Informs the platform UI of the poll cadence. The actual interval
            # is enforced by the time.sleep() in connector.run(), not by pycti.
            "duration_period": f"PT{config.poll_interval}S",
        },
    }

    helper = OpenCTIConnectorHelper(opencti_config)
    connector = ObservableGateConnector(helper, config)
    connector.run()


if __name__ == "__main__":
    main()
