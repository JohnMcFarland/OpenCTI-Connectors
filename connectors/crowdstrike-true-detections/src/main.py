import os
import sys
import time

import yaml

from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
)

from crowdstrike_detections import CrowdStrikeDetectionsConnector


class CrowdStrikeTrueDetectionsConnector(CrowdStrikeDetectionsConnector):
    """CrowdStrike True Positive Detections Connector"""

    def __init__(self):
        """
        Instantiates the connector from the config.

        Args:
            self
        Returns:
            None
        """
        base_path = os.path.dirname(os.path.abspath(__file__))
        #  Instantiate the connector helper from config
        config_file_path = base_path + "/config.yml"
        config = (
            yaml.safe_load(open(config_file_path))
            if os.path.isfile(config_file_path)
            else {}
        )

        helper = OpenCTIConnectorHelper(config)

        interval = get_config_variable(
            "CROWDSTRIKE_TRUE_DETECTIONS_INTERVAL",
            ["crowdstrike_true_detections", "interval"],
            config,
            True,
            1,
        )

        organization_name = get_config_variable(
            "CROWDSTRIKE_TRUE_DETECTIONS_ORGANIZATION_NAME",
            ["crowdstrike_true_detections", "organization_name"],
            config,
        )

        client_id = get_config_variable(
            "CROWDSTRIKE_TRUE_DETECTIONS_CLIENT_ID",
            ["crowdstrike_true_detections", "client_id"],
            config,
        )

        client_secret = get_config_variable(
            "CROWDSTRIKE_TRUE_DETECTIONS_CLIENT_SECRET",
            ["crowdstrike_true_detections", "client_secret"],
            config,
        )

        sleep_seconds = 900

        organizations_marking_definition_types = get_config_variable(
            "CROWDSTRIKE_TRUE_DETECTIONS_ORGANIZATIONS_MARKING_DEFINITIONS",
            ["crowdstrike_true_detections", "organizations_marking_definitions"],
            config,
            False,
        )

        attack_patterns_marking_definition_types = get_config_variable(
            "CROWDSTRIKE_TRUE_DETECTIONS_ATTACK_PATTERNS_MARKING_DEFINITIONS",
            ["crowdstrike_true_detections", "attack_patterns_marking_definitions"],
            config,
            False,
        )

        default_marking_definition_types = get_config_variable(
            "CROWDSTRIKE_TRUE_DETECTIONS_DEFAULT_MARKING_DEFINITIONS",
            ["crowdstrike_true_detections", "default_marking_definitions"],
            config,
            False,
        )

        super().__init__(
            helper,
            organization_name,
            False,
            client_id,
            client_secret,
            interval,
            sleep_seconds,
            organizations_marking_definition_types,
            attack_patterns_marking_definition_types,
            default_marking_definition_types,
        )

        helper.log_info(f"[{type(self).__name__}] Constructed.")


if __name__ == "__main__":
    try:
        connector = CrowdStrikeTrueDetectionsConnector()
        connector.run()
    except RuntimeError as e:
        print("RunTimeError Received, Connector shutting down.")
        print("Runtime error:" + e)
        time.sleep(10)
        sys.exit(0)
