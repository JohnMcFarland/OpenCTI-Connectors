import datetime
import ipaddress
import itertools
import json
import ntpath
import time
import traceback

from falconpy import (
    Detects,
)
from pycti import OpenCTIConnectorHelper


def get_cti_severity(severity_string: str):
    """
    Helper method to convert CrowdStrike severity into an OpenCTI severity String.

    Args:
        severity_string (_str_) - The CrowdStrike severity string

    Returns:
        The OpenCTI severity String
    """
    lower_string = severity_string.lower()
    if lower_string == "informational":
        lower_string = "low"
    return lower_string


class CrowdStrikeDetectionsConnector:
    """CrowdStrike Detections Connector Base Class"""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        organization_name,
        is_false_positive,
        client_id,
        client_secret,
        run_interval,
        sleep_interval,
        organizations_marking_definition_types,
        attack_patterns_marking_definition_types,
        default_marking_definition_types,
    ):
        """
        Instantiates the connector from the config.

        Args:
            self
        Returns:
            None
        """

        self.helper = helper
        self.is_false_positive = is_false_positive
        self.detection_status = f"{str(not self.is_false_positive).lower()}_positive"

        self.interval = run_interval

        self.client_id = client_id

        self.client_secret = client_secret

        self.cti_author = self.get_author("Crowdstrike")

        self.cs_author = self.get_author("Crowdstrike Endpoint Detection")

        self.sleep_seconds = sleep_interval

        if organizations_marking_definition_types:
            organizations_marking_types_list = (
                organizations_marking_definition_types.split(",")
            )
            self.organizations_marking_definition_ids = [
                self.get_marking_definition_id(marking_definition)
                for marking_definition in organizations_marking_types_list
            ]
        else:
            self.organizations_marking_definition_ids = []

        if attack_patterns_marking_definition_types:
            attack_pattern_marking_types_list = (
                attack_patterns_marking_definition_types.split(",")
            )
            self.attack_pattern_marking_definition_ids = [
                self.get_marking_definition_id(marking_definition)
                for marking_definition in attack_pattern_marking_types_list
            ]
        else:
            self.attack_pattern_marking_definition_ids = []

        if default_marking_definition_types:
            default_marking_types_list = default_marking_definition_types.split(",")
            self.default_marking_definition_ids = [
                self.get_marking_definition_id(marking_definition)
                for marking_definition in default_marking_types_list
            ]
        else:
            self.default_marking_definition_ids = []

        self.organization_name = organization_name
        self.organization = self.get_organization(organization_name)

        self.helper.log_info(
            f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
            f"Constructed with the following configuration: "
            f"is_false_positive='{self.is_false_positive}' "
            f"detection_status='{self.detection_status}' "
            f"interval='{self.interval}' "
            f"client_id='{self.client_id}' "
            f"sleep_seconds='{self.sleep_seconds}' "
            f"organizations_marking_definition_ids='{self.organizations_marking_definition_ids}' "
            f"attack_pattern_marking_definition_ids='{self.attack_pattern_marking_definition_ids}' "
            f"default_marking_definition_ids='{self.default_marking_definition_ids}'"
        )

    def get_author(self, author_name):
        """
        Gets the STIX entity for the supplied author name from OpenCTI. If the author does not
         exist yet within OpenCTI, an exception is raised.

        Args:
            author_name _str_: The name of the author

        Returns:
            stix2.Identity: An Identity object for the author
        """
        if not author_name:
            raise ValueError(
                f"Inputted author_name was None or empty. "
                f"'author_name' = '{author_name}'"
            )

        _author = self.helper.api.identity.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": author_name}],
                "filterGroups": [],
            }
        )

        if _author is None:
            self.helper.log_error(
                f"[{type(self).__name__}].{CrowdStrikeDetectionsConnector.__name__} No existing "
                f"Author definition found for author name: "
                f"'{author_name}' "
            )
            raise ValueError(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"Initialization Error: "
                f"No Author definition exists in OpenCTI platform for author name: '{author_name}'"
            )

        return _author

    def get_marking_definition_id(self, marking_definition_string):
        """
        This method takes a marking definition string name and returns a corresponding OpenCTI
        Object. If the marking definition is not found, a ValueError is thrown as the marking
        definitions are required to be in the platform ahead of the connector runtime.

        Args:
            marking_definition_string (_str_) - The name of the marking definition

        Returns:
            The OpenCTI MarkingDefinition object
        """

        marking_definition = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": marking_definition_string}],
                "filterGroups": [],
            }
        )

        if marking_definition is None:
            self.helper.log_error(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] No existing "
                f"Marking definition found for "
                f"type: '{marking_definition_string}'"
            )
            raise ValueError(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"CrowdStrikeDetectionsConnector "
                f"Initialization Error: No marking definition exists in OpenCTI platform for type: "
                f"'{marking_definition_string}'"
            )
        else:
            marking_definition_id = marking_definition.get("standard_id")

        return marking_definition_id

    def get_organization(self, organization_name: str):
        """
        This method takes the configured tenant organization name and returns a corresponding
        OpenCTI Object. This method creates a new Organization Identity object in OpenCTI if one
        does not already exist.

        Args:
            organization_name (_str_) - The name of the tenant organization

        Returns:
            The OpenCTI Organization Identity object
        """
        organization = self.helper.api.identity.read(
            filters={
                "mode": "and",
                "filters": [
                    {"key": "entity_type", "values": "Organization"},
                    {"key": "name", "values": organization_name},
                ],
                "filterGroups": [],
            }
        )

        if organization is None:
            organization = self.helper.api.identity.create(
                type="Organization",
                name=organization_name,
                createdBy=self.cti_author.get("standard_id"),
                objectMarking=self.organizations_marking_definition_ids,
                confidence=self.helper.connect_confidence_level,
            )

        return organization

    def get_interval(self) -> int:
        """
        Description
        -----------
        Gets specified time in hours set in configuration file
        to wait for subsequent import and converts it to seconds.
        Returns
        ---------
        int: seconds
        """
        return int(self.interval) * 60 * 60

    def get_cti_system(self, system_name, device_id):
        """
        This method takes a system name based on the CrowdStrike detection and returns a
        corresponding OpenCTI Object. This method creates a new System Identity object in OpenCTI
        if one does not already exist.

        Args:
            system_name (_str_) - The name of the system
            device_id (_str_) - The CrowdStrike device id for the system

        Returns:
            The OpenCTI System Identity object
        """

        try:
            if not system_name:
                raise ValueError(
                    f"Inputted system_name was None or empty. "
                    f"'system_name' = '{system_name}'"
                )

            description = f"'device_id'='{device_id}'"
            system = self.helper.api.identity.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "entity_type", "values": "System"},
                        {"key": "name", "values": system_name},
                    ],
                    "filterGroups": [],
                }
            )

            if system is None:
                system = self.helper.api.identity.create(
                    type="System",
                    name=system_name,
                    createdBy=self.cs_author.get("standard_id"),
                    objectMarking=self.default_marking_definition_ids,
                    confidence=self.helper.connect_confidence_level,
                    description=description,
                )
            else:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                    f"existing cti_system found in OpenCTI= "
                    f"'{system}' "
                )

        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while creating cti_system: "
                f"system_name='{system_name}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            system = None

        return system

    def get_ip_address(self, address):
        """
        This method takes an IP address based on the CrowdStrike detection and returns a
        corresponding OpenCTI Object. This method creates a new IPv4-Addr stix_cyber_observable
        object in OpenCTI if one does not already exist.

        Args:
            address (_str_) - The IP address as a String

        Returns:
            The OpenCTI IPv4-Addr stix_cyber_observable object
        """
        try:
            if not address:
                raise ValueError(
                    f"Inputted address was None or empty. " f"'address' = '{address}'"
                )

            observable_type = "IPv4-Addr"

            observable_data = {"type": observable_type, "value": address}

            ip_address = self.helper.api.stix_cyber_observable.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "entity_type", "values": observable_type},
                        {"key": "value", "values": address},
                    ],
                    "filterGroups": [],
                }
            )

            if ip_address is None:
                ip_address = self.helper.api.stix_cyber_observable.create(
                    createdBy=self.cs_author.get("standard_id"),
                    objectMarking=self.default_marking_definition_ids,
                    observableData=observable_data,
                    confidence=self.helper.connect_confidence_level,
                )
            else:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                    f"existing ip_address found in OpenCTI= "
                    f"'{ip_address}' "
                )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] IP_address = "
                f"'{ip_address}' "
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting IP address with inputs: "
                f"address='{address}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            ip_address = None

        return ip_address

    def get_mac_address(self, mac_address):
        """
        This method takes a mac address based on the CrowdStrike detection and returns a
        corresponding OpenCTI Object. This method creates a new Mac-Addr stix_cyber_observable
        object in OpenCTI if one does not already exist.

        Args:
            mac_address (_str_) - The mac address

        Returns:
            The OpenCTI Mac-Addr stix_cyber_observable object
        """
        try:
            if not mac_address:
                raise ValueError(
                    f"Inputted mac_address was None or empty. "
                    f"'mac_address' = '{mac_address}'"
                )

            observable_type = "Mac-Addr"

            observable_data = {"type": observable_type, "value": mac_address}

            cti_mac_address = self.helper.api.stix_cyber_observable.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "entity_type", "values": observable_type},
                        {"key": "value", "values": mac_address},
                    ],
                    "filterGroups": [],
                }
            )

            if cti_mac_address is None:
                cti_mac_address = self.helper.api.stix_cyber_observable.create(
                    createdBy=self.cs_author.get("standard_id"),
                    objectMarking=self.default_marking_definition_ids,
                    observableData=observable_data,
                    confidence=self.helper.connect_confidence_level,
                )

            else:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                    f"existing {observable_type} found in OpenCTI= "
                    f"'{cti_mac_address}' "
                )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"{observable_type} = "
                f"'{cti_mac_address}' "
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting MAC address with inputs: "
                f"mac_address='{mac_address}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            cti_mac_address = None

        return cti_mac_address

    def get_domain_name(self, domain_name):
        """
        This method takes a domain name based on the CrowdStrike detection and returns a
        corresponding OpenCTI Object. This method creates a new Domain-Name stix_cyber_observable
        object in OpenCTI if one does not already exist.

        Args:
            domain_name (_str_) - The domain name

        Returns:
            The OpenCTI Domain-Name stix_cyber_observable object
        """
        try:
            if not domain_name:
                raise ValueError(
                    f"Inputted domain name was None or empty. "
                    f"'domain_name' = '{domain_name}'"
                )

            observable_type = "Domain-Name"

            observable_data = {"type": observable_type, "value": domain_name}

            cti_domain_name = self.helper.api.stix_cyber_observable.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "entity_type", "values": observable_type},
                        {"key": "value", "values": domain_name},
                    ],
                    "filterGroups": [],
                }
            )

            self.helper.log_info(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"{observable_type} = "
                f"'{cti_domain_name}' "
            )

            if cti_domain_name is None:
                cti_domain_name = self.helper.api.stix_cyber_observable.create(
                    createdBy=self.cs_author.get("standard_id"),
                    objectMarking=self.default_marking_definition_ids,
                    observableData=observable_data,
                    confidence=self.helper.connect_confidence_level,
                )
            else:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                    f"Existing "
                    f"{observable_type} exists for "
                    f"cti_domain_name='{cti_domain_name}'"
                )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"{observable_type} = "
                f"'{cti_domain_name}' "
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting Domain-name with inputs: "
                f"domain_name='{domain_name}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            cti_domain_name = None

        return cti_domain_name

    def create_stix_core_relationship(
        self, relationship_type, from_object, to_object, first_seen, last_seen
    ):
        """
        This method get a stix_core_relationship between two OpenCTI objects. This method creates
        a new stix_core_relationship object in OpenCTI if one does not already exist. For existing
        relationships, if the first_seen time is less than the start_time, then the start_time of
        the existing relationship is updated to be the first_seen time. For existing
        relationships, if the last_seen time is greater than the end_time, then the end_time of
        the existing relationship is updated to be the last_seen time.

        Args:
            relationship_type (_str_) - The type of stix_core_relationship as a String
            from_object (_dict_) - The from OpenCTI STIX object
            to_object (_dict_) - The to OpenCTI STIX object
            first_seen (_str_) - The first seen timestamp as a String
            last_seen (_str_) - The last seen timestamp as a String

        Returns:
            The OpenCTI stix_sighting_relationship object
        """
        try:
            if not from_object or not to_object:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] One of "
                    f"from_object or to_object is "
                    f"None or empty when creating a stix_core_relationship. "
                    f"from_object='{from_object}', "
                    f"to_object='{to_object}"
                )
                return None

            from_id = from_object.get("id")
            to_id = to_object.get("id")

            if from_id is None or to_id is None:
                raise ValueError(
                    f"STIX Core Relationship from_id or to_id is None: "
                    f"from_id = '{from_id}', to_id='{to_id}'"
                )

            if from_id == to_id:
                raise ValueError(
                    f"Cannot create relationship with the same source and target. "
                    f"from_id='{from_id}', to_id='{to_id}'"
                )

            relationship = self.helper.api.stix_core_relationship.read(
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
            )

            if last_seen and first_seen and (last_seen < first_seen):
                last_seen = first_seen

            if relationship is None:
                relationship = self.helper.api.stix_core_relationship.create(
                    fromId=from_id,
                    toId=to_id,
                    relationship_type=relationship_type,
                    start_time=first_seen,
                    stop_time=last_seen,
                    createdBy=self.cs_author.get("standard_id"),
                    objectMarking=self.default_marking_definition_ids,
                    confidence=self.helper.connect_confidence_level,
                )
            else:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Existing "
                    f"relationship found"
                    f" from '{from_id}' to '{to_id}'"
                )
                if first_seen and first_seen < relationship.get("start_time"):
                    self.helper.api.stix_core_relationship.update_field(
                        id=relationship.get("id"),
                        input={"key": "start_time", "value": first_seen},
                    )
                    self.helper.log_debug(
                        f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                        f"Existing relationship found"
                        f" from '{from_id}' to '{to_id}' with different start time"
                    )
                if last_seen and last_seen > relationship.get("stop_time"):
                    self.helper.api.stix_core_relationship.update_field(
                        id=relationship.get("id"),
                        input={"key": "stop_time", "value": last_seen},
                    )
                    self.helper.log_debug(
                        f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                        f"Existing relationship found"
                        f" from '{from_id}' to '{to_id}' with different end time"
                    )
        except (AttributeError, ValueError) as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] An error "
                f"occurred while trying to create a core relationship"
                f" with the following parameters: "
                f"relationship_type='{relationship_type}', "
                f"from_object:'{from_object}', "
                f"to_object:'{to_object}', "
                f"first_seen:'{first_seen}', "
                f"last_seen:'{last_seen}', "
                f"Exception:'{_err}', "
                f"StackTrace:'{traceback.format_exc()}'."
            )
            relationship = None

        return relationship

    def get_attack_pattern(self, attack_pattern_name: str, attack_pattern_id: str):
        """
        This method takes an AttackPattern name and AttackPattern id based on the CrowdStrike
        detection tactic/techniques and returns a corresponding OpenCTI Object. This method creates
        a new AttackPattern object in OpenCTI if one does not already exist.

        Args:
            attack_pattern_name (_str_) - The name of the AttackPattern
            attack_pattern_id (_str_) - The id of the AttackPattern to use as the x_mitre_id

        Returns:
            The OpenCTI AttackPattern object
        """
        try:
            if not attack_pattern_id:
                raise ValueError(
                    f"Inputted attack_pattern_id was None or empty. "
                    f"'attack_pattern_id' = '{attack_pattern_id}'"
                )

            attack_pattern = self.helper.api.attack_pattern.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "x_mitre_id", "values": attack_pattern_id}],
                    "filterGroups": [],
                }
            )

            if attack_pattern is None:
                attack_pattern = self.helper.api.attack_pattern.create(
                    createdBy=self.cs_author.get("standard_id"),
                    objectMarking=self.attack_pattern_marking_definition_ids,
                    name=attack_pattern_name,
                    x_mitre_id=attack_pattern_id,
                    confidence=self.helper.connect_confidence_level,
                )
            else:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                    f"Existing "
                    f"attack_pattern exists for "
                    f"attack_pattern='{attack_pattern}'"
                )

        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] An error "
                f"occurred while trying to get an attack pattern "
                f" with the following parameters: "
                f"attack_pattern_name:'{attack_pattern_name}', "
                f"attack_pattern_id:'{attack_pattern_id}', "
                f"Exception:'{_err}', "
                f"StackTrace:'{traceback.format_exc()}'."
            )
            attack_pattern = None

        return attack_pattern

    def create_sighting_relationship(
        self, from_object, to_object, first_seen, last_seen
    ):
        """
        This method creates a sighting relationship between two OpenCTI objects.

        Args:
            from_object (_dict_) - The from OpenCTI STIX object
            to_object (_dict_) - The to OpenCTI STIX object
            first_seen (_str_) - The first seen timestamp as a String
            last_seen (_str_) - The last seen timestamp as a String

        Returns:
            The OpenCTI stix_sighting_relationship object
        """
        try:
            if not from_object or not to_object:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] One of "
                    f"from_object or to_object is "
                    f"None or empty when creating a sighting_relationship. "
                    f"from_object='{from_object}', "
                    f"to_object='{to_object}"
                )
                return None

            from_id = from_object.get("id")
            to_id = to_object.get("id")

            if from_id is None or to_id is None:
                raise ValueError(
                    f"Sighting Relationship from_id or to_id is None: "
                    f"from_id = '{from_id}', to_id='{to_id}'"
                )

            if from_id == to_id:
                raise ValueError(
                    f"Cannot create sighting relationship with the same source and target. "
                    f"from_id='{from_id}', to_id='{to_id}'"
                )

            # if relationship is None:
            relationship = self.helper.api.stix_sighting_relationship.create(
                fromId=from_id,
                toId=to_id,
                first_seen=first_seen,
                last_seen=last_seen,
                createdBy=self.cs_author.get("standard_id"),
                objectMarking=self.default_marking_definition_ids,
                confidence=self.helper.connect_confidence_level,
                x_opencti_negative=self.is_false_positive,
                count=1,
            )
        except (AttributeError, ValueError) as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] An error "
                f"occurred while trying to create a sighting relationship"
                f" with the following parameters: "
                f"from_object:'{from_object}', "
                f"to_object:'{to_object}', "
                f"first_seen:'{first_seen}', "
                f"last_seen:'{last_seen}', "
                f"Exception:'{_err}', "
                f"StackTrace:'{traceback.format_exc()}'."
            )
            relationship = None

        return relationship

    def query_crowdstrike(self, client_id, client_secret, search_time):
        """
        This method takes queries the CrowdStrike API to get the detections and detection
        information since a given timestamp.

        Args:
            client_id (_str_) - The CrowdStrike client_id
            client_secret (_str_) - The CrowdStrike client_secret
            search_time (_str_) - The time to search since as a String

        Returns:
            A list of detections
        """

        falcon_detects = Detects(client_id=client_id, client_secret=client_secret)
        search_filter = (
            f"status:'{self.detection_status}'+date_updated:>'{search_time}'"
        )
        self.helper.log_info(
            f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] search_filter: "
            f"'{search_filter}' "
        )
        # the get_detect_summaries API takes a max of 1000 Detection Ids. There should never be
        # 1000 detections within a run window but if there are we may want to alert because it
        # means there could be more than 1000 and some are getting dropped.
        detects_limit = 9999
        response = falcon_detects.QueryDetects(
            filter=search_filter, limit=detects_limit
        )
        resources = response.get("body", {}).get("resources", [])

        if len(resources) != 0:
            if len(resources) >= detects_limit:
                self.helper.log_warning(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] There were "
                    f"'{len(resources)}' {self.detection_status} detections since: "
                    f"'{search_time}'. The limit on the amount of detections"
                    f"is '{detects_limit}', meaning more detections may have "
                    f"occurred in that time and some may not have been "
                    f"processed."
                )

            self.helper.log_info(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"'{len(resources)}' "
                f"{self.detection_status} detections since: '{search_time}'"
            )

            detection_summaries = []

            for sublist in list_splitter(1000, resources):
                detect_res = falcon_detects.get_detect_summaries(ids=list(sublist))
                detection_summaries.extend(
                    detect_res.get("body", {}).get("resources", [])
                )

            return detection_summaries
        else:
            self.helper.log_info(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"'{len(resources)}' "
                f"{self.detection_status} detections since: '{search_time}'"
            )
            return []

    def get_file(self, sha256_value, md5_value, file_path, filename=None):
        """
        This method takes a sha256_value, md5_value, and file_path based on the CrowdStrike
        detection and returns a corresponding OpenCTI Object. This method creates a new File
        stix_cyber_observable object in OpenCTI if one does not already exist.

        Args:
            sha256_value (_str_) - The SHA256 hash of the file
            md5_value (_str_) - The MD5 hash of the file
            file_path (_str_) - The full file path
            filename (_str_) - The short filename of the file when no other data is given

        Returns:
            The OpenCTI File stix_cyber_observable object
        """
        parsed_file_name = None
        try:
            parsed_file_name = ntpath.basename(file_path)

            hashes = {}
            additional_names = set()
            name, search_filter = None, None

            if not sha256_value and not md5_value and not filename:
                raise ValueError(
                    f"Inputted sha256_value, md5_value, and filename were None None or empty. "
                    f"'sha256_value' = '{sha256_value}', "
                    f"'md5_value' = '{md5_value}', "
                    f"'filename'='{filename}'"
                )

            if sha256_value:
                hashes["SHA-256"] = sha256_value
                additional_names.add(sha256_value)
                name = sha256_value

            if not sha256_value and md5_value:
                hashes["MD5"] = md5_value
                additional_names.add(md5_value)
                name = md5_value

            if parsed_file_name:
                additional_names.add(parsed_file_name)

            if filename:
                additional_names.add(filename)

                if not sha256_value and not md5_value:
                    name = filename

            names_list = list(additional_names)
            names_list.sort()

            observable_data = {
                "type": "file",
                "name": name,
                "x_opencti_additional_names": names_list,
                "hashes": hashes,
                "x_opencti_description": "\n".join(names_list),
            }

            if sha256_value:
                search_filter = {"key": "hashes.SHA-256", "values": sha256_value}
            elif not sha256_value and md5_value:
                search_filter = {"key": "hashes.MD5", "values": md5_value}
            elif not sha256_value and not md5_value and filename:
                search_filter = {"key": "name", "values": filename}

            file = self.helper.api.stix_cyber_observable.read(
                filters={
                    "mode": "and",
                    "filters": [search_filter],
                    "filterGroups": [],
                }
            )

            if file is None:
                file = self.helper.api.stix_cyber_observable.create(
                    createdBy=self.cs_author.get("standard_id"),
                    objectMarking=self.default_marking_definition_ids,
                    observableData=observable_data,
                    confidence=self.helper.connect_confidence_level,
                )
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] new file = "
                    f"'{file}' "
                )

            else:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] existing "
                    f"file found= '{file}' "
                )

                x_opencti_additional_names = file.get("x_opencti_additional_names")

                if (
                    x_opencti_additional_names
                    and parsed_file_name not in x_opencti_additional_names
                ):
                    x_opencti_additional_names.append(parsed_file_name)
                    x_opencti_additional_names.sort()

                    update_id = file.get("id")
                    updated_object = self.helper.api.stix_cyber_observable.update_field(
                        id=update_id,
                        input={
                            "key": "x_opencti_additional_names",
                            "value": x_opencti_additional_names,
                        },
                    )

                    self.helper.log_debug(
                        f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                        f"updated object= '{updated_object}' "
                    )

                    updated_object = self.helper.api.stix_cyber_observable.update_field(
                        id=update_id,
                        input={
                            "key": "x_opencti_description",
                            "value": "\n".join(x_opencti_additional_names),
                        },
                    )
                    self.helper.log_debug(
                        f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                        f"updated object= '{updated_object}' "
                    )
        except ValueError as _verr:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting file with inputs: "
                f"sha256_value='{sha256_value}', "
                f"md5_value='{md5_value}', "
                f"parsed_file_name='{parsed_file_name}', "
                f"filename='{filename}', "
                f"Exception='{_verr}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            file = None

        return file

    def get_directory(self, file_path):
        """
        This method takes a file_path and file_name based on the CrowdStrike detection
        and returns a corresponding OpenCTI Object. This method creates a new Directory
        stix_cyber_observable object in OpenCTI if one does not already exist.

        Args:
            file_path (_str_) - The file path to get the directory from

        Returns:
            The OpenCTI Directory stix_cyber_observable object
        """

        try:
            if not file_path:
                raise ValueError(
                    f"Inputted file_path was None or empty. "
                    f"'file_path' = '{file_path}'"
                )
            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] file_path = "
                f"'{file_path}' "
            )

            directory_path = ntpath.dirname(file_path)

            if not directory_path:
                raise ValueError(
                    f"Parsed directory_path was None or empty. "
                    f"'directory_path' = '{directory_path}'"
                )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"directory_path after = "
                f"'{directory_path}' "
            )

            observable_data = {"type": "Directory", "path": directory_path}

            # This entity type cannot be read from OpenCTI because the StixCyberObservablesFilter
            # object does not have a field for "path"
            directory = self.helper.api.stix_cyber_observable.create(
                createdBy=self.cs_author.get("standard_id"),
                objectMarking=self.default_marking_definition_ids,
                observableData=observable_data,
                confidence=self.helper.connect_confidence_level,
            )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] directory = "
                f"'{directory}' "
            )

        except (ValueError, AttributeError) as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting directory with inputs: "
                f"file_path='{file_path}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            directory = None

        return directory

    def get_process(self, command_line: str):
        """
        This method takes a command line command based on the CrowdStrike detection
        and returns a corresponding OpenCTI Object. This method creates a new Process
        stix_cyber_observable object in OpenCTI if one does not already exist.

        Args:
            command_line (_str_) - The command line command from the CrowdStrike detection

        Returns:
            The OpenCTI Process stix_cyber_observable object
        """

        try:
            if not command_line:
                raise ValueError(
                    f"Inputted command_line was None or empty. "
                    f"'command_line' = '{command_line}'"
                )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] command_line = "
                f"'{command_line}' "
            )

            observable_data = {"type": "Process", "command_line": command_line}

            # This entity type cannot be read from OpenCTI because the StixCyberObservablesFilter
            # object does not have a field for "command_line"
            process = self.helper.api.stix_cyber_observable.create(
                createdBy=self.cs_author.get("standard_id"),
                objectMarking=self.default_marking_definition_ids,
                observableData=observable_data,
                confidence=self.helper.connect_confidence_level,
                simple_observable_description=command_line,
            )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] command_line = "
                f"'{command_line}' "
            )
        except (ValueError, AttributeError) as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting process with inputs: "
                f"command_line='{command_line}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            process = None

        return process

    def get_user_account(self, user_name, user_id):
        """
        This method takes a user_name and user_id based on the CrowdStrike detection
        and returns a corresponding OpenCTI Object. This method creates a new User-Account
        stix_cyber_observable object in OpenCTI.

        Args:
            user_name (_str_) - The user_name for the User-Account
            user_id (_str_) - The user_id for the User-Account

        Returns:
            The OpenCTI User-Account stix_cyber_observable object
        """
        try:
            observable_data = {
                "type": "User-Account",
                "user_id": user_id,
                "display_name": user_name,
                "x_opencti_description": f"{user_name} {user_id}",
            }

            if not user_name and not user_id:
                raise ValueError(
                    f"Inputted user_name and user_id were None or empty. "
                    f"'user_name' = '{user_name}' "
                    f"'user_id'= '{user_id}'"
                )

            # This entity type cannot be read from OpenCTI because the StixCyberObservablesFilter
            # object does not have a fields for "user_id" or "display_name"
            user_account = self.helper.api.stix_cyber_observable.create(
                createdBy=self.cs_author.get("standard_id"),
                objectMarking=self.default_marking_definition_ids,
                observableData=observable_data,
                confidence=self.helper.connect_confidence_level,
            )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] user_account = "
                f""
                f"'{user_account}' "
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting User-Account with inputs: "
                f"user_name='{user_name}', "
                f"user_id='{user_id}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            user_account = None

        return user_account

    def get_infrastructure(self, name, infrastructure_type):
        """
        This method takes the name and type of infrastructure based on the CrowdStrike detection
        and returns a corresponding OpenCTI Object. This method creates a new infrastructure
        object in OpenCTI if one does not already exist.

        Args:
            name (_str_) - The name of the infrastructure
            infrastructure_type (_str_) - The type of the infrastructure

        Returns:
            The OpenCTI Infrastructure object to return
        """
        try:
            if not name:
                raise ValueError(
                    f"Inputted name was None or empty. " f"'name' = '{name}'"
                )

            if not infrastructure_type:
                raise ValueError(
                    f"Inputted infrastructure_type was None or empty. "
                    f"'infrastructure_type' = '{infrastructure_type}'"
                )

            infrastructure = self.helper.api.infrastructure.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "name", "values": name},
                        {"key": "infrastructure_types", "values": infrastructure_type},
                    ],
                    "filterGroups": [],
                }
            )

            if infrastructure is None:
                infrastructure = self.helper.api.infrastructure.create(
                    createdBy=self.cs_author.get("standard_id"),
                    objectMarking=self.default_marking_definition_ids,
                    infrastructure_types=infrastructure_type,
                    name=name,
                    confidence=self.helper.connect_confidence_level,
                )
            else:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] existing "
                    f"infrastructure of "
                    f"type {infrastructure_type} found= '{infrastructure}' "
                )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting Infrastructure with inputs: "
                f"name='{name}', "
                f"infrastructure_type='{infrastructure_type}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            infrastructure = None

        return infrastructure

    def get_software(self, name, version):
        """
        This method takes the name and version of software was found in the CrowdStrike detection
        and returns a corresponding OpenCTI Object. This method creates a new Software
        stix_cyber_observable object in OpenCTI.

        Args:
            name (_str_) - The name of the software
            version (_str_) - The version of the software

        Returns:
            The OpenCTI Software stix_cyber_observable object
        """
        try:
            name = name + " Bios"
            observable_type = "Software"

            observable_data = {
                "type": observable_type,
                "name": name,
                "version": version,
            }

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"name='{name}' version='{version}'"
            )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"observable_data='{observable_data}' "
            )

            # This entity type cannot be read from OpenCTI because the StixCyberObservablesFilter
            # object does not have a field for "version"
            software = self.helper.api.stix_cyber_observable.create(
                createdBy=self.cs_author.get("standard_id"),
                objectMarking=self.default_marking_definition_ids,
                observableData=observable_data,
                confidence=self.helper.connect_confidence_level,
            )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"{observable_type} = '{software}' "
            )
        except (ValueError, TypeError) as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting Software with inputs:  "
                f"name='{name}', "
                f"version='{version}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            software = None

        return software

    def get_position(self, site_name):
        """
        This method takes the site_name that a device was found at from the CrowdStrike detection
        and returns a corresponding OpenCTI Object. This method creates a new Position location
        object in OpenCTI if one does not already exist.

        Args:
            site_name (_str_) - The CrowdStrike behavior dictionary

        Returns:
            The OpenCTI Position location object for the site_name.
        """
        try:
            if not site_name:
                raise ValueError(
                    f"Inputted site_name was None or empty. "
                    f"'site_name' = '{site_name}'"
                )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] site_name = "
                f"'{site_name}'"
            )
            position = self.helper.api.location.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "name", "values": site_name},
                        {"key": "entity_type", "values": "Position"},
                    ],
                    "filterGroups": [],
                }
            )

            if position is None:
                position = self.helper.api.location.create(
                    createdBy=self.cs_author.get("standard_id"),
                    objectMarking=self.default_marking_definition_ids,
                    type="Position",
                    name=site_name,
                    confidence=self.helper.connect_confidence_level,
                )
            else:
                self.helper.log_debug(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] existing"
                    f" position found in OpenCTI= "
                    f"'{position}' "
                )

            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] position = "
                f"'{position}' "
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Error occurred"
                f" while getting Position with inputs: "
                f"site_name='{site_name}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            position = None

        return position

    def get_incident(
        self,
        incident_id: str,
        incident_timestamp: str,
        cs_severity: str,
        first_seen: str,
        last_seen: str,
    ):
        """
        This method takes the incident_id from the CrowdStrike detection
        and returns a corresponding OpenCTI Object. This method creates a new Incident Alert
        object in OpenCTI.

        Args:
            incident_id (_str_) - The CrowdStrike behavior dictionary
            incident_timestamp (_str_) - The incident timestamp as a String
            cs_severity (_str_) - The CrowdStrike severity
            first_seen (_str_) - The first seen behavior date as a String
            last_seen (_str_) -The last seen behavior date as a String

        Returns:
            The OpenCTI Incident Alert object
        """

        try:
            year_string = incident_timestamp.split("-")[0].strip()
        except Exception:
            year_string = datetime.datetime.today().strftime("%Y")

        incident_name = f"A-{incident_id}-CSED-{year_string}"

        try:
            _incident = self.helper.api.incident.create(
                name=incident_name,
                incident_type="Alert",
                createdBy=self.cs_author.get("standard_id"),
                objectMarking=self.default_marking_definition_ids,
                confidence=self.helper.connect_confidence_level,
                severity=get_cti_severity(cs_severity),
                first_seen=first_seen,
                last_seen=last_seen,
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] An error "
                f"occurred while trying to create an Incident Alert with the following parameters: "
                f"incident_id:'{incident_id}', "
                f"incident_timestamp:'{incident_timestamp}', "
                f"cs_severity:'{cs_severity}', "
                f"first_seen:'{first_seen}', "
                f"last_seen:'{last_seen}', "
                f"Exception:'{_err}', "
                f"StackTrace:'{traceback.format_exc()}'."
            )
            _incident = None

        self.helper.log_debug(
            f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] _incident = "
            f"'{_incident}' "
        )

        return _incident

    def process_behavior(
        self,
        behavior,
        first_behavior,
        last_behavior,
        alert,
        system,
        organization,
    ):
        """
        Function takes CrowdStrike "Behavior" from a Detection and parses out relevant data
        to create in OpenCTI.

        Args:
            behavior (_dict_) - The CrowdStrike behavior dictionary
            first_behavior (_str_) - The first behavior time as a String
            last_behavior (_str_) - The last behavior time as a String
            alert (_dict_) - The alert the behavior was found in as a STIX dictionary
            system (_dict_) - The system the behavior was found on as a STIX dictionary
            organization (_dict_) - The tenant organization the behavior was found in as a STIX dictionary

        Returns:
            A list of STIX objects and relationships that have been uploaded into OpenCTI
            and to add to the report for this connector run.
        """

        behavior_objects = []
        file_name = behavior.get("filename")

        sha256_value = behavior.get("sha256")
        md5_value = behavior.get("md5")
        tactic_name = behavior.get("tactic")
        tactic_id = behavior.get("tactic_id")
        technique_name = behavior.get("technique")
        technique_id = behavior.get("technique_id")
        ioc_description = behavior.get("ioc_description")
        ioc_source = behavior.get("ioc_source")
        ioc_value = behavior.get("ioc_value")
        ioc_type = behavior.get("ioc_type")
        file_path = behavior.get("filepath")
        cmdline = behavior.get("cmdline")
        parent_cmdline = behavior.get("parent_details", {}).get("parent_cmdline", "")

        self.helper.log_info(
            f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
            f"filename='{file_name}',"
            f"file_path='{file_path}',"
            f"cmdline='{cmdline}',"
            f"ioc_type='{ioc_type}',"
            f"ioc_source='{ioc_source}',"
            f"ioc_description='{ioc_description}',"
            f"ioc_value='{ioc_value}'"
        )

        file = self.get_file(sha256_value, md5_value, file_path, file_name)
        directory = self.get_directory(file_path)

        behavior_objects.append(file)
        behavior_objects.append(directory)

        process = self.get_process(cmdline)
        behavior_objects.append(process)

        sighting_relationship_at_system = self.create_sighting_relationship(
            file, system, first_behavior, last_behavior
        )
        behavior_objects.append(sighting_relationship_at_system)

        process_sighting_relationship_at_system = self.create_sighting_relationship(
            process, system, first_behavior, last_behavior
        )
        behavior_objects.append(process_sighting_relationship_at_system)

        directory_related_to_system = self.create_stix_core_relationship(
            "related-to", directory, system, first_behavior, last_behavior
        )
        behavior_objects.append(directory_related_to_system)

        sighting_relationship_at_organization = self.create_sighting_relationship(
            file, organization, first_behavior, last_behavior
        )
        behavior_objects.append(sighting_relationship_at_organization)

        process_sighting_relationship_at_organization = self.create_sighting_relationship(
            process, organization, first_behavior, last_behavior
        )
        behavior_objects.append(process_sighting_relationship_at_organization)

        sighting_relationship_at_directory = self.create_sighting_relationship(
            file, directory, first_behavior, last_behavior
        )
        behavior_objects.append(sighting_relationship_at_directory)

        process_sighting_relationship_at_directory = self.create_sighting_relationship(
            process, directory, first_behavior, last_behavior
        )
        behavior_objects.append(process_sighting_relationship_at_directory)

        parent_process = self.get_process(parent_cmdline)
        behavior_objects.append(parent_process)

        process_related_to_parent_process_relationship = (
            self.create_stix_core_relationship(
                "related-to", process, parent_process, first_behavior, last_behavior
            )
        )
        behavior_objects.append(process_related_to_parent_process_relationship)

        parent_process_sighted_at_organization_relationship = (
            self.create_sighting_relationship(
                parent_process, organization, first_behavior, last_behavior
            )
        )
        behavior_objects.append(parent_process_sighted_at_organization_relationship)

        parent_process_sighted_at_system_relationship = (
            self.create_sighting_relationship(
                parent_process, system, first_behavior, last_behavior
            )
        )
        behavior_objects.append(parent_process_sighted_at_system_relationship)

        user_name = behavior.get("user_name")
        user_id = behavior.get("user_id")

        user_account = self.get_user_account(user_name, user_id)
        behavior_objects.append(user_account)

        sighting_relationship_at_user = self.create_sighting_relationship(
            file, user_account, first_behavior, last_behavior
        )
        behavior_objects.append(sighting_relationship_at_user)

        process_sighting_relationship_at_user = self.create_sighting_relationship(
            process, user_account, first_behavior, last_behavior
        )
        behavior_objects.append(process_sighting_relationship_at_user)

        parent_process_sighting_relationship_at_user = (
            self.create_sighting_relationship(
                parent_process, user_account, first_behavior, last_behavior
            )
        )
        behavior_objects.append(parent_process_sighting_relationship_at_user)

        file_related_to_alert_relationship = self.create_stix_core_relationship(
            "related-to", file, alert, first_behavior, last_behavior
        )
        behavior_objects.append(file_related_to_alert_relationship)

        process_related_to_alert_relationship = self.create_stix_core_relationship(
            "related-to", process, alert, first_behavior, last_behavior
        )
        behavior_objects.append(process_related_to_alert_relationship)

        parent_process_related_to_alert_relationship = (
            self.create_stix_core_relationship(
                "related-to", parent_process, alert, first_behavior, last_behavior
            )
        )
        behavior_objects.append(parent_process_related_to_alert_relationship)

        user_uses_system_relationship = self.create_stix_core_relationship(
            "related-to", user_account, system, first_behavior, last_behavior
        )
        behavior_objects.append(user_uses_system_relationship)

        user_related_to_relationship = self.create_sighting_relationship(
            user_account, organization, first_behavior, last_behavior
        )
        behavior_objects.append(user_related_to_relationship)

        user_related_to_alert_relationship = self.create_stix_core_relationship(
            "related-to", user_account, alert, first_behavior, last_behavior
        )
        behavior_objects.append(user_related_to_alert_relationship)

        tactic_attack_pattern = self.get_attack_pattern(tactic_name, tactic_id)
        behavior_objects.append(tactic_attack_pattern)

        tactic_related_to_alert_relationship = self.create_stix_core_relationship(
            "uses", alert, tactic_attack_pattern, first_behavior, last_behavior
        )
        behavior_objects.append(tactic_related_to_alert_relationship)

        technique_attack_pattern = self.get_attack_pattern(technique_name, technique_id)
        behavior_objects.append(technique_attack_pattern)

        technique_related_to_alert_relationship = self.create_stix_core_relationship(
            "uses", alert, technique_attack_pattern, first_behavior, last_behavior
        )
        behavior_objects.append(technique_related_to_alert_relationship)

        process_related_to_tactic_relationship = self.create_stix_core_relationship(
            "related-to", process, tactic_attack_pattern, first_behavior, last_behavior
        )
        behavior_objects.append(process_related_to_tactic_relationship)

        process_related_to_technique_relationship = self.create_stix_core_relationship(
            "related-to",
            process,
            technique_attack_pattern,
            first_behavior,
            last_behavior,
        )
        behavior_objects.append(process_related_to_technique_relationship)

        parent_process_related_to_tactic_relationship = (
            self.create_stix_core_relationship(
                "related-to",
                parent_process,
                tactic_attack_pattern,
                first_behavior,
                last_behavior,
            )
        )
        behavior_objects.append(parent_process_related_to_tactic_relationship)

        parent_process_related_to_technique_relationship = (
            self.create_stix_core_relationship(
                "related-to",
                parent_process,
                technique_attack_pattern,
                first_behavior,
                last_behavior,
            )
        )
        behavior_objects.append(parent_process_related_to_technique_relationship)

        file_related_to_tactic_relationship = self.create_stix_core_relationship(
            "related-to", file, tactic_attack_pattern, first_behavior, last_behavior
        )
        behavior_objects.append(file_related_to_tactic_relationship)

        file_related_to_technique_relationship = self.create_stix_core_relationship(
            "related-to", file, technique_attack_pattern, first_behavior, last_behavior
        )
        behavior_objects.append(file_related_to_technique_relationship)

        if ioc_type:
            ioc_entity = self.get_ioc_entity(
                ioc_type, ioc_value, ioc_description, ioc_source
            )
            behavior_objects.append(ioc_entity)

            ioc_sighting_relationship_at_system = self.create_sighting_relationship(
                ioc_entity, system, first_behavior, last_behavior
            )
            behavior_objects.append(ioc_sighting_relationship_at_system)

            ioc_sighting_relationship_at_organization = self.create_sighting_relationship(
                ioc_entity, organization, first_behavior, last_behavior
            )
            behavior_objects.append(ioc_sighting_relationship_at_organization)

            ioc_sighting_relationship_at_user = self.create_sighting_relationship(
                ioc_entity, user_account, first_behavior, last_behavior
            )
            behavior_objects.append(ioc_sighting_relationship_at_user)

            ioc_related_to_alert_relationship = self.create_stix_core_relationship(
                "related-to", ioc_entity, alert, first_behavior, last_behavior
            )
            behavior_objects.append(ioc_related_to_alert_relationship)

            ioc_related_to_tactic_relationship = self.create_stix_core_relationship(
                "related-to",
                ioc_entity,
                tactic_attack_pattern,
                first_behavior,
                last_behavior,
            )
            behavior_objects.append(ioc_related_to_tactic_relationship)

            ioc_related_to_technique_relationship = self.create_stix_core_relationship(
                "related-to",
                ioc_entity,
                technique_attack_pattern,
                first_behavior,
                last_behavior,
            )
            behavior_objects.append(ioc_related_to_technique_relationship)

            if ioc_type in ["hash_sha256", "hash_md5"]:
                ioc_directory = self.get_directory(ioc_description)
                behavior_objects.append(ioc_directory)

                ioc_directory_related_to_system = self.create_stix_core_relationship(
                    "related-to", ioc_directory, system, first_behavior, last_behavior
                )
                behavior_objects.append(ioc_directory_related_to_system)

                ioc_sighting_relationship_at_ioc_directory = (
                    self.create_sighting_relationship(
                        ioc_entity, ioc_directory, first_behavior, last_behavior
                    )
                )
                behavior_objects.append(ioc_sighting_relationship_at_ioc_directory)

                process_sighting_relationship_at_ioc_directory = (
                    self.create_sighting_relationship(
                        process, ioc_directory, first_behavior, last_behavior
                    )
                )
                behavior_objects.append(process_sighting_relationship_at_ioc_directory)

        return list(filter(lambda item: item is not None, behavior_objects))

    def is_ip_address_private(self, ip_address_string):
        """
        Function takes an IP address String and determine if it's a private IP address.

        Args:
            ip_address_string (_str_): String representation of an IP address.

        Returns:
            True if the supplied IP address is a private IP address. False, otherwise. If an invalid
            ip address String is provided, False is returned.
        """
        try:
            is_private = ipaddress.ip_address(ip_address_string).is_private
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] An error "
                f"occurred while trying to determine if an IP address was private: "
                f"ip_address_string:'{ip_address_string}', "
                f"Exception:'{_err}', "
                f"StackTrace:'{traceback.format_exc()}'."
            )
            is_private = False

        return is_private

    def get_windows_registry_key(self, key):
        """
        This method takes a Windows registry key name and returns a
        corresponding OpenCTI Object. This method creates a new WindowsRegistryKey stix
        object in OpenCTI if one does not already exist.

        Args:
            key (_str_) - The key name

        Returns:
            The OpenCTI WindowsRegistryKey object
        """
        try:
            if not key:
                raise ValueError(f"Inputted key was None or empty. " f"'key' = '{key}'")

            observable_data = {
                "type": "Windows-Registry-Key",
                "key": key,
            }

            stix_registry_key = self.helper.api.stix_cyber_observable.create(
                createdBy=self.cs_author.get("standard_id"),
                objectMarking=self.default_marking_definition_ids,
                observableData=observable_data,
                confidence=self.helper.connect_confidence_level,
            )

            self.helper.log_debug(
                f"[ProofpointConnector] stix_registry_key = " f"'{stix_registry_key}' "
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}] Error occurred"
                f" while getting stix_registry_key with inputs: "
                f"key='{key}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            stix_registry_key = None
        return stix_registry_key

    def get_ioc_entity(
        self, ioc_type: str, ioc_value: str, ioc_description: str, ioc_source: str
    ):
        """
        Function to parse out the correct OpenCTI observable/entity type for the CrowdStrike
        Deteciton Behavior IOC.

        Args:
            ioc_type (_str_): A CrowdStrike Detection Behavior ioc_type String
            ioc_value (_str_): A CrowdStrike Detection Behavior ioc_value String
            ioc_description (_str_): A CrowdStrike Detection Behavior ioc_description String
            ioc_source (_str_): A CrowdStrike Detection Behavior ioc_source String

        Returns:
            A OpenCTI STIX entity depending on the ioc_type. Valid return types are:
            File observable, Domain-Name observable, Windows Registry Key observable,
            Process observable
        """
        cti_ioc = None

        if ioc_type == "hash_sha256":
            cti_ioc = self.get_file(ioc_value, None, ioc_description)
        elif ioc_type == "hash_md5":
            cti_ioc = self.get_file(None, ioc_value, ioc_description)
        elif ioc_type == "domain":
            cti_ioc = self.get_domain_name(ioc_value)
        elif ioc_type == "filename":
            cti_ioc = self.get_file(None, None, None, ioc_value)
        elif ioc_type == "registry_key":
            cti_ioc = self.get_windows_registry_key(ioc_value)
        elif ioc_type == "command_line":
            cti_ioc = self.get_process(ioc_value)
        elif ioc_type == "behavior":
            self.helper.log_debug(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] IOC was of type"
                f" 'behavior', doing nothing. "
                f"ioc_type='{ioc_type}', "
                f"ioc_value='{ioc_value}', "
                f"ioc_description='{ioc_description}', "
                f"ioc_source='{ioc_source}'."
            )
        else:
            self.helper.log_warning(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Unrecognized "
                f"ioc_type received. "
                f"ioc_type='{ioc_type}', "
                f"ioc_value='{ioc_value}', "
                f"ioc_description='{ioc_description}', "
                f"ioc_source='{ioc_source}'."
            )

        return cti_ioc

    def process_detection(self, cs_detection: dict):
        """
        Function takes a CrowdStrike Detection and parses out relevant data to create in OpenCTI.

        Args:
            cs_detection (_dict_): A CrowdStrike Detection dictionary to upload into OpenCTI.

        Returns:
            A list of STIX objects and relationships that have been uploaded into OpenCTI
            and to add to the report for this connector run.
        """
        cti_objects = []

        # Parsing of CrowdStrike data into variables ------------------------------------------
        detection_id = cs_detection.get("detection_id", "")
        detection_timestamp = cs_detection.get("created_timestamp", "")
        detection_severity = cs_detection.get("max_severity_displayname", "")
        first_behavior = cs_detection.get("first_behavior", "")
        last_behavior = cs_detection.get("last_behavior", "")

        cs_device = cs_detection.get("device", {})
        device_id = cs_device.get("device_id")
        hostname = cs_device.get("hostname")
        external_ip_address = cs_device.get("external_ip")
        local_ip_address = cs_device.get("local_ip")
        mac_address = cs_device.get("mac_address")
        machine_domain = cs_device.get("machine_domain")
        device_first_seen = cs_device.get("first_seen")
        device_last_seen = cs_device.get("last_seen")

        system_manufacturer = cs_device.get("system_manufacturer")
        system_product_name = cs_device.get("system_product_name")
        try:
            cs_system_name = system_manufacturer + " " + system_product_name
        except TypeError as t_err:
            cs_system_name = ""
            self.helper.log_info(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f" Error occurred while creating cs_system_name."
                f" Setting cs_system name to '\"\"'"
                f" Exception: '{t_err}'"
                f" Stacktrace = '{traceback.format_exc()}'"
            )

        product_type_description = cs_device.get("product_type_desc")
        bios_manufacturer = cs_device.get("bios_manufacturer")
        bios_version = cs_device.get("bios_version")
        os_version = cs_device.get("os_version")
        site_name = cs_device.get("site_name")

        # Creation of OpenCTI entities using CrowdStrike data -------------------------------
        alert = self.get_incident(
            detection_id,
            detection_timestamp,
            detection_severity,
            first_behavior,
            last_behavior,
        )
        cti_objects.append(alert)

        system = self.get_cti_system(hostname, device_id)
        cti_objects.append(system)

        alert_targets_system_relationship = self.create_stix_core_relationship(
            "targets", alert, system, first_behavior, last_behavior
        )
        cti_objects.append(alert_targets_system_relationship)

        organization = self.organization
        cti_objects.append(organization)

        system_belongs_to_relationship = self.create_stix_core_relationship(
            "belongs-to", system, organization, device_first_seen, device_last_seen
        )
        cti_objects.append(system_belongs_to_relationship)

        cti_external_ip_address = self.get_ip_address(external_ip_address)
        cti_objects.append(cti_external_ip_address)

        external_ip_related_to_relationship = self.create_stix_core_relationship(
            "related-to",
            cti_external_ip_address,
            system,
            device_first_seen,
            device_last_seen,
        )
        cti_objects.append(external_ip_related_to_relationship)

        cti_local_ip_address = self.get_ip_address(local_ip_address)
        cti_objects.append(cti_local_ip_address)

        if self.is_ip_address_private(local_ip_address):
            network_infrastructure_name = self.organization_name + " Internal Network"
            network_infrastructure = self.get_infrastructure(
                network_infrastructure_name, "Network"
            )
            cti_objects.append(network_infrastructure)

            network_consists_of_ip_relationship = self.create_stix_core_relationship(
                "consists-of",
                network_infrastructure,
                cti_local_ip_address,
                device_first_seen,
                device_last_seen,
            )
            cti_objects.append(network_consists_of_ip_relationship)

            network_related_to_organization = self.create_stix_core_relationship(
                "related-to",
                network_infrastructure,
                organization,
                device_first_seen,
                device_last_seen,
            )
            cti_objects.append(network_related_to_organization)

            system_related_to_network = self.create_stix_core_relationship(
                "related-to",
                system,
                network_infrastructure,
                device_first_seen,
                device_last_seen,
            )
            cti_objects.append(system_related_to_network)

        local_ip_related_to_relationship = self.create_stix_core_relationship(
            "related-to",
            cti_local_ip_address,
            system,
            device_first_seen,
            device_last_seen,
        )
        cti_objects.append(local_ip_related_to_relationship)

        cti_mac_address = self.get_mac_address(mac_address)
        cti_objects.append(cti_mac_address)

        mac_related_to_relationship = self.create_stix_core_relationship(
            "related-to", cti_mac_address, system, device_first_seen, device_last_seen
        )
        cti_objects.append(mac_related_to_relationship)

        cti_machine_domain = self.get_domain_name(machine_domain)
        cti_objects.append(cti_machine_domain)

        domain_belongs_to_organization_relationship = self.create_stix_core_relationship(
            "belongs-to",
            cti_machine_domain,
            organization,
            device_first_seen,
            device_last_seen,
        )
        cti_objects.append(domain_belongs_to_organization_relationship)

        machine_domain_related_to_relationship = self.create_stix_core_relationship(
            "related-to",
            cti_machine_domain,
            system,
            device_first_seen,
            device_last_seen,
        )
        cti_objects.append(machine_domain_related_to_relationship)

        physical_system = self.get_infrastructure(cs_system_name, "Physical System")
        cti_objects.append(physical_system)

        physical_system_related_to_relationship = self.create_stix_core_relationship(
            "related-to", physical_system, system, device_first_seen, device_last_seen
        )
        cti_objects.append(physical_system_related_to_relationship)

        physical_system_related_to_organization_relationship = (
            self.create_stix_core_relationship(
                "related-to",
                physical_system,
                organization,
                device_first_seen,
                device_last_seen,
            )
        )
        cti_objects.append(physical_system_related_to_organization_relationship)

        cti_infrastructure = self.get_infrastructure(
            product_type_description, "Infrastructure Type"
        )
        cti_objects.append(cti_infrastructure)

        cti_infrastructure_related_to_relationship = self.create_stix_core_relationship(
            "related-to",
            cti_infrastructure,
            system,
            device_first_seen,
            device_last_seen,
        )
        cti_objects.append(cti_infrastructure_related_to_relationship)

        cti_infrastructure_related_to_organization_relationship = (
            self.create_stix_core_relationship(
                "related-to",
                cti_infrastructure,
                organization,
                device_first_seen,
                device_last_seen,
            )
        )
        cti_objects.append(cti_infrastructure_related_to_organization_relationship)

        bios_software = self.get_software(bios_manufacturer, bios_version)
        cti_objects.append(bios_software)

        physical_system_hosts_bios_relationship = self.create_stix_core_relationship(
            "hosts", physical_system, bios_software, device_first_seen, device_last_seen
        )
        cti_objects.append(physical_system_hosts_bios_relationship)

        system_related_to_bios_relationship = self.create_stix_core_relationship(
            "related-to", system, bios_software, device_first_seen, device_last_seen
        )
        cti_objects.append(system_related_to_bios_relationship)

        bios_software_related_to_organization_relationship = (
            self.create_stix_core_relationship(
                "related-to", bios_software, organization, device_first_seen, device_last_seen
            )
        )
        cti_objects.append(bios_software_related_to_organization_relationship)

        os_bios_software = self.get_software(os_version, bios_version)
        cti_objects.append(os_bios_software)

        system_related_to_os_bios_relationship = self.create_stix_core_relationship(
            "related-to", system, os_bios_software, device_first_seen, device_last_seen
        )

        cti_objects.append(system_related_to_os_bios_relationship)

        physical_system_has_os_bios_relationship = self.create_stix_core_relationship(
            "hosts",
            physical_system,
            os_bios_software,
            device_first_seen,
            device_last_seen,
        )
        cti_objects.append(physical_system_has_os_bios_relationship)

        cti_infrastructure_has_os_bios_relationship = (
            self.create_stix_core_relationship(
                "related-to",
                cti_infrastructure,
                os_bios_software,
                device_first_seen,
                device_last_seen,
            )
        )

        cti_objects.append(cti_infrastructure_has_os_bios_relationship)

        os_bios_software_related_to_organization_relationship = (
            self.create_stix_core_relationship(
                "related-to",
                os_bios_software,
                organization,
                device_first_seen,
                device_last_seen,
            )
        )
        cti_objects.append(os_bios_software_related_to_organization_relationship)

        position = self.get_position(site_name)
        cti_objects.append(position)

        system_related_to_position_relationship = self.create_stix_core_relationship(
            "related-to", system, position, device_first_seen, device_last_seen
        )
        cti_objects.append(system_related_to_position_relationship)

        organization_located_at_position_relationship = self.create_stix_core_relationship(
            "located-at", organization, position, device_first_seen, device_last_seen
        )
        cti_objects.append(organization_located_at_position_relationship)

        cti_infrastructure_located_at_position_relationship = (
            self.create_stix_core_relationship(
                "located-at",
                cti_infrastructure,
                position,
                device_first_seen,
                device_last_seen,
            )
        )
        cti_objects.append(cti_infrastructure_located_at_position_relationship)

        # --------------------------------------------------------------------------------------

        behaviors = cs_detection.get("behaviors", [])

        for behavior in behaviors:
            cti_objects.extend(
                self.process_behavior(
                    behavior,
                    first_behavior,
                    last_behavior,
                    alert,
                    system,
                    organization,
                )
            )

        valid_objects = list(filter(lambda item: item is not None, cti_objects))
        return valid_objects

    def process(self, last_run_date: str, current_run_time: float) -> None:
        """
        Function that holds most of the logic specific to the CrowdStrikeDetectionsConnector.
        Function queries CrowdStrike for all detections since a specific time and
        creates a report in OpenCTI based on the uploaded data.

        Args:
            last_run_date (_str): The date the connector was last run as a String.
                example format: '2023-01-01T00:00:00.000Z'
            current_run_time: The current date the connector is running

        Returns:
            None
        """
        detections = self.query_crowdstrike(
            self.client_id, self.client_secret, last_run_date
        )

        container_objects = []
        object_ids = []

        for detection in detections:
            container_objects.extend(self.process_detection(detection))

        for container_object in container_objects:
            object_ids.append(container_object.get("standard_id"))
        run_time_string = (
            datetime.datetime.utcfromtimestamp(current_run_time).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )[:-4]
            + "Z"
        )
        if len(object_ids) > 0:
            report_name = (
                f"CrowdStrike {not self.is_false_positive} Positive Detections Report: "
                f"{run_time_string}"
            )
            report_description = (
                f"A list of all the {self.detection_status} detections "
                f"from CrowdStrike detected between '{last_run_date}' and '{run_time_string}'. "
                f"'{len(detections)}' detections were found in that time frame. "
            )
            self.helper.log_info(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"{report_description}"
            )
            self.helper.log_info(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"len(object_ids)="
                f"'{len(object_ids)}'"
            )
            report = self.helper.api.report.create(
                name=report_name,
                description=report_description,
                createdBy=self.cs_author.get("standard_id"),
                objectMarking=self.default_marking_definition_ids,
                confidence=self.helper.connect_confidence_level,
                published=run_time_string,
                objects=object_ids,
                report_types="Processed Alert",
            )

            self.helper.api.stix_domain_object.add_file(
                id=report["id"],
                file_name=f"{report_name}_raw_data.json",
                data=json.dumps(detections),
                mime_type="application/json",
            )
        else:
            self.helper.log_info(
                f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                f"No Detections for the"
                f" previous connector run."
            )

    def run(self):
        """
        Main method for external-import connectors
        """
        self.helper.log_info(
            f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
            f"Run called."
        )

        self.helper.log_info(
            f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
            f"Fetching knowledge..."
        )

        while True:
            # Get the current timestamp and check to run
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Connector "
                    f"last run: "
                    + datetime.datetime.utcfromtimestamp(last_run).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

            else:
                last_run = None
                self.helper.log_info(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] No last "
                    f"run found. Starting connector."
                )

            # If the last_run is more than interval-1 day
            if last_run is None or ((timestamp - last_run) >= self.get_interval()):
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = (
                    f"{type(self).__name__} run @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
                )

                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.helper.log_info(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] workid "
                    f"{work_id} "
                    f"initiated"
                )

                if last_run is None:
                    past_date = timestamp - self.get_interval()
                    date_string = (
                        datetime.datetime.utcfromtimestamp(past_date).strftime(
                            "%Y-%m-%dT%H:%M:%S.%fZ"
                        )[:-4]
                        + "Z"
                    )
                else:
                    date_string = (
                        datetime.datetime.utcfromtimestamp(last_run - 60).strftime(
                            "%Y-%m-%dT%H:%M:%S.%fZ"
                        )[:-4]
                        + "Z"
                    )

                self.helper.log_info(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                    f"date_string: "
                    f"{date_string}'"
                )

                try:
                    self.process(date_string, timestamp)

                    # Store the current timestamp as a last run
                    self.helper.log_info(
                        f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                        f"Connector successfully run, storing "
                        "last_run as " + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})

                    message = "Last_run stored, next run in: " + str(
                        datetime.timedelta(seconds=self.get_interval())
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                        f"{message}"
                    )
                except Exception as ex:
                    self.helper.log_error(
                        f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                        f"{traceback.format_exc()}'"
                    )
                    self.helper.log_error(
                        f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] "
                        f"Exception occurred"
                        f": '{ex}'"
                    )

                # Sleeping for 10 minutes between connector runs
                time.sleep(self.sleep_seconds)
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info(
                    f"[{type(self).__name__}.{CrowdStrikeDetectionsConnector.__name__}] Connector "
                    f"will not run, next run in: "
                    + str(datetime.timedelta(seconds=new_interval))
                )
                # Sleeping for 10 minutes between connector runs
                time.sleep(self.sleep_seconds)


def list_splitter(split_size, iterable):
    """
    Method takes in an iterable object and splits it into a list of iterables of a given size.

    Args:
        split_size (__int__): The size to split into.
        iterable (__list__): The larger iterable to split

    Returns:
        split (__list__): A list of sub-lists of size split_size.
    """
    i = iter(iterable)
    while True:
        split = tuple(itertools.islice(i, split_size))
        if not split:
            return
        yield split
