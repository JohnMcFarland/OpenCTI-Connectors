# -*- coding: utf-8 -*-
"""OpenPhish."""
import datetime
import os
import time
import sys
import traceback

import pycti
import stix2
import yaml
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    StixCoreRelationship,
    Report,
    Identity,
)
from stix2 import Bundle

from client import OpenPhishClient

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from microservices.classify_report import classify_report


class OpenPhishConnector:
    def __init__(self) -> None:
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
        if os.path.isfile(config_file_path):
            with open(config_file_path) as fh:
                config = yaml.safe_load(fh)
        else:
            config = {}
        self.helper = OpenCTIConnectorHelper(config)
        self.helper.log_info(f"[{type(self).__name__}] Logging started")

        self.interval = get_config_variable(
            "OPENPHISH_INTERVAL_HOURS",
            ["openphish", "interval_hours"],
            config,
            True,
            3,
        )

        access_key_id = get_config_variable(
            "OPENPHISH_ACCESS_KEY_ID",
            ["openphish", "access_key_id"],
            config,
        )

        access_key_secret = get_config_variable(
            "OPENPHISH_ACCESS_KEY_SECRET",
            ["openphish", "access_key_secret"],
            config,
        )

        organizations_marking_definition_types = get_config_variable(
            "OPENPHISH_ORGANIZATIONS_MARKING_DEFINITIONS",
            ["openphish", "organizations_marking_definitions"],
            config,
            False,
        )

        observables_marking_definition_types = get_config_variable(
            "OPENPHISH_OBSERVABLES_MARKING_DEFINITIONS",
            ["openphish", "attack_patterns_marking_definitions"],
            config,
            False,
        )

        relationships_marking_definition_types = get_config_variable(
            "OPENPHISH_RELATIONSHIPS_MARKING_DEFINITIONS",
            ["openphish", "relationships_marking_definitions"],
            config,
            False,
        )

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

        if observables_marking_definition_types:
            observables_marking_definition_types_list = (
                observables_marking_definition_types.split(",")
            )
            self.observables_marking_definition_ids = [
                self.get_marking_definition_id(marking_definition)
                for marking_definition in observables_marking_definition_types_list
            ]
        else:
            self.observables_marking_definition_ids = []

        if relationships_marking_definition_types:
            relationships_marking_definition_types_list = (
                relationships_marking_definition_types.split(",")
            )
            self.relationships_marking_definition_ids = [
                self.get_marking_definition_id(marking_definition)
                for marking_definition in relationships_marking_definition_types_list
            ]
        else:
            self.relationships_marking_definition_ids = []

        feed_name = get_config_variable(
            "OPENPHISH_FEED_NAME",
            ["openphish", "feed_name"],
            config,
        )

        self.openphish_client = OpenPhishClient(
            access_key_id, access_key_secret, feed_name
        )

        self.sleep_seconds = 60
        self.author = self.get_author("OpenPhish Feed")
        self.helper.log_info("[OpenPhishConnector] Pre-attack patterns.")

        self.spearphishing_attack_pattern = self.get_attack_pattern(
            "Spearphishing Link", "T1566.002"
        )

        self.spearphishing_for_info_attack_pattern = self.get_attack_pattern(
            "Spearphishing Link", "T1598.003"
        )
        self.helper.log_info("[OpenPhishConnector] Post-attack patterns.")

        self.report_labels = [
            "tasked cr2.05",
            "tasked cr2.07",
            "tasked cr2.08",
            "tasked cr3.02",
        ]
        self.helper.log_info("[OpenPhishConnector] Post-report patterns.")

        self.custom_properties = {"created_by_ref": self.author.get("standard_id")}

        self.helper.log_info(
            f"[{type(self).__name__}] Initialization complete with the following"
            f"configuration items: "
            f"interval='{self.interval}', "
            f"access_key_id='{access_key_id}', "
            f"is access_key_secret not None/Empty?='{bool(access_key_secret)}', "
            f"organizations_marking_definition_types='{organizations_marking_definition_types}'"
            f"observables_marking_definition_types='{observables_marking_definition_types}'"
            f"relationships_marking_definition_types='{relationships_marking_definition_types}'"
            f"feed_name='{feed_name}'"
        )

    def get_interval(self) -> int:
        """
        Description
        -----------
        Gets specified time in minutes set in configuration file
        to wait for subsequent import and converts it to seconds.
        Returns
        ---------
        int: seconds
        """
        return int(self.interval) * 60 * 60

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
                f"[{type(self).__name__}] No existing "
                f"Marking definition found for "
                f"type: '{marking_definition_string}'"
            )
            raise ValueError(
                f"[{type(self).__name__}] "
                f"Initialization Error: No marking definition exists in OpenCTI platform for type: "
                f"'{marking_definition_string}'"
            )
        else:
            marking_definition_standard_id = marking_definition.get("standard_id")

        return marking_definition_standard_id

    def get_attack_pattern(self, name, x_mitre_id):
        """
        This method takes an attack pattern name and x_mitre_id and returns a corresponding OpenCTI
        Object. If the attack pattern is not found, a ValueError is thrown as the attack patterns
         are required to be in the platform ahead of the connector runtime.

        Args:
            name (_str_) - The name of the attack pattern
            x_mitre_id (_str_) - The MITRE ID of the attack pattern

        Returns:
            The OpenCTI AttackPattern
        """
        attack_pattern = self.helper.api.attack_pattern.read(
            filters={
                "mode": "and",
                "filters": [
                    {"key": "name", "values": name},
                    {"key": "x_mitre_id", "values": x_mitre_id},
                ],
                "filterGroups": [],
            }
        )

        if attack_pattern is None:
            self.helper.log_error(
                f"[{type(self).__name__}] No existing "
                f"Attack Pattern definition found for "
                f"name: '{name}' "
                f"x_mitre_id: '{x_mitre_id}'"
            )
            raise ValueError(
                f"[{type(self).__name__}] "
                f"Initialization Error: No Attack Pattern exists in OpenCTI platform for name: "
                f"'{name}' and x_mitre_id: '{x_mitre_id}'"
            )
        else:
            attack_pattern_stix = self.export_stix(
                attack_pattern.get("entity_type"), attack_pattern.get("id")
            )

        return attack_pattern_stix

    def export_stix(self, entity_type: str, entity_id: str):
        """
        Exports a STIX entity from the OpenCTI platform to be added to the workbench

        Args:
            entity_type _str_: The entity type to export
            entity_id _str_: The entity id to export
        Returns:
           _dict_: The exported STIX entity from OpenCTI if it exists in the platform
        """
        stix_bundle = self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type,
            entity_id
        )

        if len(stix_bundle["objects"]) == 0:
            raise ValueError(
                f"[OpenPhishConnector] Entity cannot be found or exported"
                f"for entity_type: '{entity_type}' and entity_id: '{entity_id}'"
            )

        self.helper.log_debug(f"[OpenPhishConnector] stix_bundle = '{stix_bundle}'")

        exported_stix = [
            stix_object
            for stix_object in stix_bundle["objects"]
            if "x_opencti_id" in stix_object
            and stix_object["x_opencti_id"] == entity_id
        ][0]

        return exported_stix

    def create_sector(self, sector_name):
        """
        This method takes a sector name and returns a
        corresponding OpenCTI Object. This method creates a new Sector Identity object in
        OpenCTI if one does not already exist.

        Args:
            sector_name (_str_) - The name of the sector

        Returns:
            The OpenCTI Sector Identity object
        """
        try:
            if not sector_name:
                raise ValueError(
                    f"Inputted sector_name was None or empty. "
                    f"'sector_name' = '{sector_name}'"
                )
            sector = stix2.Identity(
                id=Identity.generate_id(sector_name, "class"),
                name=sector_name,
                identity_class="class",
                created_by_ref=self.author.get("standard_id"),
                object_marking_refs=self.organizations_marking_definition_ids,
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}] Error occurred"
                f" while creating sector with: "
                f"sector_name='{sector_name}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            sector = None

        return sector

    def get_author(self, author_name):
        """
        Gets the STIX entity for the supplied author name from OpenCTI. If the author does not
         exist it is created.

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
            _author = self.helper.api.identity.create(
                type="Organization",
                name=author_name,
                objectMarking=self.organizations_marking_definition_ids,
            )

        return _author

    def get_label(self, label_name: str):
        """
        Gets the STIX entity for the supplied label name from OpenCTI. If the label does not
        exist yet within OpenCTI, an exception is raised.

        Args:
            label_name _str_: The name of the label

        Returns:
           stix2.Label: A Label object for the label_name
        """
        if not label_name:
            raise ValueError(
                f"Inputted label_name was None or empty. "
                f"'label_name' = '{label_name}'"
            )

        label = self.helper.api.label.read(
            filters={
                "mode": "and",
                "filters": [
                    {
                        "key": "value",
                        "values": [label_name],
                    }
                ],
                "filterGroups": [],
            }
        )

        if label is None:
            self.helper.log_error(
                f"[{type(self).__name__}] No existing "
                f"label definition found for "
                f"label_name: '{label_name}' "
            )
            raise ValueError(
                f"[{type(self).__name__}] "
                f"Initialization Error: No Label exists in OpenCTI platform for label_name: "
                f"'{label_name}'"
            )

        return label

    def create_stix_core_relationship(
        self,
        relationship_type,
        from_object,
        to_object,
        first_seen=None,
        last_seen=None,
        description=None,
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
            description (_str_) - The description as a String

        Returns:
            The OpenCTI stix_core_relationship object
        """
        try:
            if not from_object or not to_object:
                self.helper.log_debug(
                    f"[OpenPhishConnector] One of from_object or to_object is"
                    f"None or empty when creating a stix_core_relationship. "
                    f"from_object='{from_object}', "
                    f"to_object='{to_object}"
                )
                return None

            from_id = from_object.get("id")
            to_id = to_object.get("id")

            if from_id is None or to_id is None:
                self.helper.log_warning(
                    f"STIX Core Relationship from_id or to_id is None: "
                    f"from_id = '{from_id}', to_id='{to_id}'"
                )
                return None

            if from_id == to_id:
                raise ValueError(
                    f"Cannot create relationship with the same source and target."
                )

            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(relationship_type, from_id, to_id),
                relationship_type=relationship_type,
                source_ref=from_id,
                target_ref=to_id,
                created_by_ref=self.author.get("standard_id"),
                allow_custom=True,
                start_time=first_seen,
                stop_time=last_seen,
                object_marking_refs=self.relationships_marking_definition_ids,
                description=description,
            )
            self.helper.log_debug(
                f"[OpenPhishConnector] Created Core Relationship: " f"'{relationship}'"
            )

        except (AttributeError, ValueError) as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}] An error "
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

    def create_url(self, url):
        """
        This method takes an url String and returns a STIX URL Object.

        Args:
            url (_str_) - The url String

        Returns:
            The OpenCTI URL stix_cyber_observable object
        """
        try:
            if not url:
                raise ValueError(f"Inputted url was None or empty. " f"'url' = '{url}'")

            url_stix = stix2.URL(
                value=url,
                object_marking_refs=self.observables_marking_definition_ids,
                custom_properties=self.custom_properties,
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}] Error occurred"
                f" while getting url with inputs: "
                f"url='{url}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            url_stix = None

        return url_stix

    def create_domain(self, domain_name):
        """
        This method takes a domain name and returns a
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
            self.helper.log_debug(
                f"[OpenPhishConnector] observable_data = " f"'{observable_data}' "
            )

            domain_name_stix = stix2.DomainName(
                value=domain_name,
                object_marking_refs=self.observables_marking_definition_ids,
                custom_properties={
                    "created_by_ref": self.author.get("standard_id"),
                },
            )
            self.helper.log_debug(
                f"[OpenPhishConnector] {observable_type} = " f"'{domain_name_stix}' "
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}] Error occurred"
                f" while getting Domain-name with inputs: "
                f"domain_name='{domain_name}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            domain_name_stix = None
        return domain_name_stix

    def create_campaign(self, campaign_id, iso_date):
        """
        This method takes an ID associated with a campaign and returns a
        corresponding OpenCTI Object. This method creates a new Domain-Name stix_cyber_observable
        object in OpenCTI if one does not already exist.

        Args:
            campaign_id (_str_) - The campaign family id
            iso_date (_str_) - The iso date string

        Returns:
            The OpenCTI Campaign object
        """
        try:
            if not campaign_id:
                raise ValueError(
                    f"Inputted campaign_id was None or empty. "
                    f"'campaign_id' = '{campaign_id}' "
                )

            campaign_name = f"C-{campaign_id}-OP"
            campaign = stix2.Campaign(
                id=pycti.Campaign.generate_id(campaign_name),
                name=campaign_name,
                created_by_ref=self.author.get("standard_id"),
                object_marking_refs=self.observables_marking_definition_ids,
                first_seen=iso_date,
                last_seen=iso_date,
            )

            self.helper.log_debug(f"[OpenPhishConnector] Campaign = " f"'{campaign}' ")
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}] Error occurred"
                f" while creating Campaign with inputs: "
                f"campaign_id='{campaign_id}', "
                f"iso_date='{iso_date}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            campaign = None
        return campaign

    def create_ip_address(self, address):
        """
        This method takes an IP address and returns a
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

            ip_address = stix2.IPv4Address(
                value=address,
                object_marking_refs=self.observables_marking_definition_ids,
                custom_properties={
                    "created_by_ref": self.author.get("standard_id"),
                },
            )

            self.helper.log_debug(
                f"[{type(self).__name__}] IP_address = " f"'{ip_address}' "
            )
        except ValueError as _err:
            self.helper.log_warning(
                f"[{type(self).__name__}] Error occurred"
                f" while getting IP address with inputs: "
                f"address='{address}', "
                f"Exception='{_err}', "
                f"Stacktrace='{traceback.format_exc()}'."
            )
            ip_address = None

        return ip_address

    def process_openphish_url(self, openphish_url: dict):
        """
        This method processes one phishing URL from OpenPhish and parses out the necessary
        objects and relationships to add to OpenCTI.

        Args:
            openphish_url (_dict_) - The OpenPhish URL data

        Returns:
            A list of STIX Objects to add to OpenCTI.
        """
        objects = []

        url = openphish_url.get("url", "")
        sector = openphish_url.get("sector", "")
        ip = openphish_url.get("ip", "")
        host = openphish_url.get("host", "")
        family_id = openphish_url.get("family_id", "")
        isotime = openphish_url.get("isotime", "")

        date_format = "%Y-%m-%dT%H:%M:%SZ"
        iso_dt_object = datetime.datetime.strptime(isotime, date_format)
        isotime_plus_time = iso_dt_object + datetime.timedelta(0, 60)
        isotime_future_string = isotime_plus_time.strftime(date_format)

        url_stix = self.create_url(url) if url else None
        objects.append(url_stix)

        sector_stix = self.create_sector(sector) if sector else None
        objects.append(sector_stix)

        ip_stix = self.create_ip_address(ip) if ip else None
        objects.append(ip_stix)

        domain_stix = self.create_domain(host) if host else None
        objects.append(domain_stix)

        campaign_stix = self.create_campaign(family_id, isotime) if family_id else None
        objects.append(campaign_stix)

        objects.append(self.spearphishing_for_info_attack_pattern)
        objects.append(self.spearphishing_attack_pattern)

        url_related_to_spearphishing1 = self.create_stix_core_relationship(
            "related-to",
            url_stix,
            self.spearphishing_for_info_attack_pattern,
            isotime,
            isotime_future_string,
        )
        objects.append(url_related_to_spearphishing1)

        url_related_to_spearphishing2 = self.create_stix_core_relationship(
            "related-to",
            url_stix,
            self.spearphishing_attack_pattern,
            isotime,
            isotime_future_string,
        )
        objects.append(url_related_to_spearphishing2)

        campaign_uses_spearphishing1 = self.create_stix_core_relationship(
            "uses",
            campaign_stix,
            self.spearphishing_for_info_attack_pattern,
            isotime,
            isotime_future_string,
        )
        objects.append(campaign_uses_spearphishing1)

        campaign_uses_spearphishing2 = self.create_stix_core_relationship(
            "uses",
            campaign_stix,
            self.spearphishing_attack_pattern,
            isotime,
            isotime_future_string,
        )
        objects.append(campaign_uses_spearphishing2)

        # Non-attack pattern related
        url_related_to_ip = self.create_stix_core_relationship(
            "related-to", url_stix, ip_stix, isotime, isotime_future_string
        )
        objects.append(url_related_to_ip)

        domain_resolves_to_ip = self.create_stix_core_relationship(
            "resolves-to", domain_stix, ip_stix, isotime, isotime_future_string
        )
        objects.append(domain_resolves_to_ip)

        url_related_to_domain = self.create_stix_core_relationship(
            "related-to", url_stix, domain_stix, isotime, isotime_future_string
        )
        objects.append(url_related_to_domain)

        url_related_to_campaign = self.create_stix_core_relationship(
            "related-to", url_stix, campaign_stix, isotime, isotime_future_string
        )
        objects.append(url_related_to_campaign)

        campaign_targets_sector = self.create_stix_core_relationship(
            "targets", campaign_stix, sector_stix, isotime, isotime_future_string
        )
        objects.append(campaign_targets_sector)

        return objects

    def process(self, current_timestamp: int, work_id: str) -> None:
        """
        This is the main method for getting the data from OpenPhish for last four hours and
        created a list of STIX objects to upload to OpenCTI.

        Args:
            current_timestamp (_int_) - The timestamp that the connector started its run in seconds
                                        since epoch
            work_id (_str_) - The work ID of the connector run to associate with uploaded data

        Returns:
            None.
        """
        four_hours_ago = convert_epoch_seconds_to_string(
            current_timestamp - (4 * 60 * 60)
        )

        current_run_time = convert_epoch_seconds_to_string(current_timestamp)

        self.helper.log_debug(
            f"[OpenPhish] current_run_time input= '{current_run_time}'"
        )

        openphish_urls = self.openphish_client.get_latest_feed_information()

        container_objects = []
        object_ids = []
        none_null_objects = []

        for openphish_url in openphish_urls:
            stix_objects = self.process_openphish_url(openphish_url)
            container_objects.extend(stix_objects)

        for container_object in container_objects:
            if container_object and container_object.get("id"):
                object_ids.append(container_object.get("id"))
                none_null_objects.append(container_object)
            else:
                self.helper.log_debug(
                    f"[OpenPhish] no id for: " f"'{container_object}'"
                )

        if len(object_ids) > 0:
            report_name = f"OpenPhish Premium Gov Report: {current_run_time}"
            report_description = (
                f"OpenPhish has developed autonomous systems that use a custom knowledge framework "
                f"to determine the likelihood of a URL being a phishing page. The advantage of "
                f"these autonomous systems lies in their ability to operate seamlessly and "
                f"efficiently without any human intervention. This not only saves valuable time "
                f"and resources but also ensures a rapid response to new phishing threats. Through "
                f"extensive datasets and continuous evaluation, OpenPhish fine-tunes the knowledge "
                f"framework to maintain a high level of accuracy in distinguishing between "
                f"legitimate and phishing URLs. The Premium Gov Feed contains phishing "
                f"intelligence for a period of four [4] hours. This report captures a 4 hour "
                f"section of observables from {four_hours_ago} to {current_run_time}. "
                f"Some duplicates may occur between reports."
            )

            _report_types = classify_report(
                title=report_name, description=report_description,
                content=report_description or "",
                source="OpenPhish", source_url="",
                default_types=["OpenPhish Report"],
            )

            report = stix2.Report(
                id=Report.generate_id(report_name, current_run_time),
                name=report_name,
                description=report_description,
                created_by_ref=self.author.get("standard_id"),
                object_refs=object_ids,
                object_marking_refs=self.relationships_marking_definition_ids,
                published=current_run_time,
                report_types=_report_types,
                allow_custom=True,
                labels=self.report_labels,
            )

            none_null_objects.append(report)

            self.send_bundles(none_null_objects, work_id)
        else:
            self.helper.log_info(f"[{type(self).__name__}] " f"No phishing feed data.")

    def send_bundles(self, container_objects: list, work_id):
        """
        This method takes a list of STIX Objects and uploads to OpenCTI

        Args:
            container_objects (_list_) - The list of STIX2 objects to send to OpenCTI
            work_id (_str_) - The work ID of the connector run to associate with uploaded data

        Returns:
           None
        """
        container_objects_length = len(container_objects)
        self.helper.log_info(
            f"[OpenPhish] " f"len(container_objects)='{container_objects_length}'"
        )
        if container_objects_length > 0:
            self.helper.log_info(f"[OpenPhishConnector] There are bundles to send.")
            final_bundle_objects = []
            for stix_object in container_objects:
                final_bundle_objects.append(stix_object)

            self.helper.log_info(
                f"[OpenPhishConnector] "
                f"len(final_bundle_objects)='{len(final_bundle_objects)}'"
            )

            bundle = Bundle(objects=final_bundle_objects, allow_custom=True)
            serialized_bundle = bundle.serialize()
            bundles_sent = self.helper.send_stix2_bundle(
                bundle=serialized_bundle, update=True, work_id=work_id
            )

            self.helper.log_info(
                f"[OpenPhishConnector] " f"len(bundles_sent)='{len(bundles_sent)}'"
            )

    def run(self) -> None:
        """
        Main method for external-import connectors
        """
        while True:
            try:
                self.helper.log_info("[OpenPhish] Fetching knowledge ...")
                # Get the current timestamp and check to run

                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "[OpenPhish] Connector last run: "
                        + datetime.datetime.fromtimestamp(last_run, tz=datetime.timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info(
                        "[OpenPhish] No last run found. Starting connector."
                    )

                # If the last_run is more than interval-1 minute
                if last_run is None or ((timestamp - last_run) >= self.get_interval()):
                    # if True: # allows connector to run every execution no matter last_run time for
                    # debugging # pylint:
                    # disable=locally-disabled, multiple-statements,
                    now = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
                    friendly_name = "OpenPhish Feed connector run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    self.helper.log_info(f"[OpenPhish] workid {work_id} initiated")

                    try:
                        self.process(timestamp, work_id)

                        # Store the current timestamp as a last run
                        self.helper.log_info(
                            "[OpenPhish] Connector successfully run, storing last_run as "
                            + str(timestamp)
                        )
                        self.helper.set_state({"last_run": timestamp})
                        message = "Last_run stored, next run in: " + str(
                            datetime.timedelta(seconds=self.get_interval())
                        )
                        self.helper.api.work.to_processed(work_id, message)
                        self.helper.log_info(f"[OpenPhish] {message}")

                    # Done importing articles
                    except Exception as f_err:
                        self.helper.log_error(
                            f"[OpenPhish] Error occurred: '{f_err}',"
                            f" stacktrace: '{traceback.format_exc()}'"
                        )
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "[OpenPhish] Connector will not run, next run in: "
                        + str(datetime.timedelta(seconds=new_interval))
                    )
            except ConnectionError as c_err:
                self.helper.log_warning(
                    f"[OpenPhish] ConnectionError occurred: {c_err}. Traceback:"
                    f"'{traceback.format_exc()}'"
                )
            time.sleep(self.sleep_seconds)


def convert_epoch_seconds_to_string(epoch_time: int) -> str:
    """
    This method takes an integer of seconds since Epoch time and returns the equivalent date as
    a String.

    Args:
        epoch_time (_int_) - The number of seconds since epoch time

    Returns:
       The equivalent date as a String.
    """
    return datetime.datetime.fromtimestamp(epoch_time, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


if __name__ == "__main__":
    try:
        open_phish = OpenPhishConnector()
        open_phish.run()

    except Exception as e:
        print(f"Error Received, Connector shutting down."
              f"error: '{e}'"
              f"traceback: '{traceback.format_exc()}'")
        time.sleep(10)
        sys.exit(1)
