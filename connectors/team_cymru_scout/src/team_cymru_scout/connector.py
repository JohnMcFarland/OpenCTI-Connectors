import time
from pathlib import Path

from datetime import datetime, timezone
import stix2
import uuid
import yaml
from pycti import Identity, OpenCTIConnectorHelper, get_config_variable

from .client import TeamCymruScoutClient
from .stix_builder import TeamCymruScoutStixBuilder, rating_to_score

_SOURCE_NAME = "Team Cymru Scout"

_SUPPORTED_OBSERVABLE_TYPES = frozenset({"IPv4-Addr", "IPv6-Addr", "Domain-Name"})
_SUPPORTED_CONTAINER_TYPES = frozenset({
    "Report", "Grouping", "Case-Incident", "Case-Rfi", "Case-Rft",
})
_SUPPORTED_TYPES = _SUPPORTED_OBSERVABLE_TYPES | _SUPPORTED_CONTAINER_TYPES

_TLP_HIERARCHY = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]


def _parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("true", "1", "yes")


# GraphQL query to pull observables from an OpenCTI container
_CONTAINER_OBSERVABLES_QUERY = """
    query ContainerObservables($id: String!, $types: [String]) {
        container(id: $id) {
            objects(types: $types, first: 500) {
                edges {
                    node {
                        ... on IPv4Addr {
                            id
                            standard_id
                            entity_type
                            observable_value
                            objectMarking {
                                id
                                definition
                            }
                        }
                        ... on IPv6Addr {
                            id
                            standard_id
                            entity_type
                            observable_value
                            objectMarking {
                                id
                                definition
                            }
                        }
                        ... on DomainName {
                            id
                            standard_id
                            entity_type
                            observable_value
                            objectMarking {
                                id
                                definition
                            }
                        }
                    }
                }
            }
        }
    }
"""

# GraphQL mutation to add an object to a container's object_refs
_ADD_TO_CONTAINER_MUTATION = """
    mutation ContainerAddObject($id: ID!, $input: StixRefRelationshipAddInput!) {
        containerEdit(id: $id) {
            relationAdd(input: $input) {
                id
            }
        }
    }
"""


class TeamCymruScoutConnector:

    def __init__(self):
        config_path = Path(__file__).parent.parent.resolve() / "config.yml"
        config = {}
        if config_path.is_file():
            with open(config_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}

        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=True)

        api_key = get_config_variable(
            "TEAM_CYMRU_SCOUT_API_KEY",
            ["team_cymru_scout", "api_key"],
            config,
        )
        if not api_key:
            raise ValueError(
                "[TeamCymruScout] TEAM_CYMRU_SCOUT_API_KEY is required."
            )

        self.use_foundation = _parse_bool(
            get_config_variable(
                "TEAM_CYMRU_SCOUT_USE_FOUNDATION_API",
                ["team_cymru_scout", "use_foundation_api"],
                config,
                default=True,
            )
        )
        self.max_pdns = int(
            get_config_variable(
                "TEAM_CYMRU_SCOUT_MAX_PDNS",
                ["team_cymru_scout", "max_pdns"],
                config,
                isNumber=True,
                default=10,
            )
        )
        self.domain_search_size = int(
            get_config_variable(
                "TEAM_CYMRU_SCOUT_DOMAIN_SEARCH_SIZE",
                ["team_cymru_scout", "domain_search_size"],
                config,
                isNumber=True,
                default=10,
            )
        )

        self.client = TeamCymruScoutClient(self.helper, api_key)

        identity_response = self.helper.api.identity.create(
            type="Organization",
            name=_SOURCE_NAME,
            description=(
                "Team Cymru Scout -- real-time threat intelligence and "
                "internet infrastructure tracking platform."
            ),
            update=True,
        )
        self.helper.log_info(
            f"[TeamCymruScout] Author identity registered: "
            f"{identity_response.get('id')}"
        )

        self.author = stix2.Identity(
            id=Identity.generate_id(_SOURCE_NAME, "organization"),
            name=_SOURCE_NAME,
            identity_class="organization",
            description="Team Cymru Scout",
            confidence=self.helper.connect_confidence_level,
        )

        tlp_name = get_config_variable(
            "TEAM_CYMRU_SCOUT_TLP",
            ["team_cymru_scout", "tlp"],
            config,
            default="TLP:AMBER",
        )
        tlp_def = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [tlp_name]}],
                "filterGroups": [],
            }
        )
        if tlp_def is None:
            raise RuntimeError(
                f"[TeamCymruScout] {tlp_name} marking definition not found."
            )
        self.tlp_marking_id: str = tlp_def["standard_id"]
        self.helper.log_info(
            f"[TeamCymruScout] TLP marking resolved: {tlp_name} -> {self.tlp_marking_id}"
        )

        self.max_tlp = get_config_variable(
            "TEAM_CYMRU_SCOUT_MAX_TLP",
            ["team_cymru_scout", "max_tlp"],
            config,
            default="TLP:AMBER+STRICT",
        )
        if self.max_tlp not in _TLP_HIERARCHY:
            raise ValueError(
                f"[TeamCymruScout] Invalid max_tlp '{self.max_tlp}'. "
                f"Must be one of {_TLP_HIERARCHY}."
            )

        usage = self.client.get_usage()
        if usage:
            self.helper.log_info(
                f"[TeamCymruScout] API usage: "
                f"{usage.get('remaining_queries')}/{usage.get('query_limit')} queries, "
                f"{usage.get('foundation_api_usage', {}).get('remaining_queries')}/"
                f"{usage.get('foundation_api_usage', {}).get('query_limit')} foundation"
            )

    def _get_entity_tlp(self, entity: dict) -> str | None:
        markings = entity.get("objectMarking") or []
        for m in markings:
            defn = m.get("definition", "")
            if defn.startswith("TLP:"):
                return defn
        return None

    def _is_tlp_allowed(self, entity: dict) -> bool:
        tlp = self._get_entity_tlp(entity)
        if tlp is None:
            return True
        if tlp not in _TLP_HIERARCHY:
            return False
        return _TLP_HIERARCHY.index(tlp) <= _TLP_HIERARCHY.index(self.max_tlp)

    def _add_to_container(self, container_id: str, stix_id: str) -> bool:
        """Add a STIX object to a container, with retry for async ingestion."""
        for attempt in range(4):
            try:
                self.helper.api.query(
                    _ADD_TO_CONTAINER_MUTATION,
                    {
                        "id": container_id,
                        "input": {
                            "toId": stix_id,
                            "relationship_type": "object",
                        },
                    },
                )
                return True
            except Exception as exc:
                msg = str(exc)
                if "internal_id" in msg and attempt < 3:
                    time.sleep(3 * (attempt + 1))
                    continue
                self.helper.log_warning(
                    f"[TeamCymruScout] Could not add {stix_id} "
                    f"to container: {exc}"
                )
                return False
        return False

    def _normalize_foundation(self, data: dict) -> dict:
        as_info = data.get("as_info") or []
        asn = as_info[0].get("asn") if as_info else None
        as_name = as_info[0].get("as_name") if as_info else None
        insights_data = data.get("insights") or {}
        pdns_raw = data.get("pdns") or []
        pdns = [d["domain"] for d in pdns_raw if d.get("domain")]

        return {
            "country_code": data.get("country_code"),
            "asn": asn,
            "as_name": as_name,
            "insights_rating": insights_data.get("overall_rating"),
            "insights": insights_data.get("insights") or [],
            "tags": data.get("tags") or [],
            "pdns_domains": pdns[: self.max_pdns],
            "open_ports": data.get("services") or [],
        }

    def _normalize_details(self, data: dict) -> dict:
        identity = data.get("identity") or {}
        whois = data.get("whois") or {}
        summary = data.get("summary") or {}
        insights_data = summary.get("insights") or {}

        asn = identity.get("asn") or summary.get("bgp_asn")
        as_name = identity.get("as_name") or summary.get("bgp_asname")
        cc = summary.get("geo_ip_cc") or whois.get("cc")

        pdns_raw = (summary.get("pdns") or {}).get("top_pdns") or []
        pdns = [d["domain"] for d in pdns_raw if d.get("domain")]

        ports_raw = (summary.get("open_ports") or {}).get("top_open_ports") or []
        tags = summary.get("tags") or identity.get("tags") or []

        return {
            "country_code": cc,
            "asn": asn,
            "as_name": as_name,
            "insights_rating": insights_data.get("overall_rating"),
            "insights": insights_data.get("insights") or [],
            "tags": tags,
            "pdns_domains": pdns[: self.max_pdns],
            "open_ports": ports_raw,
        }

    def _enrich_ip(self, opencti_entity: dict, stix_entity: dict) -> tuple[str, list[str]]:
        ip_value = opencti_entity.get("observable_value", "")
        self.helper.log_info(f"[TeamCymruScout] Enriching IP: {ip_value}")

        if self.use_foundation:
            raw = self.client.get_ip_foundation(ip_value)
            if raw is None:
                return (f"No data returned from Scout Foundation API for {ip_value}.", [])
            enrichment = self._normalize_foundation(raw)
        else:
            raw = self.client.get_ip_details(ip_value)
            if raw is None:
                return (f"No data returned from Scout Details API for {ip_value}.", [])
            enrichment = self._normalize_details(raw)

        builder = TeamCymruScoutStixBuilder(
            self.helper, self.author, self.tlp_marking_id,
            stix_entity, opencti_entity,
        )

        if enrichment["asn"] and enrichment["as_name"]:
            builder.create_asn_belongs_to(enrichment["asn"], enrichment["as_name"])

        if enrichment["country_code"]:
            builder.create_location_located_at(enrichment["country_code"])

        if enrichment["pdns_domains"]:
            builder.create_pdns_resolves_to(enrichment["pdns_domains"])

        builder.create_assessment_note(
            enrichment["insights_rating"],
            enrichment["insights"],
            enrichment["tags"],
            enrichment["open_ports"],
        )

        score = rating_to_score(enrichment["insights_rating"])
        if score is not None:
            try:
                self.helper.api.stix_cyber_observable.update_field(
                    id=opencti_entity["id"],
                    input={"key": "x_opencti_score", "value": str(score)},
                )
                self.helper.log_info(
                    f"[TeamCymruScout] Set x_opencti_score={score} on {ip_value}"
                )
            except Exception as exc:
                self.helper.log_warning(
                    f"[TeamCymruScout] Could not update score for {ip_value}: {exc}"
                )

        return builder.send_bundle()

    def _enrich_domain(self, opencti_entity: dict, stix_entity: dict) -> tuple[str, list[str]]:
        domain_value = opencti_entity.get("observable_value", "")
        self.helper.log_info(f"[TeamCymruScout] Enriching domain: {domain_value}")

        raw = self.client.search(domain_value, size=self.domain_search_size)
        if raw is None:
            return (f"No data returned from Scout Search API for {domain_value}.", [])

        ips = raw.get("ips") or []
        if not ips:
            return (f"Scout returned no IP associations for {domain_value}.", [])

        builder = TeamCymruScoutStixBuilder(
            self.helper, self.author, self.tlp_marking_id,
            stix_entity, opencti_entity,
        )

        for ip_entry in ips:
            ip_value = ip_entry.get("ip")
            if not ip_value:
                continue

            as_info = ip_entry.get("as_info") or []
            asn = as_info[0].get("asn") if as_info else None
            as_name = as_info[0].get("as_name") if as_info else None

            builder.create_domain_ip_resolves_to(ip_value, asn, as_name)

        first_ip = ips[0]
        tags = first_ip.get("tags") or []
        insights_rating = None
        insights_list = []
        summary = first_ip.get("summary") or {}
        insights_data = summary.get("insights") or {}
        if insights_data:
            insights_rating = insights_data.get("overall_rating")
            insights_list = insights_data.get("insights") or []

        builder.create_assessment_note(
            insights_rating, insights_list, tags,
        )

        return builder.send_bundle()

    def _enrich_container(self, opencti_entity: dict, stix_entity: dict) -> str:
        """Pull all supported observables from a container and enrich each one."""
        container_id = opencti_entity.get("id")
        entity_type = opencti_entity.get("entity_type", "")
        self.helper.log_info(
            f"[TeamCymruScout] Enriching container {entity_type}: {container_id}"
        )

        # Query the container for all IPv4/IPv6/Domain observables
        result = self.helper.api.query(
            _CONTAINER_OBSERVABLES_QUERY,
            {"id": container_id, "types": list(_SUPPORTED_OBSERVABLE_TYPES)},
        )

        container_data = (result or {}).get("data", {}).get("container")
        if container_data is None:
            return f"Container {container_id} not found."

        edges = container_data.get("objects", {}).get("edges", [])
        observables = [
            e["node"] for e in edges
            if e.get("node", {}).get("id")
        ]

        if not observables:
            return f"No enrichable observables in {entity_type} {container_id}."

        self.helper.log_info(
            f"[TeamCymruScout] Found {len(observables)} observable(s) in container"
        )

        enriched = 0
        skipped = 0
        added = 0
        all_new_ids = []
        for obs in observables:
            obs_type = obs.get("entity_type", "")
            obs_value = obs.get("observable_value", "")
            obs_stix_id = obs.get("standard_id") or obs.get("id")
            obs_stix_entity = {"id": obs_stix_id}

            # Per-observable TLP gating
            if not self._is_tlp_allowed(obs):
                tlp = self._get_entity_tlp(obs)
                self.helper.log_info(
                    f"[TeamCymruScout] Skipping {obs_value} -- TLP {tlp} exceeds max"
                )
                skipped += 1
                continue

            try:
                new_ids = []
                if obs_type in ("IPv4-Addr", "IPv6-Addr"):
                    _, new_ids = self._enrich_ip(obs, obs_stix_entity)
                elif obs_type == "Domain-Name":
                    _, new_ids = self._enrich_domain(obs, obs_stix_entity)
                else:
                    continue

                all_new_ids.extend(new_ids)
                enriched += 1
            except Exception as exc:
                self.helper.log_warning(
                    f"[TeamCymruScout] Error enriching {obs_value}: {exc}"
                )

            # Throttle between Scout API calls to pace credit burn
            time.sleep(2)

        # Wait for RabbitMQ bundle processing, then batch-add to container
        if all_new_ids:
            self.helper.log_info(
                f"[TeamCymruScout] Waiting 15s for {len(all_new_ids)} "
                f"objects to be ingested before container association"
            )
            time.sleep(15)
            for sid in all_new_ids:
                if self._add_to_container(container_id, sid):
                    added += 1

            # Create a single summary Grouping for the container run
            obs_stix_ids = [
                o.get("standard_id") or o.get("id") for o in observables
            ]
            all_refs = obs_stix_ids + all_new_ids
            grp_ns = uuid.UUID("d4565c42-e0b4-4f6a-a345-1b5cb3c8d2a0")
            grp_id = "grouping--" + str(
                uuid.uuid5(grp_ns, f"container-enrichment-{container_id}")
            )
            summary_grouping = stix2.Grouping(
                id=grp_id,
                created_by_ref=self.author,
                name=(
                    f"Scout Enrichment: {entity_type} "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}"
                ),
                context="suspicious-activity",
                object_refs=all_refs,
                object_marking_refs=[self.tlp_marking_id],
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            grp_bundle = self.helper.stix2_create_bundle(
                [self.author, summary_grouping]
            )
            self.helper.send_stix2_bundle(grp_bundle)
            self.helper.log_info(
                f"[TeamCymruScout] Created summary Grouping {grp_id} "
                f"with {len(all_refs)} refs"
            )
            # Wait for summary grouping ingestion, then add it too
            time.sleep(5)
            self._add_to_container(container_id, grp_id)

        summary = (
            f"Container enrichment: "
            f"{enriched} enriched, {skipped} TLP-skipped, "
            f"{added} objects added to container, "
            f"{len(observables)} total."
        )
        self.helper.log_info(f"[TeamCymruScout] {summary}")
        return summary

    def _process_message(self, data: dict) -> str:
        opencti_entity = data["enrichment_entity"]
        stix_id = opencti_entity.get("standard_id") or opencti_entity.get("id")
        stix_entity = {"id": stix_id}
        entity_type = opencti_entity.get("entity_type", "")

        if entity_type not in _SUPPORTED_TYPES:
            return f"Unsupported entity type: {entity_type}"

        # Route container types to batch enrichment
        if entity_type in _SUPPORTED_CONTAINER_TYPES:
            return self._enrich_container(opencti_entity, stix_entity)

        if not self._is_tlp_allowed(opencti_entity):
            tlp = self._get_entity_tlp(opencti_entity)
            self.helper.log_info(
                f"[TeamCymruScout] Skipping {entity_type} -- TLP {tlp} exceeds max"
            )
            return f"Skipped: TLP {tlp} exceeds configured maximum ({self.max_tlp})."

        if entity_type in ("IPv4-Addr", "IPv6-Addr"):
            summary, _ = self._enrich_ip(opencti_entity, stix_entity)
            return summary

        summary, _ = self._enrich_domain(opencti_entity, stix_entity)
        return summary

    def start(self):
        self.helper.listen(message_callback=self._process_message)
