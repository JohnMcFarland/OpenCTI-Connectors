from pathlib import Path

import stix2
import yaml
from pycti import Identity, OpenCTIConnectorHelper, get_config_variable

from .client import TeamCymruScoutClient
from .stix_builder import TeamCymruScoutStixBuilder, rating_to_score

_SOURCE_NAME = "Team Cymru Scout"

_SUPPORTED_TYPES = frozenset({"IPv4-Addr", "IPv6-Addr", "Domain-Name"})

_ALLOWED_TLP = frozenset({
    "TLP:CLEAR",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
})


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

        self.use_foundation = get_config_variable(
            "TEAM_CYMRU_SCOUT_USE_FOUNDATION_API",
            ["team_cymru_scout", "use_foundation_api"],
            config,
            default=True,
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
                "Team Cymru Scout — real-time threat intelligence and "
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

        max_tlp_name = get_config_variable(
            "TEAM_CYMRU_SCOUT_MAX_TLP",
            ["team_cymru_scout", "max_tlp"],
            config,
            default="TLP:AMBER+STRICT",
        )
        self.max_tlp = max_tlp_name

        usage = self.client.get_usage()
        if usage:
            self.helper.log_info(
                f"[TeamCymruScout] API usage: "
                f"{usage.get('remaining_queries')}/{usage.get('query_limit')} queries, "
                f"{usage.get('foundation_api_usage', {}).get('remaining_queries')}/"
                f"{usage.get('foundation_api_usage', {}).get('query_limit')} foundation"
            )

    def _get_entity_tlp(self, entity: dict) -> str | None:
        markings = entity.get("objectMarking", [])
        for m in markings:
            defn = m.get("definition", "")
            if defn.startswith("TLP:"):
                return defn
        return None

    def _is_tlp_allowed(self, entity: dict) -> bool:
        tlp = self._get_entity_tlp(entity)
        if tlp is None:
            return True
        return tlp in _ALLOWED_TLP

    def _normalize_foundation(self, data: dict) -> dict:
        as_info = data.get("as_info", [])
        asn = as_info[0]["asn"] if as_info else None
        as_name = as_info[0]["as_name"] if as_info else None
        insights_data = data.get("insights", {})
        pdns_raw = data.get("pdns", [])
        pdns = [d["domain"] for d in pdns_raw if d.get("domain")]
        services = data.get("services", [])

        return {
            "country_code": data.get("country_code"),
            "asn": asn,
            "as_name": as_name,
            "insights_rating": insights_data.get("overall_rating"),
            "insights": insights_data.get("insights", []),
            "tags": data.get("tags") or [],
            "pdns_domains": pdns[: self.max_pdns],
            "open_ports": services,
        }

    def _normalize_details(self, data: dict) -> dict:
        identity = data.get("identity", {})
        whois = data.get("whois", {})
        summary = data.get("summary", {})
        insights_data = summary.get("insights", {})

        asn = identity.get("asn") or summary.get("bgp_asn")
        as_name = identity.get("as_name") or summary.get("bgp_asname")
        cc = summary.get("geo_ip_cc") or whois.get("cc")

        pdns_raw = summary.get("pdns", {}).get("top_pdns", [])
        pdns = [d["domain"] for d in pdns_raw if d.get("domain")]

        ports_raw = summary.get("open_ports", {}).get("top_open_ports", [])
        tags = summary.get("tags") or identity.get("tags") or []

        return {
            "country_code": cc,
            "asn": asn,
            "as_name": as_name,
            "insights_rating": insights_data.get("overall_rating"),
            "insights": insights_data.get("insights", []),
            "tags": tags,
            "pdns_domains": pdns[: self.max_pdns],
            "open_ports": ports_raw,
        }

    def _enrich_ip(self, opencti_entity: dict, stix_entity: dict) -> str:
        ip_value = opencti_entity.get("observable_value", "")
        self.helper.log_info(f"[TeamCymruScout] Enriching IP: {ip_value}")

        if self.use_foundation:
            raw = self.client.get_ip_foundation(ip_value)
            if raw is None:
                return f"No data returned from Scout Foundation API for {ip_value}."
            enrichment = self._normalize_foundation(raw)
        else:
            raw = self.client.get_ip_details(ip_value)
            if raw is None:
                return f"No data returned from Scout Details API for {ip_value}."
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

    def _enrich_domain(self, opencti_entity: dict, stix_entity: dict) -> str:
        domain_value = opencti_entity.get("observable_value", "")
        self.helper.log_info(f"[TeamCymruScout] Enriching domain: {domain_value}")

        raw = self.client.search(domain_value, size=self.domain_search_size)
        if raw is None:
            return f"No data returned from Scout Search API for {domain_value}."

        ips = raw.get("ips", [])
        if not ips:
            return f"Scout returned no IP associations for {domain_value}."

        builder = TeamCymruScoutStixBuilder(
            self.helper, self.author, self.tlp_marking_id,
            stix_entity, opencti_entity,
        )

        for ip_entry in ips:
            ip_value = ip_entry.get("ip")
            if not ip_value:
                continue

            as_info = ip_entry.get("as_info", [])
            asn = as_info[0]["asn"] if as_info else None
            as_name = as_info[0]["as_name"] if as_info else None

            builder.create_domain_ip_resolves_to(ip_value, asn, as_name)

        tags = []
        insights_list = []
        insights_rating = None
        if ips:
            first_ip = ips[0]
            tags = first_ip.get("tags", [])
            summary = first_ip.get("summary", {})
            if summary:
                insights_data = summary.get("insights", {})
                if insights_data:
                    insights_rating = insights_data.get("overall_rating")
                    insights_list = insights_data.get("insights", [])

        builder.create_assessment_note(
            insights_rating, insights_list, tags,
        )

        return builder.send_bundle()

    def _process_message(self, data: dict) -> str:
        opencti_entity = data["enrichment_entity"]
        stix_id = opencti_entity.get("standard_id") or opencti_entity.get("id")
        stix_entity = {"id": stix_id}
        entity_type = opencti_entity.get("entity_type", "")

        if entity_type not in _SUPPORTED_TYPES:
            return f"Unsupported entity type: {entity_type}"

        if not self._is_tlp_allowed(opencti_entity):
            tlp = self._get_entity_tlp(opencti_entity)
            self.helper.log_info(
                f"[TeamCymruScout] Skipping {entity_type} — TLP {tlp} exceeds max"
            )
            return f"Skipped: TLP {tlp} exceeds configured maximum ({self.max_tlp})."

        if entity_type in ("IPv4-Addr", "IPv6-Addr"):
            return self._enrich_ip(opencti_entity, stix_entity)
        elif entity_type == "Domain-Name":
            return self._enrich_domain(opencti_entity, stix_entity)

        return f"No handler for entity type: {entity_type}"

    def start(self):
        self.helper.listen(message_callback=self._process_message)
