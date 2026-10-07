import uuid
from datetime import datetime, timezone
from urllib.parse import quote

import pycountry
import stix2
from pycti import (
    Location,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)

_RATING_SCORES = {
    "malicious": 85,
    "suspicious": 50,
    "no_rating": 20,
}

_NS = uuid.UUID("7c3e1a4b-9d2f-5e6c-8a1b-0c3d5e7f9a2b")


def _note_id(observable_value: str) -> str:
    return f"note--{uuid.uuid5(_NS, observable_value)}"


def _grouping_id(observable_value: str) -> str:
    return f"grouping--{uuid.uuid5(_NS, f'grouping:{observable_value}')}"


def rating_to_score(rating: str | None) -> int | None:
    if rating is None:
        return None
    return _RATING_SCORES.get(rating)


class TeamCymruScoutStixBuilder:

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        tlp_marking_id: str,
        stix_entity: dict,
        opencti_entity: dict,
    ):
        self.helper = helper
        self.author = author
        self.tlp_marking_id = tlp_marking_id
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.bundle: list = []

        self._obs_value = opencti_entity.get("observable_value", "")
        self._entity_type = (
            opencti_entity.get("entity_type", "").lower().replace("-", "")
        )

        self._ext_ref = stix2.ExternalReference(
            source_name="Team Cymru Scout",
            url=f"https://scout.cymru.com/scout/details?query={quote(self._obs_value, safe='')}",
            description=f"Team Cymru Scout lookup for {self._obs_value}",
        )

    def _add(self, *objects):
        self.bundle.extend(objects)

    def _make_relationship(
        self, rel_type: str, source_id: str, target_id: str, description: str = "",
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            relationship_type=rel_type,
            created_by_ref=self.author,
            source_ref=source_id,
            target_ref=target_id,
            description=description or None,
            confidence=self.helper.connect_confidence_level,
            object_marking_refs=[self.tlp_marking_id],
            external_references=[self._ext_ref],
            allow_custom=True,
        )

    def create_asn_belongs_to(self, asn: int, as_name: str):
        if self._entity_type != "ipv4addr":
            return

        as_stix = stix2.AutonomousSystem(
            number=asn,
            name=as_name,
            object_marking_refs=[self.tlp_marking_id],
            custom_properties={
                "created_by_ref": self.author.id,
                "x_opencti_description": (
                    f"AS{asn} ({as_name}) as reported by Team Cymru Scout."
                ),
            },
        )
        rel = self._make_relationship(
            "belongs-to",
            self.stix_entity["id"],
            as_stix.id,
            f"{self._obs_value} belongs to AS{asn} ({as_name}).",
        )
        self._add(as_stix, rel)

    def create_location_located_at(self, country_code: str):
        if self._entity_type != "ipv4addr":
            return

        entry = pycountry.countries.get(alpha_2=country_code.upper())
        country_name = entry.name if entry else country_code

        location = stix2.Location(
            id=Location.generate_id(country_name, "Country"),
            created_by_ref=self.author,
            name=country_name,
            country=country_code.upper(),
            object_marking_refs=[self.tlp_marking_id],
            custom_properties={"x_opencti_aliases": [country_code.upper()]},
        )
        rel = self._make_relationship(
            "located-at",
            self.stix_entity["id"],
            location.id,
            f"{self._obs_value} is geolocated to {country_name}.",
        )
        self._add(location, rel)

    def create_pdns_resolves_to(self, domains: list):
        for domain in domains:
            domain_stix = stix2.DomainName(
                value=domain,
                object_marking_refs=[self.tlp_marking_id],
                custom_properties={
                    "created_by_ref": self.author.id,
                    "x_opencti_description": (
                        f"Resolved to {self._obs_value} per Team Cymru Scout PDNS."
                    ),
                },
            )
            rel = self._make_relationship(
                "resolves-to",
                domain_stix.id,
                self.stix_entity["id"],
                f"{domain} resolves to {self._obs_value} per Team Cymru Scout.",
            )
            self._add(domain_stix, rel)

    def create_domain_ip_resolves_to(
        self, ip_value: str, asn: int = None, as_name: str = None,
    ):
        if ":" in ip_value:
            return

        ipv4 = stix2.IPv4Address(
            value=ip_value,
            object_marking_refs=[self.tlp_marking_id],
            custom_properties={
                "created_by_ref": self.author.id,
                "x_opencti_description": (
                    f"Associated with {self._obs_value} per Team Cymru Scout."
                ),
            },
        )
        rel = self._make_relationship(
            "resolves-to",
            self.stix_entity["id"],
            ipv4.id,
            f"{self._obs_value} resolves to {ip_value}.",
        )
        self._add(ipv4, rel)

        if asn and as_name:
            as_stix = stix2.AutonomousSystem(
                number=asn,
                name=as_name,
                object_marking_refs=[self.tlp_marking_id],
                custom_properties={"created_by_ref": self.author.id},
            )
            as_rel = self._make_relationship(
                "belongs-to",
                ipv4.id,
                as_stix.id,
                f"{ip_value} belongs to AS{asn} ({as_name}).",
            )
            self._add(as_stix, as_rel)

    def create_assessment_note(
        self,
        insights_rating: str | None,
        insights: list,
        tags: list,
        open_ports: list | None = None,
    ):
        sections = [f"## Team Cymru Scout Assessment: {self._obs_value}"]
        sections.append(f"**Overall Rating:** {insights_rating or 'unknown'}")

        if insights:
            sections.append("\n### Insights")
            for item in insights:
                rating = item.get("rating", "no_rating")
                message = item.get("message", "")
                sections.append(f"- **{rating}**: {message}")

        if tags:
            tag_names = [t.get("name", "") for t in tags if t.get("name")]
            if tag_names:
                sections.append(f"\n### Tags\n{', '.join(tag_names)}")

        if open_ports:
            seen = set()
            port_lines = []
            for p in open_ports:
                port = p.get("port")
                if port and port not in seen:
                    seen.add(port)
                    proto = p.get("protocol_text", "") or p.get("banner", "")
                    port_lines.append(f"- {port}/{proto}")
            if port_lines:
                sections.append("\n### Open Ports")
                sections.extend(port_lines)

        content = "\n".join(sections)

        note = stix2.Note(
            id=_note_id(self._obs_value),
            created_by_ref=self.author,
            object_refs=[self.stix_entity["id"]],
            abstract=f"Team Cymru Scout: {insights_rating or 'unknown'}",
            content=content,
            object_marking_refs=[self.tlp_marking_id],
            confidence=self.helper.connect_confidence_level,
            external_references=[self._ext_ref],
            allow_custom=True,
            custom_properties={"x_opencti_note_types": ["assessment"]},
        )
        self._add(note)

    def send_bundle(self) -> str:
        if not self.bundle:
            return "No enrichment data to send."

        self.bundle.append(self.author)

        object_refs = [self.stix_entity["id"]]
        object_refs.extend(obj.id for obj in self.bundle)

        grouping = stix2.Grouping(
            id=_grouping_id(self._obs_value),
            created_by_ref=self.author,
            name=f"Enrichment {self._obs_value} {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            context="suspicious-activity",
            object_refs=object_refs,
            object_marking_refs=[self.tlp_marking_id],
            confidence=self.helper.connect_confidence_level,
            external_references=[self._ext_ref],
            allow_custom=True,
        )
        self.bundle.append(grouping)

        self.helper.log_debug(
            f"[TeamCymruScout] Sending bundle: {len(self.bundle)} objects"
        )
        self.helper.metric.inc("record_send", len(self.bundle))
        serialized = self.helper.stix2_create_bundle(self.bundle)
        bundles_sent = self.helper.send_stix2_bundle(serialized)
        return f"Sent {len(bundles_sent)} bundle(s) ({len(self.bundle)} objects)."
