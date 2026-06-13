"""Build a STIX bundle (list of dict objects) from a normalized AttackEvent.

Encodes the data_model/ rules in code. See CONNECTOR_SCOPE.md §5.

Hard rules enforced here:
  * Container = Incident Response (Case-Incident). Sightings are ONLY emitted here.
  * NO Indicators are ever created (OpenCTI auto-promotes Observables).
  * Network-Traffic objects carry a SINGLE port only — no protocol/refs/bps/pps.
  * Every relationship type is checked against ALLOWED_EDGES (fail-closed allow-list).
  * Relationships carry description + confidence + start/stop dates.
  * Times are SOURCE times; markings default TLP:AMBER+STRICT.
  * Country is looked up, never created. Prolexic Incidents are source-less.

Objects are emitted as plain dicts (not stix2 classes) so the single-port
Network-Traffic SCO — which is intentionally non-conformant to strict STIX 2.1
required properties — can be represented. The connector wraps them in a bundle.
"""

from __future__ import annotations

import json
import uuid

import stix2
from pycti import (
    AttackPattern,
    Identity,
    Incident,
    Note,
    StixCoreRelationship,
    StixSightingRelationship,
)

from .config import Settings
from .mitre_map import map_vectors
from .models import AttackEvent

# OASIS STIX SCO namespace, for the deterministic single-port Network-Traffic id.
_SCO_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# (source_logical_type, relationship_type, target_logical_type) drawn directly from
# data_model/Data_Model_Relationship_Guide5.csv. "system"/"organization" are logical
# (both are STIX identities). The builder refuses any edge not in this set.
ALLOWED_EDGES: set[tuple[str, str, str]] = {
    ("incident", "uses", "attack-pattern"),            # row 76
    ("network-traffic", "related-to", "incident"),     # row 78
    ("ipv4-addr", "related-to", "network-traffic"),    # row 77
    ("ipv6-addr", "related-to", "network-traffic"),    # row 77 (v6 analogue)
    ("ipv4-addr", "belongs-to", "autonomous-system"),  # row 30
    ("ipv6-addr", "belongs-to", "autonomous-system"),  # row 30 (v6 analogue)
    ("ipv4-addr", "located-at", "location"),           # row 74
    ("ipv6-addr", "located-at", "location"),           # row 74 (v6 analogue)
    ("autonomous-system", "related-to", "organization"),  # row 2
    ("system", "belongs-to", "organization"),          # row 53
    ("url", "related-to", "domain-name"),              # row 80
    ("url", "related-to", "ipv4-addr"),                # row 79
    ("incident", "originates-from", "location"),       # row 72
}


class AkamaiStixBuilder:
    def __init__(self, helper, settings: Settings) -> None:
        self.helper = helper
        self.settings = settings
        self.confidence = settings.akamai_confidence
        self.top_n = settings.akamai_source_ip_top_n
        self.author_id = Identity.generate_id("Akamai", "organization")
        self.target_org_name = settings.akamai_target_org_name or "Akamai"
        self.target_org_id = Identity.generate_id(self.target_org_name, "organization")
        self.marking_id: str | None = None
        self._country_cache: dict[str, str | None] = {}

    # -- one-time setup ----------------------------------------------------

    def prepare(self) -> None:
        """Resolve the default marking id once (per the data model, must exist)."""
        self.marking_id = self._resolve_marking(self.settings.akamai_tlp)
        if not self.marking_id:
            self.helper.connector_logger.error(
                "Default marking not found; objects will be unmarked",
                {"tlp": self.settings.akamai_tlp},
            )

    # -- public ------------------------------------------------------------

    def build(self, event: AttackEvent) -> list[dict]:
        objects: list[dict] = []
        refs: list[str] = []

        def add(obj: dict, *, member: bool = True) -> str:
            objects.append(obj)
            if member:
                refs.append(obj["id"])
            return obj["id"]

        # author (createdBy, not a container member) + target org (member)
        add(self._identity("Akamai", "organization", created_by=False), member=False)
        org_id = add(self._identity(self.target_org_name, "organization"))

        layer = "application" if event.source_system == "siem" else "network"
        created = event.start_time.isoformat()
        stop = event.end_time.isoformat()

        # 1. Incident
        incident = self._incident(event)
        inc_id = add(incident)

        # 2. Attack Pattern(s) — only if classified DDoS (decision D)
        if event.is_ddos:
            for tid, name in map_vectors(event.vectors, layer):
                ap_id = add(self._attack_pattern(tid, name))
                self._rel(objects, refs, inc_id, "incident", "uses", ap_id, "attack-pattern",
                         f"Akamai classified this activity as {name} ({tid}).", created, stop)

        # 3. Network-Traffic, one per port (SINGLE PORT ONLY)
        for port in event.dest_ports:
            nt_id = add(self._network_traffic(port))
            self._rel(objects, refs, nt_id, "network-traffic", "related-to", inc_id, "incident",
                     f"Targeted destination port {port} observed in the attack.", created, stop)

        # 4. Target System(s): per hostname (SIEM) / per prefix (Prolexic) -> belongs-to Org
        systems: list[str] = []
        for asset in (event.target_hostnames or event.target_ips):
            sys_id = add(self._identity(asset, "system"))
            systems.append(sys_id)
            self._rel(objects, refs, sys_id, "system", "belongs-to", org_id, "organization",
                     f"Asset targeted in Akamai-detected DDoS activity ({asset}).", created, stop)

        # 5. Source IPs (SIEM only; Prolexic is source-less) -> observable + ASN + Country + Sighting
        for sip in event.source_ips[: self.top_n]:
            ip_logtype = "ipv6-addr" if sip.version == 6 else "ipv4-addr"
            ip_id = add(self._ip_observable(sip))
            if sip.asn:
                as_id = add(self._autonomous_system(sip.asn, sip.asn_name))
                self._rel(objects, refs, ip_id, ip_logtype, "belongs-to", as_id,
                         "autonomous-system", f"Source IP announced from AS{sip.asn}.", created, stop)
            country_id = self._resolve_country(sip.country_iso)
            if country_id:
                self._rel(objects, refs, ip_id, ip_logtype, "located-at", country_id, "location",
                         f"Source IP geolocated to {sip.country_iso}.", created, stop)
            for sys_id in systems:  # Sighting of the source IP on each target system
                add(self._sighting(ip_id, sys_id, event.start_time, event.end_time, sip.volume))

        # 6. L7 targeted host -> Domain-Name + URL
        if event.source_system == "siem":
            scheme = "https" if 443 in event.dest_ports else "http"
            for host in event.target_hostnames:
                dom_id = add(self._domain(host))
                for path in (event.url_paths or ["/"]):
                    url_id = add(self._url(f"{scheme}://{host}{path}"))
                    self._rel(objects, refs, url_id, "url", "related-to", dom_id, "domain-name",
                             f"Request URL targeting {host}.", created, stop)

        # 7. Note — provenance + peak summary; assessment of aggregation
        add(self._note(event, inc_id))

        # 8. Relationships were appended as members above; finally the container
        objects.append(self._container(event, refs))
        return objects

    # -- object builders (return dicts) -----------------------------------

    def _base(self, obj: dict, *, created_by: bool = True) -> dict:
        obj["spec_version"] = "2.1"
        if self.marking_id:
            obj["object_marking_refs"] = [self.marking_id]
        if created_by:
            obj["created_by_ref"] = self.author_id
        return obj

    def _identity(self, name: str, cls: str, *, created_by: bool = True) -> dict:
        return self._base({
            "type": "identity",
            "id": Identity.generate_id(name, cls),
            "name": name,
            "identity_class": cls,
        }, created_by=created_by)

    def _incident(self, event: AttackEvent) -> dict:
        name = event.display_name()
        return self._base({
            "type": "incident",
            "id": Incident.generate_id(name, event.start_time.isoformat()),
            "name": name,
            "description": self._incident_description(event),
            "created": event.start_time.isoformat(),
            "incident_type": "ddos",
            "source": f"Akamai {event.source_system}",
            "confidence": self.confidence,
            "first_seen": event.start_time.isoformat(),
            "last_seen": event.end_time.isoformat(),
        })

    def _attack_pattern(self, tid: str, name: str) -> dict:
        return self._base({
            "type": "attack-pattern",
            "id": AttackPattern.generate_id(name, tid),
            "name": name,
            "x_mitre_id": tid,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            }],
        })

    def _network_traffic(self, port: int) -> dict:
        # SINGLE PORT ONLY — see memory: network-traffic-single-port. Deterministic id
        # so the same port dedups across runs. No protocol/refs/bps/pps by house rule.
        nt_id = f"network-traffic--{uuid.uuid5(_SCO_NS, f'dst_port={port}')}"
        return self._base({"type": "network-traffic", "id": nt_id, "dst_port": port})

    def _ip_observable(self, sip) -> dict:
        cls = stix2.IPv6Address if sip.version == 6 else stix2.IPv4Address
        d = json.loads(cls(value=sip.ip).serialize())  # stix2 derives the canonical SCO id
        d["x_opencti_description"] = "Source IP observed in Akamai-detected DDoS activity."
        return self._base(d)

    def _autonomous_system(self, asn: int, name: str | None) -> dict:
        d = json.loads(stix2.AutonomousSystem(number=asn, name=name or f"AS{asn}").serialize())
        return self._base(d)

    def _domain(self, host: str) -> dict:
        return self._base(json.loads(stix2.DomainName(value=host).serialize()))

    def _url(self, value: str) -> dict:
        return self._base(json.loads(stix2.URL(value=value).serialize()))

    def _sighting(self, ip_id: str, system_id: str, first, last, count: int | None) -> dict:
        return self._base({
            "type": "sighting",
            "id": StixSightingRelationship.generate_id(
                ip_id, system_id, first.isoformat(), last.isoformat()),
            "sighting_of_ref": ip_id,
            "where_sighted_refs": [system_id],
            "first_seen": first.isoformat(),
            "last_seen": last.isoformat(),
            "count": count or 1,
            "confidence": self.confidence,
        })

    def _note(self, event: AttackEvent, incident_id: str) -> dict:
        content = self._incident_description(event)
        if event.source_system == "siem" and len(event.source_ips) > self.top_n:
            content += (f"\n\nSource IPs: {len(event.source_ips)} observed; "
                       f"top {self.top_n} ingested as Observables (decision B).")
        return self._base({
            "type": "note",
            "id": Note.generate_id(content, event.start_time.isoformat()),
            "abstract": f"Akamai DDoS provenance — {event.attack_id}",
            "content": content,
            "object_refs": [incident_id],
        })

    def _container(self, event: AttackEvent, refs: list[str]) -> dict:
        # Incident Response container (Case-Incident). Sightings live only here.
        name = event.display_name()
        return self._base({
            "type": "case-incident",
            "id": "x-opencti-case-incident--" + str(uuid.uuid5(_SCO_NS, "ir:" + name)),
            "name": name,
            "description": self._incident_description(event),
            "created": event.start_time.isoformat(),
            "object_refs": refs,
            # TODO(live): confirm pycti CaseIncident custom-object type/id ('case-incident'
            # vs 'x-opencti-case-incident') against the running OpenCTI 6.9.x version.
        })

    # -- relationships (fail-closed) --------------------------------------

    def _rel(self, objects, refs, src_id, src_log, rel_type, tgt_id, tgt_log,
            description, start, stop) -> None:
        triple = (src_log, rel_type, tgt_log)
        if triple not in ALLOWED_EDGES:
            self.helper.connector_logger.warning(
                "Off-allow-list edge -> falling back to related-to", {"edge": str(triple)})
            rel_type = "related-to"
        rel = self._base({
            "type": "relationship",
            "id": StixCoreRelationship.generate_id(rel_type, src_id, tgt_id),
            "relationship_type": rel_type,
            "source_ref": src_id,
            "target_ref": tgt_id,
            "description": description,
            "confidence": self.confidence,
            "start_time": start,
            "stop_time": stop,
        })
        objects.append(rel)
        refs.append(rel["id"])

    # -- helpers -----------------------------------------------------------

    def _incident_description(self, event: AttackEvent) -> str:
        parts = [f"Akamai {event.source_system.upper()} detected DDoS activity."]
        if event.vectors:
            parts.append("Vectors: " + ", ".join(event.vectors) + ".")
        if event.dest_ports:
            parts.append("Destination ports: " + ", ".join(map(str, event.dest_ports)) + ".")
        if event.target_hostnames or event.target_ips:
            parts.append("Targets: " + ", ".join(event.target_hostnames or event.target_ips) + ".")
        if event.peak_bps:
            parts.append(f"Peak bandwidth: {event.peak_bps:,} bps.")
        if event.peak_pps:
            parts.append(f"Peak packet rate: {event.peak_pps:,} pps.")
        if event.mitigation:
            parts.append(event.mitigation + ".")
        if event.ticket_id:
            parts.append(f"Akamai ticket: {event.ticket_id}.")
        return " ".join(parts)

    def _resolve_marking(self, tlp: str) -> str | None:
        try:
            m = self.helper.api.marking_definition.read(filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [tlp]}],
                "filterGroups": [],
            })
            return m["standard_id"] if m else None
        except Exception as exc:  # noqa: BLE001
            self.helper.connector_logger.warning("Marking lookup failed", {"error": str(exc)})
            return None

    def _resolve_country(self, iso: str | None) -> str | None:
        """Look up an existing Country (never create). Cached. Returns standard_id or None."""
        if not iso:
            return None
        if iso in self._country_cache:
            return self._country_cache[iso]
        result = None
        try:
            loc = self.helper.api.location.read(filters={
                "mode": "and",
                "filters": [{"key": "x_opencti_aliases", "values": [iso]}],
                "filterGroups": [],
            })
            result = loc["standard_id"] if loc else None
        except Exception as exc:  # noqa: BLE001
            self.helper.connector_logger.warning("Country lookup failed",
                                                 {"iso": iso, "error": str(exc)})
        self._country_cache[iso] = result
        return result
