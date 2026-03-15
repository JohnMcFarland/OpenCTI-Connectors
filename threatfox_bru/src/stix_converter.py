"""Convert ThreatFox IOC entries into STIX 2.1 objects.

Produces per-IOC:
  SCOs:  domain-name | ipv4-addr | url | file | autonomous-system
         network-traffic (port-only, no dst_ref) for ip:port IOCs
  SDOs:  malware (malware_printable + MITRE software tags), identity (reporter)
  SROs:  observable --related-to--> malware
         observable --related-to--> malware/tool (MITRE tags)
         observable --related-to--> reporter identity
         ipv4-addr --related-to--> network-traffic
         ipv4-addr --belongs-to--> autonomous-system

No indicators, no infrastructure, no attack-patterns.
Report container assembled by connector.py.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from . import config
from .mitre_lookup import MitreLookup
from .tag_processor import ProcessedTags, TagProcessor
from .uuid_generator import (
    autonomous_system_id,
    identity_id,
    malware_id,
    network_traffic_id,
    observable_id,
    relationship_id,
    tool_id,
)

logger = logging.getLogger(__name__)

TLP_CLEAR = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": config.TLP_CLEAR_ID,
    "created": "2017-01-20T00:00:00.000Z",
    "definition_type": "statement",
    "definition": {"statement": "This information may be distributed without restriction."},
    "name": "TLP:CLEAR",
}

CTHREATFOX_IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": config.CTHREATFOX_IDENTITY_ID,
    "name": config.CTHREATFOX_IDENTITY_NAME,
    "identity_class": "organization",
    "object_marking_refs": [config.TLP_CLEAR_ID],
}


def _parse_datetime(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    dt_str = dt_str.removesuffix(" UTC").strip()
    return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def _format_datetime(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _normalize_confidence(confidence_level: int) -> int:
    return int(confidence_level * config.CONFIDENCE_MULTIPLIER)


def _build_external_references(reference: str | None, ioc_id: str) -> list[dict]:
    refs = [{
        "source_name": "ThreatFox",
        "url": f"https://threatfox.abuse.ch/ioc/{ioc_id}/",
        "description": f"ThreatFox IOC {ioc_id}",
    }]
    if reference:
        refs.append({"source_name": "ThreatFox Reference", "url": reference})
    return refs


class StixConverter:

    def __init__(self, mitre_lookup: MitreLookup):
        self._mitre = mitre_lookup
        self._tag_processor = TagProcessor(mitre_lookup)
        self._identities: dict[str, dict] = {}
        self._malware_sdos: dict[str, dict] = {}
        self._autonomous_systems: dict[str, dict] = {}
        self._mitre_software: dict[str, dict] = {}
        self._malware_name_registry: dict[str, str] = {}
        self._observables: list[dict] = []
        self._relationships: list[dict] = []
        self._seen_relationship_keys: set[str] = set()

    def convert(self, threatfox_data: dict[str, list[dict]]) -> list[dict]:
        self._reset()

        for ioc_id, entries in threatfox_data.items():
            for entry in entries:
                try:
                    self._convert_entry(ioc_id, entry)
                except Exception as exc:
                    logger.warning("Skipping IOC %s: %s", ioc_id, exc)

        all_objects: list[dict] = [TLP_CLEAR, CTHREATFOX_IDENTITY]
        all_objects.extend(self._identities.values())
        all_objects.extend(self._malware_sdos.values())
        all_objects.extend(self._autonomous_systems.values())
        all_objects.extend(self._mitre_software.values())
        all_objects.extend(self._observables)
        all_objects.extend(self._relationships)

        logger.info(
            "Converted %d IOC entries → %d STIX objects "
            "(%d identities, %d malware, %d AS, %d MITRE software, "
            "%d observables, %d relationships)",
            len(threatfox_data), len(all_objects),
            len(self._identities), len(self._malware_sdos),
            len(self._autonomous_systems), len(self._mitre_software),
            len(self._observables), len(self._relationships),
        )
        return all_objects

    def _reset(self) -> None:
        self._identities.clear()
        self._malware_sdos.clear()
        self._autonomous_systems.clear()
        self._mitre_software.clear()
        self._malware_name_registry.clear()
        self._observables.clear()
        self._relationships.clear()
        self._seen_relationship_keys.clear()

    def _convert_entry(self, ioc_id: str, entry: dict) -> None:
        ioc_value = entry.get("ioc") or entry["ioc_value"]
        ioc_type = entry["ioc_type"]
        threat_type = entry.get("threat_type", "")
        malware_printable = entry.get("malware_printable", "")
        malware_alias = entry.get("malware_alias")
        first_seen = _parse_datetime(entry.get("first_seen_utc") or entry.get("first_seen"))
        last_seen = _parse_datetime(entry.get("last_seen_utc") or entry.get("last_seen"))
        confidence_level = entry.get("confidence_level", 50)
        reference = entry.get("reference")
        reporter = (entry.get("reporter") or "").strip()
        is_anonymous = str(entry.get("anonymous", "0")) == "1"

        raw_tags = entry.get("tags")
        tags_string = ",".join(raw_tags) if isinstance(raw_tags, list) else raw_tags

        normalized_confidence = _normalize_confidence(confidence_level)
        ext_refs = _build_external_references(reference, ioc_id)

        # Reporter identity (organization, conditional)
        reporter_identity_id: Optional[str] = None
        if not is_anonymous and reporter.lower() not in config.ANONYMOUS_REPORTERS:
            reporter_identity_id = self._get_or_create_reporter_identity(reporter)

        # Malware SDO
        malware_sdo_id: Optional[str] = None
        if malware_printable:
            malware_sdo_id = self._get_or_create_malware(
                malware_printable, threat_type, malware_alias)

        # Observable SCO (primary — ipv4-addr for ip:port, network-traffic created internally)
        observable_stix_id = self._create_observable(
            ioc_type, ioc_value, normalized_confidence, ext_refs,
            reporter_identity_id, first_seen, last_seen)
        if observable_stix_id is None:
            return

        if malware_sdo_id:
            self._add_relationship(observable_stix_id, "related-to", malware_sdo_id)

        if reporter_identity_id:
            self._add_relationship(observable_stix_id, "related-to", reporter_identity_id)

        processed_tags = self._tag_processor.process_tags(tags_string)
        self._apply_tag_objects(processed_tags, observable_stix_id, ioc_type)

    def _get_or_create_reporter_identity(self, reporter: str) -> str:
        sid = identity_id(reporter)
        if sid not in self._identities:
            self._identities[sid] = {
                "type": "identity",
                "spec_version": "2.1",
                "id": sid,
                "name": reporter,
                "identity_class": "organization",
                "object_marking_refs": [config.TLP_CLEAR_ID],
            }
        return sid

    def _get_or_create_malware(
        self, malware_printable: str, threat_type: str, malware_alias: str | None
    ) -> str:
        normalized_name = malware_printable.lower()
        sid = malware_id(malware_printable)
        self._malware_name_registry[normalized_name] = sid
        self._malware_name_registry[normalized_name.replace(" ", "")] = sid

        if sid not in self._malware_sdos:
            malware_types = config.THREAT_TYPE_MALWARE_TYPES.get(threat_type, ["unknown"])
            aliases: list[str] = []
            if malware_alias:
                aliases = [a.strip() for a in malware_alias.split(",") if a.strip()]
                for alias in aliases:
                    self._malware_name_registry[alias.lower()] = sid

            obj: dict[str, Any] = {
                "type": "malware",
                "spec_version": "2.1",
                "id": sid,
                "name": malware_printable,
                "malware_types": malware_types,
                "is_family": True,
                "object_marking_refs": [config.TLP_CLEAR_ID],
            }
            if aliases:
                obj["aliases"] = aliases
            self._malware_sdos[sid] = obj

        return sid

    def _create_observable(
        self,
        ioc_type: str,
        ioc_value: str,
        confidence: int,
        ext_refs: list[dict],
        created_by_ref: Optional[str],
        first_seen: Optional[datetime],
        last_seen: Optional[datetime],
    ) -> Optional[str]:
        """Create observable SCO(s) and return the primary STIX ID.

        For ip:port: creates ipv4-addr (primary) + network-traffic (port-only,
        no dst_ref) and links them via ipv4-addr --related-to--> network-traffic.
        All upstream relationships (to malware, identity, ASN) are applied to
        the ipv4-addr as the primary observable.
        """
        base: dict[str, Any] = {
            "spec_version": "2.1",
            "object_marking_refs": [config.TLP_CLEAR_ID],
            "x_opencti_score": confidence,
            "external_references": ext_refs,
        }
        if created_by_ref:
            base["created_by_ref"] = created_by_ref
        if first_seen:
            base["x_opencti_created_at"] = _format_datetime(first_seen)
        if last_seen:
            base["x_opencti_updated_at"] = _format_datetime(last_seen)

        if ioc_type == "domain":
            sid = observable_id("domain-name", ioc_value)
            self._observables.append({**base, "type": "domain-name", "id": sid, "value": ioc_value})
            return sid

        elif ioc_type == "ip:port":
            ip, port_str = ioc_value.rsplit(":", 1)
            port = int(port_str)

            # Primary observable: ipv4-addr
            ip_sid = observable_id("ipv4-addr", ip)
            self._observables.append({**base, "type": "ipv4-addr", "id": ip_sid, "value": ip})

            # Secondary observable: network-traffic (port-only, no dst_ref)
            nt_sid = network_traffic_id(ip, port)
            self._observables.append({
                "type": "network-traffic",
                "spec_version": "2.1",
                "id": nt_sid,
                "dst_port": port,
                "protocols": ["tcp"],
                "object_marking_refs": [config.TLP_CLEAR_ID],
            })

            # Link: ipv4-addr --related-to--> network-traffic
            self._add_relationship(ip_sid, "related-to", nt_sid)

            return ip_sid

        elif ioc_type == "url":
            sid = observable_id("url", ioc_value)
            self._observables.append({**base, "type": "url", "id": sid, "value": ioc_value})
            return sid

        elif ioc_type in ("sha256_hash", "md5_hash", "sha1_hash"):
            hashes = {"SHA-256": ioc_value} if ioc_type == "sha256_hash" else \
                     {"SHA-1": ioc_value} if ioc_type == "sha1_hash" else \
                     {"MD5": ioc_value}
            sid = observable_id("file", ioc_value)
            self._observables.append({**base, "type": "file", "id": sid, "hashes": hashes})
            return sid

        else:
            logger.debug("Unsupported ioc_type '%s' — skipping", ioc_type)
            return None

    def _apply_tag_objects(
        self, tags: ProcessedTags, observable_stix_id: str, ioc_type: str
    ) -> None:
        for tag in tags.asn_tags:
            as_id = autonomous_system_id(tag.as_number)
            if as_id not in self._autonomous_systems:
                self._autonomous_systems[as_id] = {
                    "type": "autonomous-system",
                    "spec_version": "2.1",
                    "id": as_id,
                    "number": tag.as_number,
                    "object_marking_refs": [config.TLP_CLEAR_ID],
                }
            if ioc_type == "ip:port":
                self._add_relationship(observable_stix_id, "belongs-to", as_id)

        for tag in tags.software_tags:
            sw_id = self._get_or_create_mitre_software(tag)
            self._add_relationship(observable_stix_id, "related-to", sw_id)

    def _get_or_create_mitre_software(self, tag) -> str:
        normalized_tag = tag.mitre_name.lower()
        normalized_tag_nospace = normalized_tag.replace(" ", "")

        existing_id = (self._malware_name_registry.get(normalized_tag)
                       or self._malware_name_registry.get(normalized_tag_nospace))

        if existing_id:
            target = self._malware_sdos if existing_id in self._malware_sdos else self._mitre_software
            existing = target.get(existing_id)
            if existing:
                mitre_ref = {
                    "source_name": "mitre-attack",
                    "external_id": tag.mitre_external_id,
                    "url": f"https://attack.mitre.org/software/{tag.mitre_external_id}/",
                }
                existing.setdefault("external_references", [])
                if tag.mitre_external_id not in {r.get("external_id") for r in existing["external_references"]}:
                    existing["external_references"].append(mitre_ref)
            return existing_id

        sid = tool_id(tag.mitre_name) if tag.mitre_type == "tool" else malware_id(tag.mitre_name)

        if sid not in self._mitre_software:
            obj: dict[str, Any] = {
                "type": tag.mitre_type,
                "spec_version": "2.1",
                "id": sid,
                "name": tag.mitre_name,
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tag.mitre_external_id,
                    "url": f"https://attack.mitre.org/software/{tag.mitre_external_id}/",
                }],
                "object_marking_refs": [config.TLP_CLEAR_ID],
            }
            if tag.mitre_type == "malware":
                obj["malware_types"] = ["unknown"]
                obj["is_family"] = True
            self._mitre_software[sid] = obj
            self._malware_name_registry[normalized_tag] = sid
            self._malware_name_registry[normalized_tag_nospace] = sid

        return sid

    def _add_relationship(self, source_id: str, rel_type: str, target_id: str) -> None:
        triple_key = f"{source_id}:{rel_type}:{target_id}"
        if triple_key in self._seen_relationship_keys:
            return
        self._seen_relationship_keys.add(triple_key)
        rid = relationship_id(source_id, rel_type, target_id)
        self._relationships.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rid,
            "relationship_type": rel_type,
            "source_ref": source_id,
            "target_ref": target_id,
            "object_marking_refs": [config.TLP_CLEAR_ID],
        })
