"""
UDM Connector — UniFi Dream Machine Pro -> OpenCTI
connector-udm v0.4.2

Fixes vs v0.4.1:
- Added related-to SRO from source IPv4 -> Incident. The IP was being
  added to the container but had no explicit relationship to the Incident
  object it triggered. Now linked and containered.
- attributed-to is not permitted between Observable and Incident in the
  OpenCTI schema (only valid from Intrusion Set -> Threat Actor/Individual
  per the Data Model Relationship Guide). related-to is the correct type.
- Confirmed full containment scope: Source IPv4, Destination IPv4
  (fallback), Country, Software, MAC-Addr, System, OUI Organization,
  WAN System, WAN IPv4 — all entities and their SROs added to the day
  IR container.
"""

import os
import ipaddress
import urllib3
from datetime import datetime, timezone, timedelta
from typing import Optional

import pycountry
import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class ConnectorConfig:
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), "config.yml")
        config = {}
        if os.path.isfile(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}

        self.opencti_url   = get_config_variable("OPENCTI_URL",   ["opencti", "url"],   config)
        self.opencti_token = get_config_variable("OPENCTI_TOKEN", ["opencti", "token"], config)

        self.connector_id        = get_config_variable("CONNECTOR_ID",        ["connector", "id"],        config)
        self.connector_name      = get_config_variable("CONNECTOR_NAME",      ["connector", "name"],      config, default="UDM Connector")
        self.connector_log_level = get_config_variable("CONNECTOR_LOG_LEVEL", ["connector", "log_level"], config, default="INFO")
        self.connector_interval  = get_config_variable("CONNECTOR_INTERVAL",  ["connector", "interval"],  config, default="PT6H")

        self.udm_host            = get_config_variable("UDM_HOST",            ["udm", "host"],            config)
        self.udm_api_key         = get_config_variable("UDM_API_KEY",         ["udm", "api_key"],         config)
        self.udm_site            = get_config_variable("UDM_SITE",            ["udm", "site"],            config, default="default")
        self.udm_tls_verify      = get_config_variable("UDM_TLS_VERIFY",      ["udm", "tls_verify"],      config, default=False)
        self.udm_wan_ip_fallback = get_config_variable("UDM_WAN_IP",          ["udm", "wan_ip"],          config, default="")
        self.udm_internal_subnet = get_config_variable("UDM_INTERNAL_SUBNET", ["udm", "internal_subnet"], config, default="192.168.0.0/24")
        self.udm_page_size       = int(get_config_variable("UDM_PAGE_SIZE",   ["udm", "page_size"],       config, default=500))
        self.udm_backfill_days   = int(get_config_variable("UDM_BACKFILL_DAYS", ["udm", "backfill_days"], config, default=30))

        self.marking_id = get_config_variable(
            "TLP_AMBER_STRICT_ID",
            ["connector", "tlp_amber_strict_id"],
            config,
        )
        if not self.marking_id:
            raise ValueError(
                "TLP_AMBER_STRICT_ID must be set in environment or config.yml"
            )


# ---------------------------------------------------------------------------
# Country resolution
# ---------------------------------------------------------------------------

def resolve_country_name(iso2: str) -> str:
    try:
        country = pycountry.countries.get(alpha_2=iso2.upper())
        if country:
            return country.name
    except Exception:
        pass
    return iso2.upper()


# ---------------------------------------------------------------------------
# UDM API client
# ---------------------------------------------------------------------------

class UDMClient:
    def __init__(self, config: ConnectorConfig, helper):
        self.site    = config.udm_site
        self.verify  = config.udm_tls_verify
        self.helper  = helper
        self.base    = f"https://{config.udm_host}"
        self.headers = {
            "X-API-Key":    config.udm_api_key,
            "Content-Type": "application/json",
        }
        self._wan_ip_fallback = config.udm_wan_ip_fallback

    def _get(self, path: str) -> dict:
        resp = requests.get(
            f"{self.base}{path}", headers=self.headers,
            verify=self.verify, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: dict) -> dict:
        resp = requests.post(
            f"{self.base}{path}", headers=self.headers,
            json=payload, verify=self.verify, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def get_active_clients(self) -> list:
        try:
            return self._get(
                f"/proxy/network/api/s/{self.site}/stat/sta"
            ).get("data", [])
        except Exception as exc:
            self.helper.log_warning(f"[UDM] stat/sta failed: {exc}")
            return []

    def get_wan_ip(self) -> str:
        try:
            data = self._get(f"/proxy/network/api/s/{self.site}/stat/device")
            for device in data.get("data", []):
                for key in ("wan1", "wan2"):
                    ip = device.get(key, {}).get("ip")
                    if ip:
                        self.helper.log_info(f"[UDM] WAN IP via {key}: {ip}")
                        return ip
                ip = device.get("uplink", {}).get("ip")
                if ip:
                    self.helper.log_info(f"[UDM] WAN IP via uplink: {ip}")
                    return ip
        except Exception as exc:
            self.helper.log_warning(f"[UDM] WAN IP resolution failed: {exc}")
        if self._wan_ip_fallback:
            self.helper.log_info(
                f"[UDM] Using fallback WAN IP: {self._wan_ip_fallback}"
            )
            return self._wan_ip_fallback
        self.helper.log_error("[UDM] No WAN IP available")
        return ""

    def get_blocked_flows_page(self, page: int, page_size: int) -> dict:
        payload = {
            "action": ["blocked"],
            "risk": [], "policy": [], "policy_type": [], "protocol": [],
            "direction": [], "service": [],
            "source_ip": [], "source_mac": [], "source_host": [],
            "source_domain": [], "source_port": [], "source_region": [],
            "source_network_id": [], "source_zone_id": [],
            "destination_ip": [], "destination_mac": [], "destination_host": [],
            "destination_domain": [], "destination_port": [],
            "destination_region": [], "destination_network_id": [],
            "destination_zone_id": [],
            "in_network_id": [], "out_network_id": [],
            "except_for": [], "next_ai_query": [],
            "search_text": "", "skip_count": False,
            "pageNumber": page, "pageSize": page_size,
        }
        try:
            return self._post(
                f"/proxy/network/v2/api/site/{self.site}/traffic-flows",
                payload,
            )
        except Exception as exc:
            self.helper.log_warning(
                f"[UDM] traffic-flows page {page} failed: {exc}"
            )
            return {}

    def fetch_all_blocked_flows(self, cutoff_ms: int, page_size: int) -> list:
        all_flows, page = [], 1
        while True:
            resp  = self.get_blocked_flows_page(page, page_size)
            batch = resp.get("data") or []
            if not batch:
                self.helper.log_info(f"[UDM] Page {page}: empty, stopping.")
                break

            in_window = [
                f for f in batch
                if f.get("flow_start_time", 0) >= cutoff_ms
            ]
            all_flows.extend(in_window)

            self.helper.log_info(
                f"[UDM] Page {page}: {len(batch)} flows total, "
                f"{len(in_window)} in window, "
                f"has_next={resp.get('has_next', False)}, "
                f"total={resp.get('total_element_count', '?')}"
            )

            if not resp.get("has_next", False):
                break
            page += 1

        cutoff_str = datetime.fromtimestamp(
            cutoff_ms / 1000, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")
        self.helper.log_info(
            f"[UDM] fetch complete: {len(all_flows)} flows in window "
            f"(cutoff={cutoff_str})"
        )
        return all_flows


# ---------------------------------------------------------------------------
# OpenCTI helper
# ---------------------------------------------------------------------------

class OCTIHelper:
    CONFIDENCE = 85

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorConfig):
        self.h              = helper
        self.marking_id     = config.marking_id
        self.author_id      = None
        self._country_cache: dict = {}

    def _markings(self) -> list:
        return [self.marking_id]

    def get_or_create_external_ref(self, url: str) -> Optional[str]:
        try:
            obj = self.h.api.external_reference.create(
                source_name="UDM Connector",
                url=url,
            )
            return obj["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] External reference create '{url}': {exc}")
            return None

    def resolve_author(self) -> Optional[str]:
        name = "UDM Alert"
        try:
            hits = self.h.api.identity.list(
                types=["Organization"],
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [name], "operator": "eq"}],
                    "filterGroups": [],
                },
            )
            if hits:
                self.author_id = hits[0]["id"]
                self.h.log_info(f"[OCTI] Author resolved: {name} ({self.author_id})")
                return self.author_id
        except Exception as exc:
            self.h.log_warning(f"[OCTI] Author lookup failed: {exc}")
        try:
            obj = self.h.api.identity.create(
                type="Organization", name=name,
                description=(
                    "Author identity for the UDM Connector. "
                    "Represents the UDM Pro as an internal sensor source."
                ),
                objectMarking=self._markings(),
            )
            self.author_id = obj["id"]
            self.h.log_info(f"[OCTI] Created author: {name} ({self.author_id})")
            return self.author_id
        except Exception as exc:
            self.h.log_error(f"[OCTI] Failed to create author '{name}': {exc}")
            return None

    def get_or_create_system(self, name: str, description: str = "") -> Optional[str]:
        try:
            hits = self.h.api.identity.list(
                types=["System"],
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [name], "operator": "eq"}],
                    "filterGroups": [],
                },
            )
            if hits:
                return hits[0]["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] System lookup '{name}': {exc}")
        try:
            obj = self.h.api.identity.create(
                type="System", name=name, description=description,
                objectMarking=self._markings(), createdBy=self.author_id,
                confidence=self.CONFIDENCE,
            )
            self.h.log_info(f"[OCTI] Created System: {name}")
            return obj["id"]
        except Exception as exc:
            self.h.log_error(f"[OCTI] Create System '{name}': {exc}")
            return None

    def get_or_create_organization(self, raw_name: str) -> Optional[str]:
        name = raw_name.strip().title()[:100]
        if not name:
            return None
        try:
            hits = self.h.api.identity.list(
                types=["Organization"],
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [name], "operator": "eq"}],
                    "filterGroups": [],
                },
            )
            if hits:
                return hits[0]["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] Organization lookup '{name}': {exc}")
        try:
            obj = self.h.api.identity.create(
                type="Organization", name=name,
                objectMarking=self._markings(), createdBy=self.author_id,
                confidence=self.CONFIDENCE,
            )
            self.h.log_info(f"[OCTI] Created Organization: {name}")
            return obj["id"]
        except Exception as exc:
            self.h.log_error(f"[OCTI] Create Organization '{name}': {exc}")
            return None

    def get_or_create_software(self, name: str) -> Optional[str]:
        try:
            hits = self.h.api.stix_cyber_observable.list(
                types=["Software"],
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [name], "operator": "eq"}],
                    "filterGroups": [],
                },
            )
            if hits:
                return hits[0]["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] Software lookup '{name}': {exc}")
        try:
            obj = self.h.api.stix_cyber_observable.create(
                observableData={"type": "software", "name": name},
                objectMarking=self._markings(), createdBy=self.author_id,
            )
            self.h.log_info(f"[OCTI] Created Software: {name}")
            return obj["id"]
        except Exception as exc:
            self.h.log_error(f"[OCTI] Create Software '{name}': {exc}")
            return None

    def get_or_create_ipv4(self, ip: str) -> Optional[str]:
        try:
            hits = self.h.api.stix_cyber_observable.list(
                types=["IPv4-Addr"],
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [ip], "operator": "eq"}],
                    "filterGroups": [],
                },
            )
            if hits:
                return hits[0]["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] IPv4 lookup '{ip}': {exc}")
        try:
            obj = self.h.api.stix_cyber_observable.create(
                observableData={"type": "ipv4-addr", "value": ip},
                objectMarking=self._markings(), createdBy=self.author_id,
            )
            return obj["id"]
        except Exception as exc:
            self.h.log_error(f"[OCTI] Create IPv4 '{ip}': {exc}")
            return None

    def get_or_create_mac(self, mac: str) -> Optional[str]:
        try:
            hits = self.h.api.stix_cyber_observable.list(
                types=["Mac-Addr"],
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [mac], "operator": "eq"}],
                    "filterGroups": [],
                },
            )
            if hits:
                return hits[0]["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] Mac-Addr lookup '{mac}': {exc}")
        try:
            obj = self.h.api.stix_cyber_observable.create(
                observableData={"type": "mac-addr", "value": mac},
                objectMarking=self._markings(), createdBy=self.author_id,
            )
            return obj["id"]
        except Exception as exc:
            self.h.log_error(f"[OCTI] Create Mac-Addr '{mac}': {exc}")
            return None

    def get_or_create_country(self, iso2: str) -> Optional[str]:
        name = resolve_country_name(iso2)
        if name in self._country_cache:
            return self._country_cache[name]
        try:
            hits = self.h.api.location.list(
                types=["Country"],
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [name], "operator": "eq"}],
                    "filterGroups": [],
                },
            )
            if hits:
                self._country_cache[name] = hits[0]["id"]
                return hits[0]["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] Country lookup '{name}': {exc}")
        try:
            obj = self.h.api.location.create(
                type="Country", name=name,
                objectMarking=self._markings(), createdBy=self.author_id,
            )
            self.h.log_info(f"[OCTI] Created Country: {name}")
            self._country_cache[name] = obj["id"]
            return obj["id"]
        except Exception as exc:
            self.h.log_error(f"[OCTI] Create Country '{iso2}' -> '{name}': {exc}")
            return None

    def get_or_create_sro(
        self,
        rel_type: str,
        from_id: str,
        to_id: str,
        description: str = "",
        start_time: Optional[str] = None,
        stop_time: Optional[str] = None,
    ) -> Optional[str]:
        try:
            hits = self.h.api.stix_core_relationship.list(
                fromId=from_id, toId=to_id, relationship_type=rel_type,
            )
            if hits:
                return hits[0]["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] SRO lookup {rel_type}: {exc}")
        try:
            kwargs = dict(
                relationship_type=rel_type, fromId=from_id, toId=to_id,
                description=description, objectMarking=self._markings(),
                createdBy=self.author_id, confidence=self.CONFIDENCE,
            )
            if start_time:
                kwargs["start_time"] = start_time
            if stop_time:
                kwargs["stop_time"] = stop_time
            obj = self.h.api.stix_core_relationship.create(**kwargs)
            return obj["id"]
        except Exception as exc:
            self.h.log_error(
                f"[OCTI] Create SRO {rel_type} {from_id}->{to_id}: {exc}"
            )
            return None

    def upsert_sighting(
        self,
        from_id: str,
        to_id: str,
        first_seen: str,
        last_seen: str,
        count: int,
        description: str,
    ) -> Optional[str]:
        try:
            hits = self.h.api.stix_sighting_relationship.list(
                fromId=from_id, toId=to_id,
            )
            if hits:
                existing    = hits[0]
                existing_id = existing["id"]
                new_count   = (existing.get("attribute_count") or 1) + count
                try:
                    self.h.api.stix_sighting_relationship.update_field(
                        id=existing_id,
                        input={"key": "attribute_count", "value": str(new_count)},
                    )
                    self.h.api.stix_sighting_relationship.update_field(
                        id=existing_id,
                        input={"key": "last_seen", "value": last_seen},
                    )
                except Exception as upd_exc:
                    self.h.log_warning(
                        f"[OCTI] Sighting update {existing_id}: {upd_exc}"
                    )
                return existing_id
        except Exception as exc:
            self.h.log_warning(
                f"[OCTI] Sighting lookup {from_id}->{to_id}: {exc}"
            )
        try:
            obj = self.h.api.stix_sighting_relationship.create(
                fromId=from_id, toId=to_id,
                first_seen=first_seen, last_seen=last_seen,
                count=count, description=description,
                objectMarking=self._markings(), createdBy=self.author_id,
                confidence=self.CONFIDENCE,
            )
            return obj["id"]
        except Exception as exc:
            self.h.log_error(
                f"[OCTI] Create Sighting {from_id}->{to_id}: {exc}"
            )
            return None

    def get_or_create_incident(
        self,
        name: str,
        description: str,
        start_time: str,
        stop_time: str,
        objective: str,
    ) -> Optional[str]:
        try:
            hits = self.h.api.incident.list(filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [name], "operator": "eq"}],
                "filterGroups": [],
            })
            if hits:
                return hits[0]["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] Incident lookup '{name}': {exc}")
        try:
            obj = self.h.api.incident.create(
                name=name, description=description,
                first_seen=start_time, last_seen=stop_time,
                objective=objective, objectMarking=self._markings(),
                createdBy=self.author_id, confidence=self.CONFIDENCE,
            )
            self.h.log_info(f"[OCTI] Created Incident: {name}")
            return obj["id"]
        except Exception as exc:
            self.h.log_error(f"[OCTI] Create Incident '{name}': {exc}")
            return None

    def get_or_create_ir_container(self, date_str: str) -> Optional[str]:
        name    = f"UDM Blocked Flows \u2014 {date_str}"
        ext_url = f"udm://blocked-flows/{date_str}"
        try:
            hits = self.h.api.case_incident.list(filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [name], "operator": "eq"}],
                "filterGroups": [],
            })
            if hits:
                return hits[0]["id"]
        except Exception as exc:
            self.h.log_warning(f"[OCTI] IR container lookup '{name}': {exc}")
        try:
            ext_ref_id = self.get_or_create_external_ref(ext_url)
            kwargs = dict(
                name=name,
                description=(
                    f"UDM Pro blocked flows for {date_str}. "
                    f"Ingested by connector-udm."
                ),
                severity="low",
                objectMarking=self._markings(),
                createdBy=self.author_id,
                confidence=self.CONFIDENCE,
            )
            if ext_ref_id:
                kwargs["externalReferences"] = [ext_ref_id]
            obj = self.h.api.case_incident.create(**kwargs)
            self.h.log_info(f"[OCTI] Created IR container: {name}")
            return obj["id"]
        except Exception as exc:
            self.h.log_error(f"[OCTI] Create IR container '{name}': {exc}")
            return None

    def add_to_container(self, container_id: str, object_id: str) -> None:
        if not container_id or not object_id:
            return
        try:
            self.h.api.case_incident.add_stix_object_or_stix_relationship(
                id=container_id,
                stixObjectOrStixRelationshipId=object_id,
            )
        except Exception as exc:
            self.h.log_warning(
                f"[OCTI] add_to_container {container_id}<-{object_id}: {exc}"
            )

    def add_many_to_container(self, container_id: str, *object_ids) -> None:
        for oid in object_ids:
            if oid:
                self.add_to_container(container_id, oid)

    def has_any_udm_container(self) -> bool:
        try:
            hits = self.h.api.case_incident.list(
                search="UDM Blocked Flows", first=1
            )
            return bool(hits)
        except Exception as exc:
            self.h.log_warning(f"[OCTI] First-run detection failed: {exc}")
            return False


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def ms_to_iso(ts_ms) -> str:
    if not ts_ms:
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc).isoformat()


def flow_date_str(flow: dict) -> str:
    ts_ms = flow.get("flow_start_time") or flow.get("time") or 0
    return datetime.fromtimestamp(
        int(ts_ms) / 1000, tz=timezone.utc
    ).strftime("%Y-%m-%d")


def bucket_flows_by_day(flows: list) -> dict:
    buckets: dict = {}
    for flow in flows:
        buckets.setdefault(flow_date_str(flow), []).append(flow)
    return buckets


def is_internal(ip: str, subnet: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False


def _lbl(label: str, value: str, width: int = 16) -> str:
    return f"  {label:<{width}}  {value}"


def flow_description(flow: dict) -> str:
    src      = flow.get("source") or {}
    dst      = flow.get("destination") or {}
    policies = flow.get("policies") or [{}]
    policy   = policies[0]
    ips      = flow.get("ips") or {}
    td       = flow.get("traffic_data") or {}

    start_ms      = flow.get("flow_start_time") or flow.get("time")
    ts_str        = ms_to_iso(start_ms) if start_ms else "Unknown"
    internal_type = (policy.get("internal_type") or "").strip()
    ips_category  = (policy.get("ips_category") or "").strip()

    rule = "=" * 56
    thin = "-" * 56

    lines = [
        f"BLOCKED FLOW  |  {ts_str}",
        rule, "",
        "POLICY", thin,
        _lbl("Name",          policy.get("name") or "---"),
        _lbl("Type",          policy.get("type") or "---"),
    ]
    if ips_category:
        lines.append(_lbl("IPS Category",  ips_category))
    if internal_type:
        lines.append(_lbl("Internal Type", internal_type))

    if ips and internal_type == "SIGNATURE":
        lines += [
            "", "THREAT", thin,
            _lbl("Signature",    ips.get("signature") or "---"),
            _lbl("Signature ID", str(ips.get("signature_id") or "---")),
        ]
        for key, label in [
            ("signature_class", "Class"),
            ("affected_product", "Affected"),
            ("relevant_cve",     "CVE"),
        ]:
            val = (ips.get(key) or "").strip()
            if val:
                lines.append(_lbl(label, val))
        risk_text = (ips.get("alarm_category_potential_risk") or "").strip()
        if risk_text:
            lines += ["", "  Risk Assessment:", f"  {risk_text}"]

    src_ip   = src.get("ip") or "?"
    src_port = str(src.get("port") or "?")
    src_rgn  = (src.get("region") or "").strip()
    dst_ip   = dst.get("ip") or "?"
    dst_port = str(dst.get("port") or "?")
    dst_host = (dst.get("host_name") or dst.get("client_name") or "").strip()

    src_str = f"{src_ip}:{src_port}"
    if src_rgn:
        src_str += f"  [{src_rgn}]"
    dst_str = f"{dst_ip}:{dst_port}"
    if dst_host:
        dst_str += f"  ({dst_host})"

    lines += [
        "", "NETWORK", thin,
        _lbl("Protocol",    flow.get("protocol") or "---"),
        _lbl("Direction",   flow.get("direction") or "---"),
        _lbl("Risk Level",  (flow.get("risk") or "---").upper()),
        _lbl("Source",      src_str),
        _lbl("Destination", dst_str),
    ]
    if td:
        lines.append(_lbl(
            "Traffic",
            f"{td.get('bytes_total', 0):,} bytes  /  "
            f"{td.get('packets_total', 0):,} packets",
        ))
    lines.append("")
    return "\n".join(lines)


def sro_description(flow: dict) -> str:
    policies      = flow.get("policies") or [{}]
    policy        = policies[0]
    ips           = flow.get("ips") or {}
    internal_type = (policy.get("internal_type") or "---").strip()
    ips_category  = (policy.get("ips_category") or "---").strip()

    thin = "-" * 56
    lines = [
        "RELATIONSHIP  |  UDM Blocked Flow", thin,
        _lbl("Policy",        policy.get("name") or "---"),
        _lbl("Policy Type",   policy.get("type") or "---"),
        _lbl("IPS Category",  ips_category),
        _lbl("Internal Type", internal_type),
        _lbl("Protocol",      flow.get("protocol") or "---"),
        _lbl("Direction",     flow.get("direction") or "---"),
        _lbl("Risk Level",    (flow.get("risk") or "---").upper()),
    ]
    if ips and internal_type == "SIGNATURE":
        for key, label in [
            ("signature",    "Signature"),
            ("relevant_cve", "CVE"),
            ("affected_product", "Affected"),
        ]:
            val = (ips.get(key) or "").strip()
            if val:
                lines.append(_lbl(label, val))
    lines.append("")
    return "\n".join(lines)


def incident_times(flow: dict) -> tuple:
    start_ms = flow.get("flow_start_time") or flow.get("time")
    stop_ms  = flow.get("time") or flow.get("flow_start_time")
    return ms_to_iso(start_ms), ms_to_iso(stop_ms)


def incident_name(flow: dict) -> str:
    policies      = flow.get("policies") or [{}]
    internal_type = policies[0].get("internal_type") or "BLOCK"
    return f"UDM-{internal_type}-{flow.get('id', 'unknown')}"


# ---------------------------------------------------------------------------
# Per-flow processor
# ---------------------------------------------------------------------------

def _process_flow_lazy(
    flow: dict,
    container_id: str,
    octi: OCTIHelper,
    helper,
    resolve_internal_host,
    mac_cache: dict,
    wan_ip: str,
    wan_system_id: Optional[str],
    internal_subnet: str,
    stats: dict,
) -> None:
    src      = flow.get("source") or {}
    dst      = flow.get("destination") or {}
    policies = flow.get("policies") or [{}]
    policy   = policies[0]
    ips      = flow.get("ips") or {}

    src_ip     = (src.get("ip") or "").strip()
    dst_ip     = (dst.get("ip") or "").strip()
    dst_mac    = (dst.get("mac") or "").lower().strip()
    src_region = (src.get("region") or "").strip()
    flow_count = int(flow.get("count") or 1)

    start_iso, stop_iso = incident_times(flow)
    desc     = flow_description(flow)
    rel_desc = sro_description(flow)

    # ---- Incident -------------------------------------------------------
    inc_id = octi.get_or_create_incident(
        name=incident_name(flow),
        description=desc,
        start_time=start_iso,
        stop_time=stop_iso,
        objective=policy.get("name") or "Blocked Flow",
    )
    if inc_id:
        octi.add_to_container(container_id, inc_id)
        stats["incidents"] += 1

    # ---- Affected product (Software → related-to → Incident) ------------
    affected_product = (ips.get("affected_product") or "").strip()
    if affected_product and inc_id:
        sw_id = octi.get_or_create_software(affected_product)
        if sw_id:
            sro_sw = octi.get_or_create_sro(
                "related-to", sw_id, inc_id,
                description=rel_desc, start_time=start_iso, stop_time=stop_iso,
            )
            octi.add_many_to_container(container_id, sw_id, sro_sw)
            stats["observables"] += 1
            stats["relationships"] += 1

    # ---- Source IP ------------------------------------------------------
    src_ip_id = None
    if src_ip:
        src_ip_id = octi.get_or_create_ipv4(src_ip)
        if src_ip_id:
            octi.add_to_container(container_id, src_ip_id)
            stats["observables"] += 1

            # Source IPv4 → related-to → Incident
            # Links the source IP to the specific incident it triggered.
            # related-to is the schema-valid relationship for Observable →
            # Incident. attributed-to is only valid from Intrusion Set →
            # Threat Actor per the Data Model Relationship Guide.
            if inc_id:
                sro_ip_inc = octi.get_or_create_sro(
                    "related-to", src_ip_id, inc_id,
                    description=rel_desc,
                    start_time=start_iso, stop_time=stop_iso,
                )
                if sro_ip_inc:
                    octi.add_to_container(container_id, sro_ip_inc)
                    stats["relationships"] += 1

            # Source IPv4 → related-to → Country
            # originates-from is not permitted between IPv4-Addr and Country
            # in the OpenCTI schema (FUNCTIONAL_ERROR confirmed in v0.4.0).
            if src_region and len(src_region) == 2 and src_region.isalpha():
                country_id = octi.get_or_create_country(src_region)
                if country_id:
                    octi.add_to_container(container_id, country_id)
                    sro_ip_c = octi.get_or_create_sro(
                        "related-to", src_ip_id, country_id,
                        description=rel_desc,
                        start_time=start_iso, stop_time=stop_iso,
                    )
                    if sro_ip_c:
                        octi.add_to_container(container_id, sro_ip_c)
                        stats["relationships"] += 1

                    # Incident → originates-from → Country (valid pair)
                    if inc_id:
                        sro_inc_c = octi.get_or_create_sro(
                            "originates-from", inc_id, country_id,
                            description=rel_desc,
                            start_time=start_iso, stop_time=stop_iso,
                        )
                        if sro_inc_c:
                            octi.add_to_container(container_id, sro_inc_c)
                            stats["relationships"] += 1

    if not src_ip_id:
        return

    # ---- Destination resolution -----------------------------------------
    target_system_id = None

    if wan_ip and dst_ip == wan_ip and wan_system_id:
        # Inbound to WAN — add WAN System and WAN IPv4 to this container
        wan_ipv4_id = octi.get_or_create_ipv4(wan_ip)
        if wan_ipv4_id:
            sro_wan = octi.get_or_create_sro(
                "related-to", wan_ipv4_id, wan_system_id
            )
            octi.add_many_to_container(
                container_id, wan_system_id, wan_ipv4_id, sro_wan
            )
        target_system_id = wan_system_id

    elif dst_mac:
        # Known internal host — lazy create + contain System, MAC, OUI org
        target_system_id = resolve_internal_host(dst_mac, container_id)

    elif dst_ip and is_internal(dst_ip, internal_subnet):
        # Internal host with no MAC (offline at startup)
        client_name = dst.get("host_name") or dst.get("client_name") or dst_ip
        system_id   = octi.get_or_create_system(
            name=client_name,
            description=(
                f"Internal host created from flow record "
                f"(no MAC, offline at startup). "
                f"Name: {client_name} | IP: {dst_ip}"
            ),
        )
        if system_id:
            octi.add_to_container(container_id, system_id)
            target_system_id = system_id

    # ---- Sighting -------------------------------------------------------
    if target_system_id:
        sighting_id = octi.upsert_sighting(
            from_id=src_ip_id, to_id=target_system_id,
            first_seen=start_iso, last_seen=stop_iso,
            count=flow_count, description=desc,
        )
        if sighting_id:
            octi.add_to_container(container_id, sighting_id)
            stats["sightings"] += 1

    # ---- Fallback: destination IPv4 + related-to SRO --------------------
    # Traffic was blocked — related-to records the attempted connection
    # without asserting bidirectional communication.
    else:
        if dst_ip:
            dst_ip_id = octi.get_or_create_ipv4(dst_ip)
            if dst_ip_id:
                sro_dst = octi.get_or_create_sro(
                    "related-to", src_ip_id, dst_ip_id,
                    description=rel_desc,
                    start_time=start_iso, stop_time=stop_iso,
                )
                octi.add_many_to_container(container_id, dst_ip_id, sro_dst)
                stats["observables"] += 1
                stats["relationships"] += 1


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class UDMConnector:
    def __init__(self):
        self.config = ConnectorConfig()
        self.helper = OpenCTIConnectorHelper({
            "opencti": {
                "url":   self.config.opencti_url,
                "token": self.config.opencti_token,
            },
            "connector": {
                "id":              self.config.connector_id,
                "type":            "EXTERNAL_IMPORT",
                "name":            self.config.connector_name,
                "scope":           "application/json",
                "log_level":       self.config.connector_log_level,
                "duration_period": self.config.connector_interval,
            },
        })
        self.octi = OCTIHelper(self.helper, self.config)
        self.udm  = UDMClient(self.config, self.helper)

    def _execute(self):
        self.helper.log_info("[CONNECTOR] UDM Connector execute triggered.")

        if not self.octi.author_id:
            self.octi.resolve_author()
        if not self.octi.author_id:
            self.helper.log_error(
                "[CONNECTOR] Could not resolve author identity — aborting run."
            )
            return

        wan_ip = self.udm.get_wan_ip()
        wan_system_id = self.octi.get_or_create_system(
            name="UDM-WAN",
            description=(
                "WAN-facing interface of the UDM Pro. "
                "Sighting target for inbound blocked flows reaching "
                "the external interface."
            ),
        )

        # Build mac_to_info cache from active clients.
        # No OpenCTI objects created here — all deferred to first use
        # per day container in resolve_internal_host().
        mac_to_info: dict = {}
        self.helper.log_info("[STARTUP] Discovering active clients via stat/sta...")
        for client in self.udm.get_active_clients():
            hostname = client.get("hostname") or client.get("name", "")
            mac      = (client.get("mac") or "").lower().strip()
            ip       = client.get("ip", "")
            oui      = (client.get("oui") or "").strip()
            if not mac or not hostname:
                continue
            mac_to_info[mac] = {"hostname": hostname, "ip": ip, "oui": oui}
        self.helper.log_info(
            f"[STARTUP] Client discovery complete: {len(mac_to_info)} hosts cached."
        )

        mac_cache: dict = {}

        now          = datetime.now(timezone.utc)
        is_first_run = not self.octi.has_any_udm_container()

        if is_first_run:
            cutoff = now - timedelta(days=self.config.udm_backfill_days)
            self.helper.log_info(
                f"[CONNECTOR] First run — backfill {self.config.udm_backfill_days} days."
            )
        else:
            cutoff = now - timedelta(hours=8)
            self.helper.log_info(
                "[CONNECTOR] Incremental run — 8-hour lookback window."
            )

        cutoff_ms = int(cutoff.timestamp() * 1000)
        self.helper.log_info(
            f"[CONNECTOR] Cutoff: "
            f"{cutoff.strftime('%Y-%m-%d %H:%M UTC')} ({cutoff_ms} ms)"
        )

        all_flows = self.udm.fetch_all_blocked_flows(
            cutoff_ms=cutoff_ms,
            page_size=self.config.udm_page_size,
        )

        if not all_flows:
            self.helper.log_info("[CONNECTOR] No flows in window — run complete.")
            return

        octi = self.octi  # closure alias

        def resolve_internal_host(mac: str, container_id: str) -> Optional[str]:
            # Previously resolved this run — re-add to this container
            if mac in mac_cache:
                system_id = mac_cache[mac]
                octi.add_to_container(container_id, system_id)
                mac_id = octi.get_or_create_mac(mac)
                if mac_id:
                    sro = octi.get_or_create_sro("related-to", mac_id, system_id)
                    octi.add_many_to_container(container_id, mac_id, sro)
                return system_id

            # Known from startup but not yet materialized in OpenCTI
            if mac not in mac_to_info:
                return None

            info      = mac_to_info[mac]
            hostname  = info["hostname"]
            ip        = info["ip"]
            oui       = info["oui"]
            system_id = octi.get_or_create_system(
                name=hostname,
                description=(
                    f"Internal network host. "
                    f"Hostname: {hostname} | MAC: {mac} | "
                    f"IP: {ip} | OUI: {oui or 'unknown'}"
                ),
            )
            if not system_id:
                return None

            mac_cache[mac] = system_id
            octi.add_to_container(container_id, system_id)

            mac_id = octi.get_or_create_mac(mac)
            if mac_id:
                sro_mac = octi.get_or_create_sro("related-to", mac_id, system_id)
                octi.add_many_to_container(container_id, mac_id, sro_mac)

            if oui:
                org_id = octi.get_or_create_organization(oui)
                if org_id:
                    sro_oui = octi.get_or_create_sro(
                        "related-to", org_id, system_id
                    )
                    octi.add_many_to_container(container_id, org_id, sro_oui)

            return system_id

        buckets = bucket_flows_by_day(all_flows)
        totals  = {
            k: 0 for k in (
                "flows", "incidents", "observables",
                "sightings", "relationships", "errors",
            )
        }
        days_skipped = 0

        for date_str in sorted(buckets.keys()):
            flows_for_day = buckets[date_str]
            stats = {k: 0 for k in totals}

            if not flows_for_day:
                days_skipped += 1
                continue

            stats["flows"] = len(flows_for_day)
            self.helper.log_info(
                f"[DAY] {len(flows_for_day)} flows for {date_str}. "
                f"Creating container..."
            )

            container_id = octi.get_or_create_ir_container(date_str)
            if not container_id:
                self.helper.log_error(
                    f"[DAY] Could not create IR container for {date_str}."
                )
                stats["errors"] += 1
                for k in totals:
                    totals[k] += stats.get(k, 0)
                continue

            for flow in flows_for_day:
                try:
                    _process_flow_lazy(
                        flow=flow,
                        container_id=container_id,
                        octi=octi,
                        helper=self.helper,
                        resolve_internal_host=resolve_internal_host,
                        mac_cache=mac_cache,
                        wan_ip=wan_ip,
                        wan_system_id=wan_system_id,
                        internal_subnet=self.config.udm_internal_subnet,
                        stats=stats,
                    )
                except Exception as exc:
                    self.helper.log_error(
                        f"[FLOW] Unhandled error on flow {flow.get('id', '?')}: {exc}"
                    )
                    stats["errors"] += 1

            self.helper.log_info(
                f"[DAY] {date_str} done | flows={stats['flows']}"
                f" incidents={stats['incidents']}"
                f" observables={stats['observables']}"
                f" sightings={stats['sightings']}"
                f" relationships={stats['relationships']}"
                f" errors={stats['errors']}"
            )
            for k in totals:
                totals[k] += stats.get(k, 0)

        self.helper.log_info(
            f"[CONNECTOR] Run complete | days={len(buckets)}"
            f" skipped={days_skipped}"
            f" flows={totals['flows']}"
            f" incidents={totals['incidents']}"
            f" observables={totals['observables']}"
            f" sightings={totals['sightings']}"
            f" relationships={totals['relationships']}"
            f" errors={totals['errors']}"
        )

    def run(self):
        self.helper.log_info("[CONNECTOR] UDM Connector starting.")
        self.helper.schedule_iso(self._execute, self.config.connector_interval)


if __name__ == "__main__":
    connector = UDMConnector()
    connector.run()
