"""Deterministic UUIDv5 generation for STIX 2.1 objects."""

import uuid

# OASIS STIX 2.1 namespace UUID for SCOs
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# ThreatFox connector namespace for SDOs
THREATFOX_NAMESPACE = uuid.UUID("ab12c3d4-e5f6-7890-abcd-ef1234567890")


def _make_id(stix_type: str, namespace: uuid.UUID, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(namespace, key)}"


def observable_id(stix_type: str, ioc_value: str) -> str:
    key = f"{stix_type}:{ioc_value}"
    return _make_id(stix_type, STIX_NAMESPACE, key)


def autonomous_system_id(as_number: int) -> str:
    key = f"autonomous-system:{as_number}"
    return _make_id("autonomous-system", STIX_NAMESPACE, key)


def network_traffic_id(dst_ip: str, dst_port: int) -> str:
    """Deterministic ID for network-traffic SCO.

    Keyed on ip:port so each unique endpoint gets one object.
    No dst_ref embedded — port context only.
    """
    key = f"network-traffic:{dst_ip}:{dst_port}"
    return _make_id("network-traffic", STIX_NAMESPACE, key)


def malware_id(name: str) -> str:
    return _make_id("malware", THREATFOX_NAMESPACE, name.lower())


def tool_id(name: str) -> str:
    return _make_id("tool", THREATFOX_NAMESPACE, name.lower())


def identity_id(reporter: str) -> str:
    return _make_id("identity", THREATFOX_NAMESPACE, reporter.lower())


def report_id(date_str: str) -> str:
    key = f"threatfox-feed:{date_str}"
    return _make_id("report", THREATFOX_NAMESPACE, key)


def relationship_id(source_id: str, relationship_type: str, target_id: str) -> str:
    key = f"{source_id}:{relationship_type}:{target_id}"
    return _make_id("relationship", THREATFOX_NAMESPACE, key)
