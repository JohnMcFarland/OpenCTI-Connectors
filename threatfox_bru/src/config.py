"""Configuration and constants for the ThreatFox connector."""

import uuid
import os

# --- ThreatFox API ---
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_AUTH_KEY = os.environ.get("THREATFOX_AUTH_KEY", "")
THREATFOX_DEFAULT_DAYS = int(os.environ.get("THREATFOX_DAYS", "7"))
THREATFOX_MAX_DAYS = 7  # API hard cap — get_iocs does not return data older than 7 days

# --- Confidence ---
CONFIDENCE_MULTIPLIER = 0.8

# --- TLP Marking ---
TLP_CLEAR_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"

# --- OpenCTI Connector Config (from env) ---
OPENCTI_URL = os.environ.get("OPENCTI_URL", "http://localhost:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")
CONNECTOR_ID = os.environ.get("CONNECTOR_ID", "")
CONNECTOR_NAME = os.environ.get("CONNECTOR_NAME", "ThreatFox")
CONNECTOR_SCOPE = os.environ.get("CONNECTOR_SCOPE", "threatfox")
CONNECTOR_LOG_LEVEL = os.environ.get("CONNECTOR_LOG_LEVEL", "info")
CONNECTOR_INTERVAL = int(os.environ.get("CONNECTOR_INTERVAL", "360"))  # minutes

# --- [C]ThreatFox connector identity ---
# Deterministic identity SDO for the connector itself.
# Used as created_by_ref on Report containers.
# The namespace UUID is stable and non-sensitive — it is a synthetic identifier,
# not a credential. It should not be changed after first deployment as it anchors
# the [C]ThreatFox identity's deterministic UUID in the graph.
_THREATFOX_NAMESPACE = uuid.UUID("ab12c3d4-e5f6-7890-abcd-ef1234567890")
CTHREATFOX_IDENTITY_ID = f"identity--{uuid.uuid5(_THREATFOX_NAMESPACE, 'cthreatfox')}"
CTHREATFOX_IDENTITY_NAME = "[C]ThreatFox"

# --- Reporters to skip identity creation for ---
ANONYMOUS_REPORTERS = {"unknown", "anonymous", "", "0"}

# --- threat_type → malware_types mapping ---
THREAT_TYPE_MALWARE_TYPES = {
    "botnet_cc": ["remote-access-trojan", "bot"],
    "payload_delivery": ["dropper", "downloader"],
    "payload": ["trojan"],
}

# --- Tags that are descriptors, not software names — skip entirely ---
SKIP_TAGS = {"TROJAN", "trojan", "RAT", "rat", "EXECUTION", "C2", "c2",
             "PERSISTENCE", "DISCOVERY", "COLLECTION", "DEFENSE_EVASION"}
