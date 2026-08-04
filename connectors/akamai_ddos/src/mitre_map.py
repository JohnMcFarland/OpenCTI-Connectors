"""Map Akamai attack vectors / SIEM rule tags to MITRE ATT&CK DDoS techniques.

Decision D: classification is binary; if an event is DDoS, attach the matching
DDoS technique. We map to the Network/Endpoint DoS family and pick the most
specific sub-technique the vector supports, defaulting to the parent.

ATT&CK references:
  T1498        Network Denial of Service
  T1498.001    Direct Network Flood
  T1498.002    Reflection Amplification
  T1499        Endpoint Denial of Service
  T1499.001    OS Exhaustion Flood
  T1499.002    Service Exhaustion Flood
  T1499.003    Application Exhaustion Flood
"""

from __future__ import annotations

# (technique_id, name). Keys are lowercase substrings matched against the vector.
_VECTOR_RULES: list[tuple[tuple[str, ...], str, str]] = [
    (("reflection", "amplification", "ntp", "dns amplification", "memcached", "ssdp", "ldap"),
     "T1498.002", "Reflection Amplification"),
    (("syn flood", "udp flood", "icmp flood", "direct flood", "volumetric"),
     "T1498.001", "Direct Network Flood"),
    (("slow post", "slowloris", "slow read", "http flood", "application exhaustion", "rate"),
     "T1499.003", "Application Exhaustion Flood"),
    (("service exhaustion", "connection flood", "tcp exhaustion"),
     "T1499.002", "Service Exhaustion Flood"),
]

_DEFAULT_NETWORK = ("T1498", "Network Denial of Service")
_DEFAULT_ENDPOINT = ("T1499", "Endpoint Denial of Service")


def map_vectors(vectors: list[str], layer: str = "network") -> list[tuple[str, str]]:
    """Return a de-duplicated list of (technique_id, name) for the given vectors.

    `layer` ("network" for Prolexic L3/L4, "application" for SIEM L7) selects the
    fallback technique when no specific vector keyword matches.
    """
    out: dict[str, str] = {}
    for vec in vectors:
        v = (vec or "").lower()
        matched = False
        for keys, tid, name in _VECTOR_RULES:
            if any(k in v for k in keys):
                out[tid] = name
                matched = True
        if not matched:
            tid, name = _DEFAULT_ENDPOINT if layer == "application" else _DEFAULT_NETWORK
            out[tid] = name
    if not out:  # no vectors at all but is_ddos -> fall back by layer
        tid, name = _DEFAULT_ENDPOINT if layer == "application" else _DEFAULT_NETWORK
        out[tid] = name
    return list(out.items())
