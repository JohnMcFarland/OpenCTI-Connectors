from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Set, Tuple

Key = Tuple[str, str]  # (source_entity_type, relationship_type)


@dataclass(frozen=True)
class RelationshipDecision:
    allowed: bool
    reason: str


def _n(v: str) -> str:
    return (v or "").strip()


def _r(v: str) -> str:
    return (v or "").strip().lower()


# ---------------------------------------------------------------------------
# Entity type groupings
# ---------------------------------------------------------------------------

_THREAT_ACTORS: FrozenSet[str] = frozenset({
    "Threat-Actor",
    "Threat-Actor-Group",
    "Threat-Actor-Individual",
})

_INTRUSION_SETS: FrozenSet[str] = frozenset({"Intrusion-Set"})
_CAMPAIGNS: FrozenSet[str] = frozenset({"Campaign"})
_INCIDENTS: FrozenSet[str] = frozenset({"Incident"})
_THREAT_SOURCES: FrozenSet[str] = _THREAT_ACTORS | _INTRUSION_SETS | _CAMPAIGNS | _INCIDENTS

_CAPABILITIES: FrozenSet[str] = frozenset({
    "Malware", "Tool", "Attack-Pattern", "Infrastructure",
    "Indicator", "Channel", "Narrative", "Course-Of-Action",
})

_LOCATIONS: FrozenSet[str] = frozenset({
    "Country", "Region", "City", "Area", "Location", "Administrative-Area",
})

_IDENTITIES: FrozenSet[str] = frozenset({
    "Organization", "Sector", "Individual", "System", "Identity",
})

_VICTIMOLOGY: FrozenSet[str] = _IDENTITIES | _LOCATIONS | frozenset({"Vulnerability"})

_OBSERVABLES: FrozenSet[str] = frozenset({
    "IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "File",
    "Email-Addr", "Email-Message", "Mac-Addr", "Network-Traffic", "Process",
    "Windows-Registry-Key", "X509-Certificate", "Autonomous-System", "Directory",
    "Mutex", "Software", "User-Account", "Cryptocurrency-Wallet", "Bank-Account",
    "Phone-Number", "Text", "Hostname", "User-Agent", "Payment-Card", "Persona",
})

_ALL_ENTITY_TYPES: FrozenSet[str] = (
    _THREAT_SOURCES | _CAPABILITIES | _LOCATIONS | _IDENTITIES | _OBSERVABLES
    | frozenset({
        "Report", "Note", "Opinion", "Observed-Data", "Vulnerability",
        "External-Reference", "Label", "Marking-Definition",
    })
)

# ---------------------------------------------------------------------------
# Policy registry
# ---------------------------------------------------------------------------

ALLOWED: Dict[Key, Set[str]] = {}


def _register(sources: FrozenSet[str], rel: str, targets: FrozenSet[str]) -> None:
    for s in sources:
        key = (s, rel)
        if key not in ALLOWED:
            ALLOWED[key] = set()
        ALLOWED[key].update(targets)


# --- uses ---
# Threat sources use capabilities (existing)
_register(_THREAT_SOURCES, "uses", _CAPABILITIES | frozenset({"Persona"}))
# FIX #3/#4: Malware and Tool also 'use' other capabilities per CSV
_register(frozenset({"Malware", "Tool"}), "uses", frozenset({
    "Attack-Pattern", "Infrastructure", "Tool", "Malware",
}))

# --- targets ---
_register(_THREAT_SOURCES, "targets", _VICTIMOLOGY)
# FIX #5/#6/#7: Attack-Pattern targets individuals, orgs, sectors per CSV
_register(frozenset({"Attack-Pattern"}), "targets", frozenset({
    "Individual", "Organization", "Sector", "System",
}))
_register(_CAPABILITIES - frozenset({"Course-Of-Action", "Narrative", "Channel"}),
          "targets", _VICTIMOLOGY)

# --- attributed-to ---
_register(_INCIDENTS, "attributed-to", _CAMPAIGNS | _INTRUSION_SETS | _THREAT_ACTORS)
_register(_CAMPAIGNS, "attributed-to", _INTRUSION_SETS | _THREAT_ACTORS)
# FIX #1: Intrusion-Set attributed-to Individual is valid per CSV
_register(_INTRUSION_SETS, "attributed-to", _THREAT_ACTORS | frozenset({"Individual"}))

# --- originates-from ---
_register(_THREAT_SOURCES, "originates-from", _LOCATIONS)

# --- communicates-with ---
_register(_THREAT_ACTORS | _INTRUSION_SETS | _CAMPAIGNS, "communicates-with",
          frozenset({"Channel"}))
_register(frozenset({"Network-Traffic"}), "communicates-with",
          frozenset({"IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"}))

# --- has ---
_register(frozenset({"Channel"}), "has", frozenset({"Narrative"}))
_register(frozenset({"Software"}), "has", frozenset({"Vulnerability"}))

# --- resolves-to ---
_register(frozenset({"Domain-Name", "Hostname"}), "resolves-to",
          frozenset({"IPv4-Addr", "IPv6-Addr", "Domain-Name"}))
_register(frozenset({"IPv4-Addr", "IPv6-Addr"}), "resolves-to",
          frozenset({"Domain-Name", "Autonomous-System"}))

# --- belongs-to ---
_register(frozenset({"IPv4-Addr", "IPv6-Addr"}), "belongs-to",
          frozenset({"Autonomous-System"}))
_register(frozenset({"System"}), "belongs-to", _IDENTITIES)
_register(_IDENTITIES, "belongs-to", _IDENTITIES)

# --- part-of ---
_register(_IDENTITIES, "part-of", _IDENTITIES)
_register(frozenset({"System"}), "part-of", frozenset({"Infrastructure"}))

# --- exploits ---
_register(frozenset({"Malware", "Tool", "Attack-Pattern"}), "exploits",
          frozenset({"Vulnerability"}))
_register(_THREAT_SOURCES, "exploits", frozenset({"Vulnerability"}))

# --- delivers ---
_register(frozenset({"Infrastructure"}), "delivers", frozenset({"Malware", "Tool"}))

# --- impersonates ---
_register(_THREAT_ACTORS, "impersonates", _IDENTITIES)

# --- references ---
_register(frozenset({"Report"}), "references",
          frozenset({"External-Reference"}) | _ALL_ENTITY_TYPES)

# --- based-on / indicates / created-from ---
_register(frozenset({"Indicator"}), "based-on", _OBSERVABLES)
_register(frozenset({"Indicator"}), "indicates", _THREAT_SOURCES | _CAPABILITIES)
_register(frozenset({"Indicator"}), "created-from", _OBSERVABLES)

# --- related-to (Any -> Any per manual) ---
_ALL_TARGETS = _ALL_ENTITY_TYPES
for _src_group in (
    _THREAT_SOURCES, _CAPABILITIES, _OBSERVABLES,
    _IDENTITIES, _LOCATIONS,
    frozenset({"Vulnerability"}),
    frozenset({"Report", "Note", "Opinion"}),
):
    _register(_src_group, "related-to", _ALL_TARGETS)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_allowed(source_type: str, relationship_type: str,
               target_type: str) -> RelationshipDecision:
    s = _n(source_type)
    r = _r(relationship_type)
    t = _n(target_type)

    if not s or not r or not t:
        return RelationshipDecision(
            False, "relationship policy: missing source/relationship/target type"
        )

    targets = ALLOWED.get((s, r))
    if targets is None:
        return RelationshipDecision(
            False,
            f"relationship policy: no rule for ({s}, {r}) — "
            "relationship type not permitted from this source type",
        )

    if t not in targets:
        return RelationshipDecision(
            False,
            f"relationship policy: ({s}, {r}) → {t} not in allowed target set",
        )

    return RelationshipDecision(True, "relationship policy: allowed")
