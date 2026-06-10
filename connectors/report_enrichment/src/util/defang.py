from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Observable types that require defanging in note output
# ---------------------------------------------------------------------------

# These entity types contain values that, if rendered as-is in a note,
# could be inadvertently clicked or copied into a terminal and executed.
# All other entity types (SDOs: Intrusion Set, Malware, etc.) are proper
# nouns and must NOT be defanged — defanging "Handala" makes no sense.
_DEFANG_TYPES: frozenset = frozenset({
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Url",
    "Email-Addr",
    "Autonomous-System",
    "Windows-Registry-Key",
    "Mutex",
})

_IP_TYPES:     frozenset = frozenset({"IPv4-Addr"})
_IPV6_TYPES:   frozenset = frozenset({"IPv6-Addr"})
_DOMAIN_TYPES: frozenset = frozenset({"Domain-Name"})
_URL_TYPES:    frozenset = frozenset({"Url"})
_EMAIL_TYPES:  frozenset = frozenset({"Email-Addr"})


def defang_value(value: str, entity_type: str) -> str:
    """
    Defang a single observable value for safe display in analyst-facing notes.

    Entities stored in the graph are always in fanged canonical form.
    This function is called at note-write time to convert them back to
    defanged form for display — the inverse of preprocess.refang().

    Rules by entity type:
      IPv4-Addr    — replace dots with [.]
      IPv6-Addr    — replace colons with [:]
      Domain-Name  — replace dots with [.]
      Url          — replace scheme (http→hxxp, https→hxxps) and host dots
      Email-Addr   — replace @ with [at] and dots with [.]
      All others   — returned unchanged (SDOs are not defanged)
    """
    if not value or entity_type not in _DEFANG_TYPES:
        return value

    if entity_type in _IP_TYPES:
        return value.replace(".", "[.]")

    if entity_type in _IPV6_TYPES:
        return value.replace(":", "[:]")

    if entity_type in _DOMAIN_TYPES:
        return value.replace(".", "[.]")

    if entity_type in _URL_TYPES:
        v = re.sub(r"^https://", "hxxps://", value, flags=re.IGNORECASE)
        v = re.sub(r"^http://",  "hxxp://",  v,     flags=re.IGNORECASE)
        try:
            scheme_end = v.index("://") + 3
            path_start = v.find("/", scheme_end)
            if path_start == -1:
                host, path = v[scheme_end:], ""
            else:
                host, path = v[scheme_end:path_start], v[path_start:]
            host = host.replace(".", "[.]")
            return v[:scheme_end] + host + path
        except (ValueError, IndexError):
            return v.replace(".", "[.]")

    if entity_type in _EMAIL_TYPES:
        return value.replace("@", "[at]").replace(".", "[.]")

    return value


def defang_entity_name(name: str, entity_type: str) -> str:
    """Convenience wrapper — delegates to defang_value()."""
    return defang_value(name, entity_type)


def defang_text_block(text: str) -> str:
    """
    Defang observable-looking values within a freeform text block.

    Used for relationship description fields, evidence snippets, and
    other freeform strings in note output where the entity type is not
    tracked per-token. Applies conservative pattern matching to avoid
    false positives on prose text.
    """
    if not text:
        return text

    # IPv4 addresses
    text = re.sub(
        r"\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\b",
        lambda m: m.group(0).replace(".", "[.]"),
        text,
    )

    # URL schemes
    text = re.sub(r"\bhttps://", "hxxps://", text, flags=re.IGNORECASE)
    text = re.sub(r"\bhttp://",  "hxxp://",  text, flags=re.IGNORECASE)

    return text
