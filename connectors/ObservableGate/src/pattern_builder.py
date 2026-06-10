"""
pattern_builder.py — STIX 2.1 Pattern Construction

Constructs deterministic STIX 2.1 pattern strings from OpenCTI observable
dicts. Determinism is a hard requirement: the same observable must always
produce the same pattern string across runs, because the pattern drives
the STIX ID via deterministic hashing, which is the primary deduplication
mechanism for Indicators created by this connector.

Design decisions encoded here:
- Network-Traffic is excluded: its STIX pattern requires compound construction
  referencing embedded object references, incompatible with most detection
  consumers without transformation. Constituent IPs should be promoted instead.
- File hashes use priority order SHA-256 > SHA-1 > MD5. Only the highest-quality
  available hash is included. Compound OR hash patterns (SHA-256 OR MD5) are
  intentionally avoided: they produce non-deterministic STIX IDs when hash
  availability differs between runs, and create matching ambiguity at detection
  consumers.
- X509 certificates prefer SHA-256 hash over serial_number. SHA-256 is more
  stable; serial_number can be reused across CA boundaries.
- Autonomous System numbers are integers in STIX 2.1 and must not be quoted.
"""

from typing import Any, Dict, Optional


def build_pattern(observable: Dict[str, Any]) -> Optional[str]:
    """
    Construct a deterministic STIX 2.1 pattern from a raw observable dict.

    Dispatches to a type-specific factory based on entity_type. Returns None
    if the type is unsupported or the observable lacks the required value
    fields. None signals the caller to skip and log the observable rather
    than raise an exception — skipping is the correct behavior for observable
    types that cannot be patterned.

    Args:
        observable: Raw observable dict from the OpenCTI API, containing at
                    minimum 'entity_type' and type-specific value fields.

    Returns:
        A valid STIX 2.1 pattern string, e.g.:
            "[ipv4-addr:value = '1.2.3.4']"
            "[file:hashes.'SHA-256' = 'abc...']"
            "[autonomous-system:number = 13335]"
        Or None if pattern construction is not possible.
    """
    entity_type = observable.get("entity_type", "")
    factory = _PATTERN_FACTORIES.get(entity_type)
    if factory is None:
        return None
    return factory(observable)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _quote(value: Any) -> str:
    """
    Escape and single-quote a value for safe STIX pattern embedding.

    Escapes backslashes and single quotes per STIX 2.1 pattern syntax,
    preventing pattern injection from observable values containing these
    characters (e.g. Windows registry key paths with backslashes).

    Args:
        value: Raw value to escape and quote.

    Returns:
        Single-quoted, escaped string.

    Example:
        _quote("C:\\Windows\\System32")
        -> "'C:\\\\Windows\\\\System32'"
    """
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _simple(
    stix_type: str, field: str, value: Any
) -> Optional[str]:
    """
    Build a single-property STIX object pattern.

    Args:
        stix_type: STIX 2.1 object type (e.g. 'ipv4-addr', 'domain-name').
        field:     The object property to match on (e.g. 'value', 'name').
        value:     The value to match. Returns None if absent or falsy.

    Returns:
        Pattern string or None.

    Example:
        _simple("ipv4-addr", "value", "1.2.3.4")
        -> "[ipv4-addr:value = '1.2.3.4']"
    """
    if not value:
        return None
    return f"[{stix_type}:{field} = {_quote(value)}]"


# ---------------------------------------------------------------------------
# Type-specific pattern factories
# ---------------------------------------------------------------------------

def _ipv4_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("ipv4-addr", "value", obs.get("value"))


def _ipv6_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("ipv6-addr", "value", obs.get("value"))


def _domain_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("domain-name", "value", obs.get("value"))


def _url_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("url", "value", obs.get("value"))


def _email_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("email-addr", "value", obs.get("value"))


def _mutex_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("mutex", "name", obs.get("name"))


def _regkey_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("windows-registry-key", "key", obs.get("attribute_key"))


def _useraccount_pattern(obs: Dict[str, Any]) -> Optional[str]:
    # user_id is the canonical field; account_login is the OpenCTI UI
    # field name that maps to the same underlying property in some versions.
    value = obs.get("user_id") or obs.get("account_login")
    return _simple("user-account", "user_id", value)


def _macaddr_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("mac-addr", "value", obs.get("value"))


def _directory_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("directory", "path", obs.get("path"))


def _software_pattern(obs: Dict[str, Any]) -> Optional[str]:
    return _simple("software", "name", obs.get("name"))


def _as_pattern(obs: Dict[str, Any]) -> Optional[str]:
    """
    Build an Autonomous System STIX 2.1 pattern.

    ASN numbers are integers in STIX 2.1 and must NOT be quoted. Quoting
    them produces an invalid pattern that will fail at pattern evaluation
    in most detection consumers.

    OpenCTI stores the ASN number in the 'number' field as an integer.

    Args:
        obs: Observable dict with 'number' field.

    Returns:
        Pattern with unquoted integer, or None if number is absent.

    Example:
        "[autonomous-system:number = 13335]"
    """
    number = obs.get("number")
    if number is None:
        return None
    try:
        return f"[autonomous-system:number = {int(number)}]"
    except (ValueError, TypeError):
        return None


def _file_pattern(obs: Dict[str, Any]) -> Optional[str]:
    """
    Build a File STIX 2.1 pattern using the highest-quality available hash.

    Priority order: SHA-256 > SHA-1 > MD5. Only one hash type per pattern.

    Compound OR patterns (e.g. SHA-256 = X OR MD5 = Y) are intentionally
    not implemented for two reasons:
    1. Non-deterministic STIX IDs: the pattern string would differ if hash
       availability changes between runs, producing duplicate Indicators
       with different IDs but the same detection intent.
    2. Matching ambiguity: a hit on MD5 alone is not equivalent to a hit
       on SHA-256; detection consumers cannot express this distinction cleanly
       in a compound pattern.

    OpenCTI returns file hashes in the 'hashes' list, each entry a dict with
    'algorithm' and 'hash' keys. Algorithm names are normalized to uppercase
    with hyphenation to handle the variants OpenCTI produces ('SHA-256',
    'sha-256', 'Sha256').

    Args:
        obs: Observable dict with optional 'hashes' list.

    Returns:
        STIX pattern for the best available hash, or None if no recognized
        hash type is present.
    """
    raw_hashes = obs.get("hashes") or []

    # Normalize algorithm names: uppercase, ensure hyphenation.
    hashes: Dict[str, str] = {}
    for entry in raw_hashes:
        algo = str(entry.get("algorithm", "")).upper().replace(" ", "-")
        value = str(entry.get("hash", "")).strip()
        if algo and value:
            hashes[algo] = value

    # Attempt in priority order.
    for algo, stix_field in [("SHA-256", "SHA-256"), ("SHA-1", "SHA-1"), ("MD5", "MD5")]:
        value = hashes.get(algo)
        if value:
            return f"[file:hashes.'{stix_field}' = {_quote(value)}]"

    return None


def _x509_pattern(obs: Dict[str, Any]) -> Optional[str]:
    """
    Build an X509 Certificate STIX 2.1 pattern.

    Prefers SHA-256 hash as the primary identifier over serial_number.
    SHA-256 of a certificate is globally unique and stable; serial_number
    is scoped to a single CA and can be legitimately reused across CA
    boundaries, making it a weaker deduplication key.

    Args:
        obs: Observable dict with optional 'hashes' list and 'serial_number'.

    Returns:
        STIX pattern string, or None if neither hash nor serial number present.
    """
    raw_hashes = obs.get("hashes") or []
    hashes: Dict[str, str] = {
        str(h.get("algorithm", "")).upper(): str(h.get("hash", ""))
        for h in raw_hashes
    }

    sha256 = hashes.get("SHA-256")
    if sha256:
        return f"[x509-certificate:hashes.'SHA-256' = {_quote(sha256)}]"

    serial = obs.get("serial_number")
    if serial:
        return _simple("x509-certificate", "serial_number", serial)

    return None


# ---------------------------------------------------------------------------
# Dispatch table: OpenCTI entity_type -> pattern factory
#
# Network-Traffic is intentionally absent. Callers in the promotion pass
# filter it via config.excluded_observable_types before reaching build_pattern.
# If it does reach here, it returns None via the default dict.get() miss.
# ---------------------------------------------------------------------------
_PATTERN_FACTORIES: Dict[str, Any] = {
    "IPv4-Addr":            _ipv4_pattern,
    "IPv6-Addr":            _ipv6_pattern,
    "Domain-Name":          _domain_pattern,
    "Url":                  _url_pattern,
    "Email-Addr":           _email_pattern,
    "Mutex":                _mutex_pattern,
    "Windows-Registry-Key": _regkey_pattern,
    "User-Account":         _useraccount_pattern,
    "Autonomous-System":    _as_pattern,
    "StixFile":             _file_pattern,
    "X509-Certificate":     _x509_pattern,
    "Software":             _software_pattern,
    "Mac-Addr":             _macaddr_pattern,
    "Directory":            _directory_pattern,
}

# Exposed for callers that need to enumerate supported types without
# instantiating a pattern (e.g. for logging or config validation).
SUPPORTED_OBSERVABLE_TYPES: frozenset = frozenset(_PATTERN_FACTORIES.keys())
