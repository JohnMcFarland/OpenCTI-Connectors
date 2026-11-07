"""Observable kinds an operator can map a result column to, and their validators.

Pure module. Each validator returns (stix_type, canonical value, hash algo) or None
when the value is not valid for that kind. "ip" auto-detects v4/v6 and "file-hash"
auto-detects MD5/SHA-1/SHA-256 by length.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

Normalized = tuple[str, str, str | None]  # (stix_type, canonical value, hash algo)

# Letter TLDs plus IDN (punycode) TLDs such as xn--p1ai.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://\S+$", re.I)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HASH_BY_LEN = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_PLACEHOLDERS = {"-", "unknown", "n/a", "null", "none"}


def _ip(want: str | None) -> Callable[[str], Normalized | None]:
    def check(v: str) -> Normalized | None:
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return None
        stix_type = "ipv6-addr" if ip.version == 6 else "ipv4-addr"
        return (stix_type, ip.compressed, None) if want in (None, stix_type) else None
    return check


def _domain(v: str) -> Normalized | None:
    d = v.lower().rstrip(".")
    return ("domain-name", d, None) if _DOMAIN_RE.match(d) else None


def _url(v: str) -> Normalized | None:
    return ("url", v, None) if _URL_RE.match(v) else None


def _email(v: str) -> Normalized | None:
    return ("email-addr", v.lower(), None) if _EMAIL_RE.match(v) else None


def _user(v: str) -> Normalized | None:
    return "user-account", v, None


def _mac(v: str) -> Normalized | None:
    m = v.lower().replace("-", ":")
    return ("mac-addr", m, None) if _MAC_RE.match(m) else None


def _file_hash(v: str) -> Normalized | None:
    h = v.lower()
    algo = _HASH_BY_LEN.get(len(h))
    return ("file", h, algo) if algo and _HEX_RE.match(h) else None


def _port(v: str) -> Normalized | None:
    try:
        port = int(float(v))
    except (ValueError, OverflowError):
        return None
    return ("network-traffic", str(port), None) if 0 < port <= 65535 else None


# kind (as written in searches.yml) -> validator. Single source of truth for kinds.
_VALIDATORS: dict[str, Callable[[str], Normalized | None]] = {
    "ip": _ip(None),
    "ipv4-addr": _ip("ipv4-addr"),
    "ipv6-addr": _ip("ipv6-addr"),
    "domain-name": _domain,
    "url": _url,
    "email-addr": _email,
    "user-account": _user,
    "mac-addr": _mac,
    "file-hash": _file_hash,
    "port": _port,
}
OBSERVABLE_KINDS = frozenset(_VALIDATORS)


def is_placeholder(value: str) -> bool:
    """Empty or a filler value Splunk apps write for 'no data' (ES uses 'unknown')."""
    v = value.strip()
    return not v or v.lower() in _PLACEHOLDERS


def normalize_observable(kind: str, raw: str) -> Normalized | None:
    """Validate + canonicalize one value. Returns (stix_type, value, hash_algo) or None."""
    if is_placeholder(raw):
        return None
    return _VALIDATORS[kind](raw.strip())
