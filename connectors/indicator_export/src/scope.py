"""scope.py - deterministic out-of-scope filter for promotion candidates.

Crucible extraction links reference material to Attack Patterns as well as
real infrastructure: article URLs, vendor advisories, documentation-range
IPs, cloud metadata endpoints, placeholder names, and legitimate platforms
that attackers abuse. None of those should become a blocking Indicator.

Rules, applied in order (first match wins):
1. Defanged values are refanged first (hxxp, [.], (.), [:]), so the pattern
   matches real traffic. The observable in OpenCTI is not changed.
2. IP addresses (bare or as a URL host) must be globally routable.
3. URLs must use http, https, ftp, or ftps.
4. Reserved names (RFC 2606/6761 TLDs, example.*) and values containing
   "placeholder" are dropped.
5. Excluded domains (publishers, vendors, first-party service endpoints)
   drop every URL and domain on the host or any subdomain of it.
6. Shared-hosting hosts (platforms that host user content) match the exact
   host only: the bare domain and the bare root URL are dropped, a URL with
   a specific path or query is kept, and attacker-named subdomains such as
   S3 buckets are kept.

Marker: IE-SCOPE-FILTER-V1
"""

from __future__ import annotations

import ipaddress
import re
from typing import FrozenSet, Optional, Tuple
from urllib.parse import urlsplit

REASON_NON_GLOBAL_IP = "non_global_ip"
REASON_BAD_SCHEME = "bad_scheme"
REASON_UNPARSABLE = "unparsable"
REASON_RESERVED_NAME = "reserved_name"
REASON_PLACEHOLDER = "placeholder"
REASON_EXCLUDED_DOMAIN = "excluded_domain"
REASON_SHARED_HOSTING = "shared_hosting"

_URL_SCHEMES = frozenset(["http", "https", "ftp", "ftps"])
_RESERVED_SUFFIXES = (
    ".internal", ".local", ".localhost", ".test", ".example", ".invalid",
    ".lan", ".home.arpa", ".corp", ".intranet",
)
_RESERVED_NAMES = frozenset([
    "localhost", "example.com", "example.net", "example.org",
])

# Publishers, research vendors, government advisories, social sites,
# first-party service endpoints, cloud metadata hosts, and article
# placeholders. Matched on the host and every subdomain.
DEFAULT_EXCLUDED_DOMAINS = frozenset([
    # News and research publishers
    "bleepingcomputer.com", "thehackernews.com", "securityweek.com",
    "darkreading.com", "securityaffairs.com", "securityaffairs.co",
    "theregister.com", "techcentral.ie", "thediplomat.com",
    "socprime.com", "paloaltonetworks.com", "checkpoint.com",
    "wordfence.com", "hunt.io", "aryaka.com", "censys.com",
    "stepsecurity.io", "watchtowr.com", "barracuda.com", "cisco.com",
    # Advisories, standards, academia
    "cve.org", "mitre.org", "nist.gov", "cisa.gov", "ox.ac.uk",
    # Social
    "twitter.com", "x.com", "mastodon.social",
    # First-party service endpoints (blocking these breaks the service)
    "microsoft.com", "microsoftonline.com", "office.com", "login.live.com",
    "chatgpt.com", "openai.com", "openrouter.ai",
    "generativelanguage.googleapis.com", "langchain.com", "deno.land",
    "litellm.dev", "bahn.de", "swapzone.io",
    # Cloud metadata endpoints by name
    "metadata.tencentyun.com",
    # Placeholders seen in articles
    "attacker-server.com",
])

# Platforms that host user content. Exact host match only.
DEFAULT_SHARED_HOSTING_DOMAINS = frozenset([
    "raw.githubusercontent.com", "github.com", "gist.github.com", "github.io",
    "drive.google.com", "docs.google.com", "storage.googleapis.com",
    "share.google", "discord.com", "canary.discord.com", "cdn.discordapp.com",
    "dontpad.com", "paste.sh", "pastebin.com", "rawtext.host", "x0.at",
    "webhook.site", "1drv.ms", "onedrive.live.com", "dropbox.com",
    "hubs.li", "dg.th", "codegiant.io", "s3.amazonaws.com", "amazonaws.com",
    "icp0.io", "cloudns.nz", "njalla.net", "hns.to",
])

_DEFANG = (
    (re.compile(r"^hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"),
)


def refang(value: str) -> str:
    """Undo common defanging so the pattern matches live traffic."""
    text = value.strip()
    for pattern, replacement in _DEFANG:
        text = pattern.sub(replacement, text)
    return text


def _ip(text: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        try:
            return ipaddress.ip_network(text, strict=False).network_address
        except ValueError:
            return None


def _under(host: str, domains: FrozenSet[str]) -> bool:
    """True when host equals a listed domain or is a subdomain of one."""
    parts = host.split(".")
    return any(".".join(parts[i:]) in domains for i in range(len(parts)))


def _host_rules(
    host: str, value: str, excluded: FrozenSet[str], shared: FrozenSet[str],
    is_url: bool, path: str, query: str,
) -> Optional[str]:
    address = _ip(host)
    if address is not None:
        return None if address.is_global else REASON_NON_GLOBAL_IP
    if host in _RESERVED_NAMES or host.endswith(_RESERVED_SUFFIXES) or "." not in host:
        return REASON_RESERVED_NAME
    if "placeholder" in value.lower():
        return REASON_PLACEHOLDER
    if _under(host, excluded):
        return REASON_EXCLUDED_DOMAIN
    if host in shared and (not is_url or (path in ("", "/") and not query)):
        return REASON_SHARED_HOSTING
    return None


def classify(
    entity_type: str,
    value: Optional[str],
    excluded: FrozenSet[str] = DEFAULT_EXCLUDED_DOMAINS,
    shared: FrozenSet[str] = DEFAULT_SHARED_HOSTING_DOMAINS,
) -> Tuple[Optional[str], Optional[str]]:
    """Return (reason, refanged_value).

    reason is None when the value is in scope. Types other than IPs, domains
    and URLs (e.g. files) pass through untouched.
    """
    if value is None:
        return None, value
    clean = refang(str(value))

    if entity_type in ("IPv4-Addr", "IPv6-Addr"):
        address = _ip(clean)
        if address is None:
            return REASON_UNPARSABLE, clean
        return (None if address.is_global else REASON_NON_GLOBAL_IP), clean

    if entity_type == "Domain-Name":
        host = clean.lower().rstrip(".")
        return _host_rules(host, clean, excluded, shared, False, "", ""), clean

    if entity_type == "Url":
        candidate = clean if "://" in clean else "http://" + clean
        try:
            parts = urlsplit(candidate)
            host = (parts.hostname or "").lower().rstrip(".")
        except ValueError:
            return REASON_UNPARSABLE, clean
        if parts.scheme.lower() not in _URL_SCHEMES:
            return REASON_BAD_SCHEME, clean
        if not host:
            return REASON_UNPARSABLE, clean
        return _host_rules(
            host, clean, excluded, shared, True, parts.path, parts.query
        ), clean

    return None, value
