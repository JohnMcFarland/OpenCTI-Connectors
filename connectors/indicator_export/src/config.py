"""Configuration, read from environment variables only.

Everything is validated here, before the OpenCTI helper starts, so a bad
docker-compose.override.yml stops the container instead of half-running it.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import FrozenSet, Mapping, Optional, Union

from .scope import DEFAULT_EXCLUDED_DOMAINS, DEFAULT_SHARED_HOSTING_DOMAINS

MODE_DEBUG = "debug"
MODE_STREAM = "stream"

DEFAULT_EXCLUDED_ENTITY_TYPES = "System,Organization,Individual,Incident"

# Network-Traffic is a single port number in this data model, and Persona has
# no usable STIX pattern. Neither can become an Indicator.
HARDCODED_OBSERVABLE_EXCLUSIONS = frozenset(["Network-Traffic", "Persona"])

# Only these observable types become Indicators: IP addresses, file hashes,
# domains and URLs (decided 2026-11-07). Software, User-Account and the rest
# match too much benign activity to act on. StixFile patterns are hash-only.
DEFAULT_ALLOWED_OBSERVABLE_TYPES = "IPv4-Addr,IPv6-Addr,StixFile,Domain-Name,Url"


@dataclass(frozen=True)
class ExportTarget:
    """Where exports go: a CSV file (debug) or a STIX stream to one IP."""

    mode: str
    host: Optional[str] = None


def parse_export_location(raw: Optional[str]) -> ExportTarget:
    """Turn EXPORT_LOCATION into a target.

    "debug" (any case) writes CSV files. An IPv4 or IPv6 address streams STIX
    to that address. Anything else, hostnames included, is rejected.
    """
    value = (raw or "").strip()
    if value.lower() == MODE_DEBUG:
        return ExportTarget(mode=MODE_DEBUG)
    try:
        return ExportTarget(mode=MODE_STREAM, host=str(ipaddress.ip_address(value)))
    except ValueError:
        raise ValueError(
            f"EXPORT_LOCATION must be 'debug' or an IP address, got {value!r}. "
            "Put the port in EXPORT_PORT, not in EXPORT_LOCATION."
        ) from None


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in ("true", "1", "yes")


def _parse_verify(value: str) -> Union[bool, str]:
    """EXPORT_VERIFY_TLS is true, false, or a path to a CA bundle."""
    text = value.strip()
    if text.lower() in ("true", "false", "1", "0", "yes", "no"):
        return _parse_bool(text)
    return text


def _parse_csv_set(value: str) -> FrozenSet[str]:
    return frozenset(item.strip() for item in value.split(",") if item.strip())


def _parse_domain_set(value: str) -> FrozenSet[str]:
    """Comma list of domains, lowercased, without leading or trailing dots."""
    return frozenset(
        item.strip().lower().strip(".") for item in value.split(",") if item.strip().strip(".")
    )


@dataclass(frozen=True)
class Settings:
    opencti_url: str
    opencti_token: str
    connector_id: str
    connector_name: str
    connector_scope: str
    connector_duration_period: str
    connector_log_level: str

    author_name: str
    dry_run: bool
    decay_days: int
    max_errors: int
    excluded_observable_types: FrozenSet[str]
    allowed_observable_types: FrozenSet[str]
    excluded_labels: FrozenSet[str]
    excluded_domains: FrozenSet[str]
    shared_hosting_domains: FrozenSet[str]

    target: ExportTarget
    scheme: str
    port: Optional[int]
    path: str
    auth_token: str
    verify_tls: Union[bool, str]
    batch_size: int
    timeout_seconds: int
    blocked_markings: FrozenSet[str]
    max_labels: int
    excluded_entity_types: FrozenSet[str]
    data_dir: str
    csv_retention: int

    @property
    def stream_url(self) -> str:
        """Full URL for stream mode. IPv6 hosts get the required brackets."""
        host = self.target.host or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{host}{port}{self.path}"


def load_settings(env: Optional[Mapping[str, str]] = None) -> Settings:
    source = os.environ if env is None else env

    def required(key: str) -> str:
        value = source.get(key, "").strip()
        if not value:
            raise ValueError(f"Required environment variable {key} is not set.")
        return value

    def optional(key: str, default: str) -> str:
        value = source.get(key, "").strip()
        return value or default

    def integer(key: str, default: int, minimum: int = 0) -> int:
        raw = optional(key, str(default))
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"{key} must be an integer, got {raw!r}.") from None
        if value < minimum:
            raise ValueError(f"{key} must be at least {minimum}, got {value}.")
        return value

    scheme = optional("EXPORT_SCHEME", "https").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"EXPORT_SCHEME must be http or https, got {scheme!r}.")

    path = optional("EXPORT_PATH", "/")
    if not path.startswith("/"):
        path = "/" + path

    raw_port = source.get("EXPORT_PORT", "").strip()
    port = integer("EXPORT_PORT", 0, minimum=1) if raw_port else None
    if port is not None and port > 65535:
        raise ValueError(f"EXPORT_PORT must be at most 65535, got {port}.")

    return Settings(
        opencti_url=required("OPENCTI_URL"),
        opencti_token=required("OPENCTI_TOKEN"),
        connector_id=required("CONNECTOR_ID"),
        connector_name=optional("CONNECTOR_NAME", "Indicator Export"),
        connector_scope=optional("CONNECTOR_SCOPE", "indicator"),
        connector_duration_period=optional("CONNECTOR_DURATION_PERIOD", "PT1H"),
        connector_log_level=optional("CONNECTOR_LOG_LEVEL", "info"),
        author_name=optional("INDICATOR_AUTHOR_NAME", "Indicator Export"),
        # Off only when explicitly set: the first run must not write or send.
        dry_run=_parse_bool(optional("INDICATOR_DRY_RUN", "true")),
        decay_days=integer("INDICATOR_DECAY_DAYS", 30, minimum=1),
        max_errors=integer("INDICATOR_MAX_ERRORS", 50, minimum=1),
        excluded_observable_types=HARDCODED_OBSERVABLE_EXCLUSIONS
        | _parse_csv_set(source.get("INDICATOR_EXCLUDED_OBSERVABLE_TYPES", "")),
        # A blank value falls back to the default, so it cannot open every type.
        allowed_observable_types=_parse_csv_set(
            optional("INDICATOR_ALLOWED_OBSERVABLE_TYPES", DEFAULT_ALLOWED_OBSERVABLE_TYPES)
        ),
        excluded_labels=_parse_csv_set(source.get("INDICATOR_EXCLUDED_LABELS", "")),
        # Scope lists (IE-SCOPE-FILTER-V1): env values add to the built-in
        # defaults in scope.py; they never replace or empty them.
        excluded_domains=DEFAULT_EXCLUDED_DOMAINS
        | _parse_domain_set(source.get("INDICATOR_EXCLUDED_DOMAINS", "")),
        shared_hosting_domains=DEFAULT_SHARED_HOSTING_DOMAINS
        | _parse_domain_set(source.get("INDICATOR_SHARED_HOSTING_DOMAINS", "")),
        target=parse_export_location(source.get("EXPORT_LOCATION", "")),
        scheme=scheme,
        port=port,
        path=path,
        auth_token=source.get("EXPORT_AUTH_TOKEN", "").strip(),
        verify_tls=_parse_verify(optional("EXPORT_VERIFY_TLS", "true")),
        batch_size=integer("EXPORT_BATCH_SIZE", 500, minimum=1),
        timeout_seconds=integer("EXPORT_TIMEOUT_SECONDS", 30, minimum=1),
        # A blank value falls back to the default, so it cannot switch this off.
        blocked_markings=_parse_csv_set(optional("EXPORT_BLOCKED_MARKINGS", "Sensitive")),
        max_labels=integer("EXPORT_MAX_LABELS", 50, minimum=1),
        excluded_entity_types=_parse_csv_set(
            optional("EXPORT_EXCLUDED_ENTITY_TYPES", DEFAULT_EXCLUDED_ENTITY_TYPES)
        ),
        data_dir=optional("EXPORT_DATA_DIR", "/data"),
        csv_retention=integer("EXPORT_CSV_RETENTION", 5, minimum=1),
    )
