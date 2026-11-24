"""Configuration loader.

Precedence: environment variables > config.yml > defaults. Env names match
docker-compose.yml. Secrets are kept out of logs (never log full Settings).
Booleans are parsed by pydantic, so UDM_VERIFY_SSL=false really means False.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _seed_env_from_yaml(path: str = "config.yml") -> None:
    """If a config.yml exists, set any missing env vars from it (env wins)."""
    p = Path(path)
    if not p.is_file():
        return
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    flat: dict = {}
    for section, prefix in (("opencti", "OPENCTI_"), ("connector", "CONNECTOR_"),
                            ("udm", "UDM_")):
        for k, v in (data.get(section) or {}).items():
            flat[f"{prefix}{k.upper()}"] = v
    for key, val in flat.items():
        if val is not None and key not in os.environ:
            os.environ[key] = str(val)


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    # --- OpenCTI / connector (consumed by OpenCTIConnectorHelper too) ---
    opencti_url: str = Field(alias="OPENCTI_URL")
    opencti_token: str = Field(alias="OPENCTI_TOKEN")
    connector_id: str = Field(alias="CONNECTOR_ID")
    connector_name: str = Field("UDM", alias="CONNECTOR_NAME")
    connector_scope: str = Field("incident", alias="CONNECTOR_SCOPE")
    connector_duration_period: str = Field("PT1H", alias="CONNECTOR_DURATION_PERIOD")
    connector_log_level: str = Field("info", alias="CONNECTOR_LOG_LEVEL")

    # --- UDM Pro local API ---
    udm_host: str = Field(min_length=1, alias="UDM_HOST")
    udm_api_key: str = Field(min_length=1, alias="UDM_API_KEY")
    udm_site: str = Field("default", min_length=1, alias="UDM_SITE")
    udm_verify_ssl: bool = Field(False, alias="UDM_VERIFY_SSL")  # UDM ships a self-signed cert
    udm_ca_bundle: str = Field("", alias="UDM_CA_BUNDLE")
    udm_request_timeout: int = Field(30, ge=1, alias="UDM_REQUEST_TIMEOUT")

    # --- streams ---
    udm_flows_enabled: bool = Field(True, alias="UDM_FLOWS_ENABLED")
    udm_page_size: int = Field(500, ge=1, le=500, alias="UDM_PAGE_SIZE")
    udm_max_pages: int = Field(200, ge=1, alias="UDM_MAX_PAGES")
    udm_security_enabled: bool = Field(True, alias="UDM_SECURITY_ENABLED")
    # Blocked IPS threats already arrive as SIGNATURE traffic-flows (with signature,
    # CVE and ports, which the log lacks); importing both would duplicate each one.
    udm_security_skip_blocked: bool = Field(True, alias="UDM_SECURITY_SKIP_BLOCKED")
    # Logins to UniFi Network from an external address (internal logins are dropped).
    udm_admin_enabled: bool = Field(True, alias="UDM_ADMIN_ENABLED")
    # Firmware per UniFi device, re-sent only when a version changes.
    udm_inventory_enabled: bool = Field(True, alias="UDM_INVENTORY_ENABLED")
    # Read port-forward rules, to flag traffic that hit a forwarded service.
    udm_port_forwards_enabled: bool = Field(True, alias="UDM_PORT_FORWARDS_ENABLED")

    # --- windowing ---
    udm_initial_lookback_days: int = Field(30, ge=0, alias="UDM_INITIAL_LOOKBACK_DAYS")
    udm_overlap_minutes: int = Field(30, ge=0, alias="UDM_OVERLAP_MINUTES")

    # --- network context ---
    udm_wan_ips: str = Field("", alias="UDM_WAN_IPS")  # fallback if stat/device fails
    # Extra ranges to treat as internal on top of all non-global (RFC1918, CGNAT,
    # link-local, ...) space, e.g. a routed public block you own.
    udm_internal_subnets: str = Field("", alias="UDM_INTERNAL_SUBNETS")

    # --- output ---
    udm_events_per_bundle: int = Field(200, ge=1, le=2000, alias="UDM_EVENTS_PER_BUNDLE")
    udm_author_name: str = Field("UDM Alert", min_length=1, alias="UDM_AUTHOR_NAME")
    udm_gateway_name: str = Field("UDM-WAN", min_length=1, alias="UDM_GATEWAY_NAME")
    udm_organization_name: str = Field(min_length=1, alias="UDM_ORGANIZATION_NAME")
    udm_tlp: str = Field("TLP:AMBER+STRICT", alias="UDM_TLP")
    udm_confidence: int = Field(85, ge=0, le=100, alias="UDM_CONFIDENCE")
    # UDM-DRYRUN-V1: build and count bundles, send nothing, save no state.
    udm_dry_run: bool = Field(False, alias="UDM_DRY_RUN")

    @field_validator("udm_internal_subnets")
    @classmethod
    def _subnets(cls, v: str) -> str:
        for s in _csv(v):
            ipaddress.ip_network(s, strict=False)  # raises ValueError on a typo
        return v

    @field_validator("udm_wan_ips")
    @classmethod
    def _wan(cls, v: str) -> str:
        for s in _csv(v):
            ipaddress.ip_address(s)
        return v

    @property
    def verify(self) -> bool | str:
        """requests `verify=` value: CA bundle path wins over the boolean."""
        if self.udm_ca_bundle:
            return self.udm_ca_bundle
        return self.udm_verify_ssl

    @property
    def wan_ip_list(self) -> list[str]:
        return _csv(self.udm_wan_ips)

    @property
    def internal_networks(self) -> list:
        return [ipaddress.ip_network(s, strict=False) for s in _csv(self.udm_internal_subnets)]


def load_settings() -> Settings:
    _seed_env_from_yaml()
    return Settings()  # type: ignore[call-arg]
