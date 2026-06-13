"""Configuration loader.

Precedence: environment variables > config.yml > defaults. Env names match
docker-compose.yml. Secrets are kept out of logs (never log full Settings).
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _seed_env_from_yaml(path: str = "config.yml") -> None:
    """If a config.yml exists, set any missing env vars from it (env wins)."""
    p = Path(path)
    if not p.is_file():
        return
    data = yaml.safe_load(p.read_text()) or {}
    flat = {
        "OPENCTI_URL": data.get("opencti", {}).get("url"),
        "OPENCTI_TOKEN": data.get("opencti", {}).get("token"),
        "CONNECTOR_ID": data.get("connector", {}).get("id"),
        "CONNECTOR_NAME": data.get("connector", {}).get("name"),
        "CONNECTOR_SCOPE": data.get("connector", {}).get("scope"),
        "CONNECTOR_DURATION_PERIOD": data.get("connector", {}).get("duration_period"),
        "CONNECTOR_LOG_LEVEL": data.get("connector", {}).get("log_level"),
    }
    ak = data.get("akamai", {})
    for k, v in ak.items():
        flat[f"AKAMAI_{k.upper()}"] = v
    for key, val in flat.items():
        if val is not None and key not in os.environ:
            os.environ[key] = str(val)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    # --- OpenCTI / connector (consumed by OpenCTIConnectorHelper too) ---
    opencti_url: str = Field(alias="OPENCTI_URL")
    opencti_token: str = Field(alias="OPENCTI_TOKEN")
    connector_id: str = Field(alias="CONNECTOR_ID")
    connector_name: str = Field("Akamai DDoS", alias="CONNECTOR_NAME")
    connector_scope: str = Field("incident", alias="CONNECTOR_SCOPE")
    connector_duration_period: str = Field("PT1H", alias="CONNECTOR_DURATION_PERIOD")
    connector_log_level: str = Field("info", alias="CONNECTOR_LOG_LEVEL")

    # --- Akamai EdgeGrid ---
    akamai_edgerc_path: str = Field("", alias="AKAMAI_EDGERC_PATH")
    akamai_host: str = Field("", alias="AKAMAI_HOST")
    akamai_client_token: str = Field("", alias="AKAMAI_CLIENT_TOKEN")
    akamai_client_secret: str = Field("", alias="AKAMAI_CLIENT_SECRET")
    akamai_access_token: str = Field("", alias="AKAMAI_ACCESS_TOKEN")

    # --- Prolexic (L3/L4) ---
    akamai_prolexic_enabled: bool = Field(True, alias="AKAMAI_PROLEXIC_ENABLED")
    akamai_prolexic_contract: str = Field("", alias="AKAMAI_PROLEXIC_CONTRACT")

    # --- SIEM (L7) ---
    akamai_siem_enabled: bool = Field(True, alias="AKAMAI_SIEM_ENABLED")
    akamai_siem_config_ids: str = Field("", alias="AKAMAI_SIEM_CONFIG_IDS")
    akamai_siem_ddos_rule_tags: str = Field("", alias="AKAMAI_SIEM_DDOS_RULE_TAGS")

    # --- behavior ---
    akamai_initial_lookback_days: int = Field(7, alias="AKAMAI_INITIAL_LOOKBACK_DAYS")
    akamai_source_ip_top_n: int = Field(1000, alias="AKAMAI_SOURCE_IP_TOP_N")
    akamai_target_org_name: str = Field("", alias="AKAMAI_TARGET_ORG_NAME")
    akamai_tlp: str = Field("TLP:AMBER+STRICT", alias="AKAMAI_TLP")
    akamai_confidence: int = Field(80, alias="AKAMAI_CONFIDENCE")

    @property
    def siem_config_id_list(self) -> list[str]:
        return [c.strip() for c in self.akamai_siem_config_ids.split(",") if c.strip()]

    @property
    def siem_ddos_rule_tag_list(self) -> list[str]:
        return [t.strip() for t in self.akamai_siem_ddos_rule_tags.split(",") if t.strip()]


def load_settings() -> Settings:
    _seed_env_from_yaml()
    return Settings()  # type: ignore[call-arg]
