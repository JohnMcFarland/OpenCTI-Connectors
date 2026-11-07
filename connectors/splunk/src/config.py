"""Configuration loader.

Precedence: environment variables > config.yml > defaults. Env names match
docker-compose.yml. Secrets are kept out of logs (never log full Settings).

The searches themselves live in a separate YAML file (SPLUNK_SEARCHES_FILE) so the
operator can add, change, or disable sources without touching connector env vars.
See searches.py for that schema.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .searches import SearchConfigError, parse_relative


def _seed_env_from_yaml(path: str = "config.yml") -> None:
    """If a config.yml exists, set any missing env vars from it (env wins)."""
    p = Path(path)
    if not p.is_file():
        return
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    flat: dict = {}
    # A section present but empty (`opencti:`) loads as None, hence `or {}`.
    for section, prefix in (("opencti", "OPENCTI_"), ("connector", "CONNECTOR_"),
                            ("splunk", "SPLUNK_")):
        for k, v in (data.get(section) or {}).items():
            flat[f"{prefix}{k.upper()}"] = v
    for key, val in flat.items():
        if val is not None and key not in os.environ:
            os.environ[key] = str(val)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    # --- OpenCTI / connector (consumed by OpenCTIConnectorHelper too) ---
    opencti_url: str = Field(alias="OPENCTI_URL")
    opencti_token: str = Field(alias="OPENCTI_TOKEN")
    connector_id: str = Field(alias="CONNECTOR_ID")
    connector_name: str = Field("Splunk", alias="CONNECTOR_NAME")
    connector_scope: str = Field("incident", alias="CONNECTOR_SCOPE")
    connector_duration_period: str = Field("PT15M", alias="CONNECTOR_DURATION_PERIOD")
    connector_log_level: str = Field("info", alias="CONNECTOR_LOG_LEVEL")

    # --- Splunk management API (port 8089) ---
    splunk_base_url: str = Field(min_length=1, alias="SPLUNK_BASE_URL")  # e.g. https://splunk.corp:8089
    splunk_token: str = Field("", alias="SPLUNK_TOKEN")  # preferred: Splunk auth token
    splunk_username: str = Field("", alias="SPLUNK_USERNAME")  # fallback: basic auth
    splunk_password: str = Field("", alias="SPLUNK_PASSWORD")
    splunk_verify_ssl: bool = Field(True, alias="SPLUNK_VERIFY_SSL")
    splunk_ca_bundle: str = Field("", alias="SPLUNK_CA_BUNDLE")  # internal CA for self-hosted
    splunk_owner: str = Field("nobody", alias="SPLUNK_OWNER")  # servicesNS owner
    splunk_results_api: Literal["v1", "v2"] = Field("v2", alias="SPLUNK_RESULTS_API")  # v1 for Splunk < 9.0.1
    splunk_request_timeout: int = Field(60, ge=1, alias="SPLUNK_REQUEST_TIMEOUT")
    splunk_job_timeout: int = Field(900, ge=1, alias="SPLUNK_JOB_TIMEOUT")  # seconds per search job
    splunk_page_size: int = Field(10000, ge=1, le=50000, alias="SPLUNK_PAGE_SIZE")

    # --- searches ---
    splunk_searches_file: str = Field("searches.yml", alias="SPLUNK_SEARCHES_FILE")

    # --- behavior ---
    splunk_initial_lookback: str = Field("-24h", alias="SPLUNK_INITIAL_LOOKBACK")
    splunk_ingest_lag_seconds: int = Field(300, ge=0, alias="SPLUNK_INGEST_LAG_SECONDS")
    # index time_mode: how far _time may sit outside the _indextime window and still match.
    splunk_index_time_skew_seconds: int = Field(86400, ge=0, alias="SPLUNK_INDEX_TIME_SKEW_SECONDS")
    splunk_max_objects_per_case: int = Field(2000, ge=50, alias="SPLUNK_MAX_OBJECTS_PER_CASE")
    splunk_author_name: str = Field("Splunk", min_length=1, alias="SPLUNK_AUTHOR_NAME")
    splunk_sensor_system_name: str = Field("Splunk", min_length=1, alias="SPLUNK_SENSOR_SYSTEM_NAME")
    splunk_organization_name: str = Field(min_length=1, alias="SPLUNK_ORGANIZATION_NAME")
    splunk_tlp: str = Field("TLP:AMBER+STRICT", alias="SPLUNK_TLP")
    splunk_confidence: int = Field(75, ge=0, le=100, alias="SPLUNK_CONFIDENCE")

    @field_validator("splunk_initial_lookback")
    @classmethod
    def _relative(cls, v: str) -> str:
        try:
            parse_relative(v)
        except SearchConfigError as exc:
            raise ValueError(str(exc)) from None
        return v

    @property
    def verify(self) -> bool | str:
        """requests `verify=` value: CA bundle path wins over the boolean."""
        if self.splunk_ca_bundle:
            return self.splunk_ca_bundle
        return self.splunk_verify_ssl


def load_settings() -> Settings:
    _seed_env_from_yaml()
    return Settings()  # type: ignore[call-arg]
