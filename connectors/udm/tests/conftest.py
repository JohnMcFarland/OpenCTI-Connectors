from __future__ import annotations

import pytest

ENV = {"OPENCTI_URL": "http://x", "OPENCTI_TOKEN": "t", "CONNECTOR_ID": "c",
       "UDM_HOST": "192.168.1.1", "UDM_API_KEY": "k", "UDM_ORGANIZATION_NAME": "Acme"}


@pytest.fixture
def settings(monkeypatch):
    from src.config import Settings

    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    return Settings()
