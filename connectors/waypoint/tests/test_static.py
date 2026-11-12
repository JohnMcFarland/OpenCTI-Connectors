"""Repository rules: ASCII-only sources, no credentials or instance values,
OPENCTI_URL (not OPENCTI_BASE_URL), the deployment marker, and sources.yml
mounted read-only."""

import re

import yaml

from conftest import ROOT

REPO = ROOT.parents[1]
SOURCE_FILES = sorted(
    [p for p in ROOT.rglob("*") if p.is_file() and "__pycache__" not in p.parts
     and "fixtures" not in p.parts]
    + [REPO / "scripts" / "extract_profiles.py", REPO / "docs" / "WAYPOINT_SCOPE.md"])


def test_source_files_are_ascii():
    bad = [str(p.relative_to(REPO)) for p in SOURCE_FILES if any(b > 127 for b in p.read_bytes())]
    assert bad == []


def test_no_credentials_instance_values_or_connector_ids():
    uuid_re = re.compile(rb"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
    ip_re = re.compile(rb"\b(?:10|127|172\.(?:1[6-9]|2\d|3[01])|192\.168)(?:\.\d{1,3}){2,3}\b")
    token_re = re.compile(rb"(?i)(token|password|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}")
    for p in SOURCE_FILES:
        data = p.read_bytes()
        assert not uuid_re.search(data), p
        assert not ip_re.search(data), p
        assert not token_re.search(data), p


def test_opencti_url_variable_name():
    wrong = ("OPENCTI_" + "BASE_URL").encode()      # split so this file does not match
    for p in SOURCE_FILES:
        if p.name in ("test_static.py", "WAYPOINT_SCOPE.md"):
            continue   # these name the wrong variable to forbid it
        assert wrong not in p.read_bytes(), p
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "OPENCTI_URL=" in compose and "OPENCTI_TOKEN=" in compose and "CONNECTOR_ID=" in compose
    cfg = yaml.safe_load((ROOT / "config.yml").read_text(encoding="utf-8"))
    assert cfg["opencti"] == {"url": "", "token": ""} and cfg["connector"]["id"] == ""


def test_deployment_marker():
    assert "WAYPOINT-V1" in (ROOT / "main.py").read_text(encoding="utf-8")


def test_sources_mounted_read_only_and_data_volume():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    svc = compose["services"]["waypoint"]
    assert "./sources.yml:/app/sources.yml:ro" in svc["volumes"]
    assert "../microservices:/microservices:ro" in svc["volumes"]
    assert any(v.endswith(":/data") for v in svc["volumes"])
    assert svc["restart"] == "always" and svc.get("mem_limit")
    env = "\n".join(svc["environment"])
    for var in ("AGG_SOURCE_WORKERS", "AGG_RENDER_CONCURRENCY", "AGG_REPORTS_PER_CYCLE",
                "AGG_MAX_REPORTS_PER_SOURCE_POLL", "AGG_CLASSIFY_CONCURRENCY", "AGG_DRY_RUN"):
        assert var in env


def test_image_does_not_bake_in_sources_or_microservices():
    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    copy = [line for line in docker.splitlines() if line.startswith("COPY")]
    assert not any("microservices" in line or "sources.yml" in line for line in copy)
