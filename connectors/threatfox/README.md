# ThreatFox OpenCTI Connector

A custom external-import connector for [OpenCTI](https://www.opencti.io/) that ingests IOC data from [ThreatFox](https://threatfox.abuse.ch/) (abuse.ch) and converts it to STIX 2.1 objects.

---

## Overview

This connector polls the ThreatFox API on a configurable interval, converts each IOC entry into a set of STIX 2.1 SCOs, SDOs, and SROs, and pushes the bundle into OpenCTI wrapped in a dated Report container. All ingestion is non-destructive and idempotent — repeated runs merge into existing objects rather than duplicating them.

---

## Requirements

- OpenCTI 6.x (tested on 6.9.13)
- Docker and Docker Compose
- A ThreatFox API auth key ([get one free](https://auth.abuse.ch/))
- An OpenCTI user token for the connector identity

---

## Quick Start

### 1. Generate the MITRE ATT&CK software cache

The connector uses a pre-built lookup table to resolve ThreatFox tags against MITRE ATT&CK software entries. Generate it once before building:
```bash
python3 build_mitre_cache.py
```

This fetches the current MITRE ATT&CK enterprise dataset and writes `data/mitre_attack_software.json`. Re-run periodically to pick up new ATT&CK releases.

### 2. Configure environment variables

Copy `config.yml.sample` for reference. The connector is configured entirely via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENCTI_URL` | Yes | `http://opencti:8080` | OpenCTI instance URL |
| `OPENCTI_TOKEN` | Yes | — | API token for the connector user |
| `CONNECTOR_ID` | Yes | — | Stable UUID for this connector instance |
| `CONNECTOR_NAME` | No | `ThreatFox` | Display name in OpenCTI |
| `CONNECTOR_INTERVAL` | No | `360` | Poll interval in minutes |
| `CONNECTOR_LOG_LEVEL` | No | `info` | Log level |
| `THREATFOX_AUTH_KEY` | Yes | — | ThreatFox API auth key |
| `THREATFOX_DAYS` | No | `7` | Initial lookback on first run (1–7) |

### 3. Build and run
```bash
docker compose build --no-cache
docker compose up -d
docker compose logs -f
```

---

## Data Model

### What the connector produces

| STIX Type | Source | Notes |
|-----------|--------|-------|
| `domain-name` | `ioc_type: domain` | |
| `ipv4-addr` | `ioc_type: ip:port` | IP extracted from value |
| `network-traffic` | `ioc_type: ip:port` | Port-only SCO, no `dst_ref` |
| `url` | `ioc_type: url` | |
| `file` | `ioc_type: *_hash` | SHA-256, SHA-1, or MD5 |
| `autonomous-system` | ASN tags | e.g. `AS207994` |
| `malware` | `malware_printable` field | `is_family: true` |
| `malware` or `tool` | MITRE software tags | Enriched with ATT&CK S-number |
| `identity` | `reporter` field | `identity_class: organization` |
| `report` | Per run | Title: `Threat Fox Feed YYYY-MM-DD` |

### Relationships produced

| Source | Type | Target |
|--------|------|--------|
| Observable | `related-to` | Malware |
| Observable | `related-to` | MITRE Malware/Tool |
| Observable | `related-to` | Reporter identity |
| `ipv4-addr` | `belongs-to` | Autonomous system |
| `ipv4-addr` | `related-to` | Network-traffic |

### What the connector does NOT produce

- Indicators (generated automatically by OpenCTI)
- Infrastructure entities
- Attack Pattern objects
- Sightings

---

## Report Container

Each run produces a `report` SDO titled `Threat Fox Feed YYYY-MM-DD`. The report:
- Is typed `report_types: ["observable-feed"]` — a deliberate open-vocabulary value distinguishing this automated observable feed from analyst-authored `threat-report` products (see `CONNECTOR_SCOPE.md`)
- Is authored by the `[C]ThreatFox` system identity
- Contains `object_refs` for all objects produced in the run
- Uses a deterministic UUID keyed on the date — same-day re-runs merge into the same report

---

## State Management

The connector persists `last_run` timestamp via OpenCTI's connector state API. Subsequent runs fetch only the delta since the last run (day delta + 1, capped at 7 — the ThreatFox API maximum). On first run, `THREATFOX_DAYS` controls the initial lookback.

---

## Deduplication

- **Observables**: Keyed on STIX namespace + observable value — identical observables from other feeds merge automatically
- **Malware SDOs**: Keyed on lowercase name — MITRE software tags that match `malware_printable` entries reuse the existing SDO rather than creating a duplicate
- **Relationships**: Deduplicated by (source, type, target) triple within each run
- **Report**: Deterministic UUID keyed on date — intra-day re-runs merge `object_refs`

---

## MITRE Cache Refresh

The MITRE ATT&CK software cache (`data/mitre_attack_software.json`) is static and ships with the image. To update it for a new ATT&CK release:
```bash
python3 build_mitre_cache.py
docker compose build --no-cache
```

---

## Project Structure
```
threatfox/
├── src/
│   ├── __init__.py
│   ├── config.py              # Environment variable mapping and constants
│   ├── connector.py           # OpenCTI connector class, polling loop, state management
│   ├── main.py                # Entry point (connector mode + dry-run CLI)
│   ├── mitre_lookup.py        # MITRE ATT&CK software cache loader
│   ├── stix_converter.py      # ThreatFox JSON → STIX 2.1 conversion
│   ├── tag_processor.py       # Tag classification (ASN, MITRE software, skip)
│   ├── threatfox_client.py    # ThreatFox API client
│   └── uuid_generator.py      # Deterministic UUIDv5 generation
├── data/
│   └── mitre_attack_software.json   # Generated by build_mitre_cache.py
├── tests/
│   ├── test_stix_converter.py
│   ├── test_tag_processor.py
│   ├── test_uuid_generator.py
│   └── test_data/
├── build_mitre_cache.py       # One-shot MITRE cache generator
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── config.yml.sample
└── README.md
```

---

## Dry Run

Test conversion without pushing to OpenCTI:
```bash
python3 -m src.main --dry-run --input tests/test_data/sample_threatfox.json
```

Write the STIX bundle to a file for inspection:
```bash
python3 -m src.main --dry-run --input tests/test_data/sample_threatfox.json --output bundle.json
```

---

## License

MIT
