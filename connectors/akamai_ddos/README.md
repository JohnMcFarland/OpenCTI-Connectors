# Akamai DDoS Connector

Pulls Akamai DDoS telemetry into OpenCTI as **first-hand internal observation**:

- **Prolexic Analytics API** — network-layer (L3/L4) DDoS attack reports.
- **SIEM Integration API** — application-layer (L7) DoS / rate-control / Slow-POST events.

Each detected attack episode becomes an **Incident Response** container holding an
**Incident**, the matching **MITRE ATT&CK** DDoS technique, **Network-Traffic** port
objects, the targeted **System(s)**, up to the top-1000 source-IP **Observables**, and
**Sightings** of those IPs on the targeted systems. Structured per `data_model/`
(the source of truth). See [CONNECTOR_SCOPE.md](CONNECTOR_SCOPE.md) for the full design.

> **Status:** scaffolded. `config`, `akamai_client`, and `mitre_map` are implemented;
> `stix_builder`, `prolexic._normalize`, and `siem._aggregate` have skeletons + TODOs
> pending confirmation of exact API field names against a live response / Postman.

## Data-model guarantees

- Container is **Incident Response**, never Report (first-hand detection).
- **No Indicators** are created — Observables only; OpenCTI auto-promotes.
- **Network-Traffic = a single port number** (house convention), nothing else.
- Every relationship is checked against the allow-list (`ALLOWED_EDGES` in `stix_builder.py`).
- Default marking **TLP:AMBER+STRICT**; times are source times.

## Configuration

Set via environment (see `docker-compose.yml`) or `config.yml` (copy from
`config.yml.sample`). Env wins over the file.

| Key | Description |
|---|---|
| `OPENCTI_URL`, `OPENCTI_TOKEN` | OpenCTI connection |
| `CONNECTOR_ID` | UUID for this connector instance |
| `CONNECTOR_DURATION_PERIOD` | poll cadence (ISO-8601, default `PT1H`) |
| `AKAMAI_EDGERC_PATH` *or* `AKAMAI_HOST`/`_CLIENT_TOKEN`/`_CLIENT_SECRET`/`_ACCESS_TOKEN` | EdgeGrid auth |
| `AKAMAI_PROLEXIC_ENABLED`, `AKAMAI_PROLEXIC_CONTRACT` | Prolexic path |
| `AKAMAI_SIEM_ENABLED`, `AKAMAI_SIEM_CONFIG_IDS`, `AKAMAI_SIEM_DDOS_RULE_TAGS` | SIEM path |
| `AKAMAI_INITIAL_LOOKBACK_DAYS` | first-run backfill (default 7) |
| `AKAMAI_SOURCE_IP_TOP_N` | source IPs ingested per attack (default 1000) |
| `AKAMAI_TARGET_ORG_NAME` | Organization that owns the targeted assets |
| `AKAMAI_TLP`, `AKAMAI_CONFIDENCE` | default marking + confidence |

## Run

```bash
docker compose up -d --build
# or locally:
pip install -r requirements.txt
python -m src.main
```

## Layout

```
src/
  main.py          entrypoint
  config.py        pydantic-settings loader (.env / config.yml / env)
  akamai_client.py EdgeGrid Session + retry/backoff + NDJSON
  prolexic.py      L3/L4 poller  → AttackEvent
  siem.py          L7 poller      → AttackEvent
  models.py        AttackEvent / SourceIp
  mitre_map.py     vector / ruleTag → ATT&CK technique
  stix_builder.py  AttackEvent → STIX (Incident Response + Incident + Sightings)
  connector.py     scheduling, state, work lifecycle, bundle send
```
