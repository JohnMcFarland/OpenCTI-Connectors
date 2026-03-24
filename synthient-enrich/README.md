# Synthient Enrichment Connector

**Type:** Internal Enrichment  
**Trigger:** Manual — Case-Rfi  
**Scope:** IPv4-Addr, IPv6-Addr  
**Platform:** OpenCTI 6.9.13  
**Author:** Synthient (`https://synthient.com`)

---

## Overview

This connector enriches IPv4 and IPv6 observables within a Case-Rfi container using the [Synthient](https://synthient.com) IP Intelligence Platform. Synthient is a high-fidelity proxy and anonymization detection service that classifies IPs by risk score, proxy/VPN category, and behavioral profile using data aggregated from a large network of residential and commercial sensors.

The connector is triggered manually by an analyst on any Case-Rfi. It iterates all IP observables within that container, queries the Synthient v3 API for each, and writes the enrichment output back into OpenCTI — scoped to the triggering RFI so all output is contained and attributed.

---

## What It Does

For each IP observable in the triggering Case-Rfi, the connector:

1. **Updates the observable's risk score** — sets `x_opencti_score` to the Synthient `ip_risk` value (0–100), making it visible in the observable tile and queryable via filters.

2. **Creates an analysis Note** — attaches a structured note to the observable containing the full Synthient response: risk score, proxy/VPN categories, behavioral flags, enriched provider hits, device fingerprints, network context, and geolocation.

3. **Creates an AutonomousSystem entity** — creates or deduplicates the ASN and links it to the observable via `IPv4-Addr → belongs-to → Autonomous System`.

4. **Creates an Organization entity** — creates or deduplicates the network operator (ISP/org from Synthient) and links it to the ASN via `Autonomous System → related-to → Organization`.

5. **Links to a Country** — looks up the existing Country entity in OpenCTI by name and creates `IPv4-Addr → located-at → Country` if found.

6. **Adds all output to the RFI container** — every created object and relationship is explicitly added to the triggering Case-Rfi so it is scoped correctly, visible in context, and governed under the RFI's access controls.

---

## Data Model

All relationships are validated against the instance Data Model Relationship Guide.

| Source | Relationship | Target | Creation Method |
|--------|-------------|--------|-----------------|
| IPv4-Addr / IPv6-Addr | `belongs-to` | Autonomous System | STIX bundle |
| Autonomous System | `related-to` | Organization | STIX bundle |
| IPv4-Addr / IPv6-Addr | `located-at` | Country | STIX bundle |

Notes and score updates are applied via direct pycti API calls.

---

## Design Philosophy

### Manual Trigger Only

The connector is scoped to `Case-Rfi` with `auto: False`. It will never enrich an observable automatically. This is a deliberate design constraint: Synthient enrichment is intended as an analyst-driven action within an active investigation workbench, not a background pipeline that runs on every ingested IP.

Automatic enrichment would create noise at scale, generate unnecessary API calls, and produce enrichment output with no investigative context. The RFI scoping ensures every enrichment run is tied to a specific analytical question.

### Containment First

Every object and relationship created by this connector is explicitly added to the triggering RFI container. This satisfies the platform's containment requirement (no orphaned entities) and ensures that enrichment output is:

- Attributed to a specific investigation
- Governed under the RFI's TLP marking
- Visible to analysts working the case without polluting the global graph
- Expirable and auditable as a unit

### Non-Destructive

The connector never modifies, deletes, or overwrites existing entities. Score updates use `update_field` which sets a single field. Identity and ASN creation use idempotent API calls that return existing records if a matching entity is already present.

### STIX Bundle vs Direct API

OpenCTI 6.9.13 requires that STIX Cyber Observable objects (SCOs) — including `AutonomousSystem` — be created through the STIX bundle pipeline rather than direct API calls. SDOs (like `Organization`) can be created directly.

This connector uses bundles for:
- `AutonomousSystem` creation (SCO requirement)
- All `stix2.Relationship` objects (both SCO-source and SDO-source relationships must go through the bundle pipeline to be correctly committed)

It uses direct API calls for:
- `Note` creation
- `Organization` (Identity) creation
- Observable score updates
- Country lookups (read-only)

### Asynchronous Worker Resolution

STIX bundle processing is asynchronous in OpenCTI. After sending a bundle, the worker processes it in the background before the resulting objects appear in the graph with internal UUIDs. This connector polls for those UUIDs after each bundle send before attempting to use them (e.g. to add them to the RFI container or anchor a follow-on relationship).

The polling parameters (`RESOLVE_RETRIES = 6`, `RESOLVE_DELAY = 3s`) are tuned for a standard single-worker deployment. Environments with higher worker concurrency or load may require adjustment.

### Country Lookup — No Creation

Country entities are pre-populated by OpenCTI and this connector never creates them. The connector converts the ISO alpha-2 country code returned by Synthient into full name variants using `pycountry`, then looks up the existing entity by name.

The `entity_type` filter is intentionally absent from the location query. In OpenCTI 6.9.13, combining `name` and `entity_type` filters on location queries triggers an `UNSUPPORTED_ERROR`. Instead, the connector validates the returned object's `entity_type` client-side and only accepts `Country` results — explicitly rejecting `Region` objects that may share the same name. This prevents incorrect `located-at` links to continental or transnational regions.

### Known Limitations

**HK and ES country resolution** — Hong Kong (`HK`) and Spain (`ES`) are stored as `Region` objects in some OpenCTI deployments rather than `Country` objects. The connector's client-side `entity_type == "Country"` guard rejects these matches and skips the `located-at` relationship with a `WARNING` log. No located-at is created for IPs in these territories. This is consistent with the data model constraint that Regions should represent continents or important transnational groupings, not sovereign states.

**Organization name fragmentation** — Synthient returns raw ISP and org name strings (e.g. `"DigitalOcean, LLC"`, `"Amazon Technologies Inc"`). Minor string variations across API responses (trailing punctuation, subsidiary vs parent name) may produce near-duplicate Organization entities. This is accepted as low-impact informational scaffolding — the entities carry no analytical weight beyond providing a named anchor for the ASN relationship.

**IP observables only** — Synthient's v3 API is IP-centric. The connector does not enrich Domain-Name, URL, File (hash), or any other observable type. This is a source capability boundary, not a connector architecture limitation.

---

## Configuration

The connector is configured entirely via environment variables. Secrets are injected at runtime and never hardcoded.

### Required

| Variable | Description |
|----------|-------------|
| `OPENCTI_URL` | Base URL of the OpenCTI instance (e.g. `http://localhost:8080`) |
| `OPENCTI_TOKEN` | API token for the connector service account |
| `CONNECTOR_ID` | Unique UUID for this connector instance |
| `SYNTHIENT_API_KEY` | Synthient v3 API key |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `CONNECTOR_NAME` | `Synthient Enrichment` | Display name shown in OpenCTI |
| `CONNECTOR_LOG_LEVEL` | `info` | Log verbosity (`debug`, `info`, `warning`, `error`) |
| `SYNTHIENT_DAYS` | `90` | Lookback window in days for Synthient data |
| `SYNTHIENT_TLP` | `TLP:AMBER+STRICT` | TLP marking applied to all created objects |
| `SYNTHIENT_CONFIDENCE` | `90` | Confidence score (0–100) applied to all created objects and relationships |

---

## Deployment

The connector is deployed as a Docker container alongside the OpenCTI stack.

### Build and Start

```bash
cd ~/opencti-docker
sudo docker compose -f docker-compose.yml -f docker-compose.override.yml build --no-cache synthient-enrich
sudo docker compose -f docker-compose.yml -f docker-compose.override.yml up -d synthient-enrich
```

### Logs

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.override.yml logs -f synthient-enrich
```

### Restart After Code Changes

Always use `--no-cache` after modifying `connector.py` or `requirements.txt` to ensure the image is fully rebuilt.

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.override.yml build --no-cache synthient-enrich
sudo docker compose -f docker-compose.yml -f docker-compose.override.yml up -d synthient-enrich
```

---

## Usage

1. Open any **Case-Rfi** in OpenCTI that contains IPv4 or IPv6 observables.
2. Click the enrichment button (lightning bolt icon) on the case.
3. Select **Synthient Enrichment** from the connector list.
4. Click **Launch**.

The connector will process all IP observables in the RFI sequentially. Progress is visible in the connector's work log. On completion, the RFI's knowledge graph will be populated with Notes, ASN entities, Organization entities, and country relationships for each enriched IP.

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pycti` | `6.9.13` | OpenCTI connector framework — must match platform version exactly |
| `stix2` | `3.0.1` | STIX 2.1 object construction and bundle serialization |
| `requests` | `2.32.3` | HTTP client for Synthient API calls |
| `pycountry` | `24.6.1` | ISO alpha-2 country code to full name resolution |

The base Docker image is `python:3.11-slim`. The `libmagic1` system package is required by `pycti` via `python-magic` and is installed in the Dockerfile before pip dependencies.

---

## API Reference

**Endpoint:** `GET https://v3api.synthient.com/api/v3/lookup/ip/{ip}?days={N}`  
**Auth:** `Authorization: <api_key>` (no Bearer prefix)  
**Rate limiting:** Exponential backoff with up to 5 retries (initial delay 5s, max 120s) on HTTP 429 and 402 responses.

The connector does not use the Synthient Feed endpoints (`feeds.synthient.com`). Feed access requires separate tier provisioning and is handled by the companion Synthient Feed connector.
