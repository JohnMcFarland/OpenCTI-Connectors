# OpenCTI Platform Diagnostics

A suite of three diagnostic scripts for auditing the health, integrity, and data model compliance of a self-hosted OpenCTI instance. Designed for OpenCTI 6.9.x running under Docker Compose.

---

## Scripts

| Script | Domain | Transport |
|---|---|---|
| `platform_health_diag.sh` | Infrastructure and container health | Bash / Docker CLI |
| `platform_integrity_diag.py` | Graph integrity and metadata completeness | GraphQL API |
| `platform_compliance_diag.py` | Data model compliance | GraphQL API |

---

## Domain 1 — Platform Health (`platform_health_diag.sh`)

Inspects infrastructure-layer state without touching the OpenCTI API. Run from the Docker Compose working directory.

**Checks performed:**

- **1.1 Container state** — full `docker compose ps -a` output for all services
- **1.2 Resource utilization** — CPU, memory, swap, and PID counts across all containers
- **1.3 Redis memory state** — used memory, peak memory, configured `maxmemory`, eviction policy, and fragmentation ratio
- **1.4 Elasticsearch cluster health** — node heap/RAM/CPU utilization and cluster health status
- **1.5 Swap and kernel parameters** — system memory/swap totals, `vm.swappiness`, and Transparent HugePage setting
- **1.6 RabbitMQ queue depth** — message and consumer counts per queue
- **1.7 Connector container states** — running/restart status for all known custom connectors
- **1.8 Disk state** — filesystem usage, Docker system disk consumption, dangling images, and systemd journal size
- **1.9 MinIO volume audit** — lists all Docker volumes; inspects expected orphan volumes (`opencti-docker_minio_data`, `s3data`)

**Usage:**

```bash
# From ~/opencti-docker
bash scripts/platform_health_diag.sh 2>&1 | tee platform_health_$(date +%Y%m%d_%H%M%S).txt
```

No environment variables required. Requires `sudo` access and Docker Compose available as `docker compose`.

---

## Domain 2 — Platform Integrity (`platform_integrity_diag.py`)

Queries the OpenCTI GraphQL API to identify structural integrity problems in the knowledge graph.

**Checks performed:**

- **2.1 Orphaned SDOs** — STIX Domain Objects with no parent container membership, by entity type. Orphaned entities have no provenance, cannot be attributed, and are ungovernable.
- **2.2 Orphaned Observables** — STIX Cyber Observables with no parent container membership, grouped by type.
- **2.3 Duplicate Report containers** — Reports sharing identical names (case-insensitive) or identical External Reference URLs. Duplicates split the knowledge base and produce misleading query counts.
- **2.4 Stale connector registrations** — Connectors registered in OpenCTI but not currently sending heartbeats. Stale registrations indicate connectors that have stopped running without being deregistered.
- **2.5 Report container metadata completeness** — Scans all Reports for missing author, marking definition, external reference URL, published date, or a confidence score of 0 (unset default).

**Usage:**

```bash
export OPENCTI_ADMIN_TOKEN=your-token-here
# Optional — defaults to http://localhost:8080
export OPENCTI_BASE_URL=http://localhost:8080

python3 platform_integrity_diag.py 2>&1 | tee platform_integrity_$(date +%Y%m%d_%H%M%S).txt
```

---

## Domain 3 — Data Model Compliance (`platform_compliance_diag.py`)

Audits the knowledge graph against the project data model and the Four Cs framework governing all OpenCTI data in this instance.

**Checks performed:**

- **3.1 Manually created Indicators** — Identifies STIX-pattern Indicators with no linked source Observable, which indicates manual creation in violation of platform policy. YARA and Sigma Indicators are explicitly permitted and reported separately.
- **3.2 Sightings in Report containers** — Sightings must only appear inside Incident Response containers. Any Sighting found inside a Report container is a container semantics violation: it conflates external assertion with first-hand observation.
- **3.3 Relationship type compliance** — Samples up to 1,000 core relationships and validates each source → relationship → target triple against the authorized relationship set. Reports unauthorized triples with counts and creating entity.
- **3.4 URLhaus connector output audit** — Inspects recent URL Observables for container membership and marking definitions; checks whether the URLhaus connector is creating Indicators (which would be a policy violation unless YARA or Sigma).
- **3.5 Entity type misclassification** — Heuristic scan for Intrusion Sets whose names suggest they should be Threat Actor Groups (real-world org indicators: SVR, GRU, MSS, etc.) and Threat Actor Groups whose names suggest they should be Intrusion Sets (cluster designators: APT, FIN, UNC, etc.).

**Usage:**

```bash
export OPENCTI_ADMIN_TOKEN=your-token-here
# Optional — defaults to http://localhost:8080
export OPENCTI_BASE_URL=http://localhost:8080

python3 platform_compliance_diag.py 2>&1 | tee platform_compliance_$(date +%Y%m%d_%H%M%S).txt
```

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_ADMIN_TOKEN` | Yes | — | OpenCTI admin API token. Scripts will refuse to run if not set. |
| `OPENCTI_BASE_URL` | No | `http://localhost:8080` | Base URL of the OpenCTI instance. |

Tokens are never hardcoded. Both Python scripts will raise a `RuntimeError` at startup if `OPENCTI_ADMIN_TOKEN` is not present in the environment.

---

## Requirements

**Shell script:**
- Bash
- Docker Compose (`docker compose` — not `docker-compose`)
- `sudo` access

**Python scripts:**
- Python 3.8+
- `requests` library (`pip install requests`)
- Network access to the OpenCTI GraphQL endpoint
- An OpenCTI admin token with read access across all entity types

---

## Design Notes

**Read-only.** All three scripts are strictly diagnostic. They issue no mutations, create no entities, and modify no platform state.

**Pagination.** All GraphQL queries paginate fully using cursor-based pagination. Results reflect the complete platform state, not a capped sample — except the relationship compliance check in 3.3, which intentionally samples the first 1,000 relationships for performance reasons. This is noted in the output.

**Rate limiting.** The Python scripts include a configurable inter-request delay (`DELAY = 1.0` seconds) to avoid overwhelming the GraphQL worker under large datasets.

**Authorized relationship set.** The set used in check 3.3 is maintained directly in `platform_compliance_diag.py` under `AUTHORIZED_RELATIONSHIPS`. It reflects the project's Data Model Relationship Guide. If the data model is extended, this set must be updated in parallel.

**Tee output.** The recommended invocation pattern pipes output through `tee` to both display results and write a timestamped log file. Diagnostic runs should be retained for trend comparison across time.

---

## Known Limitations

- Check 3.3 samples only the first 1,000 relationships. On large instances, violations present only in later pages will not be detected. A full scan can be enabled by removing the `pages < 5` guard in the script.
- Check 3.5 uses name-based heuristics. It will produce false positives for entities whose names incidentally contain matched substrings, and will not detect misclassifications where names give no signal.
- The shell script detects containers by grepping `docker ps` output for known service name fragments. If service names in your Compose configuration differ from the defaults, container detection in checks 1.3, 1.4, and 1.6 will fail gracefully with an error message.
- Check 3.4 is scoped to the URLhaus connector specifically. It is not a general-purpose audit of all third-party connector output.
