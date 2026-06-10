# connector-ic-reports

OpenCTI External Import connector for U.S. Intelligence Community declassified
reports, cybersecurity advisories, and public analytical publications.

---

## Supported Sources

| Plugin | Source | Discovery | Frequency |
|---|---|---|---|
| `CISA` | Cybersecurity and Infrastructure Security Agency | RSS/Atom | Daily |
| `ODNI` | Office of the Director of National Intelligence | HTML scraping | Infrequent |
| `CIA` | Central Intelligence Agency (CSI + FOIA) | HTML scraping / API | Infrequent |
| `NSA` | National Security Agency / CSS | HTML scraping | Weekly |
| `DIA` | Defense Intelligence Agency | HTML scraping | Monthly |
| `State_Dept` | U.S. Department of State | RSS + HTML scraping | Monthly |
| `NASA` | NASA OIG + NTRS | HTML scraping / JSON API | Monthly |

---

## Architecture

```
connector-ic-reports/
├── Dockerfile
├── docker-compose.yml
├── config.yml.template         ← Copy to config.yml and populate
├── requirements.txt
├── ADDING_A_PLUGIN.md          ← Guide for implementing new source plugins
└── src/
    ├── main.py                 ← Entry point
    ├── connector.py            ← OpenCTI handshake, scheduler, orchestration
    ├── base_plugin.py          ← Abstract base class for all plugins
    ├── report_builder.py       ← OpenCTI API calls: identity, report, PDF attachment
    ├── http_client.py          ← Shared HTTP session with retry + rate limiting
    └── plugins/
        ├── __init__.py         ← Plugin registry / autodiscovery
        ├── cisa.py
        ├── odni.py
        ├── cia.py
        ├── nsa.py
        ├── dia.py
        ├── state_dept.py
        └── nasa.py
```

### Data flow

```
Scheduler
   └─► Plugin.fetch_new_reports()    ← Discovery (RSS / scrape / API)
         └─► Plugin.enrich_report()  ← Content retrieval (PDF download)
               └─► ReportBuilder.ingest()
                     ├── Resolve author Identity (lookup or create)
                     ├── Dedup check (External Reference URL)
                     ├── Create Report container
                     ├── Attach External Reference
                     └── Attach PDF (triggers workbench for analyst)
```

---

## Ingestion Model

This connector operates in **Report-only mode** per the CTI Ingestion Manual:

- Creates `Report` containers with `status: Draft`
- Attaches source PDF (triggers OpenCTI workbench for analyst review)
- Creates `External Reference` pointing to the canonical source URL
- Sets `Author` to the publishing organization, not the connector
- Sets `Published` to the source publication date, never the ingestion timestamp
- **Never creates**: Indicators, Observables, Threat Actors, or any other entities
- **Never overwrites** existing reports (idempotent by External Reference URL)

Entity extraction is the analyst's responsibility, consistent with the Four Cs
principle (Containment → Contextualization → Completeness → Categorization).

---

## Deployment

### Prerequisites

- OpenCTI 6.9.13+
- Docker and Docker Compose
- Network access to `.gov` and `.mil` domains from the connector host
- A dedicated OpenCTI connector token (not the admin token)

### 1. Configure

```bash
cp config.yml.template config.yml
```

Edit `config.yml`:
- Set `opencti.url` and `opencti.token`
- Enable/disable plugins as needed
- Set `max_per_run` per plugin (start conservative on first run)

### 2. Create a connector token in OpenCTI

`Settings → Connectors → Create connector` — type: External Import.
Copy the generated token into `config.yml` or inject as `OPENCTI_TOKEN`.

### 3. Build and deploy

```bash
# Build image
docker compose build

# First run (dry-run check — watch logs for errors before leaving unattended)
docker compose up

# Background deployment
docker compose up -d

# Follow logs
docker compose logs -f connector-ic-reports
```

### 4. First run behaviour

On the first run, each plugin will discover all available reports on its
listing pages. Use `max_per_run` in config to throttle ingestion volume.
Recommended first-run limits:

| Plugin | Recommended first max_per_run |
|---|---|
| CISA | 20 (high volume, structured) |
| ODNI | 5 (very low publication rate) |
| CIA | 5 (scope carefully) |
| NSA | 10 |
| DIA | 5 |
| State_Dept | 5 |
| NASA | 5 (OIG only) |

After the first run, increase limits as desired. The dedup mechanism (External
Reference URL) prevents re-ingestion of already-processed reports.

---

## Adding a New Source Plugin

See `ADDING_A_PLUGIN.md` for full implementation guide.

Short version:
1. Create `src/plugins/your_source.py` implementing `BasePlugin`
2. Add module name to `PLUGIN_MODULES` in `src/plugins/__init__.py`
3. Add config block under `plugins:` in `config.yml`

---

## Connector Token Reference

Your environment uses the following tokens (from project config):

```
OPENCTI_BASE_URL=http://localhost:8080
OPENCTI_TOKEN=0c5369df-3dae-42f9-8252-aab647737388
```

Use `OPENCTI_TOKEN` (not the admin token) as the connector token, or create a
dedicated connector identity in OpenCTI for cleaner audit trails.

---

## Known Limitations

| Issue | Mitigation |
|---|---|
| .gov sites occasionally block scraping | Rate limiting + browser-like UA headers |
| ODNI/DIA HTML structure may change | Log warnings; report structure changes in issues |
| CIA FOIA search returns stale results | Use specific `foia_search_terms` |
| NSA listing page structure varies | Fallback scraper catches most patterns |
| NASA NTRS disabled by default | Enable with tight `ntrs_search_terms` |

---

## Compliance Notes

- All reports ingested as `TLP:WHITE` unless source indicates otherwise
- No data is ever deleted from OpenCTI by this connector
- Connector is non-destructive and idempotent by design
- State is persisted via OpenCTI's native state API (not local filesystem)
