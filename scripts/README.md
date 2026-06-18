# scripts/

One-off maintenance and migration scripts that operate against the live OpenCTI
API. These are **not** connectors — they are run by hand, against a persistent
graph, and every one defaults to a non-destructive dry run.

## migrate_threatfox_reports.py

Brings already-ingested ThreatFox Report containers in line with the current
connector convention:

| Field          | Before          | After               |
|----------------|-----------------|---------------------|
| `report_types` | (any)           | `["observable-feed"]` |
| `created_by`   | `[C]ThreatFox`  | `ThreatFox`         |

Properties:

- **Dry-run by default.** Prints the plan and exits. `--apply` performs writes.
- **Idempotent.** Reports already at the target state are skipped.
- **Non-destructive.** Edits two fields on Report SDOs only. Creates no
  relationships, deletes nothing, and leaves the old `[C]ThreatFox` identity in
  place (orphaned, not removed).
- **Auditable / reversible.** In `--apply` mode it writes a JSONL journal of the
  prior `(report_types, created_by)` of every report it changes, before changing
  it, so the operation can be reconstructed or reverted.
- **Targeted.** Selects reports by authoring identity (old or new author), then
  applies a name-prefix guard (`Threat Fox Feed`) so it cannot touch unrelated
  reports.

### Environment

| Variable                          | Purpose                                              |
|-----------------------------------|-----------------------------------------------------|
| `OPENCTI_URL` or `OPENCTI_BASE_URL` | OpenCTI base URL. On the Docker network this is usually `http://opencti:8080`. Both names are accepted because the repo-wide URL/BASE_URL naming is still an open decision. |
| `OPENCTI_TOKEN`                   | API token with write access.                        |

### Running inside the OpenCTI Docker network

The script needs network reachability to the `opencti` service and a token. The
simplest self-contained way is a throwaway `python:3.11-slim` container attached
to the OpenCTI compose network, with `scripts/` mounted in.

First find the network name:

```bash
docker network ls | grep opencti
```

**Dry run first** (always):

```bash
docker run --rm -it \
  --network <opencti_network> \
  -e OPENCTI_URL="http://opencti:8080" \
  -e OPENCTI_TOKEN="<token>" \
  -v "$(pwd)/scripts:/scripts" \
  python:3.11-slim \
  sh -c "pip install -q -r /scripts/requirements.txt && python /scripts/migrate_threatfox_reports.py"
```

Review the planned changes, then **apply**:

```bash
docker run --rm -it \
  --network <opencti_network> \
  -e OPENCTI_URL="http://opencti:8080" \
  -e OPENCTI_TOKEN="<token>" \
  -v "$(pwd)/scripts:/scripts" \
  python:3.11-slim \
  sh -c "pip install -q -r /scripts/requirements.txt && python /scripts/migrate_threatfox_reports.py --apply"
```

The journal is written into the mounted `scripts/` directory (override with
`--journal /scripts/<name>.jsonl`). Keep it until you have confirmed the
migration.

### Note on new reports

This script only fixes **existing** reports. The running connector still authors
new daily reports as `[C]ThreatFox` (see `connectors/threatfox/src/config.py`).
If the `ThreatFox` author is meant to be permanent, the connector identity must
be changed too — otherwise new reports will reintroduce `[C]ThreatFox`.
