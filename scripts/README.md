# scripts/

One-off maintenance and migration scripts that operate against the live OpenCTI
API. These are **not** connectors — they are run by hand, against a persistent
graph, and every one defaults to a non-destructive dry run.

## migrate_report_author_type.py

Generic backfill tool that brings already-ingested **Report containers** in line
with a connector's current convention:

| Field          | Before          | After                            |
|----------------|-----------------|----------------------------------|
| `report_types` | (any)           | `--report-type` (default `observable-feed`) |
| `created_by`   | `--old-author`  | `--new-author`                   |

Connector-agnostic: point it at any feed via `--old-author` / `--new-author` /
`--name-prefix`.

Properties:

- **Dry-run by default.** Prints the plan and exits. `--apply` performs writes.
- **Idempotent.** Reports already at the target state are skipped.
- **Non-destructive.** Edits two fields on Report SDOs only. Creates no
  relationships, deletes nothing, and leaves the old author identity in place
  (orphaned, not removed).
- **Auditable / reversible.** In `--apply` mode it writes a JSONL journal of the
  prior `(report_types, created_by)` of every report it changes, before changing
  it, so the operation can be reconstructed or reverted.
- **Targeted.** Selects reports by authoring identity (old or new author), then
  applies the `--name-prefix` guard so it cannot touch unrelated reports.
- **Reports only.** Observables and other SDOs authored by `--old-author` are
  **not** re-authored (see "Scope" below).

### Environment

| Variable                          | Purpose                                              |
|-----------------------------------|-----------------------------------------------------|
| `OPENCTI_URL` or `OPENCTI_BASE_URL` | OpenCTI base URL. On the Docker network this is usually `http://opencti:8080`. Both names are accepted because the repo-wide URL/BASE_URL naming is still an open decision. |
| `OPENCTI_TOKEN`                   | API token with write access.                        |

### Invocations

**ThreatFox** (`[C]ThreatFox` → `ThreatFox`):

```
python migrate_report_author_type.py \
  --old-author "[C]ThreatFox" --new-author "ThreatFox" \
  --name-prefix "Threat Fox Feed"
```

**URLHaus** (`abuse.ch` → `URLHaus`):

```
python migrate_report_author_type.py \
  --old-author "abuse.ch" --new-author "URLHaus" \
  --name-prefix "URLHaus Feed"
```

Both default `--report-type` to `observable-feed`. Add `--apply` to write.

> URLHaus note: `abuse.ch` may author reports for more than one abuse.ch feed,
> so the `--name-prefix "URLHaus Feed"` guard is what scopes the run to URLHaus.
> Keep it.

### Running inside the OpenCTI Docker network

The script needs network reachability to the `opencti` service and a token. The
simplest self-contained way is a throwaway `python:3.11-slim` container attached
to the OpenCTI compose network, with `scripts/` mounted in.

First find the network name:

```bash
docker network ls | grep opencti
```

**Dry run first** (always) — URLHaus example:

```bash
docker run --rm -it \
  --network <opencti_network> \
  -e OPENCTI_URL="http://opencti:8080" \
  -e OPENCTI_TOKEN="<token>" \
  -v "$(pwd)/scripts:/scripts" \
  python:3.11-slim \
  sh -c "pip install -q -r /scripts/requirements.txt && \
         python /scripts/migrate_report_author_type.py \
           --old-author 'abuse.ch' --new-author 'URLHaus' \
           --name-prefix 'URLHaus Feed'"
```

Review the planned changes, then **apply** by appending `--apply` to the
`python` command. The journal is written into the mounted `scripts/` directory
(override with `--journal /scripts/<name>.jsonl`). Keep it until you have
confirmed the migration.

### Scope: reports only

This script fixes **existing Report containers**. It does not re-author
observables or other SDOs, and it does not change connector behavior. After
running it:

- The connector must also be updated/redeployed so **new** reports use the new
  author and type (ThreatFox and URLHaus connectors already are).
- Connectors that stamp `created_by` on every object (e.g. URLHaus) will leave
  pre-existing observables authored by the old identity. Remapping those is a
  larger, separate operation not covered here.
