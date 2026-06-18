#!/usr/bin/env python3
"""Backfill migration: retype and re-author existing ThreatFox Report containers.

Brings already-ingested ThreatFox Report containers in line with the current
connector convention:

  * report_types : <whatever>      ->  ["observable-feed"]
  * created_by   : "[C]ThreatFox"  ->  "ThreatFox"

This script mutates existing data in the OpenCTI knowledge graph. It is built to
be safe to run against a persistent, long-lived graph:

  * Dry-run by default       -- prints the planned changes and exits without
                                writing. Pass --apply to perform the mutation.
  * Idempotent               -- a report already at the target state is skipped;
                                re-running changes nothing.
  * Non-destructive          -- it edits only two fields on Report SDOs. It
                                creates no relationships, deletes nothing, and
                                never touches the old "[C]ThreatFox" identity
                                (left orphaned, not removed).
  * Auditable / reversible   -- in --apply mode it writes a JSONL journal of
                                each report's prior (report_types, created_by)
                                BEFORE the change, so the operation can be
                                reconstructed or reverted.

Selection
---------
Reports are selected by their authoring identity, not by free-text name: every
Report whose created_by is the old author ("[C]ThreatFox", the migration
source) or already the new author ("ThreatFox", so re-runs can still fix the
type). A name-prefix guard (default "Threat Fox Feed") is then applied
in-process as a second safety filter, so the script cannot touch a same-authored
report that is not part of the ThreatFox feed.

Environment
-----------
  OPENCTI_URL or OPENCTI_BASE_URL   OpenCTI base URL. The ThreatFox connector
                                    uses OPENCTI_URL; both names are accepted
                                    here because the repo-wide URL/BASE_URL
                                    naming is an open cross-connector decision
                                    and this script does not silently force one.
                                    When run inside the OpenCTI Docker network
                                    this is typically http://opencti:8080.
  OPENCTI_TOKEN                     API token with write access.

See scripts/README.md for how to run this inside the OpenCTI Docker network.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    from pycti import OpenCTIApiClient
except ImportError:  # pragma: no cover - environment guard
    sys.stderr.write(
        "pycti is not installed. Install the pinned version with:\n"
        "    pip install pycti==6.9.13\n"
    )
    raise


# Fields requested per report so we can decide and journal without extra calls.
REPORT_ATTRS = """
    id
    standard_id
    name
    report_types
    createdBy {
        ... on Identity {
            id
            standard_id
            name
            entity_type
        }
    }
"""


def resolve_url() -> str:
    """Return the OpenCTI URL, accepting either env var name (no silent default)."""
    url = os.environ.get("OPENCTI_URL") or os.environ.get("OPENCTI_BASE_URL")
    if not url:
        sys.exit(
            "ERROR: set OPENCTI_URL (or OPENCTI_BASE_URL). "
            "Inside the Docker network this is usually http://opencti:8080"
        )
    return url


def identity_filter(name: str) -> dict:
    """Match an Organization identity by exact name (mirrors the connector)."""
    return {
        "mode": "and",
        "filters": [
            {"key": "name", "values": [name], "operator": "eq", "mode": "or"},
            {"key": "entity_type", "values": ["Organization"], "operator": "eq",
             "mode": "or"},
        ],
        "filterGroups": [],
    }


def resolve_identity(client: OpenCTIApiClient, name: str) -> dict | None:
    """Return the first Organization identity with this exact name, or None."""
    matches = client.identity.list(filters=identity_filter(name), first=1)
    if isinstance(matches, list) and matches:
        return matches[0]
    return None


def ensure_new_identity(client: OpenCTIApiClient, name: str, apply: bool) -> dict | None:
    """Resolve the target author identity, creating it (apply mode only) if absent."""
    existing = resolve_identity(client, name)
    if existing:
        print(f"  target author '{name}' resolved: {existing['id']}")
        return existing
    if not apply:
        print(f"  target author '{name}' does NOT exist yet -- would be created on --apply")
        return None
    created = client.identity.create(
        type="Organization",
        name=name,
        description=(
            "ThreatFox (abuse.ch) feed source. Authoring identity for ThreatFox "
            "observable-feed report containers."
        ),
    )
    if not (created and created.get("id")):
        sys.exit(f"ERROR: failed to create target author identity '{name}'")
    print(f"  target author '{name}' created: {created['id']}")
    return created


def collect_reports(client: OpenCTIApiClient, author_ids: list[str],
                    name_prefix: str, batch: int) -> dict[str, dict]:
    """Return {report_id: report} for reports authored by any of author_ids,
    restricted to those whose name starts with name_prefix."""
    found: dict[str, dict] = {}
    for author_id in author_ids:
        flt = {
            "mode": "and",
            "filters": [
                {"key": "createdBy", "values": [author_id], "operator": "eq",
                 "mode": "or"},
            ],
            "filterGroups": [],
        }
        cursor = None
        while True:
            page = client.report.list(
                filters=flt,
                first=batch,
                after=cursor,
                customAttributes=REPORT_ATTRS,
                withPagination=True,
            )
            entities = page.get("entities", []) if isinstance(page, dict) else []
            for rep in entities:
                name = rep.get("name") or ""
                if name_prefix and not name.startswith(name_prefix):
                    continue
                found[rep["id"]] = rep
            pagination = page.get("pagination", {}) if isinstance(page, dict) else {}
            if not pagination.get("hasNextPage"):
                break
            cursor = pagination.get("endCursor")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Retype and re-author existing ThreatFox Report containers.",
    )
    parser.add_argument("--apply", action="store_true",
                        help="Perform the mutation. Without this flag the script is a dry run.")
    parser.add_argument("--report-type", default="observable-feed",
                        help="Target report_types value (default: observable-feed).")
    parser.add_argument("--old-author", default="[C]ThreatFox",
                        help="Current author identity name (default: [C]ThreatFox).")
    parser.add_argument("--new-author", default="ThreatFox",
                        help="Target author identity name (default: ThreatFox).")
    parser.add_argument("--name-prefix", default="Threat Fox Feed",
                        help="Only touch reports whose name starts with this "
                             "(safety guard; default: 'Threat Fox Feed').")
    parser.add_argument("--batch-size", type=int, default=100,
                        help="Reports per API page (default: 100).")
    parser.add_argument("--journal",
                        help="Path to the before-state JSONL journal written in "
                             "--apply mode (default: timestamped file in cwd).")
    args = parser.parse_args()

    mode = "APPLY" if args.apply else "DRY-RUN"
    url = resolve_url()
    token = os.environ.get("OPENCTI_TOKEN")
    if not token:
        sys.exit("ERROR: set OPENCTI_TOKEN")

    print(f"== ThreatFox report migration ({mode}) ==")
    print(f"  OpenCTI         : {url}")
    print(f"  report_types -> : [{args.report_type!r}]")
    print(f"  author       -> : {args.old_author!r} => {args.new_author!r}")
    print(f"  name guard      : startswith {args.name_prefix!r}")

    client = OpenCTIApiClient(url, token)

    # Resolve authors. Old may be absent (already migrated / fresh env).
    old_identity = resolve_identity(client, args.old_author)
    if old_identity:
        print(f"  source author '{args.old_author}' resolved: {old_identity['id']}")
    else:
        print(f"  source author '{args.old_author}' not found (nothing under it).")
    new_identity = ensure_new_identity(client, args.new_author, args.apply)

    # In apply mode we must have a concrete target identity to set createdBy.
    if args.apply and not new_identity:
        sys.exit("ERROR: target author identity unavailable; aborting before mutation.")

    new_author_id = new_identity["id"] if new_identity else None

    author_ids = [i["id"] for i in (old_identity, new_identity) if i]
    if not author_ids:
        print("Nothing to do: neither author identity exists.")
        return 0

    reports = collect_reports(client, author_ids, args.name_prefix, args.batch_size)
    print(f"  candidate reports: {len(reports)}")

    journal_fh = None
    if args.apply:
        journal_path = args.journal or (
            f"threatfox_migration_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.jsonl"
        )
        journal_fh = open(journal_path, "a", encoding="utf-8")
        print(f"  journal         : {journal_path}")

    target_types = [args.report_type]
    counts = {"skipped": 0, "type": 0, "author": 0, "both": 0, "errors": 0}

    try:
        for rep in reports.values():
            rid = rep["id"]
            name = rep.get("name") or rid
            cur_types = rep.get("report_types") or []
            cur_author = (rep.get("createdBy") or {}).get("name")

            needs_type = cur_types != target_types
            needs_author = cur_author != args.new_author
            if not (needs_type or needs_author):
                counts["skipped"] += 1
                continue

            change = "both" if needs_type and needs_author else (
                "type" if needs_type else "author")
            counts[change] += 1
            print(f"  [{change}] {name}: types {cur_types} -> {target_types}; "
                  f"author {cur_author!r} -> {args.new_author!r}")

            if not args.apply:
                continue

            # Audit BEFORE mutating, so the journal is a true rollback source.
            journal_fh.write(json.dumps({
                "id": rid,
                "standard_id": rep.get("standard_id"),
                "name": rep.get("name"),
                "prev_report_types": cur_types,
                "prev_created_by": rep.get("createdBy"),
            }) + "\n")
            journal_fh.flush()

            try:
                if needs_type:
                    client.stix_domain_object.update_field(
                        id=rid,
                        input=[{"key": "report_types", "value": target_types,
                                "operation": "replace"}],
                    )
                if needs_author:
                    client.stix_domain_object.update_field(
                        id=rid,
                        input=[{"key": "createdBy", "value": [new_author_id],
                                "operation": "replace"}],
                    )
            except Exception as exc:  # keep going; one bad report shouldn't abort all
                counts["errors"] += 1
                counts[change] -= 1
                print(f"      ERROR updating {rid}: {exc}", file=sys.stderr)
    finally:
        if journal_fh:
            journal_fh.close()

    print("== summary ==")
    print(f"  type-only changes : {counts['type']}")
    print(f"  author-only changes: {counts['author']}")
    print(f"  type+author changes: {counts['both']}")
    print(f"  already-correct    : {counts['skipped']}")
    print(f"  errors             : {counts['errors']}")
    if not args.apply:
        print("DRY-RUN: no changes written. Re-run with --apply to perform them.")
    return 1 if counts["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
