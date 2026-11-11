#!/usr/bin/env python3
"""Wire Crucible Collector classification into docker-compose.override.yml.

For each named service this script ensures, in the override file:
  - environment: CRUCIBLE_COLLECTOR_URL=<url>  (and CRUCIBLE_CLASSIFY_TIMEOUT
    when --timeout is given)
  - volumes:     <microservices-path>:/microservices:ro

Properties (same conventions as the other scripts/ tools):
  - Dry run by default: prints the planned changes and writes nothing.
    --apply writes the file, after saving a timestamped .bak copy.
  - Round-trip YAML (ruamel.yaml): the file is parsed and re-emitted, never
    edited by string substitution. Comments and key order are kept;
    indentation is normalised to one consistent style.
  - Idempotent: services already wired are reported as unchanged.
  - Non-destructive: only the two keys above are added or updated. A service
    missing from the file is reported and skipped (add its stanza first).

Both environment forms are handled (list "KEY=value" or mapping KEY: value).
An existing volume that already targets /microservices is replaced.

After --apply, validate with:  docker compose config -q

Usage example (on the OpenCTI VM):
  python3 wire_crucible_classify.py \\
      --file docker-compose.override.yml \\
      --collector-url http://<collector-host>:8004 \\
      --microservices-path ./connectors/microservices \\
      --services bleepingcomputer the-hacker-news security-affairs \\
      --apply
"""

import argparse
import shutil
import sys
import time
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

MOUNT_TARGET = "/microservices"


# --------------------------------------------------------------------------- #
# Environment block helpers
# --------------------------------------------------------------------------- #

def _set_env(service, key, value):
    """Set KEY=value in a service's environment. Returns a change string or None."""
    env = service.get("environment")
    # No environment yet: create it in list form.
    if env is None:
        service["environment"] = CommentedSeq([f"{key}={value}"])
        return f"add env {key}={value}"
    # Mapping form: KEY: value.
    if isinstance(env, dict):
        if str(env.get(key, "")) == value:
            return None
        old = env.get(key)
        env[key] = value
        return f"set env {key}={value}" + (f" (was {old})" if old is not None else "")
    # List form: "KEY=value" strings.
    for i, entry in enumerate(env):
        name = str(entry).split("=", 1)[0].strip()
        if name == key:
            if str(entry) == f"{key}={value}":
                return None
            env[i] = f"{key}={value}"
            return f"set env {key}={value} (was {entry})"
    env.append(f"{key}={value}")
    return f"add env {key}={value}"


# --------------------------------------------------------------------------- #
# Volume helpers
# --------------------------------------------------------------------------- #

def _target_of(volume):
    """Return the container path of a short- or long-form volume entry."""
    if isinstance(volume, dict):
        return str(volume.get("target", ""))
    parts = str(volume).split(":")
    return parts[1] if len(parts) > 1 else parts[0]


def _set_mount(service, source):
    """Ensure <source>:/microservices:ro is mounted. Returns a change string or None."""
    wanted = f"{source}:{MOUNT_TARGET}:ro"
    volumes = service.get("volumes")
    # No volumes yet: create the list.
    if volumes is None:
        service["volumes"] = CommentedSeq([wanted])
        return f"add volume {wanted}"
    # Replace any existing mount that targets /microservices.
    for i, vol in enumerate(volumes):
        if _target_of(vol) == MOUNT_TARGET:
            if str(vol) == wanted:
                return None
            volumes[i] = wanted
            return f"set volume {wanted} (was {vol})"
    volumes.append(wanted)
    return f"add volume {wanted}"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--file", default="docker-compose.override.yml")
    parser.add_argument("--collector-url", required=True)
    parser.add_argument("--microservices-path", required=True,
                        help="host path of connectors/microservices, as compose sees it")
    parser.add_argument("--timeout", help="optional CRUCIBLE_CLASSIFY_TIMEOUT seconds")
    parser.add_argument("--services", nargs="+", required=True)
    parser.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = parser.parse_args(argv)

    # Round-trip load: comments, ordering and quoting preserved.
    path = Path(args.file)
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    yaml.indent(mapping=2, sequence=4, offset=2)
    with path.open(encoding="utf-8") as fh:
        doc = yaml.load(fh)

    services = (doc or {}).get("services")
    if not isinstance(services, CommentedMap):
        print(f"ERROR: {path} has no 'services' mapping", file=sys.stderr)
        return 2

    # Plan (and in --apply mode, make) the per-service changes.
    changed = missing = 0
    for name in args.services:
        service = services.get(name)
        if service is None:
            print(f"[{name}] MISSING from {path}; add its service stanza first. Skipped.")
            missing += 1
            continue
        if not isinstance(service, dict):
            print(f"[{name}] is not a mapping; skipped.")
            missing += 1
            continue
        edits = [
            _set_env(service, "CRUCIBLE_COLLECTOR_URL", args.collector_url.rstrip("/")),
            _set_mount(service, args.microservices_path),
        ]
        if args.timeout:
            edits.append(_set_env(service, "CRUCIBLE_CLASSIFY_TIMEOUT", str(args.timeout)))
        edits = [e for e in edits if e]
        if edits:
            changed += 1
            for edit in edits:
                print(f"[{name}] {edit}")
        else:
            print(f"[{name}] already wired; unchanged.")

    # Dry run stops here.
    if not args.apply:
        print(f"\nDRY RUN: {changed} service(s) would change, {missing} missing. "
              f"Re-run with --apply to write.")
        return 1 if missing else 0

    # Apply: back up, then write the round-tripped document.
    if changed:
        backup = path.with_name(f"{path.name}.bak.{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
        with path.open("w", encoding="utf-8") as fh:
            yaml.dump(doc, fh)
        print(f"\nWrote {path} ({changed} service(s) changed). Backup: {backup}")
    else:
        print("\nNothing to change.")
    print("Validate with: docker compose config -q")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
