"""Entry point for the ThreatFox OpenCTI connector."""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="ThreatFox OpenCTI Connector")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--input", type=str)
    parser.add_argument("--output", type=str)
    parser.add_argument("--log-level", type=str, default="info",
                        choices=["debug", "info", "warning", "error"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.dry_run or args.input:
        _run_dry(args)
    else:
        _run_connector()


def _run_dry(args):
    from .mitre_lookup import MitreLookup
    from .stix_converter import StixConverter
    from .threatfox_client import ThreatFoxClient

    mitre = MitreLookup()
    converter = StixConverter(mitre)
    ioc_data = ThreatFoxClient.load_from_file(args.input) if args.input else ThreatFoxClient().get_iocs()

    if not ioc_data:
        print("No IOC data to process.")
        return

    print(f"Processing {len(ioc_data)} IOC entries...")
    stix_objects = converter.convert(ioc_data)

    type_counts = Counter(obj["type"] for obj in stix_objects)
    print(f"\nGenerated {len(stix_objects)} STIX 2.1 objects:")
    for obj_type, count in sorted(type_counts.items()):
        print(f"  {obj_type}: {count}")

    if args.output:
        bundle = {"type": "bundle", "id": "bundle--dry-run", "objects": stix_objects}
        with open(Path(args.output), "w") as f:
            json.dump(bundle, f, indent=2)
        print(f"\nSTIX bundle written to {args.output}")


def _run_connector():
    from .connector import ThreatFoxConnector
    ThreatFoxConnector().run()


if __name__ == "__main__":
    main()
