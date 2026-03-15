"""Fetch MITRE ATT&CK enterprise data and build the software lookup cache.

Usage:
    python3 build_mitre_cache.py

Writes: data/mitre_attack_software.json
"""

import json
import urllib.request
from pathlib import Path

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

OUTPUT_PATH = Path(__file__).parent / "data" / "mitre_attack_software.json"


def build_cache():
    print("Fetching MITRE ATT&CK enterprise data...")
    with urllib.request.urlopen(MITRE_URL, timeout=60) as resp:
        bundle = json.loads(resp.read())

    lookup: dict = {}

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type")
        if obj_type not in ("malware", "tool"):
            continue

        name = obj.get("name", "").strip()
        if not name:
            continue

        # Get S-number from external_references
        external_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                break

        if not external_id:
            continue

        entry = {"name": name, "external_id": external_id, "type": obj_type}

        # Index by lowercase name
        lookup[name.lower()] = entry
        # Index without spaces
        nospace = name.lower().replace(" ", "")
        if nospace != name.lower():
            lookup[nospace] = entry

        # Index all aliases
        for alias in obj.get("aliases", []):
            alias = alias.strip()
            if alias and alias.lower() != name.lower():
                lookup[alias.lower()] = entry
                nospace_alias = alias.lower().replace(" ", "")
                if nospace_alias != alias.lower():
                    lookup[nospace_alias] = entry

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(lookup, f, indent=2, sort_keys=True)

    print(f"Written {len(lookup)} entries to {OUTPUT_PATH}")


if __name__ == "__main__":
    build_cache()
