#!/usr/bin/env python3
"""
OpenCTI Platform Integrity Diagnostic — Domain 2
Checks: orphaned entities, orphaned observables, duplicate reports, stale connectors
"""

import requests
import json
from collections import defaultdict

OPENCTI_URL = "http://localhost:8080"
TOKEN = "8924b218-b275-4077-bd7a-cea6537d7bfb"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
SEP = "=" * 80

def gql(query, variables=None):
    r = requests.post(
        f"{OPENCTI_URL}/graphql",
        headers=HEADERS,
        json={"query": query, "variables": variables or {}},
        timeout=60
    )
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise Exception(f"GraphQL errors: {data['errors']}")
    return data["data"]

def section(title):
    print(f"\n{SEP}\n## {title}\n{SEP}")

# ── 2.1 Orphaned SDOs ─────────────────────────────────────────────────────────
section("2.1 — Orphaned SDOs (entities with no container membership)")

SDO_TYPES = [
    "Threat-Actor", "Intrusion-Set", "Campaign", "Malware", "Tool",
    "Attack-Pattern", "Vulnerability", "Infrastructure", "Channel",
    "Narrative", "Course-Of-Action", "Data-Source", "Data-Component"
]

ORPHAN_QUERY = """
query OrphanCheck($type: String!, $after: ID) {
  stixDomainObjects(
    first: 500
    after: $after
    filters: {
      mode: and
      filters: [
        { key: "entity_type", values: [$type] }
        { key: "containers", values: [], operator: nil }
      ]
      filterGroups: []
    }
  ) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        entity_type
        ... on StixDomainObject { created_at }
        ... on ThreatActorGroup { name }
        ... on IntrusionSet { name }
        ... on Campaign { name }
        ... on Malware { name }
        ... on Tool { name }
        ... on AttackPattern { name }
        ... on Vulnerability { name }
        ... on Infrastructure { name }
        ... on Channel { name }
        ... on Narrative { name }
        ... on CourseOfAction { name }
      }
    }
  }
}
"""

orphan_sdo_total = 0
orphan_sdo_by_type = defaultdict(list)

for sdo_type in SDO_TYPES:
    after = None
    while True:
        try:
            data = gql(ORPHAN_QUERY, {"type": sdo_type, "after": after})
            edges = data["stixDomainObjects"]["edges"]
            page_info = data["stixDomainObjects"]["pageInfo"]
            for e in edges:
                node = e["node"]
                name = node.get("name", node.get("id", "unknown"))
                orphan_sdo_by_type[sdo_type].append({
                    "id": node["id"],
                    "name": name,
                    "created_at": node.get("created_at", "")
                })
                orphan_sdo_total += 1
            if not page_info["hasNextPage"]:
                break
            after = page_info["endCursor"]
        except Exception as ex:
            print(f"  WARN: Could not query {sdo_type}: {ex}")
            break

if orphan_sdo_total == 0:
    print("✓ No orphaned SDOs found.")
else:
    print(f"⚠ {orphan_sdo_total} orphaned SDOs found:\n")
    for t, items in orphan_sdo_by_type.items():
        if items:
            print(f"  {t} ({len(items)}):")
            for item in items[:10]:
                print(f"    - {item['name'][:80]} | created: {item['created_at'][:10]} | {item['id']}")
            if len(items) > 10:
                print(f"    ... and {len(items) - 10} more")

# ── 2.2 Orphaned Observables ──────────────────────────────────────────────────
section("2.2 — Orphaned Observables (SCOs with no container membership)")

ORPHAN_OBS_QUERY = """
query OrphanObservables($after: ID) {
  stixCyberObservables(
    first: 500
    after: $after
    filters: {
      mode: and
      filters: [
        { key: "containers", values: [], operator: nil }
      ]
      filterGroups: []
    }
  ) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        entity_type
        created_at
        observable_value
      }
    }
  }
}
"""

orphan_obs_total = 0
orphan_obs_by_type = defaultdict(list)
after = None

while True:
    try:
        data = gql(ORPHAN_OBS_QUERY, {"after": after})
        edges = data["stixCyberObservables"]["edges"]
        page_info = data["stixCyberObservables"]["pageInfo"]
        for e in edges:
            node = e["node"]
            orphan_obs_by_type[node["entity_type"]].append({
                "id": node["id"],
                "value": node.get("observable_value", "")[:60],
                "created_at": node.get("created_at", "")
            })
            orphan_obs_total += 1
        if not page_info["hasNextPage"]:
            break
        after = page_info["endCursor"]
    except Exception as ex:
        print(f"  WARN: Observable orphan query failed: {ex}")
        break

if orphan_obs_total == 0:
    print("✓ No orphaned Observables found.")
else:
    print(f"⚠ {orphan_obs_total} orphaned Observables found:\n")
    for t, items in sorted(orphan_obs_by_type.items(), key=lambda x: -len(x[1])):
        print(f"  {t} ({len(items)}):")
        for item in items[:5]:
            print(f"    - {item['value'][:60]} | created: {item['created_at'][:10]}")
        if len(items) > 5:
            print(f"    ... and {len(items) - 5} more")

# ── 2.3 Duplicate Reports ─────────────────────────────────────────────────────
section("2.3 — Duplicate Report Containers (same name or external reference)")

DUP_QUERY = """
query DuplicateReports($after: ID) {
  reports(
    first: 500
    after: $after
    orderBy: name
    orderMode: asc
  ) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        name
        created_at
        published
        externalReferences {
          edges { node { url } }
        }
      }
    }
  }
}
"""

all_reports = []
after = None

while True:
    try:
        data = gql(DUP_QUERY, {"after": after})
        edges = data["reports"]["edges"]
        page_info = data["reports"]["pageInfo"]
        for e in edges:
            node = e["node"]
            urls = [ref["node"]["url"] for ref in node.get("externalReferences", {}).get("edges", [])]
            all_reports.append({
                "id": node["id"],
                "name": node["name"],
                "created_at": node.get("created_at", "")[:10],
                "published": node.get("published", "")[:10],
                "urls": urls
            })
        if not page_info["hasNextPage"]:
            break
        after = page_info["endCursor"]
    except Exception as ex:
        print(f"  WARN: Report query failed: {ex}")
        break

print(f"  Total reports scanned: {len(all_reports)}")

# Check duplicate names
name_map = defaultdict(list)
for r in all_reports:
    name_map[r["name"].strip().lower()].append(r)

dup_names = {k: v for k, v in name_map.items() if len(v) > 1}

# Check duplicate URLs
url_map = defaultdict(list)
for r in all_reports:
    for url in r["urls"]:
        if url:
            url_map[url.strip()].append(r)

dup_urls = {k: v for k, v in url_map.items() if len(v) > 1}

if not dup_names and not dup_urls:
    print("✓ No duplicate Report containers found.")
else:
    if dup_names:
        print(f"\n⚠ {len(dup_names)} duplicate Report names:\n")
        for name, reports in list(dup_names.items())[:20]:
            print(f"  \"{name[:70]}\"")
            for r in reports:
                print(f"    - {r['id']} | published: {r['published']} | created: {r['created_at']}")
    if dup_urls:
        print(f"\n⚠ {len(dup_urls)} duplicate External Reference URLs:\n")
        for url, reports in list(dup_urls.items())[:20]:
            print(f"  {url[:80]}")
            for r in reports:
                print(f"    - \"{r['name'][:60]}\" | {r['id']}")

# ── 2.4 Stale Connector Registrations ────────────────────────────────────────
section("2.4 — Stale Connector Registrations (registered in OpenCTI but not running)")

CONNECTOR_QUERY = """
query Connectors {
  connectors {
    id
    name
    connector_type
    active
    updated_at
    connector_state
  }
}
"""

try:
    data = gql(CONNECTOR_QUERY)
    connectors = data["connectors"]
    print(f"  Total registered connectors: {len(connectors)}\n")

    active = [c for c in connectors if c["active"]]
    inactive = [c for c in connectors if not c["active"]]

    print(f"  Active (heartbeat current): {len(active)}")
    for c in sorted(active, key=lambda x: x["name"]):
        print(f"    ✓ {c['name']:<45} {c['connector_type']:<25} updated: {c['updated_at'][:10]}")

    if inactive:
        print(f"\n  Inactive (no heartbeat): {len(inactive)}")
        for c in sorted(inactive, key=lambda x: x["name"]):
            print(f"    ✗ {c['name']:<45} {c['connector_type']:<25} last seen: {c['updated_at'][:10]}")
    else:
        print(f"\n  ✓ No inactive connector registrations found.")

except Exception as ex:
    print(f"  WARN: Connector query failed: {ex}")

# ── 2.5 Container Metadata Completeness ──────────────────────────────────────
section("2.5 — Report Container Metadata Completeness")

META_QUERY = """
query ReportMeta($after: ID) {
  reports(first: 500 after: $after) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        name
        published
        createdBy { id name }
        objectMarking { id definition }
        externalReferences { edges { node { url } } }
        confidence
      }
    }
  }
}
"""

missing_author = []
missing_marking = []
missing_extref = []
missing_published = []
low_confidence = []
after = None
total_reports = 0

while True:
    try:
        data = gql(META_QUERY, {"after": after})
        edges = data["reports"]["edges"]
        page_info = data["reports"]["pageInfo"]
        for e in edges:
            r = e["node"]
            total_reports += 1
            name = r["name"][:70]
            rid = r["id"]
            if not r.get("createdBy"):
                missing_author.append((name, rid))
            if not r.get("objectMarking"):
                missing_marking.append((name, rid))
            if not r.get("externalReferences", {}).get("edges"):
                missing_extref.append((name, rid))
            if not r.get("published"):
                missing_published.append((name, rid))
            if r.get("confidence") is not None and r["confidence"] == 0:
                low_confidence.append((name, rid))
        if not page_info["hasNextPage"]:
            break
        after = page_info["endCursor"]
    except Exception as ex:
        print(f"  WARN: Metadata query failed: {ex}")
        break

print(f"  Total reports scanned: {total_reports}\n")

def report_meta_issue(label, items):
    if not items:
        print(f"  ✓ {label}: none")
    else:
        print(f"  ⚠ {label}: {len(items)}")
        for name, rid in items[:10]:
            print(f"    - \"{name}\"")
        if len(items) > 10:
            print(f"    ... and {len(items) - 10} more")

report_meta_issue("Missing author", missing_author)
report_meta_issue("Missing marking definition", missing_marking)
report_meta_issue("Missing external reference URL", missing_extref)
report_meta_issue("Missing published date", missing_published)
report_meta_issue("Confidence set to 0 (default unset)", low_confidence)

print(f"\n{SEP}\n## DONE\n{SEP}")
