#!/usr/bin/env python3
"""
OpenCTI Platform Compliance Diagnostic — Domain 3
Checks: manual Indicators, sightings container violations,
relationship type violations, URLhaus output audit.
"""

import requests
import os
from collections import defaultdict, Counter
import time

OPENCTI_URL = "http://localhost:8080"
TOKEN = os.environ.get("OPENCTI_ADMIN_TOKEN", "8924b218-b275-4077-bd7a-cea6537d7bfb")
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
SEP = "=" * 80
DELAY = 1.0

AUTHORIZED_RELATIONSHIPS = {
    ("autonomous-system", "related-to", "organization"),
    ("bank-account", "related-to", "individual"),
    ("campaign", "uses", "channel"),
    ("incident", "related-to", "campaign"),
    ("incident", "uses", "channel"),
    ("indicator", "based-on", "stix-cyber-observable"),
    ("indicator", "created-from", "stix-cyber-observable"),
    ("indicator", "indicates", "attack-pattern"),
    ("indicator", "related-to", "attack-pattern"),
    ("indicator", "related-to", "intrusion-set"),
    ("indicator", "related-to", "stix-cyber-observable"),
    ("indicator", "sighted-at", "organization"),
    ("indicator", "sighted-at", "system"),
    ("individual", "part-of", "organization"),
    ("individual", "related-to", "threat-actor-group"),
    ("intrusion-set", "attributed-to", "individual"),
    ("intrusion-set", "attributed-to", "threat-actor-group"),
    ("intrusion-set", "targets", "organization"),
    ("intrusion-set", "targets", "region"),
    ("intrusion-set", "targets", "sector"),
    ("intrusion-set", "targets", "vulnerability"),
    ("intrusion-set", "uses", "attack-pattern"),
    ("intrusion-set", "uses", "channel"),
    ("intrusion-set", "uses", "infrastructure"),
    ("intrusion-set", "uses", "malware"),
    ("intrusion-set", "uses", "persona"),
    ("intrusion-set", "uses", "tool"),
    ("ipv4-addr", "belongs-to", "autonomous-system"),
    ("ipv4-addr", "related-to", "campaign"),
    ("malware", "exploits", "vulnerability"),
    ("malware", "related-to", "channel"),
    ("malware", "related-to", "tool"),
    ("malware", "targets", "individual"),
    ("malware", "targets", "organization"),
    ("malware", "targets", "system"),
    ("malware", "uses", "attack-pattern"),
    ("malware", "uses", "infrastructure"),
    ("stix-cyber-observable", "related-to", "attack-pattern"),
    ("stix-cyber-observable", "related-to", "intrusion-set"),
    ("stix-cyber-observable", "related-to", "malware"),
    ("stix-cyber-observable", "sighted-at", "system"),
    ("organization", "part-of", "sector"),
    ("persona", "related-to", "channel"),
    ("persona", "related-to", "individual"),
    ("persona", "related-to", "organization"),
    ("software", "has", "vulnerability"),
    ("software", "related-to", "incident"),
    ("software", "related-to", "intrusion-set"),
    ("software", "related-to", "organization"),
    ("software", "related-to", "system"),
    ("software", "related-to", "tool"),
    ("system", "belongs-to", "organization"),
    ("system", "part-of", "infrastructure"),
    ("threat-actor-group", "impersonates", "individual"),
    ("threat-actor-group", "uses", "channel"),
    ("tool", "related-to", "attack-pattern"),
    ("user-account", "related-to", "channel"),
    ("vulnerability", "related-to", "attack-pattern"),
    ("attack-pattern", "targets", "individual"),
    ("attack-pattern", "targets", "organization"),
    ("attack-pattern", "targets", "sector"),
    ("domain-name", "resolves-to", "ipv4-addr"),
    ("narrative", "related-to", "organization"),
    ("infrastructure", "delivers", "malware"),
    # Added 2026-03-22: production-observed relationships
    # Threat Actor targeting — mirrors Intrusion Set targeting relationships
    ("threat-actor-group", "targets", "organization"),
    ("threat-actor-group", "targets", "sector"),
    ("threat-actor-group", "targets", "region"),
    ("threat-actor-group", "targets", "vulnerability"),
    # Geography relationships
    ("incident", "originates-from", "country"),
    ("intrusion-set", "originates-from", "country"),
    ("ipv4-addr", "located-at", "country"),
    ("organization", "located-at", "country"),
    # Direct C2/callback observation
    ("malware", "communicates-with", "url"),
    # Incident as provisional adversary node (diamond model)
    ("incident", "uses", "attack-pattern"),
    # Observable clustering
    ("ipv4-addr", "related-to", "network-traffic"),
    ("network-traffic", "related-to", "incident"),
    ("url", "related-to", "ipv4-addr"),
    ("url", "related-to", "domain-name"),
    # Attribution
    ("malware", "authored-by", "intrusion-set"),
}

SCO_TYPES = {
    "ipv4-addr", "ipv6-addr", "domain-name", "url", "file",
    "network-traffic", "email-addr", "windows-registry-key",
    "user-account", "x509-certificate", "autonomous-system",
    "bank-account", "mutex", "software", "text", "cryptocurrency-wallet",
    "hostname", "payment-card", "phone-number", "media-content", "stixfile", "stix-file"
}

PERMITTED_MANUAL_INDICATOR_TYPES = {"yara", "sigma"}

def gql(query, variables=None, retries=3):
    for attempt in range(retries):
        try:
            r = requests.post(
                f"{OPENCTI_URL}/graphql",
                headers=HEADERS,
                json={"query": query, "variables": variables or {}},
                timeout=60
            )
            r.raise_for_status()
            data = r.json()
            if "errors" in data:
                msg = data["errors"][0].get("message", "unknown")
                raise Exception(f"GraphQL error: {msg}")
            return data["data"]
        except Exception as e:
            if attempt < retries - 1:
                print(f"  RETRY {attempt+1}: {e}")
                time.sleep(8)
            else:
                raise

def section(title):
    print(f"\n{SEP}\n## {title}\n{SEP}")

# ── 3.1 Manually Created Indicators ──────────────────────────────────────────
section("3.1 — Manually Created Indicators (permitted: YARA, Sigma only)")

INDICATOR_QUERY = """
query Indicators($after: ID) {
  indicators(first: 100, after: $after) {
    pageInfo { hasNextPage endCursor globalCount }
    edges {
      node {
        id
        name
        pattern_type
        created_at
        createdBy { name }
        observables { edges { node { id } } }
      }
    }
  }
}
"""

try:
    first = gql(INDICATOR_QUERY, {})
    total_indicators = first["indicators"]["pageInfo"]["globalCount"]
    print(f"Total Indicators in platform: {total_indicators}")

    all_indicators = []
    after = None
    while True:
        data = gql(INDICATOR_QUERY, {"after": after})
        page = data["indicators"]
        for e in page["edges"]:
            all_indicators.append(e["node"])
        if not page["pageInfo"]["hasNextPage"]:
            break
        after = page["pageInfo"]["endCursor"]
        time.sleep(DELAY)

    yara = [i for i in all_indicators if i.get("pattern_type", "").lower() == "yara"]
    sigma = [i for i in all_indicators if i.get("pattern_type", "").lower() == "sigma"]
    stix = [i for i in all_indicators if i.get("pattern_type", "").lower() == "stix"]
    other = [i for i in all_indicators
             if i.get("pattern_type", "").lower() not in PERMITTED_MANUAL_INDICATOR_TYPES | {"stix"}]
    no_observable = [i for i in stix
                     if not i.get("observables", {}).get("edges")]

    print(f"  YARA  (permitted manual):  {len(yara)}")
    print(f"  Sigma (permitted manual):  {len(sigma)}")
    print(f"  STIX  (auto-generated):    {len(stix)}")
    print(f"  Other pattern types:       {len(other)}")
    print(f"  STIX with no Observable:   {len(no_observable)} (likely manually created)")

    if no_observable:
        print(f"\n  ⚠ STIX Indicators with no source Observable:")
        for i in no_observable[:20]:
            creator = i.get("createdBy", {})
            cname = creator.get("name", "unknown") if creator else "unknown"
            print(f"    - {i['name'][:70]} | by: {cname} | created: {i.get('created_at','?')[:10]}")
        if len(no_observable) > 20:
            print(f"    ... and {len(no_observable)-20} more")
    else:
        print("  ✓ All STIX Indicators have linked Observables.")

    if other:
        print(f"\n  ⚠ Non-standard pattern types:")
        for i in other[:10]:
            print(f"    - [{i.get('pattern_type','?')}] {i['name'][:60]}")

except Exception as e:
    print(f"  ERROR: {e}")

time.sleep(DELAY)

# ── 3.2 Sightings in Report Containers ───────────────────────────────────────
section("3.2 — Sightings in Report Containers (must be Incident Response only)")

SIGHTINGS_QUERY = """
query Sightings($after: ID) {
  stixSightingRelationships(first: 100, after: $after) {
    pageInfo { hasNextPage endCursor globalCount }
    edges {
      node {
        id
        first_seen
        from { ... on StixCyberObservable { observable_value entity_type } }
        containers {
          edges {
            node {
              entity_type
              ... on Report { name }
            }
          }
        }
      }
    }
  }
}
"""

try:
    first = gql(SIGHTINGS_QUERY, {})
    total_sightings = first["stixSightingRelationships"]["pageInfo"]["globalCount"]
    print(f"Total Sightings: {total_sightings}")

    if total_sightings == 0:
        print("  ✓ No sightings found.")
    else:
        violations = []
        after = None
        while True:
            data = gql(SIGHTINGS_QUERY, {"after": after})
            page = data["stixSightingRelationships"]
            for e in page["edges"]:
                node = e["node"]
                for c in node.get("containers", {}).get("edges", []):
                    if c["node"].get("entity_type") == "Report":
                        obs = node.get("from", {})
                        violations.append({
                            "observable": obs.get("observable_value", "?") if obs else "?",
                            "container": c["node"].get("name", "?"),
                        })
            if not page["pageInfo"]["hasNextPage"]:
                break
            after = page["pageInfo"]["endCursor"]
            time.sleep(DELAY)

        if not violations:
            print("  ✓ All sightings are inside Incident Response containers.")
        else:
            print(f"  ⚠ {len(violations)} sightings inside Report containers (DATA MODEL VIOLATION):")
            for v in violations[:15]:
                print(f"    - Observable: {v['observable'][:50]} | Report: {v['container'][:50]}")
            if len(violations) > 15:
                print(f"    ... and {len(violations)-15} more")

except Exception as e:
    print(f"  ERROR: {e}")

time.sleep(DELAY)

# ── 3.3 Relationship Type Compliance ─────────────────────────────────────────
section("3.3 — Relationship Type Compliance (1000 relationship sample)")

REL_QUERY = """
query Rels($after: ID) {
  stixCoreRelationships(first: 200, after: $after) {
    pageInfo { hasNextPage endCursor globalCount }
    edges {
      node {
        relationship_type
        from { ... on BasicObject { entity_type } }
        to { ... on BasicObject { entity_type } }
        createdBy { name }
      }
    }
  }
}
"""

def normalize_type(t):
    if not t:
        return "unknown"
    return t.lower().replace("_", "-").replace(" ", "-")

def is_authorized(from_type, rel_type, to_type):
    f = normalize_type(from_type)
    r = rel_type.lower().replace("_", "-")
    t = normalize_type(to_type)
    if (f, r, t) in AUTHORIZED_RELATIONSHIPS:
        return True
    if f in SCO_TYPES and ("stix-cyber-observable", r, t) in AUTHORIZED_RELATIONSHIPS:
        return True
    if r == "related-to":
        return True
    return False

try:
    first = gql(REL_QUERY, {})
    total_rels = first["stixCoreRelationships"]["pageInfo"]["globalCount"]
    print(f"Total core relationships: {total_rels}")
    print(f"Sampling first 1000...")

    from collections import defaultdict, Counter
    sampled = []
    after = None
    pages = 0
    while pages < 5:
        data = gql(REL_QUERY, {"after": after})
        page = data["stixCoreRelationships"]
        for e in page["edges"]:
            sampled.append(e["node"])
        if not page["pageInfo"]["hasNextPage"]:
            break
        after = page["pageInfo"]["endCursor"]
        pages += 1
        time.sleep(DELAY)

    violations_by_triple = defaultdict(list)
    authorized_by_rel = defaultdict(set)

    for rel in sampled:
        f = rel.get("from", {}).get("entity_type", "unknown") if rel.get("from") else "unknown"
        t = rel.get("to", {}).get("entity_type", "unknown") if rel.get("to") else "unknown"
        r = rel.get("relationship_type", "unknown")
        creator = rel.get("createdBy", {})
        cname = creator.get("name", "unknown") if creator else "unknown"

        if not is_authorized(f, r, t):
            violations_by_triple[(f, r, t)].append(cname)
        else:
            authorized_by_rel[r].add(f"{f} → {t}")

    print(f"\n  Authorized relationship types in sample:")
    for rel_type, pairs in sorted(authorized_by_rel.items()):
        print(f"    {rel_type}: {len(pairs)} source-target pair(s)")

    if not violations_by_triple:
        print("\n  ✓ All sampled relationships are authorized.")
    else:
        print(f"\n  ⚠ {len(violations_by_triple)} unauthorized relationship triples found:")
        for (f, r, t), creators in sorted(violations_by_triple.items(), key=lambda x: -len(x[1])):
            unique_creators = list(set(creators))
            print(f"    [{f}] --{r}--> [{t}]")
            print(f"      Count: {len(creators)} | Creators: {', '.join(unique_creators[:3])}")

except Exception as e:
    print(f"  ERROR: {e}")

time.sleep(DELAY)

# ── 3.4 URLhaus Output Audit ──────────────────────────────────────────────────
section("3.4 — URLhaus Connector Output Audit")

try:
    RECENT_OBS_Q = """
    query {
      stixCyberObservables(
        first: 100
        orderBy: created_at
        orderMode: desc
        filters: {
          mode: and
          filters: [{ key: "entity_type", values: ["Url"] }]
          filterGroups: []
        }
      ) {
        pageInfo { globalCount }
        edges {
          node {
            entity_type
            observable_value
            created_at
            createdBy { name }
            containers { edges { node { entity_type ... on Report { name } } } }
            objectMarking { definition }
          }
        }
      }
    }
    """
    obs_data = gql(RECENT_OBS_Q)
    obs_list = obs_data["stixCyberObservables"]["edges"]
    total_urls = obs_data["stixCyberObservables"]["pageInfo"]["globalCount"]
    print(f"  Total URL observables in platform: {total_urls}")

    creator_counter = Counter()
    urlhaus_obs = []
    for e in obs_list:
        n = e["node"]
        creator = n.get("createdBy", {})
        cname = creator.get("name", "unknown") if creator else "unknown"
        creator_counter[cname] += 1
        if "urlhaus" in cname.lower():
            urlhaus_obs.append(n)

    print(f"\n  Recent URL observable creators (sample of 100):")
    for name, count in creator_counter.most_common():
        print(f"    {name}: {count}")

    if urlhaus_obs:
        print(f"\n  URLhaus URL observables — compliance check:")
        for o in urlhaus_obs[:10]:
            containers = o.get("containers", {}).get("edges", [])
            ctypes = [c["node"].get("entity_type", "?") for c in containers]
            cnames = [c["node"].get("name", "?")[:40] for c in containers]
            marking = [m.get("definition", "?") for m in (o.get("objectMarking") or [])]
            has_container = bool(containers)
            has_marking = bool(marking)
            print(f"    - {o.get('observable_value','?')[:60]}")
            print(f"      Container: {ctypes} {cnames} | Marking: {marking}")
            if not has_container:
                print(f"      ⚠ NO CONTAINER — orphaned observable")
            if not has_marking:
                print(f"      ⚠ NO MARKING DEFINITION")
    else:
        print("\n  URLhaus creator name not found in recent URL observables.")
        print("  Check connector logs to identify what entity type it creates.")

    # Check for URLhaus indicators
    URLHAUS_IND_Q = """
    query {
      indicators(first: 100, orderBy: created_at, orderMode: desc) {
        edges {
          node {
            name
            pattern_type
            createdBy { name }
            created_at
            observables { edges { node { id } } }
          }
        }
      }
    }
    """
    ind_data = gql(URLHAUS_IND_Q)
    urlhaus_indicators = [
        e["node"] for e in ind_data["indicators"]["edges"]
        if e["node"].get("createdBy") and
        "urlhaus" in e["node"]["createdBy"].get("name", "").lower()
    ]

    if urlhaus_indicators:
        print(f"\n  ⚠ URLhaus-created Indicators found: {len(urlhaus_indicators)}")
        for i in urlhaus_indicators[:10]:
            has_obs = bool(i.get("observables", {}).get("edges"))
            ptype = i.get("pattern_type", "?")
            permitted = ptype.lower() in PERMITTED_MANUAL_INDICATOR_TYPES
            flag = "✓" if permitted else "⚠ NOT PERMITTED"
            print(f"    - [{ptype}] {i['name'][:60]} {flag} | has_observable: {has_obs}")
    else:
        print("\n  ✓ No URLhaus-created Indicators found in recent sample.")

except Exception as e:
    print(f"  ERROR: {e}")

time.sleep(DELAY)

# ── 3.5 Entity Type Misclassification ────────────────────────────────────────
section("3.5 — Entity Type Misclassification Sample (IS/TAG conflation)")

REAL_WORLD_INDICATORS = [
    "svr", "fsb", "gru", "pla ", "mss", "rgb", "irgc",
    "unit 61398", "unit 74455", "bureau 121",
    "intelligence service", "ministry of state", "foreign intelligence"
]
CLUSTER_INDICATORS = [
    "apt", "fin", "unc", "muddywater", "cozy bear", "fancy bear",
    "volt typhoon", "salt typhoon", "hafnium", "nobelium",
    "ta1", "ta2", "ta3", "ta4", "ta5", "g00", "g01", "g02",
]

IS_Q = """
query { intrusionSets(first: 200) {
  pageInfo { globalCount }
  edges { node { name aliases createdBy { name } } }
} }
"""
TAG_Q = """
query { threatActorsGroup(first: 200) {
  pageInfo { globalCount }
  edges { node { name aliases createdBy { name } } }
} }
"""

try:
    is_data = gql(IS_Q)
    tag_data = gql(TAG_Q)

    total_is = is_data["intrusionSets"]["pageInfo"]["globalCount"]
    total_tag = tag_data["threatActorsGroup"]["pageInfo"]["globalCount"]
    print(f"  Total Intrusion Sets:      {total_is}")
    print(f"  Total Threat Actor Groups: {total_tag}")

    is_suspects = []
    for e in is_data["intrusionSets"]["edges"]:
        name = e["node"]["name"].lower()
        aliases = [a.lower() for a in (e["node"].get("aliases") or [])]
        for ind in REAL_WORLD_INDICATORS:
            if any(ind in n for n in [name] + aliases):
                creator = e["node"].get("createdBy", {})
                is_suspects.append({
                    "name": e["node"]["name"],
                    "indicator": ind,
                    "creator": creator.get("name", "unknown") if creator else "unknown"
                })
                break

    tag_suspects = []
    for e in tag_data["threatActorsGroup"]["edges"]:
        name = e["node"]["name"].lower()
        aliases = [a.lower() for a in (e["node"].get("aliases") or [])]
        for ind in CLUSTER_INDICATORS:
            if any(ind in n for n in [name] + aliases):
                creator = e["node"].get("createdBy", {})
                tag_suspects.append({
                    "name": e["node"]["name"],
                    "indicator": ind,
                    "creator": creator.get("name", "unknown") if creator else "unknown"
                })
                break

    if not is_suspects:
        print("  ✓ No Intrusion Sets with real-world org name indicators found.")
    else:
        print(f"\n  ⚠ Intrusion Sets possibly misclassified (should be Threat Actor Group):")
        for s in is_suspects:
            print(f"    - \"{s['name']}\" (matched: '{s['indicator']}') | by: {s['creator']}")

    if not tag_suspects:
        print("  ✓ No Threat Actor Groups with cluster name indicators found.")
    else:
        print(f"\n  ⚠ Threat Actor Groups possibly misclassified (should be Intrusion Set):")
        for s in tag_suspects:
            print(f"    - \"{s['name']}\" (matched: '{s['indicator']}') | by: {s['creator']}")

except Exception as e:
    print(f"  ERROR: {e}")

print(f"\n{SEP}\n## DONE\n{SEP}")
