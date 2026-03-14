from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger(__name__)

_CATALOGUE_TYPES: List[Dict[str, Any]] = [
    {"entity_type": "Malware",          "gql_root": "malwares",         "has_aliases": True,  "has_mitre_id": False},
    {"entity_type": "Tool",             "gql_root": "tools",            "has_aliases": True,  "has_mitre_id": False},
    {"entity_type": "Intrusion-Set",    "gql_root": "intrusionSets",    "has_aliases": True,  "has_mitre_id": False},
    {"entity_type": "Threat-Actor",     "gql_root": "threatActors",     "has_aliases": True,  "has_mitre_id": False},
    {"entity_type": "Campaign",         "gql_root": "campaigns",        "has_aliases": True,  "has_mitre_id": False},
    {"entity_type": "Attack-Pattern",   "gql_root": "attackPatterns",   "has_aliases": False, "has_mitre_id": True},
    {"entity_type": "Vulnerability",    "gql_root": "vulnerabilities",  "has_aliases": False, "has_mitre_id": False},
    {"entity_type": "Infrastructure",   "gql_root": "infrastructures",  "has_aliases": False, "has_mitre_id": False},
    {"entity_type": "Channel",          "gql_root": "channels",         "has_aliases": False, "has_mitre_id": False},
    {"entity_type": "Course-Of-Action", "gql_root": "coursesOfAction",  "has_aliases": False, "has_mitre_id": True},
]

_PAGE_SIZE = 500
_MAX_ENTITIES_PER_TYPE = 5000

# Minimum normalised name length for KB scan matching.
# 4-char floor was too aggressive — "unit", "kill", "army", "core" all match.
# 7 chars eliminates most common English false positives while retaining
# meaningful short threat intel names like "WannaCry" (8), "Lazarus" (7).
_MIN_SCAN_NAME_LEN = 7

# Common English words that happen to collide with entity names.
# These are added defensively — any name in this set is excluded from
# word-boundary matching regardless of length.
_SCAN_STOP_LIST: FrozenSet[str] = frozenset({
    # Generic org/military terms that appear in threat actor names
    "unit", "army", "navy", "office", "bureau", "agency", "command",
    "ministry", "department", "company", "service", "division", "section",
    "group", "team", "force", "corps", "guard", "network", "cluster",
    # Generic technical terms that appear in malware/tool names
    "loader", "dropper", "beacon", "agent", "client", "server", "proxy",
    "shell", "script", "module", "plugin", "driver", "handler", "manager",
    "scanner", "crawler", "stealer", "logger", "watcher", "tracker",
    # Common English words that appear in campaign/infrastructure names
    "anchor", "shadow", "ghost", "phantom", "dark", "black", "white",
    "storm", "thunder", "lightning", "fire", "ice", "iron", "steel",
    "golden", "silver", "crystal", "diamond", "stone", "rock", "sand",
    # Short words that pass the length floor but still produce noise
    "attack", "malware", "exploit", "payload", "implant", "backdoor",
})


@dataclass
class EntityEntry:
    entity_type: str
    name: str
    aliases: FrozenSet[str]
    entity_id: str
    mitre_id: Optional[str] = None

    def all_names(self) -> FrozenSet[str]:
        return self.aliases


@dataclass
class EntityKB:
    """
    Lazy-loaded, TTL-cached catalogue of named entities from the live OpenCTI
    graph. Built on first report processing run, refreshed after ttl_hours.
    """
    _entries: List[EntityEntry] = field(default_factory=list)
    _built_at: Optional[datetime] = None
    _ttl_hours: int = 24
    _ready: bool = False
    _index: Dict[str, List[EntityEntry]] = field(default_factory=dict)

    def _is_stale(self) -> bool:
        if not self._ready or self._built_at is None:
            return True
        age = datetime.now(timezone.utc) - self._built_at
        return age > timedelta(hours=self._ttl_hours)

    def ensure_ready(self, helper: Any) -> None:
        if not self._is_stale():
            return
        logger.info("EntityKB: building knowledge base from live graph...")
        self._build(helper)
        self._health_check()

    def _normalise(self, s: str) -> str:
        return (s or "").strip().lower()

    def _health_check(self) -> None:
        """
        Log a clear error if the KB built with zero entries — indicates
        token misconfiguration, network failure, or empty instance.
        Named explicitly so it appears in log search.
        """
        if len(self._entries) == 0:
            logger.error(
                "EntityKB: health check FAILED — zero entities loaded. "
                "Verify OPENCTI_TOKEN has read access to all entity types. "
                "KB-based named entity scan will produce no matches until resolved."
            )
        else:
            logger.info(
                "EntityKB: health check PASSED — %d entries across %d index terms.",
                len(self._entries), len(self._index),
            )

    def _build(self, helper: Any) -> None:
        try:
            self._ttl_hours = int(os.environ.get("QA_KB_TTL_HOURS", "24"))
        except Exception:
            self._ttl_hours = 24

        entries: List[EntityEntry] = []

        for type_def in _CATALOGUE_TYPES:
            entity_type = type_def["entity_type"]
            gql_root = type_def["gql_root"]
            has_aliases = type_def["has_aliases"]
            has_mitre_id = type_def["has_mitre_id"]

            extra_fields = ""
            if has_aliases:
                extra_fields += " aliases"
            if has_mitre_id:
                extra_fields += " x_mitre_id"

            cursor = None
            fetched = 0

            while fetched < _MAX_ENTITIES_PER_TYPE:
                after_clause = f', after: "{cursor}"' if cursor else ""
                query = f"""
                query KB_{gql_root} {{
                  {gql_root}(first: {_PAGE_SIZE}{after_clause}) {{
                    pageInfo {{ hasNextPage endCursor }}
                    edges {{ node {{ id name{extra_fields} }} }}
                  }}
                }}
                """
                try:
                    res = helper.api.query(query, {})
                    data = ((res or {}).get("data") or {}).get(gql_root) or {}
                    page_info = data.get("pageInfo") or {}
                    edges = data.get("edges") or []
                except Exception as e:
                    logger.warning("EntityKB: failed to fetch %s: %s", entity_type, e)
                    break

                for edge in edges:
                    node = (edge or {}).get("node") or {}
                    name = (node.get("name") or "").strip()
                    if not name:
                        continue

                    raw_aliases = node.get("aliases") or []
                    if not isinstance(raw_aliases, list):
                        raw_aliases = []

                    all_names: Set[str] = {self._normalise(name)}
                    for a in raw_aliases:
                        if isinstance(a, str) and a.strip():
                            all_names.add(self._normalise(a.strip()))

                    mitre_id = node.get("x_mitre_id") if has_mitre_id else None

                    entries.append(EntityEntry(
                        entity_type=entity_type,
                        name=name,
                        aliases=frozenset(all_names),
                        entity_id=node.get("id") or "",
                        mitre_id=mitre_id,
                    ))
                    fetched += 1

                if not page_info.get("hasNextPage"):
                    break
                cursor = page_info.get("endCursor")
                if not cursor:
                    break

            logger.info("EntityKB: loaded %d %s entities", fetched, entity_type)

        # Build index, applying stop-list and minimum length filter
        index: Dict[str, List[EntityEntry]] = {}
        skipped_stop = 0
        skipped_short = 0

        for entry in entries:
            for norm_name in entry.aliases:
                if len(norm_name) < _MIN_SCAN_NAME_LEN:
                    skipped_short += 1
                    continue
                if norm_name in _SCAN_STOP_LIST:
                    skipped_stop += 1
                    continue
                if norm_name not in index:
                    index[norm_name] = []
                index[norm_name].append(entry)

        self._entries = entries
        self._index = index
        self._built_at = datetime.now(timezone.utc)
        self._ready = True

        logger.info(
            "EntityKB: index built — %d entries, %d index terms "
            "(%d skipped short, %d skipped stop-list)",
            len(entries), len(index), skipped_short, skipped_stop,
        )

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Scan text for all known entity names/aliases.
        Word-boundary anchored, case-insensitive.
        Stop-list and minimum length already applied at index build time.
        """
        if not text or not self._index:
            return []

        matches: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        text_lower = text.lower()

        for norm_name, entries in self._index.items():
            try:
                pattern = r'\b' + re.escape(norm_name) + r'\b'
                m = re.search(pattern, text_lower)
            except re.error:
                continue
            if not m:
                continue

            for entry in entries:
                dedup_key = f"{entry.entity_id}:{norm_name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                start = max(0, m.start() - 80)
                end = min(len(text), m.end() + 80)
                snippet = text[start:end].replace("\n", " ").strip()

                matches.append({
                    "entity_type": entry.entity_type,
                    "name": entry.name,
                    "matched_term": norm_name,
                    "entity_id": entry.entity_id,
                    "mitre_id": entry.mitre_id,
                    "snippet": snippet[:200],
                })

        return matches

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def built_at(self) -> Optional[datetime]:
        return self._built_at

    def lookup(self, name: str) -> list:
        """Return all KB entries whose normalised name or alias matches `name`."""
        return self._index.get(self._normalise(name), [])
