"""Chunked bundles with the daily Report inside (THREATFOX-REPORT-IN-BUNDLE-V1).

The Report used to be filled with one API call per object after the bundle was
sent. Those calls ran before the workers had ingested the objects, so they
failed and the daily Reports stayed empty, while each call still cost
Elasticsearch lookups. Now every chunk carries its own copy of the day's Report
with that chunk's refs; OpenCTI merges refs on upsert, so chunk order does not
matter.

Each chunk is self-contained: an observable travels with its relationships and
the observables they link (ip -> network-traffic), and every shared object a
chunk references (malware, tool, autonomous system, reporter identity, the
ThreatFox identity) is copied into it.
"""

from __future__ import annotations

from typing import Iterable

from . import config
from .uuid_generator import report_id

CHUNK_SIZE = 1000  # objects per bundle, before shared objects and the Report

_SCO_TYPES = frozenset(
    ["domain-name", "ipv4-addr", "ipv6-addr", "url", "file", "network-traffic"]
)
_REF_FIELDS = ("source_ref", "target_ref", "created_by_ref")


def _groups(objects: list[dict]) -> list[list[dict]]:
    """Observables and relationships, grouped so linked observables and the
    edges between them stay together. Shared objects are not grouped."""
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    members = [o for o in objects if o["type"] in _SCO_TYPES or o["type"] == "relationship"]
    for obj in members:
        parent[obj["id"]] = obj["id"]
    for obj in members:
        if obj["type"] != "relationship":
            continue
        for ref in (obj["source_ref"], obj["target_ref"]):
            if ref in parent:
                union(obj["id"], ref)

    grouped: dict[str, list[dict]] = {}
    for obj in members:
        grouped.setdefault(find(obj["id"]), []).append(obj)
    return list(grouped.values())


def _shared_refs(chunk: Iterable[dict], shared: dict[str, dict]) -> list[dict]:
    """Shared objects the chunk references, in a stable order."""
    wanted: dict[str, dict] = {}
    for obj in chunk:
        for field in _REF_FIELDS:
            ref = obj.get(field)
            if ref in shared:
                wanted[ref] = shared[ref]
    return [wanted[key] for key in sorted(wanted)]


def report_name(date_str: str) -> str:
    return f"Threat Fox Feed {date_str}"


def report_description(date_str: str) -> str:
    return (
        f"Automated ThreatFox IOC ingestion for {date_str}. "
        "Contains observables, malware family references, and reporter identities "
        "sourced from the ThreatFox abuse.ch feed."
    )


def build_report(
    date_str: str, published: str, refs: Iterable[str], report_types: list[str]
) -> dict:
    """The day's Report with the given refs. Same id every run of the day."""
    return {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id(date_str),
        "name": report_name(date_str),
        "description": report_description(date_str),
        "published": published,
        "report_types": report_types,
        "created_by_ref": config.THREATFOX_IDENTITY_ID,
        "object_marking_refs": [config.TLP_CLEAR_ID],
        "object_refs": sorted(set(refs)),
    }


def chunk_bundles(
    objects: list[dict],
    date_str: str,
    published: str,
    report_types: list[str],
    chunk_size: int = CHUNK_SIZE,
) -> list[list[dict]]:
    """Split converter output into self-contained chunks, each ending with a
    copy of the day's Report holding that chunk's refs."""
    shared = {
        o["id"]: o for o in objects
        if o["type"] not in _SCO_TYPES and o["type"] != "relationship"
    }
    identity = shared.get(config.THREATFOX_IDENTITY_ID)

    chunks: list[list[dict]] = []
    current: list[dict] = []
    for group in _groups(objects):
        if current and len(current) + len(group) > chunk_size:
            chunks.append(current)
            current = []
        current.extend(group)
    if current or not chunks:
        chunks.append(current)

    bodies = [_shared_refs(chunk, shared) + chunk for chunk in chunks]
    # Shared objects nothing references (e.g. a malware whose IOC type was
    # unsupported) were sent before this change; keep sending them.
    used = {o["id"] for body in bodies for o in body}
    bodies[-1] = [o for k, o in sorted(shared.items()) if k not in used] + bodies[-1]

    out: list[list[dict]] = []
    for body in bodies:
        if identity is not None and identity not in body:
            body.insert(0, identity)  # author of the Report
        refs = [
            o["id"] for o in body
            if o["type"] != "marking-definition" and o["id"] != config.THREATFOX_IDENTITY_ID
        ]
        # STIX requires object_refs to be non-empty; no refs, no Report copy.
        out.append(body + [build_report(date_str, published, refs, report_types)] if refs else body)
    return out
