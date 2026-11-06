"""Test doubles and object builders."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.config import load_settings

BASE_ENV = {
    "OPENCTI_URL": "http://opencti:8080",
    "OPENCTI_TOKEN": "token",
    "CONNECTOR_ID": "connector-id",
    "EXPORT_LOCATION": "debug",
    "EXPORT_DATA_DIR": "unused",
}

AMBER_STRICT = {
    "id": "m-strict",
    "standard_id": "marking-definition--strict",
    "definition": "TLP:AMBER+STRICT",
}
CLEAR = {"id": "m-clear", "standard_id": "marking-definition--clear", "definition": "TLP:CLEAR"}
RED = {"id": "m-red", "standard_id": "marking-definition--red", "definition": "TLP:RED"}
SENSITIVE = {"id": "m-sens", "standard_id": "marking-definition--sens", "definition": "Sensitive"}


def settings(**overrides: str):
    return load_settings({**BASE_ENV, **overrides})


def ipv4(obs_id: str = "obs-1", value: str = "1.2.3.4", markings=None, labels=None):
    return {
        "id": obs_id,
        "entity_type": "IPv4-Addr",
        "value": value,
        "observable_value": value,
        "objectMarking": [CLEAR] if markings is None else markings,
        "objectLabel": labels or [],
    }


def ap_link(observable: Dict[str, Any], ap_id: str = "ap-1", created_at="2026-01-01T00:00:00Z"):
    return {"id": f"rel-{ap_id}", "created_at": created_at, "from": observable, "to": {"id": ap_id}}


def entity(entity_type: str, name: str, markings=None, entity_id: Optional[str] = None):
    return {
        "id": entity_id or f"{entity_type}-{name}",
        "entity_type": entity_type,
        "parent_types": ["Basic-Object", "Stix-Domain-Object"],
        "name": name,
        "objectMarking": [CLEAR] if markings is None else markings,
    }


def related(observable_id: str, other: Dict[str, Any], markings=None, reverse=False):
    me = {"id": observable_id, "entity_type": "IPv4-Addr", "parent_types": []}
    ends = (other, me) if reverse else (me, other)
    return {
        "id": f"rel-{other['id']}",
        "objectMarking": [CLEAR] if markings is None else markings,
        "from": ends[0],
        "to": ends[1],
    }


class FakeLogger:
    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def debug(self, message: str, *_: Any) -> None:
        pass

    def info(self, message: str, *_: Any) -> None:
        pass

    def warning(self, message: str, *_: Any) -> None:
        self.warnings.append(message)

    def error(self, message: str, *_: Any) -> None:
        self.errors.append(message)


class FakeClient:
    """In-memory OpenCTI with the same surface as OpenCTIClient."""

    def __init__(self, dry_run: bool = False, author: Optional[str] = "author-1") -> None:
        self.dry_run = dry_run
        self.author = author
        self.qualifying: List[Dict[str, Any]] = []
        self.relationships: Dict[str, List[Dict[str, Any]]] = {}
        self.indicators: Dict[str, Dict[str, Any]] = {}
        self.based_on: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[str, Dict[str, str]] = {}
        self.foreign: Dict[str, Dict[str, Any]] = {}
        self.writes: List[Any] = []
        self.fail_relationships_for: set = set()
        self.groupings: Dict[str, List[str]] = {}
        self.fail_grouping_adds = False
        self.definitions = [AMBER_STRICT, CLEAR, RED, SENSITIVE]
        self._next = 0

    def resolve_author(self):
        return self.author

    def marking_definitions(self):
        return self.definitions

    def default_marking(self):
        return AMBER_STRICT

    def ensure_grouping(self, name, author_id, marking_ids):
        self.groupings.setdefault(name, [])
        return name

    def add_to_grouping(self, grouping_id, indicator_id):
        if self.fail_grouping_adds:
            raise RuntimeError("grouping down")
        self.groupings[grouping_id].append(indicator_id)

    def qualifying_relationships(self):
        return self.qualifying

    def observable_relationships(self, observable_id):
        if observable_id in self.fail_relationships_for:
            raise RuntimeError("boom")
        return self.relationships.get(observable_id, [])

    def owned_indicators(self, author_id):
        return [dict(value) for value in self.indicators.values()] if author_id else []

    def read_indicator(self, stix_id):
        if stix_id in self.foreign:
            return self.foreign[stix_id]
        for indicator in self.indicators.values():
            if indicator["standard_id"] == stix_id:
                return dict(indicator)
        return None

    def based_on_observable(self, indicator_id):
        return self.based_on.get(indicator_id)

    def indicates_edges(self, indicator_id):
        return dict(self.edges.get(indicator_id, {}))

    def create_indicator(self, **fields):
        if self.dry_run:
            return None
        from pycti import Indicator

        self._next += 1
        indicator_id = f"ind-{self._next}"
        marking_by_id = {m["id"]: m for m in (AMBER_STRICT, CLEAR, RED, SENSITIVE)}
        self.indicators[indicator_id] = {
            "id": indicator_id,
            "standard_id": Indicator.generate_id(fields["pattern"]),
            "name": fields["name"],
            "pattern": fields["pattern"],
            "pattern_type": "stix",
            "confidence": fields["confidence"],
            "x_opencti_score": fields["x_opencti_score"],
            "created": "2026-02-01T00:00:00.000Z",
            "modified": "2026-02-01T00:00:00.000Z",
            "valid_from": fields["valid_from"],
            "valid_until": "2027-01-01T00:00:00.000Z",
            "revoked": False,
            "indicator_types": fields["indicator_types"],
            "objectMarking": [marking_by_id[i] for i in fields["objectMarking"]],
            "objectLabel": [],
            "createdBy": {"id": fields["createdBy"]},
        }
        return {"id": indicator_id}

    def create_relationship(self, from_id, to_id, relationship_type, confidence, author_id, marking_ids):
        self.writes.append(("relationship", from_id, relationship_type, to_id, tuple(marking_ids)))
        if self.dry_run:
            return
        if relationship_type == "indicates":
            self.edges.setdefault(from_id, {})[to_id] = f"edge-{to_id}"

    def delete_relationship(self, relationship_id):
        self.writes.append(("delete", relationship_id))
        if self.dry_run:
            return
        for edges in self.edges.values():
            for key, value in list(edges.items()):
                if value == relationship_id:
                    del edges[key]

    def add_marking(self, indicator_id, marking_id):
        self.writes.append(("marking", indicator_id, marking_id))

    def update_assessment(self, indicator_id, score, indicator_types):
        self.writes.append(("assessment", indicator_id, score))
        if not self.dry_run:
            self.indicators[indicator_id]["confidence"] = score
            self.indicators[indicator_id]["x_opencti_score"] = score
            self.indicators[indicator_id]["indicator_types"] = indicator_types

    def set_valid_until(self, indicator_id, value):
        self.writes.append(("valid_until", indicator_id, value))
        if not self.dry_run:
            self.indicators[indicator_id]["valid_until"] = value

    def revoke(self, indicator_id):
        self.writes.append(("revoke", indicator_id))
        if not self.dry_run:
            self.indicators[indicator_id]["revoked"] = True
