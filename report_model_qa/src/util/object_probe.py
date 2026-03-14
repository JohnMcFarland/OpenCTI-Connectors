from __future__ import annotations

from typing import Any, Dict, Optional


def _first_nonempty(*vals: Optional[str]) -> Optional[str]:
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _display_name(obj: Dict[str, Any]) -> str:
    return (
        _first_nonempty(
            obj.get("name") if isinstance(obj.get("name"), str) else None,
            obj.get("value") if isinstance(obj.get("value"), str) else None,
            obj.get("observable_value") if isinstance(obj.get("observable_value"), str) else None,
            obj.get("standard_id") if isinstance(obj.get("standard_id"), str) else None,
        )
        or "(unnamed)"
    )


def probe_any_id(helper: Any, internal_id: str) -> Dict[str, Any]:
    """
    Probe an internal UUID and determine whether it's:
      - a STIX core relationship
      - a STIX core/domain/observable object
      - unknown

    Uses pycti methods first to avoid GraphQL schema drift.
    """

    # 1) Relationship (pycti)
    try:
        rel = helper.api.stix_core_relationship.read(id=internal_id)
        if isinstance(rel, dict) and rel.get("id"):
            rtype = rel.get("relationship_type") or rel.get("relationshipType") or "(unknown-relationship-type)"

            f = rel.get("from") or {}
            t = rel.get("to") or {}

            f_id = f.get("id") or rel.get("fromId")
            t_id = t.get("id") or rel.get("toId")

            # Best-effort: from/to names might not be fully populated in rel response; backfill via object reads.
            f_name = _display_name(f) if isinstance(f, dict) else "(unnamed)"
            t_name = _display_name(t) if isinstance(t, dict) else "(unnamed)"
            f_type = (f.get("entity_type") or f.get("entityType")) if isinstance(f, dict) else None
            t_type = (t.get("entity_type") or t.get("entityType")) if isinstance(t, dict) else None

            if f_id and (f_name == "(unnamed)" or not f_type):
                try:
                    fo = helper.api.stix_core_object.read(id=f_id) or helper.api.stix_domain_object.read(id=f_id) or helper.api.stix_cyber_observable.read(id=f_id)
                    if isinstance(fo, dict):
                        f_name = _display_name(fo)
                        f_type = fo.get("entity_type") or fo.get("entityType") or f_type
                except Exception:
                    pass

            if t_id and (t_name == "(unnamed)" or not t_type):
                try:
                    to = helper.api.stix_core_object.read(id=t_id) or helper.api.stix_domain_object.read(id=t_id) or helper.api.stix_cyber_observable.read(id=t_id)
                    if isinstance(to, dict):
                        t_name = _display_name(to)
                        t_type = to.get("entity_type") or to.get("entityType") or t_type
                except Exception:
                    pass

            return {
                "kind": "relationship",
                "id": rel.get("id") or internal_id,
                "relationship_type": rtype,
                "from": {"id": f_id, "entity_type": f_type or "(unknown-type)", "name": f_name},
                "to": {"id": t_id, "entity_type": t_type or "(unknown-type)", "name": t_name},
                "resolved_via": "pycti.stix_core_relationship.read",
            }
    except Exception:
        pass

    # 2) Object (pycti)
    try:
        o = helper.api.stix_core_object.read(id=internal_id)
        if not o:
            o = helper.api.stix_domain_object.read(id=internal_id)
        if not o:
            o = helper.api.stix_cyber_observable.read(id=internal_id)

        if isinstance(o, dict) and o.get("id"):
            return {
                "kind": "object",
                "id": o.get("id") or internal_id,
                "entity_type": o.get("entity_type") or o.get("entityType"),
                "standard_id": o.get("standard_id") or o.get("standardId"),
                "name": _display_name(o),
                "resolved_via": "pycti.object.read",
            }
    except Exception:
        pass

    return {"kind": "unknown", "id": internal_id, "resolved_via": None}


# Backwards-compatible aliases (older imports)
def probe_any_object(helper: Any, internal_id: str) -> Dict[str, Optional[str]]:
    out = probe_any_id(helper, internal_id)
    if out.get("kind") != "object":
        return {"id": internal_id, "entity_type": None, "standard_id": None, "name": None, "resolved_via": None}
    return {
        "id": out.get("id"),
        "entity_type": out.get("entity_type"),
        "standard_id": out.get("standard_id"),
        "name": out.get("name"),
        "resolved_via": out.get("resolved_via"),
    }


def probe_core_object(helper: Any, internal_id: str) -> Dict[str, Optional[str]]:
    x = probe_any_object(helper, internal_id)
    return {"id": x.get("id"), "entity_type": x.get("entity_type"), "standard_id": x.get("standard_id")}


def probe_object_basic(helper: Any, internal_id: str) -> Dict[str, Optional[str]]:
    return probe_core_object(helper, internal_id)
