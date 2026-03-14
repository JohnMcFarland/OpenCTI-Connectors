from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def safe_get(d: Dict[str, Any], *keys: str) -> Any:
    """
    Return the first non-None value found across the provided keys.
    Logs at DEBUG level when a fallback key (not the first) is used,
    to surface silent field-name drift from OpenCTI schema changes.
    """
    for i, k in enumerate(keys):
        if k in d and d[k] is not None:
            if i > 0:
                logger.debug("safe_get: used fallback key '%s' (primary '%s' not present)", k, keys[0])
            return d[k]
    return None


def normalize_rel_type(rel_type: str) -> str:
    return (rel_type or "").strip().lower()


def obj_display_name(obj: Optional[Dict[str, Any]], fallback_id: Optional[str] = None) -> str:
    """
    Prefer <EntityType>:<Name>. If not possible, show an ID.
    Only emit '(unreadable)' when literally nothing exists.
    """
    if obj:
        et = safe_get(obj, "entity_type", "entityType")
        name = safe_get(obj, "name", "value", "observable_value", "observableValue")
        if et and name:
            return f"{et}:{name}"
        if name:
            return str(name)
        _id = safe_get(obj, "id") or fallback_id
        if _id:
            return str(_id)
    if fallback_id:
        return str(fallback_id)
    return "(unreadable)"


def extract_relationship_endpoints(
    rel: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    OpenCTI relationship shapes vary:
      - fromId/toId
      - from_id/to_id
      - from/to nested objects
    Extract IDs and inline endpoint objects when present.
    """
    from_id = safe_get(rel, "fromId", "from_id")
    to_id = safe_get(rel, "toId", "to_id")

    from_obj = safe_get(rel, "from")
    to_obj = safe_get(rel, "to")

    if isinstance(from_obj, dict) and not from_id and from_obj.get("id"):
        from_id = from_obj.get("id")
    if isinstance(to_obj, dict) and not to_id and to_obj.get("id"):
        to_id = to_obj.get("id")

    if not isinstance(from_obj, dict):
        from_obj = None
    if not isinstance(to_obj, dict):
        to_obj = None

    return from_id, to_id, from_obj, to_obj


def resolve_endpoint(
    read_any_object_fn,
    resolved_objects: Dict[str, Dict[str, Any]],
    object_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    if not object_id:
        return None
    obj = resolved_objects.get(object_id)
    if obj:
        return obj
    obj = read_any_object_fn(object_id)
    if obj:
        resolved_objects[object_id] = obj
    return obj
