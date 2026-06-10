from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def _detect_hash_key(value: str) -> str:
    """
    Detect the hash type from a hex string by its character length and
    return the correct OpenCTI StixFile observable key.

    SHA-256: 64 hex chars  → File.hashes.SHA-256
    SHA-1:   40 hex chars  → File.hashes.SHA-1
    MD5:     32 hex chars  → File.hashes.MD5
    Other:   treated as SHA-256 (let the API reject if malformed)
    """
    v = (value or "").strip()
    if not _HEX_RE.match(v):
        return "File.hashes.SHA-256"
    length = len(v)
    if length == 64:
        return "File.hashes.SHA-256"
    if length == 40:
        return "File.hashes.SHA-1"
    if length == 32:
        return "File.hashes.MD5"
    return "File.hashes.SHA-256"

_SDO_HELPER_MAP: Dict[str, str] = {
    "Intrusion-Set":  "intrusion_set",
    "Threat-Actor":   "threat_actor",
    "Campaign":       "campaign",
    "Malware":        "malware",
    "Tool":           "tool",
    "Attack-Pattern": "attack_pattern",
    "Vulnerability":  "vulnerability",
    "Infrastructure": "infrastructure",
    "Channel":        "channel",
    "Organization":   "identity",
    "Sector":         "identity",
    "Individual":     "individual",
}

_OBSERVABLE_KEY_MAP: Dict[str, str] = {
    "IPv4-Addr":            "IPv4-Addr.value",
    "IPv6-Addr":            "IPv6-Addr.value",
    "Domain-Name":          "Domain-Name.value",
    "Url":                  "Url.value",
    "Email-Addr":           "Email-Addr.value",
    "Autonomous-System":    "Autonomous-System.number",
    "Windows-Registry-Key": "Windows-Registry-Key.key",
    "Mutex":                "Mutex.name",
    "User-Account":         "User-Account.account_login",
    "StixFile":             "File.hashes.SHA-256",  # overridden at runtime by _detect_hash_key()
}

_AUTO_DESCRIPTION_TPL = (
    "Auto-created by Report Enrichment connector from extracted text. "
    "Source: {source}. Extraction basis: {basis}. "
    "Analyst review recommended before treating as authoritative."
)


def vendor_suffix_name(name: str, author: str) -> str:
    """
    Construct a vendor-suffixed entity name.
    Per data model policy: vendor-specific designators are created as separate
    entities with the authoring organisation appended in parentheses rather than
    being added as aliases to existing canonical entities.
    Example: name="Fancy Bear", author="CrowdStrike" → "Fancy Bear(CrowdStrike)"
    """
    return f"{(name or '').strip()}({(author or 'Unknown').strip().rstrip('.')})"


def _resolve_markings(helper: Any, report: Dict[str, Any]) -> List[str]:
    markings = report.get("objectMarking") or []
    ids: List[str] = []
    for m in markings:
        if isinstance(m, dict) and m.get("id"):
            ids.append(m["id"])
        elif isinstance(m, str):
            ids.append(m)
    return ids


def _resolve_created_by(report: Dict[str, Any]) -> Optional[str]:
    cb = report.get("createdBy")
    if isinstance(cb, dict):
        return cb.get("id")
    if isinstance(cb, str):
        return cb
    return None


def _resolve_author_name(report: Dict[str, Any]) -> str:
    cb = report.get("createdBy")
    if isinstance(cb, dict):
        return (cb.get("name") or cb.get("id") or "Unknown").strip()
    return "Unknown"


class EntityCreator:
    """
    Deduplicating, non-destructive entity creation with marking/createdBy
    inheritance from the report container and vendor-suffix naming support.
    """

    def __init__(self, helper: Any, report: Dict[str, Any]) -> None:
        self.helper      = helper
        self.report      = report
        self.markings    = _resolve_markings(helper, report)
        self.created_by  = _resolve_created_by(report)
        self.author_name = _resolve_author_name(report)
        self.report_id   = report.get("id") or ""
        self._id_cache: Dict[str, str] = {}
        self.created:  List[Dict[str, Any]] = []
        self.linked:   List[Dict[str, Any]] = []
        self.skipped:  List[Dict[str, Any]] = []

    def ensure_sdo(
        self,
        entity_type: str,
        name: str,
        description: str = "",
        confidence: int = 50,
        extra_fields: Optional[Dict[str, Any]] = None,
        basis: str = "",
        apply_vendor_suffix: bool = False,
    ) -> Optional[str]:
        if apply_vendor_suffix:
            name = vendor_suffix_name(name, self.author_name)
        return self._ensure_entity(entity_type, name, description, confidence,
                                   extra_fields or {}, basis, is_observable=False)

    def ensure_observable(
        self,
        entity_type: str,
        value: str,
        description: str = "",
        basis: str = "",
    ) -> Optional[str]:
        return self._ensure_entity(entity_type, value, description, 50,
                                   {}, basis, is_observable=True)

    def link_existing(self, entity_id: str, entity_type: str, entity_name: str) -> bool:
        if not entity_id or not self.report_id:
            return False
        cache_key = f"linked:{entity_id}"
        if cache_key in self._id_cache:
            return True
        # Also check the name-keyed cache used by ensure_sdo/_ensure_entity.
        # Without this, a subsequent ensure_sdo call for the same entity misses
        # the cache, does a fresh API search that may return a false negative,
        # and creates a duplicate entity. Both cache keys must be populated here.
        name_key = self._cache_key(entity_type, entity_name)
        if name_key in self._id_cache:
            return True
        try:
            self.helper.api.report.add_stix_object_or_stix_relationship(
                id=self.report_id, stixObjectOrStixRelationshipId=entity_id,
            )
            self._id_cache[cache_key] = entity_id
            self._id_cache[name_key]  = entity_id
            self.linked.append({"entity_type": entity_type, "name": entity_name, "id": entity_id})
            logger.info("Linked existing entity to report: %s:%s", entity_type, entity_name)
            return True
        except Exception as e:
            logger.warning("Failed to link entity %s to report: %s", entity_id, e)
            self.skipped.append({"entity_type": entity_type, "name": entity_name, "reason": f"link_failed: {e}"})
            return False

    def _cache_key(self, entity_type: str, name: str) -> str:
        return f"{entity_type.lower()}:{name.strip().lower()}"

    def _ensure_entity(self, entity_type, name, description, confidence,
                       extra_fields, basis, is_observable) -> Optional[str]:
        if not entity_type or not name or not name.strip():
            return None
        cache_key = self._cache_key(entity_type, name)
        if cache_key in self._id_cache:
            return self._id_cache[cache_key]
        existing_id = self._search_existing(entity_type, name, is_observable)
        if existing_id:
            self._id_cache[cache_key] = existing_id
            self._scope_to_report(existing_id, entity_type, name, created=False)
            return existing_id
        new_id = self._create_entity(entity_type, name, description, confidence,
                                     extra_fields, basis, is_observable)
        if new_id:
            self._id_cache[cache_key] = new_id
            self._scope_to_report(new_id, entity_type, name, created=True)
        return new_id

    def _search_existing(self, entity_type, name, is_observable) -> Optional[str]:
        try:
            if is_observable:
                obs_key = _OBSERVABLE_KEY_MAP.get(entity_type)
                if not obs_key:
                    return None
                # For StixFile, detect the actual hash type from the value length
                # so the search uses the correct field rather than always SHA-256.
                if entity_type == "StixFile":
                    obs_key = _detect_hash_key(name)
                results = self.helper.api.stix_cyber_observable.list(
                    filters=[{"key": obs_key, "values": [name]}], first=1,
                )
                if results and isinstance(results, list) and results[0].get("id"):
                    return results[0]["id"]
                return None
            helper_attr = _SDO_HELPER_MAP.get(entity_type)
            if not helper_attr:
                return None
            api_obj = getattr(self.helper.api, helper_attr, None)
            if api_obj is None:
                return None
            try:
                results = api_obj.list(filters=[{"key": "name", "values": [name]}], first=1)
                if results and isinstance(results, list) and results[0].get("id"):
                    return results[0]["id"]
            except Exception:
                pass
        except Exception as e:
            logger.debug("Search for %s:%s failed: %s", entity_type, name, e)
        return None

    def _create_entity(self, entity_type, name, description, confidence,
                       extra_fields, basis, is_observable) -> Optional[str]:
        if not description:
            description = _AUTO_DESCRIPTION_TPL.format(
                source=self.author_name, basis=basis or "text extraction"
            )
        try:
            if is_observable:
                return self._create_observable(entity_type, name, description)
            return self._create_sdo(entity_type, name, description, confidence, extra_fields)
        except Exception as e:
            logger.warning("Failed to create %s:%s — %s", entity_type, name, e)
            self.skipped.append({"entity_type": entity_type, "name": name, "reason": f"create_failed: {e}"})
            return None

    def _create_sdo(self, entity_type, name, description, confidence, extra_fields) -> Optional[str]:
        helper_attr = _SDO_HELPER_MAP.get(entity_type)
        if not helper_attr:
            return None
        api_obj = getattr(self.helper.api, helper_attr, None)
        if api_obj is None:
            return None
        kwargs: Dict[str, Any] = {"name": name, "description": description,
                                   "confidence": confidence, **extra_fields}
        if self.created_by:
            kwargs["createdBy"] = self.created_by
        if self.markings:
            kwargs["objectMarking"] = self.markings
        if entity_type == "Organization":
            kwargs["identity_class"] = "organization"
        elif entity_type == "Sector":
            kwargs["identity_class"] = "class"
        elif entity_type == "Individual":
            kwargs["identity_class"] = "individual"
        result = api_obj.create(**kwargs)
        return result.get("id") if isinstance(result, dict) else None

    def _create_observable(self, entity_type, value, description) -> Optional[str]:
        obs_key = _OBSERVABLE_KEY_MAP.get(entity_type)
        if not obs_key:
            return None
        if entity_type == "Autonomous-System":
            value = re.sub(r"(?i)^as", "", value).strip()
        # For StixFile, detect the actual hash type (SHA-256/SHA-1/MD5) from
        # the hex string length so the correct observable key is used.
        # Submitting an MD5 against File.hashes.SHA-256 produces a FUNCTIONAL_ERROR.
        if entity_type == "StixFile":
            obs_key = _detect_hash_key(value)
        kwargs: Dict[str, Any] = {
            "simple_observable_key":         obs_key,
            "simple_observable_value":       value,
            "simple_observable_description": description,
        }
        if self.created_by:
            kwargs["createdBy"] = self.created_by
        if self.markings:
            kwargs["objectMarking"] = self.markings
        result = self.helper.api.stix_cyber_observable.create(**kwargs)
        return result.get("id") if isinstance(result, dict) else None

    def _scope_to_report(self, entity_id, entity_type, name, created) -> None:
        if not self.report_id or not entity_id:
            return
        try:
            self.helper.api.report.add_stix_object_or_stix_relationship(
                id=self.report_id, stixObjectOrStixRelationshipId=entity_id,
            )
            entry = {"entity_type": entity_type, "name": name, "id": entity_id}
            if created:
                self.created.append(entry)
                logger.info("Created and scoped %s:%s", entity_type, name)
            else:
                self.linked.append(entry)
                logger.info("Found and scoped existing %s:%s", entity_type, name)
        except Exception as e:
            logger.warning("Failed to scope %s:%s to report: %s", entity_type, name, e)
