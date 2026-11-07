"""The outbound form of an Indicator, as a CSV row or a STIX object."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

STATUS_WOULD_CREATE = "would_create"
STATUS_ACTIVE = "active"
STATUS_DECAYING = "decaying"
STATUS_REVOKED = "revoked"


@dataclass(frozen=True)
class ExportRecord:
    stix_id: str
    name: str
    pattern: str
    pattern_type: str
    observable_type: str
    observable_value: str
    indicator_types: Tuple[str, ...]
    confidence: Optional[int]
    score: Optional[int]
    markings: Tuple[str, ...]
    marking_refs: Tuple[str, ...]
    status: str
    created: str
    valid_from: str
    valid_until: Optional[str]
    revoked: bool
    labels: Tuple[str, ...]
    labels_dropped: Dict[str, int] = field(default_factory=dict)
    opencti_id: Optional[str] = None

    def fingerprint(self) -> str:
        """Hash of what the destination sees. A label change alone must count,
        because labels never touch the Indicator in OpenCTI."""
        content = {
            "name": self.name,
            "pattern": self.pattern,
            "indicator_types": sorted(self.indicator_types),
            "confidence": self.confidence,
            "score": self.score,
            "marking_refs": sorted(self.marking_refs),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "revoked": self.revoked,
            "labels": sorted(self.labels),
        }
        encoded = json.dumps(content, sort_keys=True).encode("utf-8")
        # 64 bits is ample to detect a change, and keeps the per-Indicator
        # entry in the platform-side connector state small.
        return hashlib.sha256(encoded).hexdigest()[:16]

    def to_stix(self, modified: datetime) -> Dict[str, Any]:
        """Build the STIX 2.1 Indicator.

        modified is the send time, not the OpenCTI value. Consumers use it to
        pick the newest version of an id, and a label change would otherwise
        arrive with an unchanged timestamp and be ignored.
        """
        stix: Dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": self.stix_id,
            "created": self.created,
            "modified": modified.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "name": self.name,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "valid_from": self.valid_from,
            "revoked": self.revoked,
        }
        if self.valid_until:
            stix["valid_until"] = self.valid_until
        if self.confidence is not None:
            stix["confidence"] = self.confidence
        if self.score is not None:
            stix["x_opencti_score"] = self.score
        if self.indicator_types:
            stix["indicator_types"] = list(self.indicator_types)
        if self.labels:
            stix["labels"] = list(self.labels)
        if self.marking_refs:
            stix["object_marking_refs"] = list(self.marking_refs)
        return stix
