"""Export destinations, chosen by EXPORT_LOCATION.

Add a new destination by writing another class with a deliver method.
"""

from __future__ import annotations

import csv
import glob
import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Protocol, Sequence

import requests

from .config import MODE_DEBUG, Settings
from .records import ExportRecord
from .store import StateStore

CSV_COLUMNS = (
    "indicator_id",
    "name",
    "pattern",
    "observable_type",
    "observable_value",
    "indicator_types",
    "confidence",
    "marking",
    "status",
    "valid_from",
    "valid_until",
    "revoked",
    "labels",
    "label_count",
    "labels_dropped",
    "exported_at",
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# A pattern always starts with "[", and a rewritten one would no longer match.
_UNESCAPED_COLUMNS = frozenset(["pattern"])


class ExportError(RuntimeError):
    """The destination did not accept the data. Retried next cycle."""


class Sink(Protocol):
    def deliver(self, records: Sequence[ExportRecord], dry_run: bool) -> str:
        """Send records and return a short summary. Raises ExportError."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def neutralize_formula(value: Any) -> Any:
    """Stop spreadsheets running a cell as a formula.

    Observable values and entity names can come from attackers, so anything
    that opens this file in Excel must see them as text.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_row(record: ExportRecord, exported_at: str) -> Dict[str, Any]:
    row = {
        "indicator_id": record.stix_id,
        "name": record.name,
        "pattern": record.pattern,
        "observable_type": record.observable_type,
        "observable_value": record.observable_value,
        "indicator_types": " | ".join(record.indicator_types),
        "confidence": record.confidence,
        "marking": " | ".join(record.markings),
        "status": record.status,
        "valid_from": record.valid_from,
        "valid_until": record.valid_until or "",
        "revoked": record.revoked,
        "labels": " | ".join(record.labels),
        "label_count": len(record.labels),
        "labels_dropped": ";".join(
            f"{reason}={count}" for reason, count in sorted(record.labels_dropped.items())
        ),
        "exported_at": exported_at,
    }
    return {
        column: value if column in _UNESCAPED_COLUMNS else neutralize_formula(value)
        for column, value in row.items()
    }


class CsvSink:
    """Writes a full snapshot each cycle. Runs in dry-run too: the file is how
    a dry run gets reviewed."""

    def __init__(
        self,
        directory: str,
        retention: int,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.directory = directory
        self.retention = retention
        self.clock = clock

    def deliver(self, records: Sequence[ExportRecord], dry_run: bool) -> str:
        now = self.clock()
        os.makedirs(self.directory, exist_ok=True)
        path = os.path.join(
            self.directory, f"indicators_{now.strftime('%Y%m%dT%H%M%SZ')}.csv"
        )

        # Same-directory temp file and a rename, so a reader never sees a
        # partly written snapshot.
        handle, temp_path = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
        try:
            with os.fdopen(handle, "w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS)
                writer.writeheader()
                exported_at = now.isoformat()
                writer.writerows(_csv_row(record, exported_at) for record in records)
            os.chmod(temp_path, 0o640)
            os.replace(temp_path, path)
        except OSError as exc:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise ExportError(f"Could not write {path}: {exc}") from exc

        self._prune()
        return f"Wrote {len(records)} rows to {path}"

    def _prune(self) -> None:
        pattern = os.path.join(self.directory, "indicators_*.csv")
        snapshots = sorted(glob.glob(pattern))
        for old in snapshots[: -self.retention]:
            os.unlink(old)


class StixStreamSink:
    """POSTs STIX 2.1 bundles to the configured address.

    Sends only what changed. An Indicator counts as sent once the destination
    answers 2xx; anything else is sent again next cycle.
    """

    def __init__(
        self,
        url: str,
        store: StateStore,
        batch_size: int,
        timeout_seconds: int,
        verify_tls: Any,
        auth_token: str = "",
        session: Any = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.url = url
        self.store = store
        self.batch_size = batch_size
        self.timeout_seconds = timeout_seconds
        self.verify_tls = verify_tls
        self.auth_token = auth_token
        self.session = session or requests.Session()
        self.clock = clock

    def deliver(self, records: Sequence[ExportRecord], dry_run: bool) -> str:
        sent = self.store.sent_fingerprints()
        changed = [
            record for record in records if sent.get(record.stix_id) != record.fingerprint()
        ]
        if dry_run:
            return f"Dry run: would stream {len(changed)} of {len(records)} to {self.url}"

        delivered = 0
        for start in range(0, len(changed), self.batch_size):
            batch = changed[start : start + self.batch_size]
            self._post(batch)
            self.store.mark_sent((r.stix_id, r.fingerprint()) for r in batch)
            delivered += len(batch)
        return f"Streamed {delivered} of {len(records)} to {self.url}"

    def _post(self, batch: List[ExportRecord]) -> None:
        modified = self.clock()
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [record.to_stix(modified) for record in batch],
        }
        headers = {"Content-Type": "application/stix+json;version=2.1"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        try:
            # Redirects stay off: data may only go to the configured address.
            response = self.session.post(
                self.url,
                json=bundle,
                headers=headers,
                timeout=self.timeout_seconds,
                verify=self.verify_tls,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise ExportError(f"Stream to {self.url} failed: {exc}") from exc
        if not 200 <= response.status_code < 300:
            raise ExportError(f"{self.url} answered {response.status_code}")


def build_sink(settings: Settings, store: StateStore) -> Sink:
    if settings.target.mode == MODE_DEBUG:
        return CsvSink(settings.data_dir, settings.csv_retention)
    return StixStreamSink(
        url=settings.stream_url,
        store=store,
        batch_size=settings.batch_size,
        timeout_seconds=settings.timeout_seconds,
        verify_tls=settings.verify_tls,
        auth_token=settings.auth_token,
    )
