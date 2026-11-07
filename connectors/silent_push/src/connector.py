"""
Silent Push connector for OpenCTI: IOFA and open-source (OSINT) feeds.

Twice a day (every INTERVAL_HOURS) it runs two independent streams, each with
its own work item, state file and observable-feed Report for that slot:

  IOFA   the two IOFA export files, with bulk enrichment of new values
  OSINT  the open-source feeds, read through Feed Scan, already enriched

A stream that finds nothing new makes no Report, and one failing does not stop
the other.

There is no backlog for IOFA: its first run records what exists as a baseline
and ingests nothing. OSINT's first run takes the last OSINT_INITIAL_LOOKBACK_HOURS
(24 by default); every later run takes what was added since the previous
successful run, less a small overlap that the state file deduplicates.

IOFA enriches only new values, under a per-run budget, because the 15,000
requests a month are shared across the organisation. Whatever does not fit stays
unhandled and comes up again next run. Values are marked handled only after
their bundle is sent, so a failed run loses nothing.

Bundles are chunked, and each carries its own copy of the Report with that
chunk's refs, so nothing depends on workers processing chunks in order.
"""

import json
import math
import os
import random
import time
from datetime import datetime, timedelta, timezone

import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from client import (
    DOMAIN_EXPORT,
    IP_EXPORT,
    SilentPushAPIError,
    SilentPushClient,
    batch_size,
)
from seen_store import Cursor, SeenStore
from stix_builder import (
    STREAM_IOFA,
    STREAM_OSINT,
    SilentPushStixBuilder,
    is_excluded,
    osint_value,
    row_value,
    unflatten,
)

CONNECTOR_VERSION = "2.1.0"
CHUNK_SIZE = 1000  # STIX objects per bundle
MAX_EMPTY_BATCHES = 3  # consecutive empty answers before giving up on the run
EXPECTED_TYPE = {"domain": "domain-name", "ipv4": "ipv4-addr"}

# Re-read this much before the previous run, to cover clock skew and rows
# Silent Push timestamps slightly late. The state file drops the repeats.
OSINT_OVERLAP = timedelta(hours=1)

# These feeds come into the platform through their own connectors.
DEFAULT_OSINT_EXCLUDE = (
    "UrlHaus,FeodoTracker,ThreatFox Official Recent Domains,"
    "ThreatFox Recent IPs,ThreatFox Recent URLs,OpenPhish,"
    "AlienVault Domain,AlienVault IP"
)


def _flag(value) -> bool:
    return str(value).strip().lower() == "true"


def slot_start(now: datetime, interval_seconds: int) -> datetime:
    """Start of the UTC slot holding `now`. Names the Report for that slot."""
    stamp = int(now.timestamp())
    return datetime.fromtimestamp(stamp - stamp % interval_seconds, tz=timezone.utc)


def seconds_until_next_slot(now: datetime, interval_seconds: int) -> float:
    return interval_seconds - now.timestamp() % interval_seconds


def plan_batches(
    domains: list[str], ips: list[str], budget: int
) -> list[tuple[str, list[str]]]:
    """
    Alternate domain and IP batches, up to `budget`.

    Alternating stops a long carry-over of one type starving the other.
    Shuffling stops a value the API cannot answer from holding back the same
    neighbours on every run.
    """
    queues = []
    for kind, values in (("domain", domains), ("ipv4", ips)):
        shuffled = random.sample(values, len(values))
        size = batch_size(kind)
        queues.append(
            [
                (kind, shuffled[start : start + size])
                for start in range(0, len(shuffled), size)
            ]
        )

    planned = []
    for index in range(max(len(queue) for queue in queues)):
        planned += [queue[index] for queue in queues if index < len(queue)]
    return planned[:budget]


class SilentPushConnector:
    def __init__(self) -> None:
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config: dict = {}
        if os.path.isfile(config_path):
            with open(config_path, encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}

        self.helper = OpenCTIConnectorHelper(config)

        def setting(name: str, default=None):
            return get_config_variable(
                f"SILENT_PUSH_{name.upper()}",
                ["silent_push", name],
                config,
                default=default,
            )

        api_key = setting("api_key")
        if not api_key:
            raise ValueError("SILENT_PUSH_API_KEY is required")
        self.interval_seconds = int(setting("interval_hours", 12)) * 3600
        self.run_on_startup = _flag(setting("run_on_startup", True))
        self.enrich_budget = int(setting("enrich_batch_budget", 60))
        self.iofa_enabled = _flag(setting("iofa_enabled", True))
        self.osint_enabled = _flag(setting("osint_enabled", True))
        self.osint_exclude = {
            name.strip()
            for name in str(
                setting("osint_exclude_feeds", DEFAULT_OSINT_EXCLUDE) or ""
            ).split(",")
            if name.strip()
        }

        state_dir = setting("state_dir", "/data")
        self.client = SilentPushClient(api_key)
        self.store = SeenStore(state_dir, "seen_iofa.txt")
        self.osint_store = SeenStore(state_dir, "seen_osint.txt")
        self.osint_cursor = Cursor(state_dir, "osint_last_run.txt")
        self.osint_initial_lookback = timedelta(
            hours=float(setting("osint_initial_lookback_hours", 24))
        )
        self._catalogue: list[dict] | None = None
        self.builder = SilentPushStixBuilder(
            marking_id=self._resolve_marking(setting("tlp", "TLP:AMBER")),
            confidence=int(setting("confidence", 70)),
        )

    def _resolve_marking(self, tlp_name: str) -> str:
        """Use the platform's own marking; never emit a hand-rolled TLP."""
        marking = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [tlp_name]}],
                "filterGroups": [],
            }
        )
        if not marking:
            raise RuntimeError(f"{tlp_name} marking definition not found")
        return marking["standard_id"]

    def run(self) -> None:
        self.helper.connector_logger.info(
            "Silent Push connector starting",
            {
                "version": CONNECTOR_VERSION,
                "interval_seconds": self.interval_seconds,
                "enrich_batch_budget": self.enrich_budget,
                "iofa_enabled": self.iofa_enabled,
                "osint_enabled": self.osint_enabled,
            },
        )
        if self.run_on_startup:
            self.run_once()
        while True:
            now = datetime.now(timezone.utc)
            time.sleep(seconds_until_next_slot(now, self.interval_seconds))
            self.run_once()

    def run_once(self) -> None:
        slot = slot_start(datetime.now(timezone.utc), self.interval_seconds)
        self._catalogue = None  # fetched at most once per run, when needed
        streams = (
            (STREAM_IOFA, self.iofa_enabled, self._ingest),
            (STREAM_OSINT, self.osint_enabled, self._ingest_osint),
        )
        for stream, enabled, ingest in streams:
            if enabled:
                self._run_stream(stream, slot, ingest)

    def _run_stream(self, stream: str, slot: datetime, ingest) -> None:
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"Silent Push {stream} {slot:%Y-%m-%d %H:%M} UTC",
        )
        try:
            stats = ingest(slot, work_id)
        except Exception as exc:
            self.helper.connector_logger.error(
                "Silent Push run failed", {"stream": stream, "error": str(exc)}
            )
            self.helper.api.work.to_processed(
                work_id, f"Run failed: {exc}", in_error=True
            )
            return

        self.helper.connector_logger.info(
            "Silent Push run complete", {"stream": stream, **stats}
        )
        self.helper.api.work.to_processed(work_id, f"Run complete: {stats}")

    def _feeds(self) -> list[dict]:
        if self._catalogue is None:
            self._catalogue = self.client.list_feeds()
        return self._catalogue

    def _ingest(self, slot: datetime, work_id: str) -> dict:
        if not self.store.exists():
            return self._save_baseline()

        seen = self.store.load()
        domains = _unseen(self.client.download_export(DOMAIN_EXPORT), seen)
        ips = _unseen(self.client.download_export(IP_EXPORT), seen)
        del seen

        stats = {
            "new": len(domains) + len(ips),
            "ingested": 0,
            "no_enrichment_row": 0,
            "benign_or_sinkhole_skipped": 0,
            "unusable_skipped": 0,
            "batches_deferred": 0,
        }
        if domains or ips:
            feeds = self._iofa_feeds()
            batches = plan_batches(domains, ips, self.enrich_budget)
            self._process(batches, feeds, slot, work_id, stats)

        handled = (
            stats["ingested"]
            + stats["benign_or_sinkhole_skipped"]
            + stats["unusable_skipped"]
        )
        stats["carried_over"] = stats["new"] - handled
        return stats

    def _save_baseline(self) -> dict:
        domains = self.client.download_export(DOMAIN_EXPORT)
        ips = self.client.download_export(IP_EXPORT)
        self.store.write_baseline(domains + ips)
        # Warning level: on a volume that was lost, this is also a silent gap.
        self.helper.connector_logger.warning(
            "No state file: saved a baseline and ingested nothing",
            {
                "stream": STREAM_IOFA,
                "path": self.store.path,
                "values": len(domains) + len(ips),
            },
        )
        return {"baseline": len(domains) + len(ips)}

    def _iofa_feeds(self) -> dict[str, dict]:
        feeds = {
            feed["uuid"]: feed
            for feed in self._feeds()
            if feed.get("category") == "iofa" and feed.get("uuid")
        }
        # Without the catalogue every value would land unattributed and then
        # count as handled, losing its Intrusion Set, Malware or Tool link for good.
        if not feeds:
            raise SilentPushAPIError("Feed catalogue lists no IOFA feeds")
        return feeds

    def _process(
        self,
        batches: list[tuple[str, list[str]]],
        feeds: dict[str, dict],
        slot: datetime,
        work_id: str,
        stats: dict,
    ) -> None:
        buffer: dict[str, object] = {}
        handled: list[str] = []
        empty_streak = 0

        def flush() -> None:
            if buffer:
                self._send_chunk(buffer, slot, work_id, STREAM_IOFA)
                buffer.clear()
            self.store.append(handled)
            handled.clear()

        for kind, batch in batches:
            rows = self.client.enrich(kind, batch)
            if not rows:
                # Left unhandled, so it comes up again next run.
                stats["batches_deferred"] += 1
                empty_streak += 1
                if empty_streak >= MAX_EMPTY_BATCHES:
                    self.helper.connector_logger.warning(
                        "Silent Push enrichment keeps returning nothing; "
                        "stopping this run",
                        {"kind": kind},
                    )
                    break
                continue
            empty_streak = 0

            by_value = {row_value(kind, row): row for row in rows}
            if not any(_key(value) in by_value for value in batch):
                # Rows that match nothing mean the shape changed. Ingesting on
                # would strip context from every value and mark them handled.
                raise SilentPushAPIError(
                    f"{kind} enrichment rows match none of the values sent"
                )

            for value in batch:
                row = by_value.get(_key(value))
                if row is None:
                    # Bare, not deferred: a value the API never answers would
                    # otherwise be re-sent on every run forever.
                    stats["no_enrichment_row"] += 1
                    row = {}
                handled.append(value)
                if is_excluded(row):
                    stats["benign_or_sinkhole_skipped"] += 1
                    continue
                try:
                    objects = self.builder.build_indicator(
                        value, EXPECTED_TYPE[kind], row, feeds
                    )
                except (ValueError, stix2.exceptions.STIXError) as exc:
                    # One bad value must not fail every run it comes up in.
                    self.helper.connector_logger.warning(
                        "Skipping value STIX rejected",
                        {"value": value, "error": str(exc)},
                    )
                    objects = []
                if not objects:
                    stats["unusable_skipped"] += 1
                    continue
                stats["ingested"] += 1
                # Keyed by id so shared entities appear once per bundle.
                buffer.update({obj.id: obj for obj in objects})

            if len(buffer) >= CHUNK_SIZE:
                flush()
        flush()

    def _osint_query(self, days: int) -> str:
        open_source = [
            feed
            for feed in self._feeds()
            if feed.get("category") == "open_source" and feed.get("vendor")
        ]
        if not open_source:
            raise SilentPushAPIError("Feed catalogue lists no open-source feeds")
        # Leave out vendors whose every feed is excluded, so their rows are
        # never paged: each page costs quota and about 25 seconds. Rows are
        # still filtered by feed name, for vendors with a mix.
        vendors = sorted(
            {
                feed["vendor"]
                for feed in open_source
                if feed.get("name") not in self.osint_exclude
            }
        )
        if not vendors:
            raise SilentPushAPIError("Every open-source feed is excluded")
        # Feed Scan cannot filter on feed category or feed uuid (live-tested),
        # so select by vendor and confirm the category on each row.
        # Feed Scan honours relative windows in whole days only, so this
        # narrows server side and feed_scan_since cuts at the exact time.
        return (
            'datasource = ["FEED"] AND feed_scope = ["GLOBAL"] AND vendor = '
            + json.dumps(vendors, ensure_ascii=False)
            + f' AND first_seen_on >= "now-{days}d"'
        )

    def _ingest_osint(self, slot: datetime, work_id: str) -> dict:
        started = datetime.now(timezone.utc)
        last_run = self.osint_cursor.read()
        cutoff = (
            last_run - OSINT_OVERLAP
            if last_run
            else started - self.osint_initial_lookback
        )
        days = max(1, math.ceil((started - cutoff) / timedelta(days=1)))
        rows = self.client.feed_scan_since(self._osint_query(days), cutoff)
        stats = {
            "since": cutoff.isoformat(timespec="seconds"),
            "rows": len(rows),
            "excluded_feed_rows": 0,
            "unusable_rows": 0,
        }
        grouped: dict[tuple[str, str], list[dict]] = {}
        for raw in rows:
            row = unflatten(raw)
            if row.get("feed_category") != "open_source":
                continue
            if row.get("feed") in self.osint_exclude:
                stats["excluded_feed_rows"] += 1
                continue
            classified = osint_value(row)
            if classified is None:
                stats["unusable_rows"] += 1
                continue
            grouped.setdefault(classified, []).append(row)

        if not rows:
            # Thousands normally arrive every twelve hours. If none did, keep
            # the cursor where it is, so the next run reads this window again
            # in case Feed Scan was briefly returning nothing.
            self.helper.connector_logger.warning(
                "Feed Scan returned no OSINT rows; cursor not moved",
                {"since": stats["since"]},
            )
            return stats
        if last_run is None:
            self.helper.connector_logger.warning(
                "No OSINT cursor: taking the initial lookback window",
                {"since": stats["since"], "path": self.osint_cursor.path},
            )

        if not self.osint_store.exists():
            self.osint_store.write_baseline([])
        seen = self.osint_store.load()
        new = [key for key in grouped if key[1] not in seen]
        del seen
        stats.update(
            {
                "values": len(grouped),
                "new": len(new),
                "ingested": 0,
                "benign_or_sinkhole_skipped": 0,
                "unusable_skipped": 0,
            }
        )

        buffer: dict[str, object] = {}
        handled: list[str] = []

        def flush() -> None:
            if buffer:
                self._send_chunk(buffer, slot, work_id, STREAM_OSINT)
                buffer.clear()
            self.osint_store.append(handled)
            handled.clear()

        for stix_type, value in new:
            value_rows = grouped[(stix_type, value)]
            handled.append(value)
            if any(is_excluded(row) for row in value_rows):
                stats["benign_or_sinkhole_skipped"] += 1
                continue
            try:
                objects = self.builder.build_osint_indicator(
                    stix_type, value, value_rows
                )
            except (ValueError, stix2.exceptions.STIXError) as exc:
                self.helper.connector_logger.warning(
                    "Skipping value STIX rejected",
                    {"stream": STREAM_OSINT, "value": value, "error": str(exc)},
                )
                stats["unusable_skipped"] += 1
                continue
            stats["ingested"] += 1
            buffer.update({obj.id: obj for obj in objects})
            if len(buffer) >= CHUNK_SIZE:
                flush()
        flush()
        # Only after every bundle went out: a failed run re-reads its window.
        self.osint_cursor.write(started)
        return stats

    def _send_chunk(
        self, objects: dict, slot: datetime, work_id: str, stream: str
    ) -> None:
        report = self.builder.build_report(slot, list(objects), stream)
        bundle = stix2.Bundle(
            objects=[self.builder.author, *objects.values(), report],
            allow_custom=True,
        )
        self.helper.send_stix2_bundle(
            bundle.serialize(), update=True, work_id=work_id
        )


def _unseen(values: list[str], seen: set[str]) -> list[str]:
    return [value for value in dict.fromkeys(values) if value not in seen]


def _key(value: str) -> str:
    return value.rstrip(".").lower()
