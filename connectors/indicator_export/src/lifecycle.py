"""Indicator promotion and lifecycle.

The rule, carried over from ObservableGate: no Indicator exists unless it is
based on an Observable with a related-to Attack Pattern relationship.

One pass covers both directions. Observables that qualify get an Indicator or
a sync. Indicators we own whose observable no longer qualifies enter decay,
and are revoked when the decay window ends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set

from pycti import Indicator

from .config import Settings
from .grouping import grouping_day
from .labels import ObservableContext, build_context
from .opencti_client import OpenCTIClient, creator_id
from .patterns import build_pattern
from .store import DecayEntry, StateStore

REASON_OBSERVABLE_MISSING = "OBSERVABLE_MISSING"
REASON_NO_LONGER_QUALIFIES = "NO_LONGER_QUALIFIES"

_MAX_NAME_LENGTH = 200

# Diamond Model coverage. Every Indicator has infrastructure (the observable)
# and capability (the Attack Pattern); adversary and victim raise the score.
SCORE_BASE = 50
SCORE_ADVERSARY_OR_VICTIM = 75
SCORE_FULL_DIAMOND = 100


def score_for(context: ObservableContext) -> int:
    if context.has_adversary and context.has_victim:
        return SCORE_FULL_DIAMOND
    if context.has_adversary or context.has_victim:
        return SCORE_ADVERSARY_OR_VICTIM
    return SCORE_BASE


@dataclass
class Qualifying:
    observable: Dict[str, Any]
    attack_pattern_ids: Set[str] = field(default_factory=set)
    earliest_link: Optional[str] = None


@dataclass
class CycleResult:
    """What the export step needs from the lifecycle pass."""

    observables: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    contexts: Dict[str, ObservableContext] = field(default_factory=dict)
    previews: List[Dict[str, Any]] = field(default_factory=list)
    decaying: Set[str] = field(default_factory=set)
    stats: Dict[str, int] = field(
        default_factory=lambda: {
            "promoted": 0,
            "synced": 0,
            "restored": 0,
            "decay_entered": 0,
            "revoked": 0,
            "collisions": 0,
            "revoked_but_qualifying": 0,
            "unpatternable": 0,
            "errors": 0,
        }
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


class LifecycleManager:
    def __init__(
        self,
        client: OpenCTIClient,
        store: StateStore,
        settings: Settings,
        logger: Any,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.client = client
        self.store = store
        self.settings = settings
        self.logger = logger
        self.clock = clock

    def run_cycle(self) -> CycleResult:
        result = CycleResult()
        author_id = self.client.resolve_author()
        default_marking = self.client.default_marking()

        owned = self.client.owned_indicators(author_id)
        owned_by_observable: Dict[str, Dict[str, Any]] = {}
        for indicator in owned:
            observable = self.client.based_on_observable(indicator["id"])
            if observable:
                result.observables[indicator["id"]] = observable
                owned_by_observable.setdefault(observable["id"], indicator)

        qualifying = self._collect_qualifying()

        matched: Set[str] = set()
        for observable_id, entry in qualifying.items():
            if result.stats["errors"] >= self.settings.max_errors:
                self.logger.error("Error limit reached. Stopping promotion pass.")
                break
            try:
                indicator_id = self._process_qualifying(
                    entry, owned_by_observable, author_id, default_marking, result
                )
                if indicator_id:
                    matched.add(indicator_id)
            except Exception as exc:  # noqa: BLE001 - one bad object must not stop the pass
                result.stats["errors"] += 1
                self.logger.error(f"Promotion failed for {observable_id}: {exc}")

        # An empty result with Indicators on record points at a failed or
        # broken query, not at every observable losing its Attack Pattern.
        # Reconciling on that would put the whole set into decay.
        if owned and not qualifying:
            self.logger.error(
                "No qualifying observables but Indicators exist. Skipping "
                "reconciliation for this cycle."
            )
            result.stats["errors"] += 1
            return result

        promotion_finished = result.stats["errors"] < self.settings.max_errors
        for indicator in owned:
            if not promotion_finished:
                self.logger.error("Error limit reached. Skipping reconciliation.")
                break
            if indicator["id"] in matched or indicator.get("revoked"):
                continue
            observable = result.observables.get(indicator["id"])
            if observable and observable["id"] in qualifying:
                # Failed in the promotion pass above, or a second Indicator on
                # the same observable. Neither means the condition lapsed.
                continue
            try:
                self._handle_lapsed(indicator, observable, result)
            except Exception as exc:  # noqa: BLE001
                result.stats["errors"] += 1
                self.logger.error(f"Reconcile failed for {indicator['id']}: {exc}")

        return result

    def context_for(self, observable_id: str, result: CycleResult) -> ObservableContext:
        """Fetch relationships once per cycle, for score and labels both."""
        if observable_id not in result.contexts:
            result.contexts[observable_id] = build_context(
                observable_id, self.client.observable_relationships(observable_id)
            )
        return result.contexts[observable_id]

    # -- promotion ---------------------------------------------------------

    def _collect_qualifying(self) -> Dict[str, Qualifying]:
        qualifying: Dict[str, Qualifying] = {}
        for relationship in self.client.qualifying_relationships():
            observable = relationship.get("from") or {}
            attack_pattern = relationship.get("to") or {}
            observable_id = observable.get("id")
            if not observable_id or not attack_pattern.get("id"):
                continue
            if observable.get("entity_type") in self.settings.excluded_observable_types:
                continue
            labels = {
                label.get("value", "") for label in observable.get("objectLabel") or []
            }
            if labels & self.settings.excluded_labels:
                continue
            entry = qualifying.setdefault(observable_id, Qualifying(observable))
            entry.attack_pattern_ids.add(attack_pattern["id"])
            linked = relationship.get("created_at")
            if linked and (entry.earliest_link is None or linked < entry.earliest_link):
                entry.earliest_link = linked
        return qualifying

    def _process_qualifying(
        self,
        entry: Qualifying,
        owned_by_observable: Dict[str, Dict[str, Any]],
        author_id: Optional[str],
        default_marking: Dict[str, Any],
        result: CycleResult,
    ) -> Optional[str]:
        observable = entry.observable
        observable_id = observable["id"]
        pattern = build_pattern(observable)
        if pattern is None:
            result.stats["unpatternable"] += 1
            return None

        context = self.context_for(observable_id, result)
        score = score_for(context)
        indicator_types = (
            ["anomalous-activity"] if score == SCORE_BASE else ["malicious-activity"]
        )
        markings = observable.get("objectMarking") or [default_marking]

        existing = owned_by_observable.get(observable_id)
        if existing is None:
            stix_id = Indicator.generate_id(pattern)
            found = self.client.read_indicator(stix_id)
            if found and (author_id is None or creator_id(found) != author_id):
                # Same pattern means same Indicator, and someone else owns it.
                # Leave it alone rather than edit what we do not control.
                result.stats["collisions"] += 1
                self.logger.warning(
                    f"Pattern already held by an Indicator we do not own: {stix_id}"
                )
                return None
            if found is None:
                return self._promote(
                    entry, pattern, stix_id, score, indicator_types,
                    markings, author_id, result,
                )
            # Ours, but the based-on link is gone. Put it back.
            self.client.create_relationship(
                found["id"], observable_id, "based-on", score, author_id,
                [marking["id"] for marking in markings],
            )
            result.observables[found["id"]] = observable
            existing = found

        self._sync(existing, entry, score, indicator_types, markings, author_id, result)
        return existing["id"]

    def _promote(
        self,
        entry: Qualifying,
        pattern: str,
        stix_id: str,
        score: int,
        indicator_types: List[str],
        markings: List[Dict[str, Any]],
        author_id: Optional[str],
        result: CycleResult,
    ) -> Optional[str]:
        observable = entry.observable
        entity_type = observable["entity_type"]
        value = observable.get("observable_value") or pattern
        name = f"{entity_type}: {value}"[:_MAX_NAME_LENGTH]
        valid_from = entry.earliest_link or self.clock().isoformat()
        marking_ids = [marking["id"] for marking in markings]

        created = self.client.create_indicator(
            name=name,
            pattern=pattern,
            valid_from=valid_from,
            confidence=score,
            x_opencti_score=score,
            indicator_types=indicator_types,
            x_opencti_main_observable_type=entity_type,
            createdBy=author_id,
            objectMarking=marking_ids,
        )
        result.stats["promoted"] += 1

        if created is None:  # dry run
            now = self.clock().isoformat()
            result.previews.append(
                {
                    "id": None,
                    "standard_id": stix_id,
                    "name": name,
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "confidence": score,
                    "x_opencti_score": score,
                    "created": now,
                    "modified": now,
                    "valid_from": valid_from,
                    "valid_until": None,
                    "revoked": False,
                    "indicator_types": indicator_types,
                    "objectMarking": markings,
                    "objectLabel": [],
                    "observable": observable,
                }
            )
            return None

        indicator_id = created["id"]
        # Queued now, so it lands in a Grouping even if it is never exported.
        self.store.queue_grouping(grouping_day(self.clock()), [indicator_id])
        result.observables[indicator_id] = observable
        self.client.create_relationship(
            indicator_id, observable["id"], "based-on", score, author_id, marking_ids
        )
        for attack_pattern_id in sorted(entry.attack_pattern_ids):
            self.client.create_relationship(
                indicator_id, attack_pattern_id, "indicates", score,
                author_id, marking_ids,
            )
        return indicator_id

    # -- sync --------------------------------------------------------------

    def _sync(
        self,
        indicator: Dict[str, Any],
        entry: Qualifying,
        score: int,
        indicator_types: List[str],
        markings: List[Dict[str, Any]],
        author_id: Optional[str],
        result: CycleResult,
    ) -> None:
        indicator_id = indicator["id"]

        if indicator.get("revoked"):
            # Revocation stays final. Count it so the case is visible.
            result.stats["revoked_but_qualifying"] += 1
            self.logger.warning(f"Revoked Indicator qualifies again: {indicator_id}")
            return

        decay = self.store.get_decay(indicator_id)
        if decay:
            self.client.set_valid_until(indicator_id, decay.prior_valid_until)
            if not self.client.dry_run:
                self.store.clear_decay(indicator_id)
            result.stats["restored"] += 1

        if (
            indicator.get("x_opencti_score") != score
            or indicator.get("confidence") != score
            or sorted(indicator.get("indicator_types") or []) != sorted(indicator_types)
        ):
            self.client.update_assessment(indicator_id, score, indicator_types)

        # Markings only ever get added here. A raised observable marking must
        # reach the Indicator; a lowered one is left for an analyst to review.
        current = {marking["id"] for marking in indicator.get("objectMarking") or []}
        for marking in markings:
            if marking["id"] not in current:
                self.client.add_marking(indicator_id, marking["id"])

        edges = self.client.indicates_edges(indicator_id)
        marking_ids = sorted(current | {marking["id"] for marking in markings})
        for attack_pattern_id in sorted(entry.attack_pattern_ids - set(edges)):
            self.client.create_relationship(
                indicator_id, attack_pattern_id, "indicates", score,
                author_id, marking_ids,
            )
        for attack_pattern_id in sorted(set(edges) - entry.attack_pattern_ids):
            self.client.delete_relationship(edges[attack_pattern_id])

        result.stats["synced"] += 1

    # -- decay -------------------------------------------------------------

    def _handle_lapsed(
        self,
        indicator: Dict[str, Any],
        observable: Optional[Dict[str, Any]],
        result: CycleResult,
    ) -> None:
        indicator_id = indicator["id"]
        reason = REASON_NO_LONGER_QUALIFIES if observable else REASON_OBSERVABLE_MISSING
        now = self.clock()
        decay = self.store.get_decay(indicator_id)

        if decay is None:
            deadline = (now + timedelta(days=self.settings.decay_days)).isoformat()
            self.client.set_valid_until(indicator_id, deadline)
            if not self.client.dry_run:
                self.store.put_decay(
                    indicator_id,
                    DecayEntry(deadline, indicator.get("valid_until"), reason),
                )
            result.stats["decay_entered"] += 1
            result.decaying.add(indicator_id)
            self.logger.info(f"Decay entered: {indicator_id} ({reason})")
            return

        deadline_time = _parse_time(decay.deadline)
        if deadline_time is not None and deadline_time > now:
            result.decaying.add(indicator_id)
            return

        self.client.revoke(indicator_id)
        if not self.client.dry_run:
            self.store.clear_decay(indicator_id)
        result.stats["revoked"] += 1
        self.logger.info(f"Revoked: {indicator_id} ({decay.reason})")
