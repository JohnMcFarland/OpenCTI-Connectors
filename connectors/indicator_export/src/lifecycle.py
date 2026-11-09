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
from .inherit import EdgeKey, inherited_edges
from .labels import ObservableContext, build_context
from .opencti_client import OpenCTIClient, creator_id
from .patterns import build_pattern
from .scope import classify
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
    relationships: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
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
            "out_of_scope": 0,
            "inherited_edges": 0,
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

        qualifying = self._collect_qualifying(result)

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
            relationships = self.client.observable_relationships(observable_id)
            result.relationships[observable_id] = relationships
            result.contexts[observable_id] = build_context(observable_id, relationships)
        return result.contexts[observable_id]

    def _wanted_edges(
        self, entry: Qualifying, marking_ids: List[str], result: CycleResult
    ) -> Dict[EdgeKey, List[str]]:
        """Attack Pattern edges plus edges inherited from the observable.

        IE-INHERIT-EDGES-V1: an inherited edge carries the Indicator's markings
        plus those of the observable edge it came from.
        """
        base = set(marking_ids)
        wanted: Dict[EdgeKey, List[str]] = {
            ("indicates", ap_id): sorted(base) for ap_id in entry.attack_pattern_ids
        }
        observable_id = entry.observable["id"]
        self.context_for(observable_id, result)
        inherited = inherited_edges(observable_id, result.relationships.get(observable_id, []))
        for key, source_markings in inherited.items():
            wanted.setdefault(key, sorted(base | source_markings))
        return wanted

    # -- promotion ---------------------------------------------------------

    def _collect_qualifying(self, result: CycleResult) -> Dict[str, Qualifying]:
        qualifying: Dict[str, Qualifying] = {}
        dropped: Dict[str, Set[str]] = {}
        for relationship in self.client.qualifying_relationships():
            observable = relationship.get("from") or {}
            attack_pattern = relationship.get("to") or {}
            observable_id = observable.get("id")
            if not observable_id or not attack_pattern.get("id"):
                continue
            entity_type = observable.get("entity_type")
            if entity_type not in self.settings.allowed_observable_types:
                continue
            if entity_type in self.settings.excluded_observable_types:
                continue
            labels = {
                label.get("value", "") for label in observable.get("objectLabel") or []
            }
            if labels & self.settings.excluded_labels:
                continue
            # IE-SCOPE-FILTER-V1: drop reference material and non-routable
            # values; refang the value the pattern is built from.
            reason, value = classify(
                entity_type, observable.get("value"),
                self.settings.excluded_domains, self.settings.shared_hosting_domains,
            )
            if reason:
                dropped.setdefault(reason, set()).add(observable_id)
                continue
            if value != observable.get("value"):
                observable = {**observable, "value": value}
            entry = qualifying.setdefault(observable_id, Qualifying(observable))
            entry.attack_pattern_ids.add(attack_pattern["id"])
            linked = relationship.get("created_at")
            if linked and (entry.earliest_link is None or linked < entry.earliest_link):
                entry.earliest_link = linked
        result.stats["out_of_scope"] = sum(len(ids) for ids in dropped.values())
        if dropped:
            detail = ", ".join(f"{k}={len(v)}" for k, v in sorted(dropped.items()))
            self.logger.info(f"Out of scope, not promoted: {detail}")
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
        # IE-VALIDFROM-NOW-V1: valid_from is creation time. OpenCTI derives
        # valid_until and the decay start from valid_from, so a backdated
        # value creates the Indicator already expired (born revoked).
        valid_from = self.clock().isoformat()
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
            # Count the inherited edges a live run would create.
            wanted = self._wanted_edges(entry, marking_ids, result)
            result.stats["inherited_edges"] += sum(
                1 for _, target in wanted if target not in entry.attack_pattern_ids
            )
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
        self._sync_edges(indicator_id, entry, marking_ids, score, author_id, result)
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

        # IE-DECAY-BASESCORE-V1: platform decay lowers x_opencti_score over
        # time and ignores an update back to the base score. Compare against
        # decay_base_score so only a changed Diamond assessment is written.
        base_score = indicator.get("decay_base_score")
        current_score = base_score if base_score is not None else indicator.get("x_opencti_score")
        if (
            current_score != score
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

        marking_ids = sorted(current | {marking["id"] for marking in markings})
        self._sync_edges(indicator_id, entry, marking_ids, score, author_id, result)

        result.stats["synced"] += 1

    def _sync_edges(
        self,
        indicator_id: str,
        entry: Qualifying,
        marking_ids: List[str],
        score: int,
        author_id: Optional[str],
        result: CycleResult,
    ) -> None:
        """Match managed edges to the wanted set: indicates to qualifying
        Attack Patterns, plus edges inherited from the observable.

        Edges are revoked, never deleted, and only edges this connector
        authored are touched. An analyst's edge to one of our Indicators is
        left alone in both directions.
        """
        wanted = self._wanted_edges(entry, marking_ids, result)
        edges = self.client.managed_edges(indicator_id)
        for key in sorted(set(wanted) | set(edges)):
            relationship_type, target_id = key
            existing = edges.get(key, [])
            ours = [e for e in existing if author_id and e["creator"] == author_id]
            if key in wanted:
                if any(not e["revoked"] for e in existing):
                    continue
                if ours:
                    # Came back: restore our old edge rather than mint a second.
                    self.client.set_relationship_revoked(ours[0]["id"], False)
                    continue
                if existing:
                    # Only someone else's revoked edge. Their call, not ours.
                    continue
                self.client.create_relationship(
                    indicator_id, target_id, relationship_type, score,
                    author_id, wanted[key],
                )
                if target_id not in entry.attack_pattern_ids:
                    result.stats["inherited_edges"] += 1
            else:
                for edge in ours:
                    if not edge["revoked"]:
                        self.client.set_relationship_revoked(edge["id"], True)

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
