"""
connector.py — ObservableGate Connector Logic

Implements the two-pass promotion and reconciliation cycle that enforces
the platform's minimum Indicator quality standard:

    No Indicator may exist unless it is based-on an Observable that has
    a confirmed Related To -> Attack Pattern relationship.

The Attack Pattern (capability) paired with the Observable (infrastructure,
in Diamond Model terms) is the minimum viable Indicator: it establishes that
the observable was used in a way that maps to a known adversary technique.

Pass 1 — Promotion:
    Queries all Observables with AP relationships. Creates Indicators for
    those that do not yet have one. Syncs indicates edges and confidence
    for Observables whose Indicator already exists.

Pass 2 — Reconciliation:
    Queries all connector-owned non-revoked Indicators. Verifies that each
    still has a qualifying Observable with AP relationships. Manages the
    decay lifecycle: entering decay (valid_until = now + DECAY_DAYS),
    maintaining it, restoring from it, or revoking after the window elapses.

Confidence model:
    Floor (GATE_CONFIDENCE_FLOOR, default 15):
        Attack Pattern context only. Technique identified; no adversary
        attribution or victim targeting context.
    Ceiling (GATE_CONFIDENCE_CEILING, default 85):
        Attack Pattern + Malware, Intrusion-Set, Threat-Actor-Group,
        Organization, or Individual relationship on the same Observable.
        Attribution or targeting context is present.

Indicator types (STIX indicator_types field):
    "anomalous-activity" at floor confidence — technique present, no actor.
    "malicious-activity" at ceiling confidence — actor/victim context confirmed.

Decay reason codes (structured for log aggregation):
    OBSERVABLE_DELETED:      Source Observable no longer exists.
    AP_RELATIONSHIP_REMOVED: Observable exists but has no AP relationships.
    INDICATES_EMPTY:         All indicates edges removed during sync.
    DECAY_RESTORED:          Condition re-met during decay window.
    DECAY_ACTIVE:            Within decay window, no action required.
    DECAY_ELAPSED:           Decay window elapsed; revocation applied.
"""

import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set

from config import ObservableGateConfig
from pattern_builder import build_pattern
from api_client import ObservableGateAPIClient

# Structured reason codes for all reconciliation lifecycle events.
# Use these constants in log messages; never inline the strings.
REASON_OBSERVABLE_DELETED   = "OBSERVABLE_DELETED"
REASON_AP_REMOVED           = "AP_RELATIONSHIP_REMOVED"
REASON_INDICATES_EMPTY      = "INDICATES_EMPTY"
REASON_DECAY_RESTORED       = "DECAY_RESTORED"
REASON_DECAY_ACTIVE         = "DECAY_ACTIVE"
REASON_DECAY_ELAPSED        = "DECAY_ELAPSED"

# Maps OpenCTI entity_type to x_opencti_main_observable_type.
# This drives how the Indicator is displayed and filtered in the platform UI.
# Matches the entity_type keys used in OpenCTI 6.9.x.
_MAIN_OBSERVABLE_TYPE_MAP: Dict[str, str] = {
    "IPv4-Addr":            "IPv4-Addr",
    "IPv6-Addr":            "IPv6-Addr",
    "Domain-Name":          "Domain-Name",
    "Url":                  "Url",
    "Email-Addr":           "Email-Addr",
    "Mutex":                "Mutex",
    "Windows-Registry-Key": "Windows-Registry-Key",
    "User-Account":         "User-Account",
    "Autonomous-System":    "Autonomous-System",
    "StixFile":             "StixFile",
    "X509-Certificate":     "X509-Certificate",
    "Software":             "Software",
    "Mac-Addr":             "Mac-Addr",
    "Directory":            "Directory",
}


class ObservableGateConnector:
    """
    ObservableGate: promotion gate enforcing minimum Indicator quality.

    This connector is a lifecycle manager, not an intelligence author. It
    does not create Observables, Attack Patterns, or adversary relationships.
    It examines existing graph state and promotes Observable-Attack Pattern
    pairs to Indicators when the condition is met, maintaining those Indicators
    as the underlying graph state evolves.

    Args:
        helper: Initialized OpenCTIConnectorHelper instance.
        config: ObservableGateConfig with all operational parameters.
    """

    def __init__(self, helper, config: ObservableGateConfig):
        self.helper = helper
        self.config = config
        self.client = ObservableGateAPIClient(helper, config)

    def run(self) -> None:
        """
        Main execution loop. Runs indefinitely, one cycle per GATE_POLL_INTERVAL.

        Resolves the connector identity at startup to fail fast on token
        misconfiguration before the first cycle begins.

        Each cycle is wrapped in a work item for visibility in the OpenCTI
        connector panel. work.to_processed() fires in the finally block of
        each cycle to guarantee the work item is always closed regardless
        of cycle outcome.
        """
        self.helper.log_info(
            f"ObservableGate starting. "
            f"Poll interval: {self.config.poll_interval}s | "
            f"Dry run: {self.config.dry_run} | "
            f"Decay days: {self.config.decay_days} | "
            f"Confidence floor: {self.config.confidence_floor} | "
            f"Confidence ceiling: {self.config.confidence_ceiling}"
        )

        # Resolve and cache the connector identity at startup. Fails fast if
        # the token is misconfigured rather than discovering the error mid-cycle.
        self.client.get_connector_identity_id()

        while True:
            work_id: Optional[str] = None
            cycle_message: str = "Cycle completed."
            cycle_error: bool = False

            try:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id,
                    f"ObservableGate cycle — "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
                )

                stats = self._execute_cycle()

                cycle_message = (
                    f"Cycle complete. "
                    f"Promoted: {stats['promoted']} | "
                    f"Synced: {stats['synced']} | "
                    f"Decay entered: {stats['decay_entered']} | "
                    f"Restored: {stats['restored']} | "
                    f"Revoked: {stats['revoked']} | "
                    f"Errors: {stats['errors']}"
                )
                self.helper.log_info(cycle_message)

                self.helper.set_state(
                    {
                        "last_run": datetime.now(timezone.utc).isoformat(),
                        "last_stats": stats,
                    }
                )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("ObservableGate received shutdown signal.")
                cycle_message = "Shutdown during cycle."
                cycle_error = True
                raise

            except Exception as e:
                cycle_message = f"Unhandled cycle error: {e}"
                cycle_error = True
                self.helper.log_error(cycle_message)

            finally:
                # work.to_processed() must always fire — per project constraint.
                if work_id:
                    try:
                        self.helper.api.work.to_processed(
                            work_id, cycle_message, in_error=cycle_error
                        )
                    except Exception as e:
                        self.helper.log_error(
                            f"Failed to close work item {work_id}: {e}"
                        )

            self.helper.log_info(
                f"Sleeping {self.config.poll_interval}s until next cycle."
            )
            time.sleep(self.config.poll_interval)

    # ------------------------------------------------------------------
    # Cycle orchestration
    # ------------------------------------------------------------------

    def _execute_cycle(self) -> Dict[str, int]:
        """
        Execute one full promotion + reconciliation cycle.

        Runs Pass 1 (promotion) followed by Pass 2 (reconciliation).
        Pass 2 must always follow Pass 1 in the same cycle: it is the
        mechanism that catches AP relationships removed between runs and
        manages the decay lifecycle for affected Indicators.

        Per-entity exceptions are caught and counted rather than aborting
        the run. If the error count exceeds GATE_MAX_ERRORS, the current
        pass is aborted to prevent cascading API failures.

        Returns:
            Stats dict with keys: promoted, synced, decay_entered, restored,
            revoked, errors.
        """
        stats: Dict[str, int] = {
            "promoted":      0,
            "synced":        0,
            "decay_entered": 0,
            "restored":      0,
            "revoked":       0,
            "errors":        0,
        }

        # ------------------------------------------------------------------
        # Pass 1: Promotion
        # ------------------------------------------------------------------
        self.helper.log_info("=== Pass 1: Promotion ===")
        qualifying = self.client.get_qualifying_observables()

        for observable_id, obs_data in qualifying.items():
            if stats["errors"] >= self.config.max_errors:
                self.helper.log_error(
                    f"Max error threshold ({self.config.max_errors}) reached. "
                    "Aborting promotion pass."
                )
                break
            try:
                action = self._process_qualifying_observable(
                    observable_id, obs_data
                )
                if action in stats:
                    stats[action] += 1
            except Exception as e:
                stats["errors"] += 1
                self.helper.log_error(
                    f"[Pass 1] Error on observable {observable_id}: {e}"
                )

        # ------------------------------------------------------------------
        # Pass 2: Reconciliation
        # ------------------------------------------------------------------
        self.helper.log_info("=== Pass 2: Reconciliation ===")
        connector_indicators = self.client.get_connector_indicators()

        for indicator in connector_indicators:
            if stats["errors"] >= self.config.max_errors:
                self.helper.log_error(
                    f"Max error threshold ({self.config.max_errors}) reached. "
                    "Aborting reconciliation pass."
                )
                break
            try:
                action = self._reconcile_indicator(indicator)
                if action in stats:
                    stats[action] += 1
            except Exception as e:
                stats["errors"] += 1
                self.helper.log_error(
                    f"[Pass 2] Error on indicator {indicator.get('id')}: {e}"
                )

        return stats

    # ------------------------------------------------------------------
    # Pass 1: Per-observable promotion logic
    # ------------------------------------------------------------------

    def _process_qualifying_observable(
        self,
        observable_id: str,
        obs_data: Dict[str, Any],
    ) -> str:
        """
        Process one qualifying observable in the promotion pass.

        Determines whether a connector-owned Indicator already exists.
        If not, promotes the observable by creating an Indicator, a based-on
        link, and indicates edges for all qualifying Attack Patterns.
        If yes, syncs indicates edges and updates confidence.

        Args:
            observable_id: Internal ID of the observable.
            obs_data:      Aggregated data dict from get_qualifying_observables.

        Returns:
            Action string: "promoted", "synced".

        Raises:
            RuntimeError: If Indicator creation fails (propagates to the
                          error counter in _execute_cycle).
        """
        observable = obs_data["observable"]
        attack_patterns = obs_data["attack_patterns"]
        earliest_rel_date = obs_data["earliest_rel_date"]

        entity_type = observable.get("entity_type", "Unknown")

        # Attempt to build the STIX pattern. None = unsupported type or
        # missing value fields. Log and skip rather than raise.
        pattern = build_pattern(observable)
        if pattern is None:
            self.helper.log_info(
                f"[Pass 1] Cannot build pattern for {entity_type} "
                f"({observable_id}). Skipping."
            )
            # Not an error — just an observable that cannot be patterned.
            return "synced"

        # Determine confidence from adversary/victim context.
        confidence = self._determine_confidence(observable_id)

        # Select indicator_types based on confidence level.
        # malicious-activity: adversary or victim context confirms the use was malicious.
        # anomalous-activity: technique only; use may be malicious but unattributed.
        indicator_types = (
            ["malicious-activity"]
            if confidence == self.config.confidence_ceiling
            else ["anomalous-activity"]
        )

        # Resolve the most restrictive marking from the source observable.
        markings = self.client.get_most_restrictive_marking_ids(
            observable.get("objectMarking") or []
        )

        # Resolve x_opencti_main_observable_type for the Indicator.
        main_observable_type = _MAIN_OBSERVABLE_TYPE_MAP.get(entity_type, entity_type)

        # Check for an existing connector-owned Indicator.
        existing = self.client.get_existing_indicator(observable_id)

        if existing is None:
            return self._promote_observable(
                observable_id=observable_id,
                entity_type=entity_type,
                pattern=pattern,
                attack_patterns=attack_patterns,
                earliest_rel_date=earliest_rel_date,
                confidence=confidence,
                indicator_types=indicator_types,
                main_observable_type=main_observable_type,
                markings=markings,
            )
        else:
            return self._sync_existing_indicator(
                indicator=existing,
                attack_patterns=attack_patterns,
                confidence=confidence,
                indicator_types=indicator_types,
            )

    def _promote_observable(
        self,
        observable_id: str,
        entity_type: str,
        pattern: str,
        attack_patterns: List[Dict[str, Any]],
        earliest_rel_date: Optional[str],
        confidence: int,
        indicator_types: List[str],
        main_observable_type: str,
        markings: List[str],
    ) -> str:
        """
        Create a new Indicator for a qualifying observable.

        Creates three things atomically (as separate API calls):
        1. The Indicator entity itself.
        2. A based-on relationship: Indicator -> Observable.
        3. An indicates relationship for each qualifying Attack Pattern.

        All three are required for a well-formed Indicator under this
        platform's minimum Indicator standard. If the Indicator creation
        fails, the based-on and indicates calls are not attempted.

        valid_from is set to the earliest AP relationship creation date,
        accurately reflecting when the observable first became associated
        with a known technique rather than when the connector processed it.

        Args:
            observable_id:       Internal ID of the observable.
            entity_type:         OpenCTI entity_type string.
            pattern:             STIX 2.1 pattern string.
            attack_patterns:     List of AP dicts with 'id' and 'name'.
            earliest_rel_date:   ISO string of earliest AP relationship date.
            confidence:          Confidence score.
            indicator_types:     STIX indicator_types list.
            main_observable_type: x_opencti_main_observable_type value.
            markings:            List of marking definition IDs.

        Returns:
            "promoted"

        Raises:
            RuntimeError: If Indicator creation returns None (API failure).
        """
        # Fallback for the rare case where no relationship date is available.
        valid_from = earliest_rel_date or datetime.now(timezone.utc).isoformat()

        name = self._build_indicator_name(entity_type, pattern)

        self.helper.log_info(
            f"[Pass 1] Promoting {entity_type} {observable_id}: "
            f"'{name}' | confidence={confidence} | APs={len(attack_patterns)}"
        )

        indicator = self.client.create_indicator(
            name=name,
            pattern=pattern,
            valid_from=valid_from,
            confidence=confidence,
            indicator_types=indicator_types,
            main_observable_type=main_observable_type,
            marking_ids=markings,
        )

        if indicator is None:
            raise RuntimeError(
                f"Indicator creation returned None for observable {observable_id}. "
                "See preceding API error log for detail."
            )

        indicator_id = indicator["id"]

        # based-on: Indicator -> Observable (mandatory; the condition link).
        self.client.create_relationship(
            from_id=indicator_id,
            to_id=observable_id,
            relationship_type="based-on",
            confidence=confidence,
            marking_ids=markings,
        )

        # indicates: Indicator -> Attack Pattern (one per qualifying AP).
        for ap in attack_patterns:
            self.client.create_relationship(
                from_id=indicator_id,
                to_id=ap["id"],
                relationship_type="indicates",
                confidence=confidence,
                marking_ids=markings,
            )

        return "promoted"

    def _sync_existing_indicator(
        self,
        indicator: Dict[str, Any],
        attack_patterns: List[Dict[str, Any]],
        confidence: int,
        indicator_types: List[str],
    ) -> str:
        """
        Sync an existing connector-owned Indicator with current observable state.

        Actions performed:
        - Clears valid_until if the Indicator is in decay but the observable
          is still qualifying (condition was re-met; decay should not be active).
        - Updates confidence if the adversary/victim context has changed.
        - Adds missing indicates edges for Attack Patterns added since creation.

        Stale indicates edge removal is handled exclusively in Pass 2
        (reconciliation), which has the authoritative current AP set.

        Args:
            indicator:       Existing Indicator dict from get_existing_indicator.
            attack_patterns: Current AP list from the observable.
            confidence:      Current computed confidence score.
            indicator_types: Current STIX indicator type list.

        Returns:
            "synced"
        """
        indicator_id = indicator["id"]

        # An observable in the Pass 1 working set has a qualifying condition.
        # If valid_until is set, the decay was entered in a previous cycle
        # when the condition lapsed, and the condition has since been restored.
        if indicator.get("valid_until"):
            self.helper.log_info(
                f"[Pass 1] {REASON_DECAY_RESTORED}: Indicator {indicator_id} "
                "is in decay but observable is qualifying. Clearing valid_until."
            )
            self.client.clear_indicator_valid_until(indicator_id)

        # Update confidence if the adversary/victim context has changed.
        if indicator.get("confidence") != confidence:
            self.helper.log_info(
                f"[Pass 1] Confidence update on {indicator_id}: "
                f"{indicator.get('confidence')} -> {confidence}"
            )
            self.client.update_indicator_confidence(indicator_id, confidence)

        # Add any indicates edges for Attack Patterns added since the
        # Indicator was created. Missing = present on observable, absent on Indicator.
        current_ap_ids: Set[str] = {
            ap["id"]
            for ap in self.client.get_indicator_indicates_aps(indicator_id)
        }
        expected_ap_ids: Set[str] = {ap["id"] for ap in attack_patterns}
        missing_ap_ids = expected_ap_ids - current_ap_ids

        if missing_ap_ids:
            markings = [m["id"] for m in (indicator.get("objectMarking") or [])]
            for ap_id in missing_ap_ids:
                self.helper.log_info(
                    f"[Pass 1] Adding missing indicates edge: "
                    f"{indicator_id} -> {ap_id}"
                )
                self.client.create_relationship(
                    from_id=indicator_id,
                    to_id=ap_id,
                    relationship_type="indicates",
                    confidence=confidence,
                    marking_ids=markings,
                )

        return "synced"

    # ------------------------------------------------------------------
    # Pass 2: Per-indicator reconciliation logic
    # ------------------------------------------------------------------

    def _reconcile_indicator(self, indicator: Dict[str, Any]) -> str:
        """
        Reconcile one connector-owned Indicator against current graph state.

        Evaluates whether the qualifying condition still holds:
        - Observable exists (based-on link resolves)
        - Observable has at least one Related To -> Attack Pattern relationship

        Manages the decay lifecycle based on condition state. Also performs
        indicates edge cleanup: removes edges pointing to Attack Patterns that
        are no longer related to the source Observable.

        Args:
            indicator: Indicator dict from get_connector_indicators.

        Returns:
            Action string for stats counting. One of:
            "decay_entered", "restored", "revoked", "synced".
        """
        indicator_id = indicator["id"]
        valid_until = indicator.get("valid_until")

        # Resolve the source observable via the based-on link.
        observable = self.client.get_indicator_based_on_observable(indicator_id)

        if observable is None:
            # based-on link is broken: observable was deleted or the relationship
            # was explicitly removed.
            return self._handle_condition_lapsed(
                indicator_id, valid_until, REASON_OBSERVABLE_DELETED
            )

        observable_id = observable.get("id")

        # Get current AP relationships on the source observable.
        current_aps = self.client.get_observable_ap_relationships(observable_id)

        if not current_aps:
            # Observable exists but has no AP relationships.
            return self._handle_condition_lapsed(
                indicator_id, valid_until, REASON_AP_REMOVED
            )

        # ------------------------------------------------------------------
        # Condition is met. Handle restoration from decay if applicable.
        # ------------------------------------------------------------------
        action = "synced"

        if valid_until:
            # Indicator is in decay but condition still holds. This occurs when
            # an AP relationship was briefly removed and re-added between cycles.
            self.helper.log_info(
                f"[Pass 2] {REASON_DECAY_RESTORED}: Indicator {indicator_id} "
                "condition is met during decay window. Clearing valid_until."
            )
            self.client.clear_indicator_valid_until(indicator_id)
            action = "restored"

        # ------------------------------------------------------------------
        # Sync indicates edges: remove any pointing to APs no longer on the
        # observable. These are stale edges from AP relationships that were
        # subsequently removed from the observable.
        # ------------------------------------------------------------------
        current_ap_ids_on_observable: Set[str] = {ap["id"] for ap in current_aps}
        current_indicates_aps = self.client.get_indicator_indicates_aps(indicator_id)
        current_indicates_ids: Set[str] = {ap["id"] for ap in current_indicates_aps}

        stale_ap_ids = current_indicates_ids - current_ap_ids_on_observable
        for ap_id in stale_ap_ids:
            self.helper.log_info(
                f"[Pass 2] Removing stale indicates edge: "
                f"{indicator_id} -> {ap_id}"
            )
            self.client.delete_relationship(
                from_id=indicator_id,
                to_id=ap_id,
                relationship_type="indicates",
            )

        # If all indicates edges were removed, the Indicator has no technique
        # context remaining. Treat as condition lapsed even though the observable
        # and its AP relationships still exist. This guards against a race where
        # Pass 1 added the indicates edges in the same cycle they were just removed.
        remaining_indicates = current_indicates_ids - stale_ap_ids
        if not remaining_indicates:
            return self._handle_condition_lapsed(
                indicator_id, valid_until, REASON_INDICATES_EMPTY
            )

        # ------------------------------------------------------------------
        # Re-evaluate and sync confidence.
        # Pass 2 is the authoritative confidence sync: it has the full
        # current state of the observable's relationships available.
        # ------------------------------------------------------------------
        new_confidence = self._determine_confidence(observable_id)
        if indicator.get("confidence") != new_confidence:
            self.helper.log_info(
                f"[Pass 2] Confidence sync on {indicator_id}: "
                f"{indicator.get('confidence')} -> {new_confidence}"
            )
            self.client.update_indicator_confidence(indicator_id, new_confidence)

        return action

    def _handle_condition_lapsed(
        self,
        indicator_id: str,
        valid_until: Optional[str],
        reason: str,
    ) -> str:
        """
        Manage the decay lifecycle when the qualifying condition has lapsed.

        Three states based on valid_until:
        - Not set: enter decay (set valid_until = now + DECAY_DAYS).
        - Set and future: decay is active, log progress, no action.
        - Set and past: decay elapsed, revoke the Indicator.

        Args:
            indicator_id: Internal ID of the Indicator.
            valid_until:  Current valid_until value (ISO string or None).
            reason:       Reason code explaining why the condition lapsed.

        Returns:
            "decay_entered" | "revoked" | "synced" (decay active, no change).
        """
        now = datetime.now(timezone.utc)

        if valid_until is None:
            # First cycle with lapsed condition: enter decay.
            expiry = now + timedelta(days=self.config.decay_days)
            expiry_str = expiry.isoformat()

            self.helper.log_warning(
                f"[Pass 2] DECAY ENTERED: indicator={indicator_id} | "
                f"reason={reason} | expiry={expiry_str}"
            )
            self.client.set_indicator_valid_until(indicator_id, expiry_str)
            return "decay_entered"

        # Parse the existing valid_until.
        try:
            expiry_dt = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            # Unparseable valid_until: treat as elapsed to avoid a permanently
            # indeterminate decay state. Log clearly so the anomaly is visible.
            self.helper.log_warning(
                f"[Pass 2] Unparseable valid_until on {indicator_id}: "
                f"'{valid_until}'. Treating as elapsed and revoking."
            )
            self.client.revoke_indicator(indicator_id, reason)
            return "revoked"

        if expiry_dt > now:
            # Still within decay window.
            days_remaining = (expiry_dt - now).days
            self.helper.log_info(
                f"[Pass 2] {REASON_DECAY_ACTIVE}: indicator={indicator_id} | "
                f"reason={reason} | days_remaining={days_remaining}"
            )
            return "synced"

        # Decay window has elapsed. Revoke.
        self.helper.log_warning(
            f"[Pass 2] {REASON_DECAY_ELAPSED}: indicator={indicator_id} | "
            f"reason={reason} | expired={valid_until}"
        )
        self.client.revoke_indicator(indicator_id, reason)
        return "revoked"

    # ------------------------------------------------------------------
    # Confidence determination
    # ------------------------------------------------------------------

    def _determine_confidence(self, observable_id: str) -> int:
        """
        Determine the Indicator confidence score for an observable.

        Binary model:
        - GATE_CONFIDENCE_CEILING if adversary or victim context is present.
        - GATE_CONFIDENCE_FLOOR otherwise.

        Adversary types: Malware, Intrusion-Set, Threat-Actor-Group.
        Victim types: Organization, Individual.
        Tool: excluded (see config.py class docstring for rationale).

        The min_rel_confidence from the AP relationship is not used in the
        current binary model; confidence is a function of context richness,
        not relationship quality. It is available in obs_data for future
        threshold extensions without requiring a schema change.

        Args:
            observable_id: Internal ID of the observable.

        Returns:
            GATE_CONFIDENCE_FLOOR or GATE_CONFIDENCE_CEILING.
        """
        has_context = self.client.has_adversary_or_victim(observable_id)
        return (
            self.config.confidence_ceiling
            if has_context
            else self.config.confidence_floor
        )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _build_indicator_name(self, entity_type: str, pattern: str) -> str:
        """
        Build a human-readable Indicator name from entity type and pattern.

        Prefixed with "ObservableGate:" to make connector-owned Indicators
        immediately identifiable in list views. The pattern value is truncated
        to 80 characters to keep names manageable without losing meaningful
        identification information.

        Args:
            entity_type: OpenCTI entity_type string.
            pattern:     Full STIX 2.1 pattern string.

        Returns:
            Name string: "ObservableGate: {entity_type} ({pattern[:80]})"
        """
        truncated = pattern if len(pattern) <= 80 else pattern[:77] + "..."
        return f"ObservableGate: {entity_type} ({truncated})"
