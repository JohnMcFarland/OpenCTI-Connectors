"""
config.py — ObservableGate Connector Configuration

Loads all operational parameters from environment variables. Required
variables raise ValueError at startup, preventing silent misconfiguration.
No defaults carry sensitive values.
"""

import os


class ObservableGateConfig:
    """
    Configuration for the ObservableGate connector.

    All values sourced exclusively from environment variables. The connector
    fails explicitly on missing required configuration rather than silently
    using incorrect values.

    Class-level frozensets define the entity types used in confidence
    determination. These are not configurable — they reflect deliberate
    data model decisions documented in the design spec:

    ADVERSARY_ENTITY_TYPES:
        Malware, Intrusion-Set, Threat-Actor-Group. Presence of any of
        these on an Observable elevates confidence to ceiling. Tool is
        intentionally excluded: Tool lacks inherent adversary character
        without an Attack Pattern, and Attack Pattern is already the
        mandatory base condition for promotion — Tool adds no signal.

    VICTIM_ENTITY_TYPES:
        Organization, Individual. Victim targeting context provides the
        same confidence elevation as adversary attribution — it confirms
        the observable was used against a specific target, not just that
        a technique was identified.

    HARDCODED_EXCLUSIONS:
        Network-Traffic is always excluded. Its STIX 2.1 pattern requires
        compound construction referencing embedded object references,
        incompatible with most detection consumers without transformation.
        Promote constituent IP observables instead.
    """

    ADVERSARY_ENTITY_TYPES: frozenset = frozenset([
        "Malware",
        "Intrusion-Set",
        "Threat-Actor-Group",
    ])

    VICTIM_ENTITY_TYPES: frozenset = frozenset([
        "Organization",
        "Individual",
    ])

    HARDCODED_EXCLUSIONS: frozenset = frozenset(["Network-Traffic", "Persona"])

    def __init__(self):
        # ------------------------------------------------------------------
        # OpenCTI platform connection
        # ------------------------------------------------------------------
        self.opencti_base_url: str = self._require("OPENCTI_BASE_URL")
        self.opencti_token: str = self._require("OPENCTI_TOKEN")

        # ------------------------------------------------------------------
        # Connector registration (used by pycti OpenCTIConnectorHelper)
        # ------------------------------------------------------------------
        self.connector_id: str = self._require("CONNECTOR_ID")
        self.connector_name: str = os.environ.get(
            "CONNECTOR_NAME", "ObservableGate"
        )
        # CONNECTOR_SCOPE is unused for routing (this connector drives its own
        # poll loop) but required by pycti for registration.
        self.connector_scope: str = os.environ.get(
            "CONNECTOR_SCOPE", "application/json"
        )
        self.connector_log_level: str = os.environ.get(
            "CONNECTOR_LOG_LEVEL", "info"
        )

        # ------------------------------------------------------------------
        # Polling configuration
        # ------------------------------------------------------------------
        # Seconds between full promotion + reconciliation cycles.
        self.poll_interval: int = int(os.environ.get("GATE_POLL_INTERVAL", "3600"))

        # ------------------------------------------------------------------
        # Confidence bounds
        #
        # Floor: Attack Pattern context only (technique identified, no actor
        #        attribution or victim targeting confirmed). Matches the
        #        platform OSINT baseline of 15.
        # Ceiling: Attack Pattern + adversary or victim relationship present.
        #          Set to 85 to reserve the top confidence band for indicators
        #          that have undergone explicit analyst review.
        # ------------------------------------------------------------------
        self.confidence_floor: int = int(
            os.environ.get("GATE_CONFIDENCE_FLOOR", "15")
        )
        self.confidence_ceiling: int = int(
            os.environ.get("GATE_CONFIDENCE_CEILING", "85")
        )

        # ------------------------------------------------------------------
        # Decay lifecycle
        # ------------------------------------------------------------------
        # Days before a decaying Indicator (condition lapsed) is revoked.
        # During this window the Indicator's valid_until field signals
        # downstream consumers that the detection rule is sunset.
        self.decay_days: int = int(os.environ.get("GATE_DECAY_DAYS", "30"))

        # ------------------------------------------------------------------
        # Operational safety controls
        # ------------------------------------------------------------------
        # Dry run: log all would-be actions without committing any.
        # First run in any new environment must be a dry run.
        self.dry_run: bool = (
            os.environ.get("GATE_DRY_RUN", "false").lower() == "true"
        )

        # Per-cycle error threshold. If exceeded, the current pass is aborted
        # to prevent a broken graph state from cascading into thousands of
        # failed API calls.
        self.max_errors: int = int(os.environ.get("GATE_MAX_ERRORS", "50"))

        # ------------------------------------------------------------------
        # Observable type exclusions
        # ------------------------------------------------------------------
        # GATE_EXCLUDED_OBSERVABLE_TYPES: comma-separated entity_type values
        # to exclude in addition to the hardcoded Network-Traffic exclusion.
        # Example: "Process,Directory"
        extra_raw: str = os.environ.get("GATE_EXCLUDED_OBSERVABLE_TYPES", "")
        extra_types: set = {t.strip() for t in extra_raw.split(",") if t.strip()}
        self.excluded_observable_types: frozenset = (
            self.HARDCODED_EXCLUSIONS | frozenset(extra_types)
        )

        # GATE_EXCLUDED_LABELS: comma-separated label value strings.
        # Any observable carrying at least one of these labels will be skipped
        # during the promotion pass, regardless of type or AP relationships.
        # Example: "Dummy Data,Test,Sandbox"
        labels_raw: str = os.environ.get("GATE_EXCLUDED_LABELS", "")
        self.excluded_labels: frozenset = frozenset(
            lbl.strip() for lbl in labels_raw.split(",") if lbl.strip()
        )

    def _require(self, key: str) -> str:
        """
        Retrieve a required environment variable, failing fast if absent.

        Args:
            key: Environment variable name.

        Returns:
            Stripped string value.

        Raises:
            ValueError: If the variable is absent or evaluates to an empty string.
        """
        value = os.environ.get(key, "").strip()
        if not value:
            raise ValueError(
                f"Required environment variable '{key}' is not set or empty. "
                "Verify your docker-compose.override.yml."
            )
        return value
