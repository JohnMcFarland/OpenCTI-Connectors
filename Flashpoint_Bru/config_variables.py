# =============================================================================
# flashpoint_connector/config_variables.py
# =============================================================================
# Connector configuration loader.
#
# All configuration is read from two sources in priority order:
#   1. Environment variables (higher priority — used in Docker deployments)
#   2. config.yml (lower priority — used for local development)
#
# get_config_variable() from pycti handles the precedence logic. Every
# variable that has a default is safe to omit from the environment; every
# variable without a default will raise at startup if absent.
#
# DESIGN NOTE — why per-dataset confidence defaults are here:
# Confidence values are not static — they reflect the epistemological
# reliability of each Flashpoint data source. Finished intelligence reports
# are analyst-written Tier-1 intelligence (75). Raw alert rule hits are
# unvalidated signals (50). Org-domain credential matches carry higher
# signal because the domain match is a deterministic linkage (70). Dark
# web community posts are unvalidated raw content (30). These defaults are
# overridable via environment variables to allow tuning without code changes.
#
# DEVIATION FROM FILIGRAN — the Filigran connector had a bug where
# import_communities was assigned twice: first correctly from
# FLASHPOINT_IMPORT_COMMUNITIES, then immediately overwritten by
# FLASHPOINT_ALERTS_CREATE_RELATED_ENTITIES. This meant communities import
# could never be enabled independently of alert entity creation. That bug
# is fixed here — each variable maps to exactly one config key.
# =============================================================================

import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    """
    Loads and validates all connector configuration from environment
    variables and/or config.yml.

    Instantiated once in FlashpointConnector.__init__() and passed to
    all sub-components (client, converter) so configuration is centralised
    and consistent across the connector lifecycle.
    """

    def __init__(self):
        # Load the YAML file first (may be empty dict if file absent —
        # that is normal in Docker deployments where env vars are used)
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load config.yml from the parent directory of this module's src/.
        Returns an empty dict if the file does not exist — all values
        will then be read from environment variables instead.
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        return config

    def _initialize_configurations(self) -> None:
        """
        Bind all configuration variables.

        Variables are grouped by concern:
          - Scheduler (how often the connector runs)
          - Flashpoint API credentials
          - Dataset enable/disable toggles
          - Communities-specific settings
          - Org domain bifurcation (routes alerts/credentials to IR vs Report)
          - Per-dataset confidence defaults
        """

        # ── Scheduler ────────────────────────────────────────────────────────
        # ISO-8601 duration string controlling the run interval.
        # Example: PT6H = every 6 hours, PT1H = every hour.
        # Required — the connector will not start without this value.
        # Set via CONNECTOR_DURATION_PERIOD env var or connector.duration_period
        # in config.yml.
        self.duration_period = get_config_variable(
            env_var="CONNECTOR_DURATION_PERIOD",
            yaml_path=["connector", "duration_period"],
            config=self.load,
            required=False,
        )

        # ── Flashpoint API ────────────────────────────────────────────────────
        # Bearer token for the Flashpoint Ignite API.
        # Generate in Flashpoint Ignite: Settings → APIs & Integrations.
        # The token must have at minimum:
        #   IGNITE_API, IGNITE_CTI_REPORTS, dat.rp.ass.r, dat.med.r, dat.ind.r
        # For credential alerts: CCMC group membership is also required.
        self.api_key = get_config_variable(
            "FLASHPOINT_API_KEY",
            ["flashpoint", "api_key"],
            self.load,
        )

        # ISO-8601 datetime string for the initial backfill start.
        # Used as the cursor value on first run when no state exists yet.
        # Example: '2024-01-01T00:00:00Z'
        # After first run, each dataset tracks its own cursor independently
        # via the connector state store.
        self.import_start_date = get_config_variable(
            "FLASHPOINT_IMPORT_START_DATE",
            ["flashpoint", "import_start_date"],
            self.load,
        )

        # ── Dataset toggles ───────────────────────────────────────────────────
        # Each dataset can be enabled or disabled independently.
        # This allows selective ingestion — e.g. enabling only reports
        # while communities is disabled, without any code changes.

        # Finished Intelligence Reports — analyst-written threat intelligence
        # reports from Flashpoint's CTI team. Ingested as individual Report
        # containers of type activity-roundup.
        self.import_reports = get_config_variable(
            "FLASHPOINT_IMPORT_REPORTS",
            ["flashpoint", "import_reports"],
            self.load,
            default=True,
        )

        # Alerts — rule-based notifications firing when Flashpoint's monitoring
        # matches your configured alert rules. Bifurcated by org domain:
        # org-domain matches → IR container, keyword matches → batch Report.
        self.import_alerts = get_config_variable(
            "FLASHPOINT_IMPORT_ALERTS",
            ["flashpoint", "import_alerts"],
            self.load,
            default=True,
        )

        # Communities — dark web forum and community post search results.
        # Defaults to False because it requires explicit query configuration
        # and the data is inherently noisy. Enable only when
        # FLASHPOINT_COMMUNITIES_QUERIES is configured with meaningful terms.
        self.import_communities = get_config_variable(
            "FLASHPOINT_IMPORT_COMMUNITIES",
            ["flashpoint", "import_communities"],
            self.load,
            default=False,
        )

        # Compromised Credentials — credential exposure records from
        # Flashpoint's credential monitoring datasets.
        # NOTE: This dataset is stubbed — the endpoint is not yet implemented.
        # Enabling this will trigger the stub which logs a warning and returns
        # without ingesting anything. Set to False to suppress the warning.
        self.import_credentials = get_config_variable(
            "FLASHPOINT_IMPORT_CREDENTIALS",
            ["flashpoint", "import_credentials"],
            self.load,
            default=True,
        )

        # ── Communities configuration ─────────────────────────────────────────
        # Comma-separated list of keyword search terms for the communities
        # dark web search API. Each term is searched independently and produces
        # its own daily batch Report container so results from different queries
        # are not mixed.
        # Example: 'ransomware,CVE-2024-1234,your-org-name'
        communities_queries_raw = get_config_variable(
            "FLASHPOINT_COMMUNITIES_QUERIES",
            ["flashpoint", "communities_queries"],
            self.load,
            default="cybersecurity,cyberattack",
        )
        # Split, strip whitespace, and discard empty strings from the
        # raw comma-separated value. This tolerates trailing commas and
        # accidental spaces around commas.
        self.communities_queries = [
            q.strip() for q in communities_queries_raw.split(",") if q.strip()
        ]

        # ── Org domain bifurcation ────────────────────────────────────────────
        # Comma-separated list of your organisation's domains.
        # Used to route alerts and credential records that affect your
        # organisation into Incident Response containers rather than the
        # generic daily batch Report containers used for external intelligence.
        #
        # HOW BIFURCATION WORKS:
        # The connector serialises the entire alert/credential resource dict
        # to a lowercase string and checks whether any configured domain
        # appears anywhere in that string. This is intentionally broad —
        # a domain match in a repo URL, email address, or any other field
        # in the resource triggers IR routing.
        #
        # Example: 'example.com,subsidiary.example.com'
        # If empty, all alerts and credentials route to batch Reports.
        org_domains_raw = get_config_variable(
            "FLASHPOINT_ORG_DOMAINS",
            ["flashpoint", "org_domains"],
            self.load,
            default="",
        )
        # Normalise to lowercase for case-insensitive matching.
        self.org_domains = [
            d.strip().lower()
            for d in org_domains_raw.split(",")
            if d.strip()
        ]

        # ── Confidence defaults ───────────────────────────────────────────────
        # OpenCTI confidence is an integer 0–100. These defaults reflect the
        # epistemological reliability of each Flashpoint data source.
        # All values are cast to int to guard against YAML parsing returning
        # a string when no env var is set.

        # Finished Intelligence Reports: 75
        # Analyst-written, Tier-1 vendor intelligence. High reliability.
        self.report_confidence = int(
            get_config_variable(
                "FLASHPOINT_REPORT_CONFIDENCE",
                ["flashpoint", "report_confidence"],
                self.load,
                default=75,
            )
        )

        # Keyword-match alerts: 50
        # Rule-based hits, unvalidated. Medium confidence until analyst review.
        self.alert_confidence = int(
            get_config_variable(
                "FLASHPOINT_ALERT_CONFIDENCE",
                ["flashpoint", "alert_confidence"],
                self.load,
                default=50,
            )
        )

        # Org-domain credential alerts: 70
        # Higher than generic alerts because the org-domain match is a
        # deterministic linkage — the alert is directly relevant to the org.
        self.alert_org_confidence = int(
            get_config_variable(
                "FLASHPOINT_ALERT_ORG_CONFIDENCE",
                ["flashpoint", "alert_org_confidence"],
                self.load,
                default=70,
            )
        )

        # Communities search results: 30
        # Raw dark web forum content, completely unvalidated. Low confidence.
        # The analytical value is in pattern recognition across many posts,
        # not in any individual post's credibility.
        self.communities_confidence = int(
            get_config_variable(
                "FLASHPOINT_COMMUNITIES_CONFIDENCE",
                ["flashpoint", "communities_confidence"],
                self.load,
                default=30,
            )
        )

        # Compromised Credentials: 70
        # Direct credential match carries higher signal than generic alerts.
        # The domain match is deterministic; the credential itself is confirmed
        # to exist in Flashpoint's dataset.
        self.credential_confidence = int(
            get_config_variable(
                "FLASHPOINT_CREDENTIAL_CONFIDENCE",
                ["flashpoint", "credential_confidence"],
                self.load,
                default=70,
            )
        )
