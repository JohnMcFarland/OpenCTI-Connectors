"""
base_plugin.py
Abstract base class for all IC source plugins.

Every plugin must inherit from BasePlugin and implement the two abstract methods.
The local 'seen' state has been intentionally removed — deduplication is handled
exclusively by the graph dedup check in report_builder.py, which queries OpenCTI's
External References directly. This ensures the graph is the single source of truth:
reports deleted from OpenCTI will be re-ingested on the next run automatically,
and no local state can diverge from the actual graph state.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------

@dataclass
class RawReport:
    """
    Minimal representation of a discovered report before full enrichment.
    The url field is the canonical deduplication key — it is passed to
    report_builder which checks it against the live graph.
    """
    url: str
    title: str
    published: Optional[datetime] = None
    summary: Optional[str] = None
    # Arbitrary plugin-specific metadata (e.g. category tags, series name)
    meta: dict = field(default_factory=dict)


@dataclass
class EnrichedReport:
    """
    Fully resolved report ready for ingestion into OpenCTI.
    All fields are optional except raw — plugins set what they can resolve.
    """
    raw: RawReport
    pdf_bytes: Optional[bytes] = None          # Downloaded PDF content
    pdf_filename: Optional[str] = None         # Filename to use in OpenCTI
    html_content: Optional[str] = None         # Full HTML (fallback if no PDF)
    author_name: Optional[str] = None          # Overrides plugin default if set
    marking: Optional[str] = None              # Overrides plugin default if set
    report_type: Optional[str] = None          # Overrides plugin default if set
    labels: list[str] = field(default_factory=list)
    # Final published date, resolved with fallback logic in the plugin
    resolved_published: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class BasePlugin(ABC):
    """
    Abstract base class for all IC report source plugins.

    Plugin authors must implement:
        - fetch_new_reports()  — discovery / feed polling
        - enrich_report()      — full content retrieval and metadata resolution

    Plugins must set as class attributes:
        - name                 — human-readable plugin name, e.g. "CISA"
        - author_name          — OpenCTI Identity name for this source

    Plugins may override:
        - default_marking      — TLP marking string (default: TLP:CLEAR)
        - report_type          — OpenCTI report type vocabulary value
        - confidence           — 0-100 integer
    """

    # --- Plugin identity (must be set by subclass as class attributes) -----
    name: str = NotImplemented
    author_name: str = NotImplemented
    default_marking: str = "TLP:CLEAR"
    report_type: str = "threat-report"
    confidence: int = 75

    def __init__(self, config: dict, logger: logging.Logger):
        """
        Args:
            config:  Plugin-specific config block from config.yml
            logger:  Shared logger instance — plugin gets its own child logger
        """
        self.config = config
        self.log = logger.getChild(self.name)

    # --- Abstract interface -------------------------------------------------

    @abstractmethod
    def fetch_new_reports(self) -> list[RawReport]:
        """
        Discover reports from this source.

        Implementations must:
        - Return RawReport objects for all reports found in this run
        - Not raise on transient network errors — log and return empty list
        - Honour max_per_run config to avoid flooding on first run

        Deduplication is NOT the plugin's responsibility — report_builder
        handles it via External Reference URL lookup against the live graph.

        Discovery mechanism is plugin-defined:
            - RSS/Atom parsing
            - Sitemap crawling
            - HTML scraping
            - Static URL list from config
        """
        ...

    @abstractmethod
    def enrich_report(self, raw: RawReport) -> Optional[EnrichedReport]:
        """
        Fully resolve a RawReport into an EnrichedReport.

        Implementations must attempt to:
        - Download the PDF (preferred) or capture HTML content
        - Resolve the publication date with maximum fidelity
        - Set author_name, marking, report_type if overriding plugin defaults

        Return None if the report cannot be meaningfully enriched (e.g. 404,
        access denied, or content that fails quality checks).
        """
        ...

    # --- Config helper ------------------------------------------------------

    def get_config(self, key: str, default=None):
        """Safe config accessor with default fallback."""
        return self.config.get(key, default)
