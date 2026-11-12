"""Waypoint engine: one article-ingestion engine for every sources.yml profile.

Modules:
    settings   engine-wide constants and AGG_* budgets (environment)
    profile    sources.yml loading and per-entry validation
    dates      tolerant publication-date parsing
    text       HTML to text, page metadata, article text
    discovery  feed / sitemap / listing / json discovery, link canonicalisation
    scope      scope filters and named skip checks (skip_if)
    dedup      graph dedup by External Reference URL
    render     pdf-renderer calls with retry and failure classification
    report     Report id, file name, classification, the report.create call
    worker     one source's poll and per-item ingestion
    scheduler  due sources, global budgets, round-robin render queue
    status     /data/status.json
    timing     the clock and sleep every module uses (patched in tests)
"""

import os
import sys

# The shared microservices/ package (pdf-renderer client, Crucible
# classifier) lives next to this connector's directory: mounted at
# /microservices in the container (the parent of /app), and at
# connectors/microservices in the repo. Neither is copied into the image.
_PARENT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)
