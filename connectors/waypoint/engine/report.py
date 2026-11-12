"""The Report: id, file name, description, classification and the one write.

Data model (unchanged from the generated connectors; docs/WAYPOINT_SCOPE.md,
"Data model invariants"):
- One container-only Report per article: no Labels, entities, Observables
  or Relationships.
- STIX id = uuid5(NAMESPACE_URL, article URL).
- createdBy = the publisher's Organization, resolved once per source.
- published = the article's own date.
- The source's TLP on the Report and on the attached file (filesMarkings).
- report_types from the Crucible Collector when configured, else the
  profile's report_type.
- One External Reference, the canonical article URL.
- At most one PDF; plain-text description capped at MAX_DESCRIPTION_CHARS.
- One report.create per article, PDF inline, update=False.

Building the Report (page fetch, description, classification) is separate
from writing it, so the scheduler can prepare in worker threads and write
from one thread.
"""

import os
import re
import threading
import uuid
from urllib.parse import urlparse

from pycti.api.opencti_api_client import File

from .text import article_text, meta_description

# Shared Crucible classifier. Without the mounted microservices package the
# engine still runs and every Report keeps its profile's report_type.
try:
    from microservices.classify_report import classify_report
except ImportError:  # pragma: no cover - exercised in standalone deployments
    classify_report = None

# AGG_CLASSIFY_CONCURRENCY: Collector calls in flight across all sources.
_classify_slots = threading.BoundedSemaphore(2)


def set_classify_concurrency(n):
    """Set how many /classify calls may be in flight at once."""
    global _classify_slots
    _classify_slots = threading.BoundedSemaphore(max(1, int(n)))


def collector_configured():
    """True when Report types come from the Crucible Collector."""
    return classify_report is not None and bool(os.environ.get("CRUCIBLE_COLLECTOR_URL"))


# --------------------------------------------------------------------------- #
# Identity of the Report and its file
# --------------------------------------------------------------------------- #

def report_id(link):
    """Return a deterministic STIX Report id derived from the article URL."""
    return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, link))


def slug_from_url(url, profile):
    """Return a filesystem-safe slug from the URL path ('report' for root)."""
    segments = [s for s in urlparse(url).path.split("/") if s]
    if profile.slug_from_id:
        # The longest numeric segment is the article id (/article/5357/1 -> 5357).
        ids = [seg for seg in segments if seg.isdigit()]
        if ids:
            return f"{profile.file_prefix}-{max(ids, key=len)}"
    # Prefer the last non-numeric segment (some sites end with a numeric id).
    for seg in reversed(segments):
        if not seg.isdigit():
            seg = re.sub(r"\.html?$", "", seg)
            return re.sub(r"[^A-Za-z0-9._-]", "_", seg)[:120] or "report"
    return segments[-1] if segments else "report"


def pdf_file_name(url, profile):
    """The attached PDF's name: <file_prefix>-rendered-<slug>.pdf."""
    return f"{profile.file_prefix}-rendered-{slug_from_url(url, profile)}.pdf"


# --------------------------------------------------------------------------- #
# Build (worker thread) and write (single writer thread)
# --------------------------------------------------------------------------- #

def build_draft(item, published, pdf_bytes, profile, page_for, log):
    """Everything report.create needs, computed without writing anything.

    At most one plain GET of the article page (page_for), made only when
    needed: the feed has no summary (the page's own meta description is
    used), or the Collector is configured and the feed has no full text (the
    page's article text is classified). Any failure is logged and the Report
    is still created.
    """
    url = item["link"]
    name = item["title"] or url
    description = item["description"]
    classify = collector_configured()
    page = b""
    if not description or (classify and not item.get("full_text")):
        page = page_for(item) or b""
    if not description:
        description = meta_description(page)

    # Report type from the Crucible Collector, sent the full article text
    # (feed full text, else the article page's text). The shared helper
    # returns the default type and logs a WARNING on error or timeout, and
    # makes no call when CRUCIBLE_COLLECTOR_URL is unset.
    report_types = [profile.report_type]
    if classify_report is not None:
        text = (item.get("full_text")
                or (article_text(page, profile.content_selectors, profile.hide_selectors)
                    if classify else "")
                or description)
        with _classify_slots:
            report_types = classify_report(
                title=name, description=description, content=text,
                source=profile.name, source_url=url,
                default_types=[profile.report_type],
                logger=log.log_warning,
            )
    return {
        "url": url, "name": name, "description": description,
        "published": published, "report_types": report_types,
        "pdf_bytes": pdf_bytes, "file_name": pdf_file_name(url, profile) if pdf_bytes else None,
    }


def write_report(api, draft, profile, author_id, marking_id, log):
    """Create the External Reference and the Report, PDF attached inline."""
    external_reference = api.external_reference.create(
        source_name=profile.author_name,
        url=draft["url"],
        description=f"Source article on {profile.name}",
    )
    # One PDF, the file itself marked with the Report's TLP (a file does not
    # inherit the Report's marking on its own).
    file_kwargs = {}
    if draft["pdf_bytes"]:
        file_kwargs = {
            "files": [File(draft["file_name"], draft["pdf_bytes"], "application/pdf")],
            "filesMarkings": [[marking_id]],
        }
    api.report.create(
        stix_id=report_id(draft["url"]),
        name=draft["name"],
        description=draft["description"],
        published=draft["published"],
        report_types=draft["report_types"],
        confidence=profile.confidence,
        createdBy=author_id,
        objectMarking=[marking_id],
        externalReferences=[external_reference["id"]],
        update=False,
        **file_kwargs,
    )
    # Log the report type actually applied (Collector result or default).
    log.log_info(
        f"Created Report for {draft['url']} ({draft['name'][:80]}) "
        f"report_types={draft['report_types']}"
        + ("" if draft["pdf_bytes"] else " (no PDF)")
    )


# --------------------------------------------------------------------------- #
# Graph references resolved once
# --------------------------------------------------------------------------- #

def resolve_author(api, profile):
    """Create or look up the publisher Organization; return its id."""
    author = api.identity.create(
        type="Organization",
        name=profile.author_name,
        description=profile.author_description,
    )
    return author["id"]


def resolve_marking(api, tlp):
    """The marking definition id for `tlp`; RuntimeError when it is missing."""
    marking = api.marking_definition.read(
        filters={
            "mode": "and",
            "filters": [{"key": "definition", "values": [tlp]}],
            "filterGroups": [],
        }
    )
    if not marking:
        raise RuntimeError(
            f"Could not resolve marking '{tlp}'. Refusing to create Reports "
            f"without a resolved marking UUID."
        )
    return marking["id"]


def ensure_vocabulary(api, report_type, log):
    """Register the default report type (a failure is only a warning)."""
    try:
        api.vocabulary.create(
            name=report_type,
            category="report_types_ov",
            description="Open-source reporting ingested from public OSINT publishers.",
        )
    except Exception as exc:
        log.log_warning(
            f"Could not register report_type '{report_type}' ({exc}). "
            f"Add it under Settings -> Taxonomies -> Report types if missing."
        )
