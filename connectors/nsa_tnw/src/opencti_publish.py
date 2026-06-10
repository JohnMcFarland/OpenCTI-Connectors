import os
from datetime import datetime, timezone
from typing import Dict, Optional

from pycti import OpenCTIConnectorHelper


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_report_from_item(helper: OpenCTIConnectorHelper, item: Dict, now_iso: Optional[str] = None) -> str:
    """
    Minimal, safe publish:
      - Create a Report
      - Put govinfo PDF URL in externalReferences
      - Do NOT download the PDF
      - Do NOT create observables/indicators/relationships yet
    Returns created report id.
    """
    now_iso = now_iso or _utc_now_iso()

    title = item.get("title") or item.get("external_id") or "NSA The Next Wave"
    external_id = item.get("external_id") or item.get("pdf_url") or title
    pdf_url = item.get("pdf_url")

    report_prefix = os.getenv("TNW_REPORT_PREFIX", "NSA TNW").strip()
    report_type = os.getenv("TNW_REPORT_TYPE", "technical-report").strip()
    author = os.getenv("TNW_REPORT_AUTHOR", "NSA/CSS").strip()
    confidence = int(os.getenv("TNW_CONFIDENCE_LEVEL", "15"))
    marking_name = os.getenv("TNW_REPORT_MARKING_DEFINITION_NAME", "TLP:CLEAR").strip()

    # Marking definition
    marking = helper.api.marking_definition.read(filters={"mode": "and", "filters": [
        {"key": "definition_type", "values": ["TLP"]},
        {"key": "definition", "values": [marking_name]},
    ]})
    if not marking:
        # fallback: allow name match if definition match fails
        marking = helper.api.marking_definition.read(filters={"mode": "and", "filters": [
            {"key": "definition", "values": [marking_name]},
        ]})

    marking_ids = [marking["id"]] if marking and "id" in marking else []

    # External references (govinfo is stable)
    external_references = []
    if pdf_url:
        external_references.append({
            "source_name": "govinfo.gov",
            "url": pdf_url,
            "external_id": external_id,
        })

    report_name = f"{report_prefix} | {title}"

    data = {
        "type": "report",
        "spec_version": "2.1",
        "x_opencti_internal_id": external_id,
    }

    report_id = helper.api.report.create(
        name=report_name,
        description=f"Ingested by NSA Published Reports connector. Source PDF: {pdf_url}" if pdf_url else "Ingested by NSA Published Reports connector.",
        report_types=[report_type],
        confidence=confidence,
        published=now_iso,
        created=now_iso,
        modified=now_iso,
        createdBy=helper.api.identity.create(type="Organization", name=author) if author else None,
        objectMarking=marking_ids,
        externalReferences=external_references if external_references else None,
        x_opencti_stix_ids=[external_id],
    )

    return report_id["id"]
