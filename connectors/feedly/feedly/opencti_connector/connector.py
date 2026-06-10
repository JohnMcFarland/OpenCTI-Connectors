import io
import json
import tempfile
import threading
import multiprocessing
import time
from datetime import datetime
from typing import Optional, Set, List
from uuid import NAMESPACE_DNS, uuid5

import weasyprint
import requests
from feedly.api_client.enterprise.indicators_of_compromise import StixIoCDownloader
from feedly.api_client.session import FeedlySession
from markdown import markdown
from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils

FEEDLY_AI_UUID = "identity--477866fd-8784-46f9-ab40-5592ed4eddd7"

# Well-known STIX 2.1 TLP marking definition IDs (stable, spec-defined)
TLP_MARKING_IDS = {
    "TLP:CLEAR":        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "TLP:WHITE":        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN":        "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "TLP:AMBER":        "marking-definition--f88d31f6-1f95-4d47-99f6-d7b1d6e95a5b",
    "TLP:AMBER+STRICT": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "TLP:RED":          "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c2",
}

# pdfkit options for article rendering



def _weasyprint_worker(html: str, url: str, queue) -> None:
    """Module-level worker for subprocess-isolated weasyprint rendering.
    Runs in a child process so all weasyprint/Cairo/Pango heap is fully
    released when the process exits, preventing memory accumulation.
    """
    import weasyprint
    try:
        pdf = weasyprint.HTML(string=html, base_url=url).write_pdf()
        queue.put(("ok", pdf))
    except Exception as exc:
        queue.put(("error", str(exc)))


class FeedlyConnector:
    def __init__(
        self,
        feedly_api_key: str,
        cti_helper: OpenCTIConnectorHelper,
        marking: str = "TLP:CLEAR",
        confidence: int = 50,
        attach_pdf: bool = True,
        pdf_timeout: int = 30,
        pdf_render_timeout: int = 120,
        pdf_max_mb: int = 12,
        pdf_user_agent: str = "Mozilla/5.0 (compatible; Feedly-OpenCTI/1.0)",
    ):
        self.feedly_session = FeedlySession(
            feedly_api_key, client_name="feedly.opencti.client"
        )
        self.cti_helper = cti_helper
        self.marking_id = TLP_MARKING_IDS.get(marking.upper())
        if not self.marking_id:
            raise ValueError(
                f"Unknown marking definition '{marking}'. "
                f"Valid values: {list(TLP_MARKING_IDS.keys())}"
            )
        self.confidence = confidence
        self.attach_pdf = attach_pdf
        self.pdf_timeout = pdf_timeout
        self.pdf_render_timeout = pdf_render_timeout
        self.pdf_max_mb = pdf_max_mb
        self.pdf_user_agent = pdf_user_agent

    def fetch_and_publish(self, stream_id: str, newer_than: datetime) -> Optional[str]:
        bundle = self.fetch_bundle(stream_id, newer_than)
        if not bundle.get("objects"):
            return None

        # Collect report metadata before sending — we need stix id + article URL + name
        report_meta = _extract_report_meta(bundle)

        self.cti_helper.send_stix2_bundle(json.dumps(bundle))

        if self.attach_pdf and report_meta:
            self._attach_pdfs(report_meta)

        return _get_last_article_published_date(bundle)

    def fetch_bundle(self, stream_id: str, newer_than: datetime) -> dict:
        bundle = StixIoCDownloader(
            session=self.feedly_session,
            newer_than=newer_than,
            older_than=None,
            stream_id=stream_id,
        ).download_all()

        # --- presentation tweaks
        _make_reports_content_instead_of_descriptions(bundle)

        # --- keep observables, drop indicators (SDO type "indicator")
        _drop_indicators_keep_observables(bundle)

        # --- keep helper fields for any remaining indicators (no-op if indicators dropped)
        _add_main_observable_type_to_indicators(bundle)

        # --- normalize TA -> intrusion-set (Feedly sometimes uses TA)
        _transform_threat_actors_to_intrusion_sets(bundle)

        # --- report author as organization (from external_references[1].source_name)
        _add_source_name_as_author_to_all_reports(bundle)

        # --- remove auto labels
        _strip_labels(bundle)

        # --- force report type
        _force_report_type_open_source(bundle)

        # --- drop network-traffic SCOs and references
        _drop_network_traffic(bundle)

        # --- drop all relationship and sighting SROs
        _drop_all_relationships(bundle)

        # --- strip all SDOs and SCOs except report and identity
        _keep_reports_and_identities_only(bundle)

        # --- apply marking definitions and confidence to all objects
        _apply_marking_and_confidence(bundle, self.marking_id, self.confidence)

        self.cti_helper.log_info(f"Found {_count_reports(bundle)} new reports")
        return bundle

    def _attach_pdfs(self, report_meta: List[dict]) -> None:
        """For each report, fetch the article URL, render to PDF, upload to OpenCTI."""
        pdf_max_bytes = self.pdf_max_mb * 1024 * 1024
        for meta in report_meta:
            stix_id = meta["stix_id"]
            article_url = meta.get("article_url")
            report_name = meta.get("name", stix_id)

            if not article_url:
                self.cti_helper.log_info(
                    f"No article URL for report '{report_name}', skipping PDF"
                )
                continue

            try:
                pdf_bytes = self._render_pdf(article_url)
            except Exception as e:
                self.cti_helper.log_error(
                    f"PDF render failed for '{report_name}' ({article_url}): {e}"
                )
                continue

            if len(pdf_bytes) > pdf_max_bytes:
                self.cti_helper.log_info(
                    f"PDF for '{report_name}' exceeds {self.pdf_max_mb}MB limit, skipping upload"
                )
                continue

            # Resolve internal OpenCTI ID from STIX ID with retry (bundle processing is async)
            internal_id = self._resolve_report_id(stix_id, report_name)
            if not internal_id:
                self.cti_helper.log_info(
                    f"Report '{report_name}' ({stix_id}) not resolved after retries — likely pre-existing, skipping PDF"
                )
                continue

            try:
                file_name = _safe_filename(report_name) + ".pdf"
                self.cti_helper.api.stix_domain_object.add_file(
                    id=internal_id,
                    file_name=file_name,
                    data=io.BytesIO(pdf_bytes),
                    mime_type="application/pdf",
                )
                self.cti_helper.log_info(
                    f"Attached PDF '{file_name}' to report '{report_name}'"
                )
            except Exception as e:
                self.cti_helper.log_error(
                    f"PDF upload failed for '{report_name}': {e}"
                )

    def _render_pdf(self, url: str) -> bytes:
        """Fetch article and render to PDF bytes via weasyprint.
        Runs weasyprint in a child process so all C-level heap (Cairo, Pango,
        fontTools) is unconditionally released when the process exits,
        preventing memory accumulation in the parent process.
        """
        headers = {"User-Agent": self.pdf_user_agent}
        response = requests.get(url, headers=headers, timeout=self.pdf_timeout)
        response.raise_for_status()
        html = response.text
        queue = multiprocessing.Queue()
        proc = multiprocessing.Process(target=_weasyprint_worker, args=(html, url, queue))
        proc.start()
        proc.join(timeout=self.pdf_render_timeout)
        if proc.is_alive():
            proc.kill()
            proc.join()
            raise TimeoutError(
                f"weasyprint render exceeded {self.pdf_render_timeout}s timeout"
            )
        if queue.empty():
            raise RuntimeError("weasyprint worker returned no result")
        status, payload = queue.get()
        if status == "error":
            raise RuntimeError(payload)
        return payload
    def _resolve_report_id(self, stix_id: str, report_name: str, retries: int = 12, delay: float = 5.0) -> Optional[str]:
        """
        Resolve a report to its OpenCTI internal ID.

        Strategy (in order):
        1. standard_id exact match — fast path for clean ingestions
        2. name exact match — catches worker re-derived STIX ID divergence
           (e.g. Unicode normalisation differences in deterministic UUIDs)

        Retries handle async bundle processing lag.
        """
        for attempt in range(retries):
            # --- Pass 1: standard_id exact match ---
            try:
                result = self.cti_helper.api.report.read(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "standard_id", "values": [stix_id]}],
                        "filterGroups": [],
                    }
                )
                if result and result.get("id"):
                    return result["id"]
            except Exception as e:
                self.cti_helper.log_info(
                    f"standard_id lookup attempt {attempt + 1}/{retries} failed: {e}"
                )

            # --- Pass 2: name exact match (handles UUID divergence) ---
            try:
                result = self.cti_helper.api.report.read(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "name", "values": [report_name]}],
                        "filterGroups": [],
                    }
                )
                if result and result.get("id"):
                    self.cti_helper.log_info(
                        f"Resolved report '{report_name}' via name fallback "
                        f"(stix_id mismatch: connector={stix_id}, "
                        f"opencti={result.get('standard_id')})"
                    )
                    return result["id"]
            except Exception as e:
                self.cti_helper.log_info(
                    f"name lookup attempt {attempt + 1}/{retries} failed: {e}"
                )

            if attempt < retries - 1:
                self.cti_helper.log_info(
                    f"Report not yet visible (attempt {attempt + 1}/{retries}), "
                    f"retrying in {delay}s"
                )
                time.sleep(delay)
        return None


# ---------------------------------------------------------------------------
# Bundle transformation helpers
# ---------------------------------------------------------------------------

def _extract_report_meta(bundle: dict) -> List[dict]:
    """Extract stix_id, article_url, and name from each report in the bundle."""
    meta = []
    for o in bundle.get("objects", []):
        if o.get("type") != "report":
            continue
        ext_refs = o.get("external_references") or []
        # Prefer the canonical article URL (non-Feedly) over the Feedly reader URL.
        # ext_refs[0] is the Feedly reader link; the original article URL may be
        # at a different index. Select the first URL that is not a feedly.com link.
        article_url = None
        for ref in ext_refs:
            url = (ref or {}).get("url", "")
            if url and "feedly.com" not in url:
                article_url = url
                break
        # Fall back to ext_refs[0] if no non-Feedly URL found
        if not article_url and ext_refs:
            article_url = (ext_refs[0] or {}).get("url")
        meta.append({
            "stix_id": o["id"],
            "article_url": article_url,
            "name": o.get("name", ""),
        })
    return meta


def _safe_filename(name: str) -> str:
    """Sanitise a report name for use as a filename."""
    keepchars = frozenset(" .-_")
    cleaned = "".join(c if (c.isalnum() or c in keepchars) else "_" for c in name)
    return cleaned[:120].strip()


def _count_reports(bundle: dict) -> int:
    return sum(1 for o in bundle.get("objects", []) if o.get("type") == "report")


def _drop_all_relationships(bundle: dict) -> None:
    """
    Remove all relationship and sighting SROs from the bundle.
    Containment is preserved via object_refs on report objects.
    """
    drop_types = {"relationship", "sighting"}
    dropped_ids: Set[str] = set()

    new_objects: List[dict] = []
    for o in bundle.get("objects", []):
        if o.get("type") in drop_types:
            if isinstance(o.get("id"), str):
                dropped_ids.add(o["id"])
            continue
        new_objects.append(o)

    # Prune any dangling object_refs on reports pointing at dropped SROs
    if dropped_ids:
        for o in new_objects:
            if o.get("type") == "report" and isinstance(o.get("object_refs"), list):
                o["object_refs"] = [
                    r for r in o["object_refs"] if r not in dropped_ids
                ]

    bundle["objects"] = new_objects


def _apply_marking_and_confidence(bundle: dict, marking_id: str, confidence: int) -> None:
    """Apply marking definition ref and confidence score to every object in the bundle."""
    SCO_TYPES = {
        "artifact", "autonomous-system", "directory", "domain-name",
        "email-addr", "email-message", "file", "ipv4-addr", "ipv6-addr",
        "mac-addr", "mutex", "network-traffic", "process", "software",
        "url", "user-account", "windows-registry-key", "x509-certificate",
    }
    for o in bundle.get("objects", []):
        obj_type = o.get("type", "")
        if obj_type in ("bundle", "marking-definition", "extension-definition"):
            continue
        existing = o.get("object_marking_refs", [])
        if marking_id not in existing:
            o["object_marking_refs"] = existing + [marking_id]
        if obj_type not in SCO_TYPES and "confidence" not in o:
            o["confidence"] = confidence


def _make_reports_content_instead_of_descriptions(bundle: dict) -> None:
    for o in bundle.get("objects", []):
        if o.get("type") == "report":
            o["content"], o["description"] = (
                markdown(o.get("description", "")),
                o.get("name", ""),
            )


def _add_main_observable_type_to_indicators(bundle: dict) -> None:
    for o in bundle.get("objects", []):
        if o.get("type") == "indicator" and "pattern" in o:
            pattern = o["pattern"]
            stix_type = pattern.removeprefix("[").split(":")[0].strip()
            o["x_opencti_main_observable_type"] = (
                OpenCTIStix2Utils.stix_observable_opencti_type(stix_type)
            )


def _transform_threat_actors_to_intrusion_sets(bundle: dict) -> None:
    for o in bundle.get("objects", []):
        if o.get("type") == "threat-actor":
            o["type"] = "intrusion-set"
            if "id" in o and isinstance(o["id"], str):
                o["id"] = o["id"].replace("threat-actor", "intrusion-set")
        if o.get("type") == "relationship":
            if "source_ref" in o and isinstance(o["source_ref"], str):
                o["source_ref"] = o["source_ref"].replace("threat-actor", "intrusion-set")
            if "target_ref" in o and isinstance(o["target_ref"], str):
                o["target_ref"] = o["target_ref"].replace("threat-actor", "intrusion-set")


def _add_source_name_as_author_to_all_reports(bundle: dict) -> None:
    source_identity_objects: List[dict] = []
    for o in bundle.get("objects", []):
        if o.get("type") == "report":
            source_identity_object = _add_source_name_as_author_to_report(o)
            if source_identity_object:
                source_identity_objects.append(source_identity_object)
    bundle["objects"].extend(source_identity_objects)


def _add_source_name_as_author_to_report(report: dict) -> Optional[dict]:
    ext_refs = report.get("external_references") or []
    if len(ext_refs) < 2:
        return None
    source_name = (ext_refs[1] or {}).get("source_name")
    if not source_name:
        return None
    report["created_by_ref"] = _make_source_id(source_name)
    return _make_source_identity_object(source_name)


def _make_source_identity_object(source_name: str) -> dict:
    return {
        "type": "identity",
        "name": source_name,
        "identity_class": "organization",
        "id": _make_source_id(source_name),
    }


def _make_source_id(source_name: str) -> str:
    return f"identity--{uuid5(NAMESPACE_DNS, 'feedly:source:' + source_name)}"


def _keep_reports_and_identities_only(bundle: dict) -> None:
    """
    Strip all objects from the bundle except:
      - report
      - identity  (publisher entities created by _add_source_name_as_author)
      - marking-definition
      - extension-definition

    object_refs on report objects are pruned to remove references to
    any dropped objects, keeping the report container clean.
    """
    KEEP_TYPES = {"report", "identity", "marking-definition", "extension-definition"}
    dropped_ids: Set[str] = set()
    new_objects: List[dict] = []
    for o in bundle.get("objects", []):
        if o.get("type") in KEEP_TYPES:
            new_objects.append(o)
        else:
            if isinstance(o.get("id"), str):
                dropped_ids.add(o["id"])
    if dropped_ids:
        for o in new_objects:
            if o.get("type") == "report" and isinstance(o.get("object_refs"), list):
                o["object_refs"] = [
                    r for r in o["object_refs"] if r not in dropped_ids
                ]
    bundle["objects"] = new_objects


def _force_report_type_open_source(bundle: dict) -> None:
    for o in bundle.get("objects", []):
        if o.get("type") == "report":
            o["report_types"] = ["Open Source Report"]


def _strip_labels(bundle: dict) -> None:
    for o in bundle.get("objects", []):
        if "labels" in o:
            try:
                del o["labels"]
            except Exception:
                pass


def _drop_indicators_keep_observables(bundle: dict) -> None:
    objects = bundle.get("objects", [])
    removed_ids: Set[str] = set()

    for o in objects:
        if o.get("type") == "indicator" and isinstance(o.get("id"), str):
            removed_ids.add(o["id"])

    if not removed_ids:
        return

    new_objects: List[dict] = []
    for o in objects:
        t = o.get("type")

        if t == "indicator" and o.get("id") in removed_ids:
            continue

        if t == "relationship":
            if o.get("source_ref") in removed_ids or o.get("target_ref") in removed_ids:
                continue

        if t == "sighting":
            if o.get("sighting_of_ref") in removed_ids:
                continue

        if t == "report" and isinstance(o.get("object_refs"), list):
            o["object_refs"] = [r for r in o["object_refs"] if r not in removed_ids]

        new_objects.append(o)

    bundle["objects"] = new_objects


def _drop_network_traffic(bundle: dict) -> None:
    removed_ids: Set[str] = set()

    for o in bundle.get("objects", []):
        if o.get("type") == "network-traffic" and isinstance(o.get("id"), str):
            removed_ids.add(o["id"])

    if not removed_ids:
        return

    new_objects: List[dict] = []
    for o in bundle.get("objects", []):
        t = o.get("type")

        if t == "network-traffic" and o.get("id") in removed_ids:
            continue

        if t == "relationship" and (
            o.get("source_ref") in removed_ids or o.get("target_ref") in removed_ids
        ):
            continue

        if t == "observed-data" and isinstance(o.get("object_refs"), list):
            kept = [ref for ref in o["object_refs"] if ref not in removed_ids]
            if not kept:
                continue
            o = dict(o)
            o["object_refs"] = kept

        if t == "report" and isinstance(o.get("object_refs"), list):
            o["object_refs"] = [ref for ref in o["object_refs"] if ref not in removed_ids]

        new_objects.append(o)

    bundle["objects"] = new_objects


def _get_last_article_published_date(bundle: dict) -> Optional[str]:
    return max(
        (
            o.get("published")
            for o in bundle.get("objects", [])
            if o.get("type") == "report" and o.get("published")
        ),
        default=None,
    )
