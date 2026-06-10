#!/usr/bin/env python3
"""
Synthient Feed Connector — OpenCTI 6.9.13

Ingests Synthient's bulk proxy intelligence Feed into OpenCTI on a scheduled
basis, producing:
  - Infrastructure entities per commercial proxy provider
  - IPv4/IPv6 observables (up to configurable cap, most-recent-first)
  - related-to relationships from each IP to its provider Infrastructure
  - CIDR Notes attached to Infrastructure entities (from blacklist endpoint)
  - One dated Report container per calendar day

Source endpoints (feeds.synthient.com):
  GET /v3/feeds/anonymizers  — per-IP proxy sightings (JSONL)
  GET /v3/feeds/blacklist    — CIDR subnet ranges (CSV)

Design document: DESIGN.md
Scope document:  CONNECTOR_SCOPE.md
"""

import csv
import datetime
import io
import json
import os
import sys
import time
import traceback

import requests
import stix2
from pycti import (
    Infrastructure,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)

# ─────────────────────────────────────────────
FEEDS_BASE = "https://feeds.synthient.com"
AUTHOR_NAME = "Synthient"
CHUNK_SIZE = 1000          # STIX objects per bundle chunk
RESOLVE_RETRIES = 6        # retries waiting for worker to process entity
RESOLVE_DELAY = 5          # seconds between retries
BLACKLIST_WORKER_WAIT = 10 # seconds to wait after content bundles before blacklist Notes
# ─────────────────────────────────────────────


class SynthientFeedConnector:

    def __init__(self):
        config = {
            "opencti": {
                "url": os.environ["OPENCTI_URL"],
                "token": os.environ["OPENCTI_TOKEN"],
            },
            "connector": {
                "id": os.environ["CONNECTOR_ID"],
                "type": "EXTERNAL_IMPORT",
                "name": os.environ.get("CONNECTOR_NAME", "Synthient Feed"),
                "scope": os.environ.get("CONNECTOR_SCOPE", "IPv4-Addr,IPv6-Addr"),
                "log_level": os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
                "auto": True,
                "only_contextual": False,
            },
        }
        self.helper = OpenCTIConnectorHelper(config)

        # ── API ──────────────────────────────────────────────────────────
        self.api_key: str = os.environ["SYNTHIENT_API_KEY"]

        # ── Feed filtering ───────────────────────────────────────────────
        # last_observed: window string passed directly to the API (24H, 7D, 1M …)
        self.last_observed: str = os.environ.get("SYNTHIENT_FEED_LAST_OBSERVED", "7D")
        # allowlists — empty list means "accept all"
        self.filter_categories: list[str] = self._split(
            os.environ.get("SYNTHIENT_FEED_CATEGORIES", "")
        )
        self.filter_providers: list[str] = self._split(
            os.environ.get("SYNTHIENT_FEED_PROVIDERS", "")
        )
        self.filter_countries: list[str] = self._split(
            os.environ.get("SYNTHIENT_FEED_COUNTRY_CODES", "")
        )
        self.max_ips: int = int(os.environ.get("SYNTHIENT_FEED_MAX_IPS", "5000"))
        self.include_blacklist: bool = (
            os.environ.get("SYNTHIENT_INCLUDE_BLACKLIST", "true").strip().lower() == "true"
        )

        # ── OpenCTI metadata ─────────────────────────────────────────────
        self.tlp_string: str = os.environ.get("SYNTHIENT_TLP", "TLP:AMBER+STRICT")
        self.confidence: int = int(os.environ.get("SYNTHIENT_CONFIDENCE", "90"))

        # ── Connector behaviour ──────────────────────────────────────────
        self.interval: int = int(os.environ.get("SYNTHIENT_INTERVAL", "86400"))
        self.state_file: str = os.environ.get(
            "SYNTHIENT_STATE_FILE", "/var/lib/synthient/state.json"
        )

        # ── Resolved at startup ──────────────────────────────────────────
        # createdBy parameters require internal OpenCTI UUIDs (not STIX IDs).
        # object_marking_refs in STIX bundles require STIX IDs.
        # Both are resolved once during start() and stored here.
        self.author_id: str | None = None        # internal UUID
        self.author_stix_id: str | None = None   # STIX identity--…
        self.tlp_id: str | None = None           # internal UUID
        self.tlp_stix_id: str | None = None      # STIX marking-definition--…

    # ────────────────────────────────────────────────────────────────────
    # Utilities
    # ────────────────────────────────────────────────────────────────────

    @staticmethod
    def _split(val: str) -> list[str]:
        """Parse comma-separated env var into an uppercase list."""
        return [v.strip().upper() for v in val.split(",") if v.strip()] if val.strip() else []

    def _headers(self) -> dict:
        return {"Authorization": self.api_key}

    def _resolve_author(self) -> tuple[str, str]:
        """
        Resolve or create the 'Synthient' Organization identity.
        Returns (internal_uuid, stix_id).
        """
        obj = self.helper.api.identity.create(
            type="Organization",
            name=AUTHOR_NAME,
            description=(
                "Synthient IP Intelligence Platform — high-fidelity residential proxy, "
                "VPN, and anonymization detection. https://synthient.com"
            ),
        )
        return obj["id"], obj["standard_id"]

    def _resolve_tlp(self) -> tuple[str, str]:
        """
        Resolve the configured TLP marking definition.
        Returns (internal_uuid, stix_id).
        Raises ValueError if the marking is not found in this OpenCTI instance.
        """
        marking = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [
                    {"key": "definition", "values": [self.tlp_string.upper()]}
                ],
                "filterGroups": [],
            }
        )
        if not marking:
            raise ValueError(
                f"TLP marking '{self.tlp_string}' not found in this OpenCTI instance. "
                f"Check the SYNTHIENT_TLP environment variable."
            )
        return marking["id"], marking["standard_id"]

    def _send_chunks(self, objects: list) -> None:
        """Send a list of STIX objects in bundles of CHUNK_SIZE."""
        total_chunks = -(-len(objects) // CHUNK_SIZE)  # ceiling division
        for i in range(0, len(objects), CHUNK_SIZE):
            chunk = objects[i : i + CHUNK_SIZE]
            bundle = stix2.Bundle(objects=chunk, allow_custom=True)
            self.helper.send_stix2_bundle(bundle.serialize())
            self.helper.log_debug(
                f"Bundle chunk {i // CHUNK_SIZE + 1}/{total_chunks} sent "
                f"({len(chunk)} objects)"
            )

    def _resolve_internal_id(self, stix_id: str) -> str | None:
        """
        Resolve the OpenCTI internal UUID for a given STIX ID.
        Retries up to RESOLVE_RETRIES times with RESOLVE_DELAY seconds between
        attempts, accommodating the async nature of the OpenCTI bundle worker.
        """
        for attempt in range(RESOLVE_RETRIES):
            obj = self.helper.api.stix_domain_object.read(id=stix_id)
            if obj:
                return obj["id"]
            self.helper.log_debug(
                f"Entity {stix_id} not yet available "
                f"(attempt {attempt + 1}/{RESOLVE_RETRIES})"
            )
            time.sleep(RESOLVE_DELAY)
        self.helper.log_warning(
            f"Could not resolve internal ID for {stix_id} after "
            f"{RESOLVE_RETRIES} attempts"
        )
        return None

    def _load_state(self) -> dict:
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_state(self, state: dict) -> None:
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)

    # ────────────────────────────────────────────────────────────────────
    # STIX object factories
    # ────────────────────────────────────────────────────────────────────

    def _make_infrastructure(
        self, provider: str, category: str
    ) -> stix2.Infrastructure:
        """
        Build a stix2.Infrastructure entity for a named proxy provider.
        ID is deterministic via Infrastructure.generate_id(name), ensuring
        deduplication across runs via STIX ID collision in the OpenCTI worker.
        """
        name = f"{provider} Proxy Infrastructure"
        return stix2.Infrastructure(
            id=Infrastructure.generate_id(name),
            name=name,
            infrastructure_types=["anonymization"],
            description=(
                f"Commercial {category} provider. "
                f"Provider identifier: {provider}. "
                f"Tracked by Synthient IP Intelligence."
            ),
            created_by_ref=self.author_stix_id,
            object_marking_refs=[self.tlp_stix_id],
            custom_properties={
                "x_opencti_created_by_ref": self.author_stix_id,
                "x_opencti_confidence_level": self.confidence,
            },
        )

    def _make_ip_objects(
        self,
        ip: str,
        provider: str,
        category: str,
        last_observed: str,
        country_code: str,
        infra_stix_id: str,
    ) -> tuple:
        """
        Build an IPv4/IPv6 observable and its related-to -> Infrastructure relationship.

        Observable description contains technical provenance only (per section 3.4j of
        the CTI Ingestion Manual). Threat context lives in the relationship description.

        IP score defaults to 50 — proxy IPs represent potential threat context but
        are not confirmed malicious; the enrichment connector can update this score
        when ip_risk data is available.

        Note: ASN/ISP relationships are NOT created here. The Feed response does not
        include ASN data. ASN enrichment belongs to the enrichment connector (L1 in
        DESIGN.md known limitations).

        Note: Country is stored in the observable description only. The data model
        does not define an IPv4-Addr -> Location relationship (L3 in DESIGN.md).
        """
        description = (
            f"Synthient proxy intelligence: category={category}, "
            f"provider={provider}, country={country_code}, "
            f"last_observed={last_observed}. "
            f"Source: Synthient anonymizers feed."
        )
        custom = {
            "x_opencti_description": description,
            "x_opencti_created_by_ref": self.author_stix_id,
            "x_opencti_score": 50,
        }

        if ":" in ip:  # IPv6
            ip_stix_id = stix2.IPv6Address(value=ip).id
            ip_obj = stix2.IPv6Address(
                id=ip_stix_id,
                value=ip,
                object_marking_refs=[self.tlp_stix_id],
                custom_properties=custom,
            )
        else:           # IPv4
            ip_stix_id = stix2.IPv4Address(value=ip).id
            ip_obj = stix2.IPv4Address(
                id=ip_stix_id,
                value=ip,
                object_marking_refs=[self.tlp_stix_id],
                custom_properties=custom,
            )

        # Relationship: IPv4/IPv6 -> related-to -> Infrastructure
        # Fallback per section 3.4k: no more specific Observable->Infrastructure
        # relationship is defined in the Data Model Relationship Guide (DM-GAP-001).
        rel = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", ip_stix_id, infra_stix_id
            ),
            relationship_type="related-to",
            source_ref=ip_stix_id,
            target_ref=infra_stix_id,
            description=(
                f"IP observed as {category} by provider {provider} "
                f"per Synthient feed. Last observed: {last_observed}."
            ),
            created_by_ref=self.author_stix_id,
            object_marking_refs=[self.tlp_stix_id],
            custom_properties={
                "x_opencti_confidence_level": self.confidence,
            },
        )
        return ip_obj, rel

    # ────────────────────────────────────────────────────────────────────
    # Anonymizers feed
    # ────────────────────────────────────────────────────────────────────

    def _run_anonymizers(
        self,
    ) -> tuple[list, list[str], dict, dict]:
        """
        Stream the anonymizers endpoint line-by-line (JSONL, stream=True).

        Single-value filters are pushed to the API via query params to minimise
        download size. Multi-value allowlists are enforced client-side.

        The feed is always requested with order=desc and full=false so that:
          - When the cap is hit, the most recently observed IPs are retained.
          - Records are deduplicated on (ip_address, provider) by the API.

        Returns:
            content_objects    -- [stix2 objects] for bundle sending
            all_stix_ids       -- [str] all STIX IDs (for Report object_refs)
            provider_infra_map -- {provider: stix2.Infrastructure}
            stats              -- {ip_count, filtered_count, provider_count, cap_reached}
        """
        params: dict = {
            "last_observed": self.last_observed,
            "format": "JSONL",
            "full": "false",
            "order": "desc",
        }
        # Single-value filters pushed to API; multi-value handled client-side
        if len(self.filter_categories) == 1:
            params["type"] = self.filter_categories[0]
        if len(self.filter_providers) == 1:
            params["provider"] = self.filter_providers[0]
        if len(self.filter_countries) == 1:
            params["country_code"] = self.filter_countries[0]

        url = f"{FEEDS_BASE}/v3/feeds/anonymizers"
        self.helper.log_info(f"Streaming anonymizers: {url}  params={params}")

        provider_infra_map: dict[str, stix2.Infrastructure] = {}
        content_objects: list = []
        all_stix_ids: list[str] = []
        ip_count = filtered_count = 0
        cap_reached = False

        with requests.get(
            url,
            headers=self._headers(),
            params=params,
            stream=True,
            timeout=300,
        ) as resp:
            resp.raise_for_status()

            for raw in resp.iter_lines():
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    self.helper.log_debug(f"Skipping malformed JSONL: {raw[:80]}")
                    continue

                ip       = rec.get("ip_address", "").strip()
                provider = rec.get("provider",    "").strip().upper()
                category = rec.get("category",    "").strip().upper()
                last_obs = rec.get("last_observed", "").strip()
                country  = rec.get("country_code", "").strip().upper()

                if not ip or not provider:
                    continue

                # ── Client-side multi-value filtering ─────────────────
                if self.filter_categories and category not in self.filter_categories:
                    filtered_count += 1
                    continue
                if self.filter_providers and provider not in self.filter_providers:
                    filtered_count += 1
                    continue
                if self.filter_countries and country not in self.filter_countries:
                    filtered_count += 1
                    continue

                # ── Infrastructure entity (one per provider) ──────────
                if provider not in provider_infra_map:
                    infra = self._make_infrastructure(provider, category)
                    provider_infra_map[provider] = infra
                    content_objects.append(infra)
                    all_stix_ids.append(infra.id)
                    self.helper.log_debug(f"New provider: {provider} ({category})")

                # ── Volume cap ────────────────────────────────────────
                if ip_count >= self.max_ips:
                    cap_reached = True
                    break

                # ── IP observable + relationship ───────────────────────
                ip_obj, rel = self._make_ip_objects(
                    ip, provider, category, last_obs, country,
                    provider_infra_map[provider].id,
                )
                content_objects.extend([ip_obj, rel])
                all_stix_ids.extend([ip_obj.id, rel.id])
                ip_count += 1

                if ip_count % 500 == 0:
                    self.helper.log_info(
                        f"  {ip_count} IPs buffered | "
                        f"{len(provider_infra_map)} providers | "
                        f"{filtered_count} filtered"
                    )

        stats = {
            "ip_count": ip_count,
            "filtered_count": filtered_count,
            "provider_count": len(provider_infra_map),
            "cap_reached": cap_reached,
        }
        self.helper.log_info(
            f"Anonymizers complete -- "
            f"IPs: {ip_count} | providers: {len(provider_infra_map)} | "
            f"filtered: {filtered_count} | cap_reached: {cap_reached}"
        )
        return content_objects, all_stix_ids, provider_infra_map, stats

    # ────────────────────────────────────────────────────────────────────
    # Blacklist feed
    # ────────────────────────────────────────────────────────────────────

    def _run_blacklist(
        self,
        provider_infra_map: dict[str, stix2.Infrastructure],
        run_date_str: str,
    ) -> None:
        """
        Fetch the blacklist endpoint (CSV) and attach CIDR Notes to each
        provider's Infrastructure entity.

        CIDRs are not representable as IPv4-Addr observables in OpenCTI
        (no native subnet/CIDR observable type). They are stored as Notes
        on the relevant Infrastructure entity per the design decision in
        DESIGN.md section 3.1.

        This method is called AFTER content bundles have been sent so that
        Infrastructure entities exist in the graph for internal ID resolution.
        """
        url = f"{FEEDS_BASE}/v3/feeds/blacklist"
        self.helper.log_info(f"Fetching blacklist: {url}")

        try:
            resp = requests.get(
                url,
                headers=self._headers(),
                params={"format": "CSV", "order": "desc"},
                timeout=300,
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            self.helper.log_error(f"Blacklist fetch failed: {e}")
            return

        # ── Group CIDRs by provider ───────────────────────────────────
        provider_cidrs: dict[str, list[tuple[str, str, str]]] = {}
        for row in csv.DictReader(io.StringIO(resp.text)):
            cidr     = row.get("cidr",          "").strip()
            provider = row.get("provider",       "").strip().upper()
            category = row.get("category",       "").strip().upper()
            last_obs = row.get("last_observed",  "").strip()
            if cidr and provider:
                provider_cidrs.setdefault(provider, []).append(
                    (cidr, category, last_obs)
                )

        total_cidrs = sum(len(v) for v in provider_cidrs.values())
        self.helper.log_info(
            f"Blacklist parsed -- "
            f"{total_cidrs} CIDRs across {len(provider_cidrs)} providers"
        )

        for provider, cidrs in provider_cidrs.items():
            # ── Resolve Infrastructure STIX ID ────────────────────────
            if provider in provider_infra_map:
                infra_stix_id = provider_infra_map[provider].id
            else:
                # Provider only in blacklist, not in anonymizers run.
                # Create Infrastructure entity now.
                first_category = cidrs[0][1] if cidrs else "UNKNOWN"
                infra = self._make_infrastructure(provider, first_category)
                self._send_chunks([infra])
                infra_stix_id = infra.id

            # ── Resolve internal OpenCTI UUID (worker is async) ───────
            internal_id = self._resolve_internal_id(infra_stix_id)
            if not internal_id:
                self.helper.log_warning(
                    f"Cannot resolve Infrastructure internal ID for {provider} "
                    f"-- skipping CIDR note"
                )
                continue

            # ── Build Note content ────────────────────────────────────
            categories_seen = ", ".join(sorted({c[1] for c in cidrs}))
            cidr_block = "\n".join(c[0] for c in cidrs)
            note_content = (
                f"Synthient Blacklist -- CIDR Ranges for {provider}\n\n"
                f"Category: {categories_seen}\n"
                f"Total ranges: {len(cidrs)}\n"
                f"Last updated: {run_date_str}\n\n"
                f"CIDR Ranges:\n{cidr_block}"
            )

            try:
                note = self.helper.api.note.create(
                    attribute_abstract=f"Synthient Blacklist CIDRs -- {provider}",
                    content=note_content,
                    note_types=["analysis"],
                    confidence=self.confidence,
                    createdBy=self.author_id,
                    objectMarking=[self.tlp_id],
                )
                self.helper.api.note.add_stix_object_or_stix_relationship(
                    id=note["id"],
                    stixObjectOrStixRelationshipId=internal_id,
                )
                self.helper.log_debug(
                    f"CIDR note created for {provider} ({len(cidrs)} ranges)"
                )
            except Exception as e:
                self.helper.log_warning(
                    f"CIDR note failed for {provider}: {e}"
                )

    # ────────────────────────────────────────────────────────────────────
    # Report container
    # ────────────────────────────────────────────────────────────────────

    def _create_report(
        self,
        run_date_str: str,
        run_ts: str,
        all_stix_ids: list[str],
        stats: dict,
    ) -> str:
        """
        Create (or retrieve) the daily Report container.

        Strategy:
          1. Direct API call to report.create() -- gives us the internal UUID
             needed for Note->Report associations (blacklist notes) and ensures
             the Report exists even before the bundle worker runs.
          2. stix2.Report bundle sent with all object_refs -- the worker creates
             the object-to-Report associations atomically. This avoids N+1
             add_stix_object_or_stix_relationship calls for potentially 10k+ objects.

        Dedup: checks by name. If today's Report already exists, reuses it and
        skips creation. The object_refs bundle is still sent to add any new
        objects from this run.

        Returns the internal OpenCTI UUID of the Report.
        """
        report_name = f"Synthient Proxy Feed -- {run_date_str}"

        cap_note = " [VOLUME CAP REACHED]" if stats["cap_reached"] else ""
        filter_parts = [f"last_observed={self.last_observed}"]
        if self.filter_categories:
            filter_parts.append(f"categories={','.join(self.filter_categories)}")
        if self.filter_providers:
            filter_parts.append(f"providers={','.join(self.filter_providers)}")
        if self.filter_countries:
            filter_parts.append(f"countries={','.join(self.filter_countries)}")

        description = (
            f"Synthient proxy intelligence feed ingested {run_ts}. "
            f"IPs ingested: {stats['ip_count']}{cap_note}. "
            f"IPs filtered: {stats['filtered_count']}. "
            f"Providers: {stats['provider_count']}. "
            f"Filters: {'; '.join(filter_parts)}. "
            f"IP cap: {self.max_ips}."
        )

        ext_ref = {
            "source_name": "Synthient",
            "url": (
                f"{FEEDS_BASE}/v3/feeds/anonymizers"
                f"?last_observed={self.last_observed}"
            ),
            "description": "Synthient anonymizers feed",
        }

        # ── Dedup: check for existing Report ─────────────────────────
        existing = self.helper.api.report.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [report_name]}],
                "filterGroups": [],
            }
        )
        if existing:
            self.helper.log_info(
                f"Reusing existing Report '{report_name}' ({existing['id']})"
            )
            report_internal_id = existing["id"]
            report_stix_id = existing["standard_id"]
        else:
            # ── Create via direct API ─────────────────────────────────
            report = self.helper.api.report.create(
                name=report_name,
                report_types=["threat-report"],
                published=f"{run_date_str}T00:00:00.000Z",
                description=description,
                createdBy=self.author_id,
                objectMarking=[self.tlp_id],
                confidence=self.confidence,
                externalReferences=[ext_ref],
            )
            report_internal_id = report["id"]
            report_stix_id = report["standard_id"]
            self.helper.log_info(
                f"Created Report '{report_name}' ({report_internal_id})"
            )

        # ── Associate objects via STIX bundle ─────────────────────────
        # Include the Report STIX object with all object_refs. The worker
        # processes this bundle and creates all object->Report associations.
        # The Report already exists in the graph, so the worker merges/updates.
        if all_stix_ids:
            published_dt = datetime.datetime.strptime(
                run_date_str, "%Y-%m-%d"
            ).replace(tzinfo=datetime.timezone.utc)

            stix_report = stix2.Report(
                id=report_stix_id,
                name=report_name,
                report_types=["threat-report"],
                published=published_dt,
                object_refs=all_stix_ids,
                description=description,
                created_by_ref=self.author_stix_id,
                object_marking_refs=[self.tlp_stix_id],
                external_references=[
                    {
                        "source_name": ext_ref["source_name"],
                        "url": ext_ref["url"],
                    }
                ],
                custom_properties={
                    "x_opencti_report_status": 0,
                    "x_opencti_created_by_ref": self.author_stix_id,
                    "x_opencti_confidence_level": self.confidence,
                },
            )
            bundle = stix2.Bundle(objects=[stix_report], allow_custom=True)
            self.helper.send_stix2_bundle(bundle.serialize())
            self.helper.log_info(
                f"Sent Report bundle with {len(all_stix_ids)} object_refs"
            )

        return report_internal_id

    # ────────────────────────────────────────────────────────────────────
    # Main process
    # ────────────────────────────────────────────────────────────────────

    def _process(self) -> None:
        run_ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        run_date = run_ts[:10]
        self.helper.log_info(f"{'='*60}")
        self.helper.log_info(f"Synthient Feed run started: {run_ts}")
        self.helper.log_info(f"{'='*60}")

        # 1. Stream anonymizers endpoint -- buffer all STIX objects
        content_objects, all_stix_ids, provider_infra_map, stats = (
            self._run_anonymizers()
        )

        # 2. Send content bundles (Infrastructure + IPs + Relationships)
        #    Report bundle is sent separately in _create_report.
        if content_objects:
            total_chunks = -(-len(content_objects) // CHUNK_SIZE)
            self.helper.log_info(
                f"Sending {len(content_objects)} objects in "
                f"{total_chunks} bundle chunk(s)..."
            )
            self._send_chunks(content_objects)
        else:
            self.helper.log_info(
                "No content objects to send (check filters / API response)."
            )

        # 3. Create/retrieve Report and send object_refs bundle
        report_id = self._create_report(run_date, run_ts, all_stix_ids, stats)

        # 4. Blacklist CIDR Notes
        #    Must run after content bundles -- Infrastructure entities must be
        #    in the graph before we can attach Notes to them.
        if self.include_blacklist:
            if content_objects:
                self.helper.log_info(
                    f"Pausing {BLACKLIST_WORKER_WAIT}s for worker to process "
                    f"content bundles before blacklist Note creation..."
                )
                time.sleep(BLACKLIST_WORKER_WAIT)
            self._run_blacklist(provider_infra_map, run_date)

        # 5. Persist state
        self._save_state(
            {
                "last_run_timestamp": run_ts,
                "last_run_date": run_date,
                "last_run_ip_count": stats["ip_count"],
                "last_run_cap_reached": stats["cap_reached"],
                "last_run_provider_count": stats["provider_count"],
                "last_run_filtered_count": stats["filtered_count"],
                "report_id": report_id,
            }
        )

        self.helper.log_info(f"{'='*60}")
        self.helper.log_info(
            f"Synthient Feed run complete -- "
            f"IPs: {stats['ip_count']} | "
            f"providers: {stats['provider_count']} | "
            f"cap_reached: {stats['cap_reached']} | "
            f"report: {report_id}"
        )
        self.helper.log_info(f"{'='*60}")

    # ────────────────────────────────────────────────────────────────────
    # Entry point
    # ────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        self.helper.log_info("Synthient Feed connector initialising...")

        # Resolve author organization and TLP marking once at startup.
        # Both are idempotent: create-or-get. Failures here are fatal.
        self.author_id, self.author_stix_id = self._resolve_author()
        self.tlp_id, self.tlp_stix_id = self._resolve_tlp()

        self.helper.log_info(
            f"Author '{AUTHOR_NAME}' resolved: internal={self.author_id}"
        )
        self.helper.log_info(
            f"TLP '{self.tlp_string}' resolved: internal={self.tlp_id}"
        )

        while True:
            try:
                self._process()
            except KeyboardInterrupt:
                self.helper.log_info("Connector stopped.")
                sys.exit(0)
            except Exception:
                self.helper.log_error(
                    f"Unhandled exception in run:\n{traceback.format_exc()}"
                )

            self.helper.log_info(f"Next run in {self.interval}s")
            time.sleep(self.interval)


if __name__ == "__main__":
    import traceback
    try:
        SynthientFeedConnector().start()
    except Exception as e:
        with open("/tmp/crash.txt", "w") as f:
            f.write(traceback.format_exc())
        print(traceback.format_exc(), flush=True)
        raise
