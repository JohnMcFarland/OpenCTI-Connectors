"""Build a STIX bundle (list of dict objects) from a normalized Case.

Encodes the repo data model (Data_Model_Acceptable_Relationships.csv + CTI Ingestion
Manual) in code. Splunk is an INTERNAL source ("what we saw"), so:

  * Container = Incident Response (case-incident). Sightings are ONLY emitted here.
  * NO Indicators are ever created (OpenCTI auto-promotes Observables).
  * NO Labels (labels are reserved for collection requirements).
  * Network-Traffic objects carry a SINGLE port only (house rule).
  * Every observable is related-to >= 1 named Identity (the System it was seen on).
  * Sighting targets are Systems: the asset named in the result row, else the
    Splunk sensor System.
  * Attack Patterns are looked up by MITRE ID, never created.
  * Relationship verbs come from ALLOWED_EDGES; anything else is `related-to` with a
    description (manual §3.4k escape hatch).
  * Times are SOURCE times; marking defaults to TLP:AMBER+STRICT and is fail-closed.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta

import stix2
from pycti import (
    CaseIncident,
    Identity,
    Incident,
    Note,
    StixCoreRelationship,
    StixSightingRelationship,
)

from .cases import Case, Observed, Sighted
from .config import Settings
from .opencti_lookup import OpenCTILookup
from .searches import SearchDef

# OASIS STIX SCO namespace, for the deterministic single-port Network-Traffic id.
# Same key shape as akamai_ddos so the same port dedups across connectors.
_SCO_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# Precise verbs from Data_Model_Acceptable_Relationships.csv that this connector can
# emit. Every other edge it builds (observable->system, network-traffic->incident,
# system->organization) has no listed verb, so it is `related-to` + description.
ALLOWED_EDGES: set[tuple[str, str, str]] = {
    ("incident", "uses", "attack-pattern"),
}

_STIX_CLASSES = {
    "ipv4-addr": lambda v: stix2.IPv4Address(value=v),
    "ipv6-addr": lambda v: stix2.IPv6Address(value=v),
    "domain-name": lambda v: stix2.DomainName(value=v),
    "url": lambda v: stix2.URL(value=v),
    "email-addr": lambda v: stix2.EmailAddress(value=v),
    "user-account": lambda v: stix2.UserAccount(account_login=v),
    "mac-addr": lambda v: stix2.MACAddress(value=v),
}


class _Bundle:
    """Collects objects once by id, tracks container members, and enforces the
    per-case object cap (2 slots always reserved for the Note and the container)."""

    def __init__(self, max_objects: int) -> None:
        self.objects: dict[str, dict] = {}
        self.refs: dict[str, None] = {}  # ordered set
        self.max_objects = max_objects
        self.dropped = {"technique link(s)": 0, "observable(s)": 0, "sighting(s)": 0,
                        "system(s)": 0}

    def room(self) -> int:
        """Objects that can still be added."""
        return self.max_objects - len(self.objects) - 2

    def fits(self, cost: int, what: str) -> bool:
        """True if `cost` more objects fit; otherwise counts one dropped `what`."""
        if cost <= self.room():
            return True
        self.dropped[what] += 1
        return False

    def add(self, obj: dict, *, member: bool = True) -> str:
        self.objects.setdefault(obj["id"], obj)
        if member:
            self.refs[obj["id"]] = None
        return obj["id"]

    def ref(self, object_id: str) -> None:
        """Member that already exists in OpenCTI and is not shipped in the bundle."""
        self.refs[object_id] = None


class SplunkStixBuilder:
    def __init__(self, helper, settings: Settings, lookup: OpenCTILookup) -> None:
        self.log = helper.connector_logger
        self.settings = settings
        self.lookup = lookup
        self.confidence = settings.splunk_confidence
        self.max_objects = settings.splunk_max_objects_per_case
        self.author_id = Identity.generate_id(settings.splunk_author_name, "organization")
        self.org_name = settings.splunk_organization_name
        self.org_id = Identity.generate_id(self.org_name, "organization")
        self.sensor_id = Identity.generate_id(settings.splunk_sensor_system_name, "system")
        self.marking_id: str | None = None
        self._static: list[tuple[dict, bool]] = []

    # -- one-time setup ----------------------------------------------------

    def prepare(self) -> None:
        """Resolve the default marking once and build the per-deployment objects.

        Fail closed: unmarked internal telemetry is worse than not ingesting it."""
        self.marking_id = self.lookup.marking(self.settings.splunk_tlp)
        if not self.marking_id:
            raise RuntimeError(
                f"Configured TLP marking could not be resolved ({self.settings.splunk_tlp}); "
                "refusing to start. Verify the marking exists in OpenCTI.")
        # Same in every bundle: author (createdBy only, not a member), owning Org, the
        # Splunk sensor System, and its timeless ownership edge.
        self._static = [
            (self._identity(self.settings.splunk_author_name, "organization"), False),
            (self._identity(self.org_name, "organization"), True),
            (self._identity(self.settings.splunk_sensor_system_name, "system"), True),
            (self._rel(self.sensor_id, "system", "related-to", self.org_id, "organization",
                       f"Splunk deployment operated by {self.org_name}."), True),
        ]

    # -- public ------------------------------------------------------------

    def build(self, search: SearchDef, case: Case) -> list[dict]:
        if not self.marking_id:
            raise RuntimeError("prepare() must resolve the marking before build()")
        b = _Bundle(self.max_objects)
        for obj, member in self._static:
            b.add(obj, member=member)
        inc_id = b.add(self._incident(search, case))                # 1. Incident
        unresolved = self._add_techniques(b, search, case, inc_id)  # 2. MITRE links
        self._add_observables(b, search, case, inc_id)              # 3. observables + assets
        self._add_remaining_systems(b, case)                        # 4. other assets
        if any(b.dropped.values()):
            self.log.warning("Case exceeds SPLUNK_MAX_OBJECTS_PER_CASE; case truncated",
                             {"search": search.name, "group": case.key, **b.dropped})
        b.add(self._note(search, case, inc_id))                            # 5. provenance
        # 6. Container last, so every member above is collected
        details = self._import_details(case, unresolved, b.dropped)
        b.add(self._container(case, list(b.refs), details), member=False)
        return list(b.objects.values())

    # -- build steps -------------------------------------------------------

    @staticmethod
    def _span(first: datetime, last: datetime) -> tuple[str, str]:
        """Relationship start/stop. STIX 2.1 requires stop_time LATER than start_time,
        so a single instant gets a 1-second interval (Sightings keep exact times)."""
        return first.isoformat(), max(last, first + timedelta(seconds=1)).isoformat()

    def _add_techniques(self, b: _Bundle, search: SearchDef, case: Case,
                        inc_id: str) -> list[str]:
        """Incident uses existing MITRE Attack Patterns; returns IDs not found."""
        unresolved: list[str] = []
        for tid in case.techniques:
            ap_id = self.lookup.attack_pattern(tid)
            if not ap_id:
                unresolved.append(tid)
                continue
            if not b.fits(1, "technique link(s)"):
                continue
            b.ref(ap_id)
            b.add(self._rel(inc_id, "incident", "uses", ap_id, "attack-pattern",
                            f"Splunk search '{search.name}' tagged this activity with {tid}.",
                            *self._span(case.first_seen, case.last_seen)))
        return unresolved

    def _system_id(self, asset: str | None) -> str:
        return self.sensor_id if asset is None else Identity.generate_id(asset, "system")

    def _add_system(self, b: _Bundle, asset: str | None) -> str:
        """Asset System, owned by the Org. Ownership is not bounded by the case, so that
        edge carries no dates and dedups to one relationship per asset."""
        sys_id = self._system_id(asset)
        if sys_id not in b.objects:
            b.add(self._identity(asset, "system"))
            b.add(self._rel(sys_id, "system", "related-to", self.org_id, "organization",
                            f"Asset {asset} owned by {self.org_name}."))
        return sys_id

    def _fit_sightings(self, b: _Bundle, ob: Observed) -> list[Sighted]:
        """The most-seen Sightings of `ob` that fit under the cap, counting the
        observable itself and any System they would add."""
        room = b.room() - 1 - (ob.kind == "network-traffic")
        ranked = sorted(ob.sightings.values(), key=lambda s: (-s.count, s.system or ""))
        chosen: list[Sighted] = []
        for s in ranked:
            cost = 2 if self._system_id(s.system) in b.objects else 4
            if cost <= room:
                room -= cost
                chosen.append(s)
        if chosen:
            b.dropped["sighting(s)"] += len(ranked) - len(chosen)
        return chosen

    def _add_observables(self, b: _Bundle, search: SearchDef, case: Case, inc_id: str) -> None:
        """Observables -> related-to + a Sighting on each System they were actually seen
        on, with that pairing's own count and times. They arrive most-seen first, and
        add their Systems as they go, so under the cap the most-seen activity survives
        and a Sighting is lost rather than moved to another System."""
        for ob in case.observables:
            seen_on = self._fit_sightings(b, ob)
            if not seen_on:
                b.dropped["observable(s)"] += 1
                continue
            ob_id = b.add(self._observable(ob, search))
            seen = f"Observed by Splunk search '{search.name}' (field {', '.join(sorted(ob.fields))})."
            if ob.kind == "network-traffic":
                # Ports describe the activity, not an asset: link to the Incident.
                b.add(self._rel(ob_id, "network-traffic", "related-to", inc_id, "incident",
                                f"Port {ob.value}. {seen}",
                                *self._span(case.first_seen, case.last_seen)))
            for s in seen_on:
                sys_id = self._add_system(b, s.system)
                first, last = s.first or case.first_seen, s.last or case.last_seen
                b.add(self._rel(ob_id, ob.kind, "related-to", sys_id, "system", seen,
                                *self._span(first, last)))
                b.add(self._sighting(ob_id, sys_id, first, last, s.count, seen))

    def _add_remaining_systems(self, b: _Bundle, case: Case) -> None:
        """Assets named in the rows that no imported observable was seen on."""
        for asset in case.systems:
            if self._system_id(asset) not in b.objects and b.fits(2, "system(s)"):
                self._add_system(b, asset)

    # -- object builders ---------------------------------------------------

    def _base(self, obj: dict, *, created_by: bool = True) -> dict:
        obj["spec_version"] = "2.1"
        obj["object_marking_refs"] = [self.marking_id]
        if created_by:
            obj["created_by_ref"] = self.author_id
        return obj

    def _identity(self, name: str, cls: str) -> dict:
        obj_id = Identity.generate_id(name, cls)
        return self._base({
            "type": "identity",
            "id": obj_id,
            "name": name,
            "identity_class": cls,
        }, created_by=obj_id != self.author_id)

    def _incident(self, search: SearchDef, case: Case) -> dict:
        obj = {
            "type": "incident",
            "id": Incident.generate_id(case.title, case.created.isoformat()),
            "name": case.title,
            "description": case.description,
            "created": case.created.isoformat(),
            "incident_type": case.incident_type,
            "source": f"Splunk: {search.name}",
            "confidence": self.confidence,
            "first_seen": case.first_seen.isoformat(),
            "last_seen": case.last_seen.isoformat(),
        }
        if case.severity:
            obj["severity"] = case.severity
        return self._base(obj)

    def _observable(self, ob: Observed, search: SearchDef) -> dict:
        if ob.kind == "network-traffic":
            # SINGLE PORT ONLY: no protocol, refs, or byte counts by house rule.
            d = {"type": "network-traffic",
                 "id": f"network-traffic--{uuid.uuid5(_SCO_NS, f'dst_port={ob.value}')}",
                 "dst_port": int(ob.value)}
        elif ob.kind == "file":
            d = json.loads(stix2.File(hashes={ob.hash_algo: ob.value}).serialize())
        else:
            d = json.loads(_STIX_CLASSES[ob.kind](ob.value).serialize())
        # Technical provenance only; behaviour belongs on relationships.
        d["x_opencti_description"] = (
            f"Value of field {', '.join(sorted(ob.fields))} in Splunk search '{search.name}'.")
        return self._base(d)

    def _sighting(self, ob_id: str, system_id: str, first_seen: datetime, last_seen: datetime,
                  count: int, description: str) -> dict:
        first, last = first_seen.isoformat(), last_seen.isoformat()
        return self._base({
            "type": "sighting",
            "id": StixSightingRelationship.generate_id(ob_id, [system_id], first, last),
            "sighting_of_ref": ob_id,
            "where_sighted_refs": [system_id],
            "description": description,
            "first_seen": first,
            "last_seen": last,
            "count": count,
            "confidence": self.confidence,
            "x_opencti_negative": False,
        })

    def _note(self, search: SearchDef, case: Case, inc_id: str) -> dict:
        # Stable content only: OpenCTI derives a Note's id from its content, so anything
        # that changes as the case grows would leave a stale Note behind on every update.
        # Per-run details go in the container description instead (upserted in place).
        content = "\n".join([
            f"Search: {search.name} (app {search.app}, {search.time_mode}-time window)",
            f"Group: {case.key}",
            "",
            "SPL:",
            search.spl,
        ])
        return self._base({
            "type": "note",
            "id": Note.generate_id(case.created.isoformat(), content),
            "abstract": f"Splunk provenance: {search.name}",
            "content": content,
            "created": case.created.isoformat(),
            "object_refs": [inc_id],
        })

    def _import_details(self, case: Case, unresolved: list[str],
                        dropped: dict[str, int]) -> str:
        lines = [f"Results: {case.row_count}, "
                 f"{case.first_seen.isoformat()} to {case.last_seen.isoformat()}."]
        if case.rejected:
            lines.append("Values rejected as invalid for their mapped type: "
                         + ", ".join(f"{f} x{n}" for f, n in sorted(case.rejected.items())) + ".")
        if unresolved:
            lines.append("MITRE techniques not found in OpenCTI (not linked): "
                         + ", ".join(unresolved) + ".")
        if any(dropped.values()):
            lines.append(f"Not imported because the case exceeded SPLUNK_MAX_OBJECTS_PER_CASE "
                         f"({self.max_objects}): "
                         + ", ".join(f"{n} {what}" for what, n in dropped.items() if n) + ".")
        return "\n".join(lines)

    def _container(self, case: Case, refs: list[str], details: str) -> dict:
        obj = {
            "type": "case-incident",
            "id": CaseIncident.generate_id(case.title, case.created.isoformat()),
            "name": case.title,
            "description": f"{case.description}\n\nImport details:\n{details}",
            "created": case.created.isoformat(),
            "object_refs": refs,
        }
        if case.severity:
            obj["severity"] = case.severity
        return self._base(obj)

    # -- relationships -----------------------------------------------------

    def _rel(self, src_id, src_log, rel_type, tgt_id, tgt_log, description,
             start: str | None = None, stop: str | None = None) -> dict:
        # Only related-to (the manual's escape hatch) or a verb listed for this exact
        # pair may be emitted. Anything else is a coding error: fail loudly.
        if rel_type != "related-to" and (src_log, rel_type, tgt_log) not in ALLOWED_EDGES:
            raise ValueError(f"Edge not on the data-model allow-list: "
                             f"{src_log},{rel_type},{tgt_log}")
        rel = {
            "type": "relationship",
            "id": StixCoreRelationship.generate_id(rel_type, src_id, tgt_id, start, stop),
            "relationship_type": rel_type,
            "source_ref": src_id,
            "target_ref": tgt_id,
            "description": description,
            "confidence": self.confidence,
        }
        if start and stop:
            rel["start_time"], rel["stop_time"] = start, stop
        return self._base(rel)
