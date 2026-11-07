"""
Turns Silent Push IOFA values and their enrichment rows into STIX 2.1 objects.

Two streams share it. IOFA builds from the export value plus a bulk enrichment
row. OSINT builds from Feed Scan rows, which carry the same enrichment flattened
into dotted keys.

Output follows Data_Model_Acceptable_Relationships.csv:
  observable related-to Organization   (mandatory Observable-to-Identity floor)
  observable related-to intrusion-set  (Threat Actor and APT feeds)
  observable related-to malware        (botnet and TDS feeds)
  observable related-to tool           (C2 framework and RMM feeds)
  ipv4-addr  belongs-to autonomous-system
  ipv4-addr  located-at country

Observables only. Indicators are never created here; promotion belongs to the
platform pipeline. Feed names and tags go in the description, not on Labels,
since they are not collection requirements.
"""

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import pycountry
import stix2
from pycti import (
    Identity,
    IntrusionSet,
    Location,
    Malware,
    Note,
    Report,
    StixCoreRelationship,
    Tool,
)

AUTHOR_NAME = "Silent Push"
REPORT_TYPE = "observable-feed"
STREAM_IOFA = "IOFA"
STREAM_OSINT = "OSINT"
MAX_URL_LENGTH = 2048
ACTOR_SUFFIX = " (SilentPush)"

# Note ids hash the created date, so it must not move between runs.
NOTE_CREATED = datetime(2026, 11, 7, tzinfo=timezone.utc)

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[^\s./:@]{1,63}\.)+[^\s./:@\d][^\s./:@]*$")

_FEED_SUFFIX_RE = re.compile(r"\s+(?:Domains|IPs)$", re.IGNORECASE)
_ACTOR_FEED_RE = re.compile(r"^(?:Threat Actor|APT) - (.+)$")
_BOTNET_FEED_RE = re.compile(r"^Botnet(?: API)? - (.+?)(?: C2)?$")
_C2_FEED_RE = re.compile(r"^(\S+) C2$")

# The Domain and IP feeds of a pair must land on one entity.
_ACTOR_ALIASES = {"Fin7": "FIN7"}
_MALWARE_ALIASES = {"Cobaltstrike": "Cobalt Strike"}
_SCREENCONNECT_FEED = "Screen Connect RMM leveraged by Threat Actors"

# Dual-use software attackers run, which the data model classes as Tool.
_TOOLS = {"Cobalt Strike", "Sliver", "Havoc", "Adaptix", "ScreenConnect"}


def classify(raw: str | None) -> tuple[str, str] | None:
    """Return (stix_type, normalised_value), or None if unusable."""
    value = (raw or "").strip()
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
        return f"ipv{address.version}-addr", str(address)
    except ValueError:
        pass
    domain = value.rstrip(".").lower()
    if _DOMAIN_RE.match(domain):
        return "domain-name", domain
    return None


def classify_url(raw: str | None) -> tuple[str, str] | None:
    value = (raw or "").strip()
    try:
        parsed = urlparse(value)
        host = parsed.hostname
    except ValueError:
        return None
    if (
        parsed.scheme in ("http", "https")
        and host
        and len(value) <= MAX_URL_LENGTH
        and not any(char.isspace() for char in value)
    ):
        return "url", value
    return None


def unflatten(row: dict) -> dict:
    """Feed Scan flattens nested fields to "a.b.c" keys; rebuild the nesting."""
    nested: dict = {}
    for key, value in row.items():
        parts = str(key).split(".")
        target = nested
        for part in parts[:-1]:
            child = target.get(part)
            if not isinstance(child, dict):
                child = target[part] = {}
            target = child
        if not isinstance(target.get(parts[-1]), dict):
            target[parts[-1]] = value
    return nested


def parse_seen_time(raw) -> datetime | None:
    """Feed Scan timestamps look like 2026-11-07T01:47:47, in UTC."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def osint_value(row: dict) -> tuple[str, str] | None:
    """(stix_type, value) for a nested Feed Scan row, or None if unusable."""
    indicator = row.get("indicator")
    if not isinstance(indicator, str):
        return None
    kind = row.get("type")
    if kind == "url":
        return classify_url(indicator)
    classified = classify(indicator)
    if classified is None:
        return None
    is_domain = classified[0] == "domain-name"
    if (kind == "domain" and not is_domain) or (kind == "ip" and is_domain):
        return None
    return classified


def parse_listing_date(raw) -> datetime | None:
    """Silent Push listing dates are YYYYMMDD integers."""
    try:
        parsed = datetime.strptime(str(int(raw)), "%Y%m%d")
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _to_int(raw) -> int | None:
    if raw is None or isinstance(raw, bool):
        return None
    try:
        return int(float(raw))
    except (TypeError, ValueError, OverflowError):
        return None


def risk_to_score(raw) -> int | None:
    score = _to_int(raw)
    return None if score is None else max(0, min(100, score))


def _section(row: dict, key: str) -> dict:
    value = row.get(key)
    return value if isinstance(value, dict) else {}


def is_excluded(row: dict) -> bool:
    """Silent Push itself says this is benign or sinkholed, not attacker-run."""
    return bool(
        _section(row, "benign_info").get("known_benign")
        or _section(row, "sinkhole_info").get("known_sinkhole_ip")
        or _section(row, "ns_reputation").get("is_sinkholed")
        or _section(row, "ip_flags").get("is_sinkhole")
    )


def row_value(kind: str, row: dict) -> str | None:
    """The domain or IP an enrichment row describes, normalised for matching."""
    if kind == "ipv4":
        value = row.get("ip")
    else:
        info = _section(row, "domaininfo")
        value = row.get("domain") or info.get("domain") or info.get("query")
    return value.rstrip(".").lower() if isinstance(value, str) else None


def feed_entity(feed_name: str) -> tuple[str, str] | None:
    """
    Return ("intrusion-set" | "malware" | "tool", entity name) for a feed, or None.

    Works from the name because the catalogue has no field for this and feed
    tags are inconsistent. New feeds that follow the naming scheme are picked up.
    """
    base = _FEED_SUFFIX_RE.sub("", " ".join(feed_name.split()))

    match = _ACTOR_FEED_RE.match(base)
    if match:
        actor = match.group(1)
        return "intrusion-set", _ACTOR_ALIASES.get(actor, actor) + ACTOR_SUFFIX

    if base == _SCREENCONNECT_FEED:
        return "tool", "ScreenConnect"
    match = _BOTNET_FEED_RE.match(base) or _C2_FEED_RE.match(base)
    if match:
        name = _MALWARE_ALIASES.get(match.group(1), match.group(1))
        return ("tool" if name in _TOOLS else "malware"), name
    return None


class SilentPushStixBuilder:
    def __init__(self, marking_id: str, confidence: int) -> None:
        self.marking_id = marking_id
        self.confidence = confidence
        self.author = stix2.Identity(
            id=Identity.generate_id(AUTHOR_NAME, "organization"),
            name=AUTHOR_NAME,
            identity_class="organization",
            description=(
                "Silent Push is a preemptive threat intelligence vendor. "
                "Authoring identity for its IOFA feeds."
            ),
        )

    def _relationship(
        self,
        rel_type: str,
        source_id: str,
        target_id: str,
        description: str,
        start_time: datetime | None,
    ) -> stix2.Relationship:
        # Keyed on start_time alone. The first-listed date is stable, whereas
        # the last-listed date moves and would mint a duplicate edge.
        kwargs = {"start_time": start_time} if start_time else {}
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                rel_type, source_id, target_id, start_time
            ),
            relationship_type=rel_type,
            source_ref=source_id,
            target_ref=target_id,
            description=description,
            confidence=self.confidence,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking_id],
            allow_custom=True,
            **kwargs,
        )

    def _observable(self, stix_type: str, value: str, row: dict, description: str):
        custom = {
            "x_opencti_created_by_ref": self.author.id,
            "x_opencti_create_indicator": False,
            "x_opencti_description": description,
        }
        score = risk_to_score(row.get("sp_risk_score"))
        if score is not None:
            custom["x_opencti_score"] = score

        factory = {
            "domain-name": stix2.DomainName,
            "ipv4-addr": stix2.IPv4Address,
            "ipv6-addr": stix2.IPv6Address,
            "url": stix2.URL,
        }
        return factory[stix_type](
            value=value,
            object_marking_refs=[self.marking_id],
            custom_properties=custom,
        )

    def _entity(self, kind: str, name: str) -> list:
        """The Intrusion Set, Malware or Tool, plus its Assessment Note."""
        common = {
            "name": name,
            "confidence": self.confidence,
            "created_by_ref": self.author.id,
            "object_marking_refs": [self.marking_id],
            "allow_custom": True,
        }
        if kind == "intrusion-set":
            entity = stix2.IntrusionSet(id=IntrusionSet.generate_id(name), **common)
            claim = (
                f"Silent Push attributes the infrastructure in its {name} "
                "IOFA feeds to this group."
            )
        elif kind == "tool":
            entity = stix2.Tool(id=Tool.generate_id(name), **common)
            claim = (
                f"Silent Push associates the infrastructure in its {name} "
                "IOFA feeds with attacker use of this tool."
            )
        else:
            entity = stix2.Malware(
                id=Malware.generate_id(name), is_family=True, **common
            )
            claim = (
                f"Silent Push associates the infrastructure in its {name} "
                "IOFA feeds with this software."
            )

        content = (
            f"{claim} This is the vendor's assessment and has not been "
            "independently verified. IOFA entries are predictive and may not "
            "yet have been used in an attack."
        )
        note = stix2.Note(
            id=Note.generate_id(NOTE_CREATED, content),
            created=NOTE_CREATED,
            modified=NOTE_CREATED,
            abstract=f"Silent Push attribution: {name}",
            content=content,
            object_refs=[entity.id],
            confidence=self.confidence,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking_id],
            allow_custom=True,
            custom_properties={"x_opencti_note_types": ["assessment"]},
        )
        return [entity, note]

    def _asn_objects(self, observable, row: dict, start_time) -> list:
        number = _to_int(row.get("asn"))
        if not number or number < 0:
            return []
        name = row.get("asname")
        name = name.strip() if isinstance(name, str) and name.strip() else f"AS{number}"
        system = stix2.AutonomousSystem(
            number=number,
            name=name,
            object_marking_refs=[self.marking_id],
            custom_properties={"x_opencti_created_by_ref": self.author.id},
        )
        return [
            system,
            self._relationship(
                "belongs-to",
                observable.id,
                system.id,
                f"{observable.value} is announced by AS{number} per Silent Push.",
                start_time,
            ),
        ]

    def _country_objects(self, observable, row: dict, start_time) -> list:
        code = _section(row, "ip_location").get("country_code")
        if not isinstance(code, str):
            return []
        country = pycountry.countries.get(alpha_2=code.strip().upper())
        if country is None:
            return []
        location = stix2.Location(
            id=Location.generate_id(country.name, "Country"),
            name=country.name,
            country=country.alpha_2,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking_id],
            custom_properties={"x_opencti_location_type": "Country"},
            allow_custom=True,
        )
        return [
            location,
            self._relationship(
                "located-at",
                observable.id,
                location.id,
                f"{observable.value} geolocates to {country.name} per Silent Push.",
                start_time,
            ),
        ]

    def build_indicator(
        self, raw_value: str, expected_type: str, row: dict, feeds: dict[str, dict]
    ) -> list:
        """Return the value's STIX objects, or [] if it is unusable."""
        classified = classify(raw_value)
        if classified is None or classified[0] != expected_type:
            return []
        stix_type, value = classified

        listings = _iofa_listings(row, feeds)
        start_time = parse_listing_date(
            _section(row, "listing_score_explain").get("listed_first")
        )
        observable = self._observable(
            stix_type, value, row, _describe(row, listings)
        )
        objects = [
            observable,
            self._relationship(
                "related-to",
                observable.id,
                self.author.id,
                f"{value} is listed in Silent Push IOFA data.",
                start_time,
            ),
        ]

        # A pair of feeds maps to one entity, and an edge is keyed on its date,
        # so take one edge per entity, from its earliest listing.
        targets: dict[tuple[str, str], dict] = {}
        for listing in sorted(listings, key=lambda item: item["first"] or NOTE_CREATED):
            entity = feed_entity(listing["name"])
            if entity:
                targets.setdefault(entity, listing)

        for (kind, name), listing in targets.items():
            entity_objects = self._entity(kind, name)
            objects += entity_objects
            objects.append(
                self._relationship(
                    "related-to",
                    observable.id,
                    entity_objects[0].id,
                    f"{value} is listed in the Silent Push IOFA feed "
                    f"'{listing['name']}'.",
                    listing["first"],
                )
            )

        if stix_type == "ipv4-addr":
            objects += self._asn_objects(observable, row, start_time)
            objects += self._country_objects(observable, row, start_time)
        return objects

    def build_osint_indicator(
        self, stix_type: str, value: str, rows: list[dict]
    ) -> list:
        """
        One value from the open-source feeds, built from all its Feed Scan rows.

        A value listed in several feeds has one row per feed. The enrichment is
        the same on each, so the first row supplies the ASN and country.
        """
        row = rows[0]
        first_seen = [parse_seen_time(item.get("first_seen_on")) for item in rows]
        first_seen = [moment for moment in first_seen if moment]
        start_time = min(first_seen) if first_seen else None

        scores = [risk_to_score(item.get("sp_risk_score")) for item in rows]
        scores = [score for score in scores if score is not None]
        score_row = {"sp_risk_score": max(scores)} if scores else {}

        observable = self._observable(
            stix_type, value, score_row, _describe_osint(rows)
        )
        objects = [
            observable,
            self._relationship(
                "related-to",
                observable.id,
                self.author.id,
                f"{value} is listed in open-source feeds collected by Silent Push.",
                start_time,
            ),
        ]
        if stix_type == "ipv4-addr":
            objects += self._asn_objects(observable, row, start_time)
            objects += self._country_objects(observable, row, start_time)
        return objects

    def build_report(
        self, slot: datetime, object_refs: list[str], stream: str = STREAM_IOFA
    ) -> stix2.Report:
        name = f"Silent Push {stream} — {slot:%Y-%m-%d %H:%M} UTC"
        if stream == STREAM_OSINT:
            description = (
                "Indicators newly listed in the open-source threat feeds that "
                "Silent Push collects and enriches, gathered in this run's "
                "window. The original source is a third party, named in each "
                "observable's description; Silent Push supplies the score, ASN "
                "and location."
            )
        else:
            description = (
                "Indicators newly added to Silent Push Indicators of Future "
                "Attack (IOFA) data, collected in this run's window. IOFA "
                "entries are predictive: they reflect attacker infrastructure "
                "patterns and may not yet have been used in an attack. Each "
                "observable's description names its source feeds."
            )
        return stix2.Report(
            id=Report.generate_id(name, slot),
            name=name,
            published=slot,
            report_types=[REPORT_TYPE],
            description=description,
            confidence=self.confidence,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking_id],
            object_refs=object_refs,
            allow_custom=True,
        )


def _iofa_listings(row: dict, feeds: dict[str, dict]) -> list[dict]:
    """Join the row's feed attribution to the catalogue, keeping IOFA only."""
    entries = row.get("listing_score_feeds_explain")
    listings = []
    for entry in entries if isinstance(entries, list) else []:
        feed = feeds.get(entry.get("feed_uuid")) if isinstance(entry, dict) else None
        if feed and feed.get("name"):
            listings.append(
                {
                    "name": feed["name"],
                    "tags": feed.get("tags") or [],
                    "first": parse_listing_date(entry.get("listed_first")),
                }
            )
    return listings


def _describe(row: dict, listings: list[dict]) -> str:
    if listings:
        names = "; ".join(sorted({listing["name"] for listing in listings}))
        parts = [f"Listed in Silent Push IOFA feeds: {names}."]
    else:
        parts = ["Listed in Silent Push IOFA data; no feed attribution returned."]

    explain = _section(row, "listing_score_explain")
    first = parse_listing_date(explain.get("listed_first"))
    recent = parse_listing_date(explain.get("listed_recent"))
    if first:
        parts.append(f"First listed: {first:%Y-%m-%d}.")
    if recent:
        parts.append(f"Last listed: {recent:%Y-%m-%d}.")

    tags = {str(tag) for listing in listings for tag in listing["tags"] if tag}
    tags.discard("iofa")
    if tags:
        parts.append(f"Feed tags: {', '.join(sorted(tags))}.")
    return " ".join(parts)


def _describe_osint(rows: list[dict]) -> str:
    sources = set()
    for row in rows:
        feed, vendor = row.get("feed"), row.get("vendor")
        if feed:
            sources.add(f"{feed} ({vendor})" if vendor else str(feed))
    if sources:
        parts = [
            "Listed in open-source feeds collected by Silent Push: "
            f"{'; '.join(sorted(sources))}."
        ]
    else:
        parts = ["Listed in open-source feeds collected by Silent Push."]

    first = [parse_seen_time(row.get("first_seen_on")) for row in rows]
    last = [parse_seen_time(row.get("last_seen_on")) for row in rows]
    first = [moment for moment in first if moment]
    last = [moment for moment in last if moment]
    if first:
        parts.append(f"Added to feed: {min(first):%Y-%m-%d}.")
    if last:
        parts.append(f"Last seen: {max(last):%Y-%m-%d}.")

    tags = set()
    for row in rows:
        for field in ("feed_tags", "indicator_tags"):
            values = row.get(field)
            if isinstance(values, list):
                tags |= {str(tag) for tag in values if tag}
    tags.discard("iofa")
    if tags:
        parts.append(f"Feed tags: {', '.join(sorted(tags))}.")
    return " ".join(parts)
