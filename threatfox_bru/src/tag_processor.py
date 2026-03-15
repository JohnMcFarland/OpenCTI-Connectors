"""Tag classification and routing for ThreatFox tags.

Categories:
- ASN: Creates autonomous-system SCO
- MITRE_SOFTWARE: Creates malware/tool SDO
- SKIP: Tactics, technique descriptors, ISP names, operational metadata
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from . import config
from .mitre_lookup import MitreLookup

logger = logging.getLogger(__name__)

ASN_PATTERN = re.compile(r"^AS(\d+)$")


class TagCategory(Enum):
    ASN = auto()
    MITRE_SOFTWARE = auto()
    SKIP = auto()


@dataclass
class TagResult:
    category: TagCategory
    raw_tag: str
    as_number: Optional[int] = None
    mitre_name: Optional[str] = None
    mitre_external_id: Optional[str] = None
    mitre_type: Optional[str] = None


@dataclass
class ProcessedTags:
    asn_tags: list = field(default_factory=list)
    software_tags: list = field(default_factory=list)
    skipped_tags: list = field(default_factory=list)


class TagProcessor:
    def __init__(self, mitre_lookup: MitreLookup):
        self._mitre = mitre_lookup

    def classify_tag(self, tag: str) -> TagResult:
        tag = tag.strip()

        asn_match = ASN_PATTERN.match(tag)
        if asn_match:
            return TagResult(category=TagCategory.ASN, raw_tag=tag,
                             as_number=int(asn_match.group(1)))

        if tag in config.SKIP_TAGS:
            return TagResult(category=TagCategory.SKIP, raw_tag=tag)

        mitre_entry = self._mitre.get(tag)
        if mitre_entry:
            return TagResult(
                category=TagCategory.MITRE_SOFTWARE,
                raw_tag=tag,
                mitre_name=mitre_entry["name"],
                mitre_external_id=mitre_entry["external_id"],
                mitre_type=mitre_entry["type"],
            )

        return TagResult(category=TagCategory.SKIP, raw_tag=tag)

    def process_tags(self, tags_string: Optional[str]) -> ProcessedTags:
        result = ProcessedTags()
        if not tags_string:
            return result

        for tag in tags_string.split(","):
            tag = tag.strip()
            if not tag:
                continue
            classified = self.classify_tag(tag)
            if classified.category == TagCategory.ASN:
                result.asn_tags.append(classified)
            elif classified.category == TagCategory.MITRE_SOFTWARE:
                result.software_tags.append(classified)
            else:
                result.skipped_tags.append(classified)

        return result
