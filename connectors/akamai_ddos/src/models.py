"""Normalized intermediate model shared by both pollers.

Both prolexic.py and siem.py emit `AttackEvent` so stix_builder.py stays
source-agnostic. Times are SOURCE times (never ingestion time).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SourceIp:
    ip: str
    version: int  # 4 or 6
    asn: int | None = None
    asn_name: str | None = None
    country_iso: str | None = None
    volume: int | None = None  # request count / event weight, used for top-N ranking


@dataclass
class AttackEvent:
    source_system: str  # "prolexic" | "siem"
    attack_id: str  # stable per-attack id from the source
    start_time: datetime  # -> Incident.first_seen + Sighting.first_seen
    end_time: datetime  # -> Incident.last_seen  + Sighting.last_seen
    is_ddos: bool = True  # gate (decision D); only DDoS gets the MITRE technique
    vectors: list[str] = field(default_factory=list)  # raw vector / ruleTag strings
    protocols: list[str] = field(default_factory=list)
    dest_ports: list[int] = field(default_factory=list)  # one Network-Traffic per port
    target_hostnames: list[str] = field(default_factory=list)  # System per hostname
    target_ips: list[str] = field(default_factory=list)  # victim IPs / prefixes
    url_paths: list[str] = field(default_factory=list)  # L7 only
    peak_bps: int | None = None  # -> Incident description / Note, NOT Network-Traffic
    peak_pps: int | None = None
    source_ips: list[SourceIp] = field(default_factory=list)  # ranked; builder keeps top-N
    mitigation: str | None = None  # scrubbing / action -> Incident desc / Note
    ticket_id: str | None = None
    raw: dict = field(default_factory=dict)  # original payload for provenance

    def display_name(self) -> str:
        vec = ", ".join(self.vectors[:3]) or "DDoS"
        tgt = (self.target_hostnames or self.target_ips or ["unknown target"])[0]
        day = self.start_time.date().isoformat()
        return f"Akamai {self.source_system} DDoS — {vec} vs {tgt} — {day}"
