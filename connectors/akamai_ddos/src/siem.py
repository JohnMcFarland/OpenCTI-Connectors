"""SIEM Integration poller: application-layer (L7) DoS / rate / Slow-POST events.

Endpoint: GET /siem/v1/configs/{configId}  (NDJSON stream)
  incremental via the returned `offset` token (last NDJSON line is an offset-context
  object, NOT an event); first run uses `from`/`to` over the backfill window.

Confirmed event shape (see tests/fixtures/siem-event-200.json):
  { "type": "akamai_siem", "format": "json", "version": "1.0",
    "attackData": { "clientIP", "configId", "policyId", "appliedAction",
        "rules","ruleActions","ruleMessages","ruleTags","ruleData","ruleSelectors",
        "ruleVersions",  # each is a %3b-separated list of BASE64 tokens, URL-encoded
        "slowPostAction"(W|A), "slowPostRate" },
    "geo": { "asn", "city", "continent", "country", "regionCode" },
    "httpMessage": { "host","method","path","port","protocol","query","start"(epoch),
        "requestId","status","bytes", ... } }

Rule facets are URL-encoded then base64 per element, joined by `;` (`%3b`). Decode =
unquote -> split ';' -> base64-decode each. clientIP is a REAL per-request source IP
(decision E keeps them all), ranked by request count; the builder keeps top-N.
"""

from __future__ import annotations

import base64
import urllib.parse
from collections import Counter, defaultdict

from .akamai_client import AkamaiClient
from .config import Settings
from .models import AttackEvent, SourceIp

_BASE = "/siem/v1/configs"
# Default DDoS classifiers when AKAMAI_SIEM_DDOS_RULE_TAGS is unset: a decoded
# ruleTag containing any of these substrings counts as DDoS (case-insensitive).
_DEFAULT_DDOS_HINTS = ("DOS", "DDOS", "RATE", "FLOOD", "SLOW_POST", "SLOWLORIS")


class SiemPoller:
    def __init__(self, client: AkamaiClient, settings: Settings, logger) -> None:
        self.client = client
        self.settings = settings
        self.logger = logger
        self.ddos_tags = [t.upper() for t in settings.siem_ddos_rule_tag_list]

    def fetch(self, config_id: str, offset: str | None, from_ts: int | None,
              to_ts: int | None) -> tuple[list[AttackEvent], str | None]:
        params: dict = {"limit": 10000}
        if offset:
            params["offset"] = offset
        else:
            params["from"] = from_ts
            if to_ts:
                params["to"] = to_ts

        raw_events: list[dict] = []
        next_offset = offset
        for obj in self.client.iter_ndjson(f"{_BASE}/{config_id}", params=params):
            if "attackData" not in obj:  # final offset-context line
                next_offset = obj.get("offset", next_offset)
                continue
            if self._is_ddos(obj):
                raw_events.append(obj)

        episodes = self._aggregate(raw_events)
        return episodes, next_offset

    # -- classification ----------------------------------------------------

    def _is_ddos(self, event: dict) -> bool:
        attack = event.get("attackData", {})
        if attack.get("slowPostAction"):
            return True
        tags = [t.upper() for t in decode_facet(attack.get("ruleTags", ""))]
        hints = self.ddos_tags or list(_DEFAULT_DDOS_HINTS)
        return any(any(h in tag for h in hints) for tag in tags)

    # -- aggregation -------------------------------------------------------

    def _aggregate(self, raw_events: list[dict]) -> list[AttackEvent]:
        """Group per-request events into episodes keyed by (configId, policyId, host)."""
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for ev in raw_events:
            a = ev.get("attackData", {})
            h = ev.get("httpMessage", {})
            key = (a.get("configId"), a.get("policyId"), h.get("host"))
            groups[key].append(ev)

        episodes: list[AttackEvent] = []
        for (config_id, policy_id, host), evs in groups.items():
            starts = [_int(ev.get("httpMessage", {}).get("start")) for ev in evs]
            starts = [s for s in starts if s is not None] or [0]

            ip_counts: Counter[str] = Counter()
            ip_meta: dict[str, dict] = {}
            vectors: set[str] = set()
            ports: set[int] = set()
            paths: set[str] = set()
            slow_post = False
            for ev in evs:
                a = ev.get("attackData", {})
                g = ev.get("geo", {})
                h = ev.get("httpMessage", {})
                ip = a.get("clientIP")
                if ip:
                    ip_counts[ip] += 1
                    ip_meta[ip] = {"asn": g.get("asn"), "country": g.get("country")}
                vectors.update(decode_facet(a.get("ruleTags", "")))
                if a.get("slowPostAction"):
                    slow_post = True
                if h.get("port"):
                    p = _int(h["port"])
                    if p is not None:
                        ports.add(p)
                if h.get("path"):
                    paths.add(h["path"])
            if slow_post:
                vectors.add("Slow POST")

            source_ips = [
                SourceIp(
                    ip=ip,
                    version=6 if ":" in ip else 4,
                    asn=_first_int(ip_meta[ip].get("asn")),
                    country_iso=ip_meta[ip].get("country"),
                    volume=count,
                )
                for ip, count in ip_counts.most_common()  # ranked; builder applies top-N
            ]

            from datetime import datetime, timezone

            episodes.append(AttackEvent(
                source_system="siem",
                attack_id=f"{config_id}:{policy_id}:{host}:{min(starts)}",
                start_time=datetime.fromtimestamp(min(starts), tz=timezone.utc),
                end_time=datetime.fromtimestamp(max(starts), tz=timezone.utc),
                is_ddos=True,
                vectors=sorted(vectors),
                dest_ports=sorted(ports),
                target_hostnames=[host] if host else [],
                url_paths=sorted(paths),
                source_ips=source_ips,
                raw={"config_id": config_id, "policy_id": policy_id, "event_count": len(evs)},
            ))
        return episodes


# -- facet decoding --------------------------------------------------------

def decode_facet(value: str) -> list[str]:
    """Decode a SIEM rule facet: URL-decode, split on ';', base64-decode each token."""
    if not value:
        return []
    out: list[str] = []
    for token in urllib.parse.unquote(value).split(";"):
        token = token.strip()
        if not token:
            continue
        try:
            pad = token + "=" * (-len(token) % 4)
            out.append(base64.b64decode(pad).decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 - keep raw token if it isn't valid base64
            out.append(token)
    return out


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_int(value) -> int | None:
    if not value:
        return None
    for part in str(value).split():
        n = _int(part)
        if n is not None:
            return n
    return None
