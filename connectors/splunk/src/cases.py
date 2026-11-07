"""Group Splunk result rows into Cases (one Case = one Incident Response container).

Pure module (no pycti / network). A Case's `title` + `created` become its OpenCTI id
(case-incident, Incident, Note), so both are derived deterministically: templates
render from the group's earliest row, never from whichever row Splunk returned first,
and in rolling mode `RollingCases` pins them to what was first sent.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .observables import is_placeholder, normalize_observable
from .searches import SEVERITIES, TEMPLATE_RE, SearchDef

_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_YYYYMMDD_RE = re.compile(r"^\d{8}$")
_FAR_FUTURE = datetime.max.replace(tzinfo=timezone.utc)


@dataclass
class Sighted:
    """Where one value was actually seen: rows carrying it together with this asset."""

    system: str | None  # asset name; None = the row named no asset (the sensor saw it)
    count: int = 0
    first: datetime | None = None  # None = untimed rows; the case's times apply
    last: datetime | None = None

    def add(self, when: datetime | None) -> None:
        self.count += 1
        if when:
            self.first = min(self.first or when, when)
            self.last = max(self.last or when, when)


@dataclass
class Observed:
    kind: str  # concrete STIX type: ipv4-addr, file, network-traffic, ...
    value: str  # canonical value (hash value for files, port as str)
    hash_algo: str | None = None  # files only
    fields: set[str] = field(default_factory=set)  # source columns, for provenance
    count: int = 0  # rows in the case that carried this value
    sightings: dict[str | None, Sighted] = field(default_factory=dict)  # by asset key


@dataclass
class Case:
    key: str  # stable group key (dedup + deterministic naming)
    title: str  # part of the OpenCTI id
    description: str
    incident_type: str
    severity: str | None
    created: datetime  # part of the OpenCTI id; the earliest time first sent
    first_seen: datetime
    last_seen: datetime
    timed: bool  # False: no row had a parseable time; the times are the window start
    row_count: int
    systems: list[str]
    observables: list[Observed]
    techniques: list[str]
    rejected: dict[str, int] = field(default_factory=dict)  # field -> invalid value count

    def anchor(self, title: str, created: datetime, severity: str | None = None) -> None:
        """Pin identity to what was first sent for this group (rolling windows): a group
        that gains earlier rows or loses its oldest ones keeps the same OpenCTI case.
        Only the reported first_seen may still move earlier. Severity never drops: a
        critical row leaving the window does not make the case less severe."""
        self.title = title
        self.created = created
        known = [s for s in (self.severity, severity) if s]
        self.severity = max(known, key=SEVERITIES.index) if known else None
        if self.timed:
            self.first_seen = min(self.first_seen, created)
        else:
            self.first_seen = self.last_seen = created

    def fingerprint(self, linked: Iterable[str] = ()) -> str:
        """Changes when the case's content changes; used to skip unchanged re-sends.
        `linked` = techniques that resolve in OpenCTI, so a case is re-sent once a
        technique that was missing when it was first sent becomes linkable."""
        parts = [self.key, self.title, self.created.isoformat(), self.description,
                 self.severity or "", self.first_seen.isoformat(),
                 self.last_seen.isoformat(), str(self.row_count),
                 *sorted(s.lower() for s in self.systems),  # row order must not matter
                 *self.techniques, *(f"linked={t}" for t in linked),
                 *(f"{f}!{n}" for f, n in sorted(self.rejected.items())),
                 *(f"{o.kind}={o.value}:{o.count}:"
                   + ",".join(sorted(f"{k}={s.count}" for k, s in o.sightings.items()))
                   for o in self.observables)]
        return hashlib.sha1("\x1f".join(parts).encode()).hexdigest()


class RollingCases:
    """Per-search memory for rolling windows:
    {group key: [title, created, fingerprint, end of the last run that returned it,
                 highest severity]}.

    A case counts as remembered only once `mark_sent` confirms it went out, so a run
    that fails part-way keeps what it sent and retries the rest. A group missing from
    a run stays pinned until a whole window has passed since it was last returned:
    until then it can still reappear (e.g. a notable that was reopened, then closed
    again). `horizon` is this run's window start. `cap` limits only those missing groups,
    longest gone first: a group still being returned is never evicted, because losing
    its pin would split it into a second case."""

    def __init__(self, stored: dict, cap: int, run_at: int, horizon: int) -> None:
        self._stored = stored
        self._cap = cap
        self._run_at = run_at
        self._horizon = horizon
        self._current: dict[str, list] = {}
        self._unsent: dict[str, list] = {}

    def needs_send(self, case: Case, linked: Iterable[str] = ()) -> bool:
        prior = self._stored.get(case.key)
        if prior:
            case.anchor(prior[0], datetime.fromisoformat(prior[1]), prior[4])
        fp = case.fingerprint(linked)
        entry = [case.title, case.created.isoformat(), fp, self._run_at, case.severity]
        if prior and prior[2] == fp:
            self._current[case.key] = entry
            return False
        self._unsent[case.key] = entry
        return True

    def mark_sent(self, case: Case) -> None:
        self._current[case.key] = self._unsent.pop(case.key)

    def commit(self, returned: Iterable[str] = ()) -> dict:
        """`returned`: every group in this run's results, sent or not. One whose send
        failed is still live, however long a send outage has lasted."""
        live = {k: self._stored[k] for k in returned if k in self._stored} | self._current
        missing = [(k, v) for k, v in self._stored.items()
                   if k not in live and v[3] >= self._horizon]
        missing.sort(key=lambda kv: (kv[1][3], kv[1][1]))
        room = max(0, self._cap - len(live))
        return {**dict(missing[max(0, len(missing) - room):]), **live}


def build_cases(search: SearchDef, rows: list[dict], fallback_time: datetime) -> list[Case]:
    """Group result rows by `group_by` and normalize each group into a Case."""
    fields = search.referenced_fields()
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(_group_key(search, row, fields), []).append(row)
    return [_build_case(search, key, grp, fallback_time) for key, grp in groups.items()]


def _group_key(search: SearchDef, row: dict, fields: list[str]) -> str:
    parts = [",".join(values(row, f)) for f in search.group_by]
    if any(parts):
        return " | ".join(p or "-" for p in parts)
    # No grouping, or this row lacks every group column: the row is its own case.
    # Hash only the columns this entry reads, so Splunk bookkeeping that differs
    # between dispatches of the same event (_serial, _bkt, ...) cannot change the key.
    stable = {f: values(row, f) for f in fields}
    return hashlib.sha1(json.dumps(stable, sort_keys=True).encode()).hexdigest()[:16]


def _row_time(search: SearchDef, row: dict) -> datetime | None:
    times = [t for t in (parse_time(v) for v in values(row, search.time_field)) if t]
    return min(times) if times else None


def _earliest_row(timed: list[tuple[datetime | None, dict]]) -> dict:
    """Earliest row; ties (incl. all-untimed) broken by content so the choice never
    depends on result order. Rows are only serialized when there is a tie."""
    t0 = min(t or _FAR_FUTURE for t, _ in timed)
    tied = [r for t, r in timed if (t or _FAR_FUTURE) == t0]
    return tied[0] if len(tied) == 1 else min(tied, key=lambda r: json.dumps(r, sort_keys=True))


def _build_case(search: SearchDef, key: str, rows: list[dict], fallback_time: datetime) -> Case:
    timed = [(_row_time(search, r), r) for r in rows]
    times = [t for t, _ in timed if t]
    first = min(times) if times else fallback_time
    last = max(times) if times else fallback_time
    anchor_row = _earliest_row(timed)

    observed: dict[tuple[str, str], Observed] = {}
    rejected: dict[str, int] = {}
    for when, row in timed:
        # A value is sighted only on the assets named in the rows that carry it, never
        # on every asset in the group: that would record sightings that did not happen.
        row_systems = _unique(v for f in search.system_fields for v in values(row, f)) or [None]
        seen_in_row: set[tuple[str, str]] = set()
        for fld, kind in search.observables.items():
            for raw_val in values(row, fld):
                norm = normalize_observable(kind, raw_val)
                if norm is None:
                    if not is_placeholder(raw_val):  # "no data" is not bad data
                        rejected[fld] = rejected.get(fld, 0) + 1
                    continue
                stix_type, value, algo = norm
                ob = observed.setdefault((stix_type, value), Observed(stix_type, value, algo))
                ob.fields.add(fld)
                if (stix_type, value) not in seen_in_row:
                    seen_in_row.add((stix_type, value))
                    ob.count += 1
                    for system in row_systems:
                        ob.sightings.setdefault(_asset_key(system), Sighted(system)).add(when)

    systems = _unique(v for r in rows for f in search.system_fields for v in values(r, f))
    techniques = sorted({m for r in rows for f in search.attack_pattern_fields
                         for v in values(r, f) for m in _MITRE_RE.findall(v)})

    # Highest severity across the group's rows, so one critical row is never hidden.
    severity = None
    if search.severity_field:
        mapped = {search.severity_map.get(v.lower()) for r in rows
                  for v in values(r, search.severity_field)} - {None}
        severity = max(mapped, key=SEVERITIES.index) if mapped else None

    # Untimed rows only have the run's fallback time, which changes every run; keep it
    # out of the text so an unchanged case renders (and fingerprints) identically.
    ctx = {
        "search_name": search.name,
        "group": key,
        "count": str(len(rows)),
        "first_seen": first.isoformat() if times else "",
        "last_seen": last.isoformat() if times else "",
        # Group columns render in full (every multivalue value, or the key when the row
        # has none), so a title built from them still tells groups apart.
        **{f: ",".join(values(anchor_row, f)) or key for f in search.group_by},
    }
    title = render(search.title, anchor_row, ctx) or f"{search.name}: {key}"
    description = render(search.description, anchor_row, ctx) if search.description else ""
    if not description:
        window = f" between {ctx['first_seen']} and {ctx['last_seen']}" if times else ""
        description = (f"Splunk search '{search.name}' returned {len(rows)} result(s) for "
                       f"group '{key}'{window}.")

    return Case(
        key=key,
        title=title,
        description=description,
        incident_type=search.incident_type,
        severity=severity,
        created=first,
        first_seen=first,
        last_seen=last,
        timed=bool(times),
        row_count=len(rows),
        systems=systems,
        # Most-seen first, so a size cap keeps the most significant observables.
        observables=sorted(observed.values(), key=lambda o: (-o.count, o.kind, o.value)),
        techniques=techniques,
        rejected=rejected,
    )


# -- helpers -----------------------------------------------------------------


def values(row: dict, fld: str) -> list[str]:
    """Splunk JSON results carry a field as a string, or a list for multivalue."""
    v = row.get(fld)
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if x is not None and str(x) != ""]
    s = str(v)
    return [s] if s != "" else []


def parse_time(v: str) -> datetime | None:
    """Accept epoch seconds or ISO-8601 (Splunk renders _time in the job owner's TZ).
    A value that fits neither is untimed: one bad row must not fail the whole search."""
    if not _YYYYMMDD_RE.match(v):  # 20240101 is a date, not an epoch in 1970
        try:
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            pass
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


def render(template: str, row: dict, ctx: dict[str, str]) -> str:
    """Substitute {field} with ctx keys first, then the row's first value for that field."""
    def sub(m: re.Match) -> str:
        k = m.group(1).strip()
        if k in ctx:
            return ctx[k]
        return next(iter(values(row, k)), "")
    return TEMPLATE_RE.sub(sub, template).strip()


def _asset_key(system: str | None) -> str | None:
    """OpenCTI ignores case in System names, so DC01 and dc01 are one asset."""
    return system.lower() if system else None


def _unique(it) -> list[str]:
    """Distinct assets, trimmed, without placeholders, first spelling wins."""
    seen: dict[str, str] = {}
    for s in it:
        if not is_placeholder(s):
            seen.setdefault(_asset_key(s.strip()), s.strip())
    return list(seen.values())
