"""Operator-defined search definitions: the searches.yml schema and its validation.

Pure module (no pycti / network). Each entry is one source the operator wants
imported: an SPL query or a saved search, plus a field map that says which result
columns are which observable types. Everything is validated at startup so a bad
entry fails the container instead of a run. See searches.yml.sample for the schema.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .observables import OBSERVABLE_KINDS

# OpenCTI incident_severity_ov / case_severity_ov, lowest to highest.
SEVERITIES = ("low", "medium", "high", "critical")

# Splunk ES urgency / common severity words -> OpenCTI severity.
DEFAULT_SEVERITY_MAP = {
    "informational": "low", "info": "low", "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

TEMPLATE_RE = re.compile(r"\{([^{}]+)\}")

# Built-in template keys (not result columns).
_CTX_KEYS = {"search_name", "group", "count", "first_seen", "last_seen"}

# Template keys that change as a case gains rows. The title is part of the case id,
# so a title using one of these would mint a new case on every update.
_VOLATILE_TITLE_KEYS = {"count", "last_seen"}

_RELATIVE_RE = re.compile(r"^-(\d+)([smhdw])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class SearchConfigError(ValueError):
    """The searches file is malformed. Raised at startup, never mid-run."""


@dataclass
class SearchDef:
    name: str
    spl: str
    app: str = "search"
    enabled: bool = True
    time_mode: str = "index"  # "index" (_indextime window, tolerates late arrival) | "event"
    lookback: str = ""  # set = rolling window (e.g. "-7d") every run instead of the cursor
    time_field: str = "_time"
    group_by: list[str] = field(default_factory=list)
    title: str = "{search_name}: {group}"
    description: str = ""
    incident_type: str = "alert"
    severity_field: str = ""
    severity_map: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SEVERITY_MAP))
    system_fields: list[str] = field(default_factory=list)
    observables: dict[str, str] = field(default_factory=dict)  # field -> kind
    attack_pattern_fields: list[str] = field(default_factory=list)
    max_results: int = 10000  # rows per Splunk job; larger windows are split

    def referenced_fields(self) -> list[str]:
        """Every column this entry reads. Results are projected to these, so a search
        that forgets `table` does not ship `_raw` for every row."""
        cols = [self.time_field, *self.group_by, *self.system_fields, *self.observables,
                *self.attack_pattern_fields]
        if self.severity_field:
            cols.append(self.severity_field)
        # Only template keys can be built-ins: a real column may share a built-in's name
        # (`stats min(_time) as first_seen`, ES `search_name`) and must still be fetched.
        for tpl in (self.title, self.description):
            cols += [k for k in (t.strip() for t in TEMPLATE_RE.findall(tpl))
                     if k not in _CTX_KEYS]
        return list(dict.fromkeys(c for c in cols if c))


def parse_relative(value: str) -> int:
    """'-24h' -> 86400. Only plain '-<n><s|m|h|d|w>' offsets, so the connector can turn
    windows into epoch bounds (needed to split oversized windows)."""
    m = _RELATIVE_RE.match(value.strip())
    if not m:
        raise SearchConfigError(
            f"Relative time {value!r} must look like -<n><s|m|h|d|w>, e.g. -24h or -7d")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


def load_searches(path: str) -> list[SearchDef]:
    p = Path(path)
    if not p.is_file():
        raise SearchConfigError(f"Searches file not found: {path}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    entries = data.get("searches")
    if not isinstance(entries, list) or not entries:
        raise SearchConfigError("Searches file must contain a non-empty 'searches:' list")
    out: list[SearchDef] = []
    names: set[str] = set()
    for i, raw in enumerate(entries):
        sd = _parse_search(raw, i)
        if sd.name in names:
            raise SearchConfigError(f"Duplicate search name: {sd.name!r}")
        names.add(sd.name)
        out.append(sd)
    return out


def _parse_search(raw: dict, index: int) -> SearchDef:
    if not isinstance(raw, dict):
        raise SearchConfigError(f"searches[{index}] must be a mapping")
    name = str(raw.get("name") or "").strip()
    if not name:
        raise SearchConfigError(f"searches[{index}].name is required")
    spl, saved = raw.get("spl"), raw.get("saved_search")
    if bool(spl) == bool(saved):
        raise SearchConfigError(f"{name}: set exactly one of 'spl' or 'saved_search'")
    if saved:
        spl = f'| savedsearch "{str(saved).replace(chr(34), "")}"'
    spl = str(spl).strip()
    # Over REST a query must start with a command; prefix `search` unless it already
    # starts with one (a pipe = generating command).
    if not spl.startswith("|") and not re.match(r"search\s", spl, re.I):
        spl = f"search {spl}"

    time_mode = str(raw.get("time_mode") or "index").lower()
    if time_mode not in ("index", "event"):
        raise SearchConfigError(f"{name}: time_mode must be 'index' or 'event'")

    lookback = str(raw.get("lookback") or "")
    if lookback:
        try:
            parse_relative(lookback)
        except SearchConfigError as exc:
            raise SearchConfigError(f"{name}: lookback: {exc}") from None

    observables = raw.get("observables") or {}
    if not isinstance(observables, dict):
        raise SearchConfigError(f"{name}: 'observables' must map field -> kind")
    for fld, kind in observables.items():
        if kind not in OBSERVABLE_KINDS:
            raise SearchConfigError(
                f"{name}: field {fld!r} has unknown kind {kind!r} "
                f"(allowed: {', '.join(sorted(OBSERVABLE_KINDS))})")

    severity_map = dict(DEFAULT_SEVERITY_MAP)
    severity_map.update({str(k).lower(): str(v).lower()
                         for k, v in (raw.get("severity_map") or {}).items()})
    bad = sorted({v for v in severity_map.values() if v not in SEVERITIES})
    if bad:
        raise SearchConfigError(
            f"{name}: severity_map values must be one of {', '.join(SEVERITIES)} (got {bad})")

    group_by = _as_list(raw.get("group_by"))
    if lookback and not group_by:
        # Rolling mode tracks a case across runs by its group. Without one the key is a
        # hash of the row, so any changed value would look like a new case.
        raise SearchConfigError(f"{name}: lookback requires group_by")
    title = str(raw.get("title") or "{search_name}: {group}")
    title_keys = {k.strip() for k in TEMPLATE_RE.findall(title)}
    volatile = title_keys & _VOLATILE_TITLE_KEYS
    if volatile:
        raise SearchConfigError(
            f"{name}: title must not use {sorted(volatile)}; the title identifies the case, "
            "so a changing title would duplicate it (use them in description instead)")
    # The title (with first_seen) is the case id in OpenCTI, so it must tell groups
    # apart; otherwise two groups that render the same title would merge into one case.
    if "group" not in title_keys and not (group_by and set(group_by) <= title_keys):
        title += " ({group})"

    try:
        max_results = int(raw.get("max_results", 10000))
    except (TypeError, ValueError):
        max_results = 0
    if max_results <= 0:
        raise SearchConfigError(f"{name}: max_results must be a positive integer")

    return SearchDef(
        name=name,
        spl=spl,
        app=str(raw.get("app") or "search"),
        enabled=_as_bool(raw.get("enabled", True), f"{name}: enabled"),
        time_mode=time_mode,
        lookback=lookback,
        time_field=str(raw.get("time_field") or "_time"),
        group_by=group_by,
        title=title,
        description=str(raw.get("description") or ""),
        incident_type=str(raw.get("incident_type") or "alert"),
        severity_field=str(raw.get("severity_field") or ""),
        severity_map=severity_map,
        system_fields=_as_list(raw.get("system_fields")),
        observables={str(k): str(v) for k, v in observables.items()},
        attack_pattern_fields=_as_list(raw.get("attack_pattern_fields")),
        max_results=max_results,
    )


def _as_bool(v, what: str) -> bool:
    """YAML booleans, plus quoted "true"/"false" (a quoted "false" must not mean True)."""
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "yes", "on", "1"):
        return True
    if s in ("false", "no", "off", "0"):
        return False
    raise SearchConfigError(f"{what} must be true or false (got {v!r})")


def _as_list(v) -> list[str]:
    if v is None or v == "":
        return []
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    return [str(x) for x in v]
