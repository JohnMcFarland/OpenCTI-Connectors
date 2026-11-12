"""Publication-date parsing (ported unchanged from the generated connectors).

Every function returns an ISO-8601 UTC string ("2026-11-09T22:09:33+00:00")
or None. A Report's `published` is always the article's own date; an item
whose date cannot be parsed is skipped, never stamped with ingestion time.
"""

import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from .settings import MIN_VALID_YEAR

# Written dates the RFC 2822 parser gets wrong (it ignores AM/PM and a colon
# offset such as +02:00): parsed by parse_loose_date first.
_LOOSE_FIRST_RE = re.compile(r"\d\s*[AaPp]\.?[Mm]\b|[+-]\d{2}:\d{2}\s*$")
_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
_TZ_HOURS = {"utc": 0, "gmt": 0, "z": 0, "wet": 0, "bst": 1, "cet": 1, "cest": 2,
             "eet": 2, "eest": 3, "est": -5, "edt": -4, "cst": -6, "cdt": -5,
             "mst": -7, "mdt": -6, "pst": -8, "pdt": -7, "aest": 10, "aedt": 11}
_LOOSE_DATE_RE = re.compile(
    r"(?:(?P<d1>\d{1,2})(?:st|nd|rd|th)?\s+(?P<m1>[A-Za-z]{3,9})\.?,?\s+(?P<y1>\d{4})"
    r"|(?P<m2>[A-Za-z]{3,9})\.?\s+(?P<d2>\d{1,2})(?:st|nd|rd|th)?,?\s+(?P<y2>\d{4})"
    r"|(?P<y3>\d{4})-(?P<o3>\d{1,2})-(?P<d3>\d{1,2}))"
    r"(?:[\sT,@-]{0,4}(?P<h>\d{1,2}):(?P<mi>\d{2})(?::(?P<s>\d{2}))?"
    r"\s*(?P<ap>[AaPp]\.?[Mm]\b\.?)?)?"
    r"(?:\s*(?P<tz>[A-Za-z]{1,4}\b|[+-]\d{2}:?\d{2}))?")

_RELATIVE_RE = re.compile(r"\b(\d+|an?|one)\s+(minute|hour|day|week)s?\s+ago\b"
                          r"|\b(yesterday|today)\b", re.IGNORECASE)
_RELATIVE_UNITS = {"minute": 60, "hour": 3600, "day": 86400, "week": 604800}

_ISO_FMT = "%Y-%m-%dT%H:%M:%S+00:00"


def parse_date(date_str):
    """Parse a date (RFC 2822, ISO 8601, or a common written form such as
    "Friday, October 30, 2026 - 17:15" or "11 Nov 2026 12:00:00 AM CET")."""
    # Written forms with AM/PM or a colon offset go to the loose parser first
    # (but not ISO strings, which fromisoformat handles exactly).
    if (date_str and _LOOSE_FIRST_RE.search(date_str)
            and not re.match(r"\s*\d{4}-", date_str)):
        return parse_loose_date(date_str)
    parsed = parse_rfc2822(date_str)
    if parsed or not date_str:
        return parsed
    try:
        dt = datetime.fromisoformat(date_str.strip().replace("Z", "+00:00"))
    except ValueError:
        return parse_loose_date(date_str)
    if dt.year < MIN_VALID_YEAR:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(_ISO_FMT)


def parse_relative_date(date_str, now=None):
    """Parse "8 hours ago", "1 day ago", "yesterday" against `now` (UTC), or None."""
    match = _RELATIVE_RE.search(date_str or "")
    if not match:
        return None
    now = now or datetime.now(timezone.utc)
    if match.group(3):
        delta = timedelta(days=1 if match.group(3).lower() == "yesterday" else 0)
    else:
        count = match.group(1).lower()
        count = 1 if count in ("a", "an", "one") else int(count)
        delta = timedelta(seconds=count * _RELATIVE_UNITS[match.group(2).lower()])
    return (now - delta).strftime(_ISO_FMT)


def parse_loose_date(date_str):
    """Parse a written date ("Nov 11, 2026 1:11pm", "30 October 2026"), or None.

    Known zone abbreviations and numeric offsets are applied; anything else
    is taken as UTC (the date is what matters for a Report).
    """
    for match in _LOOSE_DATE_RE.finditer(date_str or ""):
        g = match.groupdict()
        month_name = g["m1"] or g["m2"]
        if month_name:
            month = _MONTHS.get(month_name[:3].lower())
            day, year = int(g["d1"] or g["d2"]), int(g["y1"] or g["y2"])
        else:
            month, day, year = int(g["o3"]), int(g["d3"]), int(g["y3"])
        if not month:
            continue
        hour, minute, second = int(g["h"] or 0), int(g["mi"] or 0), int(g["s"] or 0)
        if g["ap"]:
            hour = hour % 12 + (12 if g["ap"][0] in "Pp" else 0)
        offset = timedelta(0)
        tz = (g["tz"] or "").lower()
        if tz[:1] in "+-" and tz:
            digits = tz[1:].replace(":", "")
            offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:] or 0))
            offset = offset if tz[0] == "+" else -offset
        elif tz in _TZ_HOURS:
            offset = timedelta(hours=_TZ_HOURS[tz])
        try:
            dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc) - offset
        except ValueError:
            continue
        if dt.year < MIN_VALID_YEAR:
            continue
        return dt.strftime(_ISO_FMT)
    # Listing/byline text such as "8 hours ago" (relative to now).
    return parse_relative_date(date_str)


def parse_rfc2822(date_str):
    """Parse an RFC 2822 date string and return an ISO-8601 UTC string."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None or dt.year < MIN_VALID_YEAR:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(_ISO_FMT)
