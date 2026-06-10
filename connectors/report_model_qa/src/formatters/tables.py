from __future__ import annotations

from typing import List, Optional, Tuple


def format_4col_table(
    rows: List[Tuple[str, str, str, str]],
    max_rows: int = 50,
    headers: Optional[Tuple[str, str, str, str]] = None,
) -> str:
    """
    Generic 4-column markdown table.

    Default headers: Source | Relationship | Target | Reason
    Override via the headers parameter for non-relationship contexts
    (e.g. document extraction suggestions).
    """
    if headers is None:
        headers = ("Source", "Relationship", "Target", "Reason")

    h1, h2, h3, h4 = headers
    out: List[str] = []
    out.append(f"| {h1} | {h2} | {h3} | {h4} |")
    out.append("|---|---|---|---|")
    for s, r, t, why in rows[:max_rows]:
        s = (s or "").replace("|", "\\|")
        r = (r or "").replace("|", "\\|")
        t = (t or "").replace("|", "\\|")
        why = (why or "").replace("|", "\\|")
        out.append(f"| {s} | {r} | {t} | {why} |")
    return "\n".join(out)
