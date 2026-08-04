"""F-05 regression: seen_attack_ids eviction must drop the OLDEST ids, in order.

The pre-fix code did `list(set(...))[-5000:]`, which slices a set whose iteration
order is arbitrary, so it evicted an arbitrary subset rather than the oldest. These
tests pin the insertion-ordered contract of cap_seen_ids, which the connector state
update now uses. The logic lives in src/models.py (stdlib only) so this runs without
pycti/stix2 installed.
"""

from __future__ import annotations

from src.models import cap_seen_ids


def test_evicts_oldest_and_retains_last_5000_in_order():
    # 5100 ids pushed through a single update: first 100 evicted, last 5000 kept.
    all_ids = [str(i) for i in range(5100)]
    result = cap_seen_ids([], all_ids, 5000)

    assert len(result) == 5000
    assert result == [str(i) for i in range(100, 5100)]  # oldest 0..99 gone, in order
    assert all(str(i) not in result for i in range(100))


def test_accumulates_across_runs_preserving_order():
    state = cap_seen_ids([], ["a", "b", "c"], 5000)
    state = cap_seen_ids(state, ["d", "e"], 5000)
    assert state == ["a", "b", "c", "d", "e"]


def test_dedups_without_reordering():
    # Re-seen ids must not move or duplicate; ordering is first-seen.
    result = cap_seen_ids(["a", "b", "c"], ["b", "d", "a", "e"], 5000)
    assert result == ["a", "b", "c", "d", "e"]


def test_cap_counts_from_the_end_after_dedup():
    existing = [str(i) for i in range(4999)]
    result = cap_seen_ids(existing, ["x", "y", "z"], 5000)  # 5002 unique -> keep last 5000
    assert len(result) == 5000
    assert result[-3:] == ["x", "y", "z"]
    assert result[0] == "2"  # ids "0" and "1" evicted as oldest
