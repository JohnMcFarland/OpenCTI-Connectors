"""Graph dedup by External Reference URL (no local dedup state).

An article counts as ingested when an External Reference with its URL
exists AND some Report cites that reference. A reference with no citing
Report (left behind by a failed Report create) does not count, so the
article is retried. Any connector's Report counts, so moving a source to
Waypoint (or back) never duplicates an article.
"""


def ingested_links(api, items, log):
    """Return the item links already ingested.

    Two exact-match batched queries, id/url fields only:
    1. External References whose url is one of the item links.
    2. Reports citing any of those references.
    If query 1 fails the exception propagates and the caller skips the poll
    (nothing written). If query 2 fails, any matching reference counts as
    ingested (conservative: never duplicate).
    """
    links = sorted({item["link"] for item in items})
    if not links:
        return set()

    # Query 1: External References with these URLs.
    refs = api.external_reference.list(
        filters={
            "mode": "and",
            "filters": [{"key": "url", "values": links}],
            "filterGroups": [],
        },
        first=max(100, 5 * len(links)),
        customAttributes="id url",
    ) or []
    url_by_ref = {r["id"]: r.get("url") for r in refs if r.get("url") in links}
    if not url_by_ref:
        return set()

    # Query 2: Reports citing those references.
    try:
        reports = api.report.list(
            filters={
                "mode": "and",
                "filters": [{"key": "externalReferences", "values": sorted(url_by_ref)}],
                "filterGroups": [],
            },
            first=max(100, 5 * len(url_by_ref)),
            customAttributes="id externalReferences { edges { node { id } } }",
        ) or []
    except Exception as exc:
        log.log_warning(
            f"Citing-Report query failed ({exc}); treating every matching "
            f"External Reference as ingested."
        )
        return set(url_by_ref.values())

    cited = set()
    for report in reports:
        cited.update(report.get("externalReferencesIds") or [])
    return {url_by_ref[ref_id] for ref_id in cited if ref_id in url_by_ref}
