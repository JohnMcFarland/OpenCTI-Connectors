"""Data model invariants (docs/WAYPOINT_SCOPE.md), one test each.

Each runs for every live (enabled) source, through the scheduler path the
deployment uses (discover -> select -> render queue -> single writer).
"""

import dataclasses
import uuid
from unittest.mock import MagicMock, patch

import pytest

from conftest import PDF, PROFILES, FakeGraph, make_feed, test_settings, wire_graph
from engine import report
from engine.render import ContentUnavailable
from engine.scheduler import Scheduler
from engine.status import StatusStore
from engine.worker import SourceWorker


def _site_link(slug, n):
    host = sorted(PROFILES[slug].allowed_hosts)[0]
    return f"https://{host}/inv/article-{n}/"


def _run(slug, items, tmp_path, render=PDF, settings=None, graph=None, ticks=1):
    """One scheduler over one source; returns (api, graph, render mock, worker).

    request_delay is zeroed: the scheduler's per-source cooldown is a real
    wait (tested in test_scheduler.py), not something to sit through here.
    """
    p = dataclasses.replace(PROFILES[slug], request_delay=0)
    graph = graph or FakeGraph()
    api = MagicMock()
    wire_graph(api, graph)
    api.identity.create.return_value = {"id": "org-" + slug}
    api.marking_definition.read.return_value = {"id": "tlp-clear-id"}
    session = MagicMock()
    page = b"<html><body><p>public page</p></body></html>"
    feed = items if isinstance(items, bytes) else make_feed(items)
    session.get.side_effect = lambda url, **k: MagicMock(
        content=feed if url in p.feed_urls else page, text="<p>public</p>", status_code=200)
    w = SourceWorker(p, settings or test_settings(), api, MagicMock(), session=session)
    log = MagicMock()
    sched = Scheduler({slug: w}, w.settings, log, StatusStore(str(tmp_path / "s.json")), "cid")
    with patch("engine.render.render_live_pdf") as rl:
        if isinstance(render, Exception):
            rl.side_effect = render
        else:
            rl.return_value = render
        sched.start(api)
        for _ in range(ticks):
            for wk in sched.workers.values():
                wk.next_due = 0
            sched.tick()
    return api, graph, rl, w


def _create_kw(api):
    assert api.report.create.call_count == 1
    return api.report.create.call_args.kwargs


def test_container_only_no_labels_entities_or_relationships(live_slug, tmp_path):
    api, _, _, _ = _run(live_slug, [_site_link(live_slug, 1)], tmp_path)
    kw = _create_kw(api)
    for forbidden in ("objects", "objectLabel", "labels", "content", "x_opencti_labels"):
        assert forbidden not in kw
    for writer in (api.stix_cyber_observable.create, api.indicator.create,
                   api.stix_core_relationship.create, api.label.create, api.malware.create):
        writer.assert_not_called()


def test_report_id_is_uuid5_of_the_article_url(live_slug, tmp_path):
    url = _site_link(live_slug, 2)
    api, _, _, _ = _run(live_slug, [url], tmp_path)
    assert _create_kw(api)["stix_id"] == "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))


def test_created_by_is_the_publisher_resolved_once(live_slug, tmp_path):
    api, _, _, _ = _run(live_slug, [_site_link(live_slug, i) for i in range(1, 4)],
                        tmp_path, ticks=2)
    assert api.identity.create.call_count == 1
    org = api.identity.create.call_args.kwargs
    assert org["type"] == "Organization" and org["name"] == PROFILES[live_slug].author_name
    for call in api.report.create.call_args_list:
        assert call.kwargs["createdBy"] == "org-" + live_slug
        assert "objects" not in call.kwargs     # author never in the contents


def test_published_is_the_article_date_and_undated_items_are_skipped(live_slug, tmp_path):
    p = PROFILES[live_slug]
    good, undated = _site_link(live_slug, 1), _site_link(live_slug, 2)
    feed = (f"<rss><channel>"
            f"<item><title>a</title><link>{good}</link>"
            f"<pubDate>Mon, 09 Nov 2026 17:09:33 -0500</pubDate><description>s</description></item>"
            f"<item><title>b</title><link>{undated}</link><description>s</description></item>"
            f"</channel></rss>").encode()
    api, _, _, w = _run(live_slug, feed, tmp_path)
    kw = _create_kw(api)
    assert kw["published"] == "2026-11-09T22:09:33+00:00"
    assert "no usable publication date" in w.permanent_skips[undated]
    assert p.max_age_days == 0   # live sources take every new post


def test_tlp_on_report_and_file_and_confidence_50(live_slug, tmp_path):
    api, _, _, _ = _run(live_slug, [_site_link(live_slug, 1)], tmp_path)
    kw = _create_kw(api)
    api.marking_definition.read.assert_called_with(filters={
        "mode": "and", "filters": [{"key": "definition", "values": ["TLP:CLEAR"]}],
        "filterGroups": []})
    assert kw["objectMarking"] == ["tlp-clear-id"]
    assert kw["filesMarkings"] == [["tlp-clear-id"]]
    assert kw["confidence"] == 50


def test_report_types_from_collector_else_default(live_slug, tmp_path, monkeypatch):
    api, _, _, _ = _run(live_slug, [_site_link(live_slug, 1)], tmp_path)
    assert _create_kw(api)["report_types"] == ["open-source-reporting"]
    monkeypatch.setenv("CRUCIBLE_COLLECTOR_URL", "http://collector.example:8004")
    with patch("engine.report.classify_report", side_effect=lambda **kw: ["threat-report"]):
        api, _, _, _ = _run(live_slug, [_site_link(live_slug, 1)], tmp_path)
    assert _create_kw(api)["report_types"] == ["threat-report"]


def test_one_external_reference_canonical_url(live_slug, tmp_path):
    url = _site_link(live_slug, 1)
    api, _, _, _ = _run(live_slug, [url + "?utm_source=rss&utm_medium=feed"], tmp_path)
    assert api.external_reference.create.call_count == 1
    assert api.external_reference.create.call_args.kwargs["url"] == url
    assert len(_create_kw(api)["externalReferences"]) == 1


def test_dedup_is_the_graphs_no_local_state(live_slug, tmp_path):
    """A brand-new process (fresh worker) skips what any Report already cites."""
    graph = FakeGraph()
    graph.add_ingested(_site_link(live_slug, 1), report_id="old-connector-report")
    api, _, _, _ = _run(live_slug, [_site_link(live_slug, 1), _site_link(live_slug, 2)],
                        tmp_path, graph=graph)
    assert graph.created() == {report.report_id(_site_link(live_slug, 2))}
    # Run again with another fresh process: nothing new.
    api, _, _, _ = _run(live_slug, [_site_link(live_slug, 1), _site_link(live_slug, 2)],
                        tmp_path, graph=graph)
    api.report.create.assert_not_called()


def test_one_pdf_named_for_the_source(live_slug, tmp_path):
    api, _, rl, _ = _run(live_slug, [_site_link(live_slug, 1)], tmp_path)
    files = _create_kw(api)["files"]
    assert len(files) == 1 and files[0].data == PDF and files[0].mime == "application/pdf"
    assert files[0].name == f"{PROFILES[live_slug].file_prefix}-rendered-article-1.pdf"
    assert rl.call_count == 1
    api.stix_domain_object.add_file.assert_not_called()


def test_oversized_pdf_is_not_attached(live_slug, tmp_path):
    big = b"%PDF" + b"0" * (25 * 1024 * 1024)
    api, _, _, _ = _run(live_slug, [_site_link(live_slug, 1)], tmp_path, render=big)
    kw = _create_kw(api)
    assert "files" not in kw and "filesMarkings" not in kw


def test_no_pdf_when_no_usable_article(live_slug, tmp_path):
    api, _, _, _ = _run(live_slug, [_site_link(live_slug, 1)], tmp_path,
                        render=ContentUnavailable("HTTP 422: no article"))
    assert "files" not in _create_kw(api)


def test_description_plain_text_no_links_capped(live_slug, tmp_path):
    url = _site_link(live_slug, 1)
    body = "<p>See <a href='https://evil.example/x'>this link</a> &amp; more.</p>" + "word " * 1000
    feed = (f"<rss><channel><item><title>a</title><link>{url}</link>"
            f"<pubDate>Mon, 09 Nov 2026 12:00:00 GMT</pubDate>"
            f"<description><![CDATA[{body}]]></description></item></channel></rss>").encode()
    api, _, _, _ = _run(live_slug, feed, tmp_path)
    desc = _create_kw(api)["description"]
    assert "<" not in desc and "href" not in desc and "https://evil" not in desc
    assert desc.startswith("See this link & more.")
    assert len(desc) <= 2000


def test_one_report_create_inline_pdf_update_false(live_slug, tmp_path):
    api, _, _, _ = _run(live_slug, [_site_link(live_slug, 1)], tmp_path)
    kw = _create_kw(api)
    assert kw["update"] is False and "files" in kw
    api.report.update_field.assert_not_called()
    api.stix_domain_object.add_file.assert_not_called()


def test_bleepingcomputer_renders_with_its_user_agent(tmp_path):
    bc = "bleepingcomputer"
    _, _, rl, _ = _run(bc, [_site_link(bc, 1)], tmp_path)
    assert rl.call_args.kwargs["headers"] == {"User-Agent": PROFILES[bc].render_headers["User-Agent"]}
