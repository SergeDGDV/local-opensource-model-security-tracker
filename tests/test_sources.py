"""Offline tests for connector parsing and the ingest pipeline.

No network. Connector parsing is exercised against fixtures shaped like the real
payloads so a regression is caught without waiting for a live fetch.
"""

from __future__ import annotations

import json

import pytest

from lomst.config import SourceConfig
from lomst.db import Store
from lomst.sources.base import Observation, iso_date, strip_html
from lomst.sources.feeds import RssConnector
from lomst.sources.security import _severity_from_cvss
from lomst.sources.trackers import _balanced_objects


# ------------------------------------------------------------------ text helpers


def test_strip_html_flattens_and_decodes():
    out = strip_html("<p>Hello &amp; <b>welcome</b>&#8217;s</p>")
    # Tags become spaces rather than being deleted, so adjacent words are never
    # fused ("foo</b><b>bar" must not become "foobar"). That leaves an extra
    # space before trailing punctuation, which is harmless for search and digests.
    assert "Hello & welcome" in out
    assert "&amp;" not in out and "<b>" not in out
    assert out.endswith("s")


def test_strip_html_does_not_fuse_adjacent_words():
    assert strip_html("<td>foo</td><td>bar</td>") == "foo bar"


def test_strip_html_truncates_with_ellipsis():
    out = strip_html("x" * 900, limit=100)
    assert out is not None and len(out) <= 101 and out.endswith("…")


def test_strip_html_on_empty_is_none():
    assert strip_html("") is None
    assert strip_html(None) is None
    assert strip_html("<div>   </div>") is None


@pytest.mark.parametrize(
    "raw",
    [
        "2026-08-15",
        "2026-08-15T10:30:00Z",
        "2026-08-15T10:30:00+00:00",
        "Wed, 19 Aug 2026 20:04:52 +0000",
        "Aug 15, 2026",
    ],
)
def test_iso_date_normalises_known_formats(raw):
    out = iso_date(raw)
    assert out is not None and out.startswith("2026-08")


def test_iso_date_rejects_garbage():
    assert iso_date("not a date") is None
    assert iso_date(None) is None


# -------------------------------------------------------------------- RSS parsing


RSS_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>Test feed</title>
    <item>
      <title>Qwen3 released under Apache 2.0</title>
      <link>https://example.test/qwen3</link>
      <guid>https://example.test/qwen3</guid>
      <pubDate>Wed, 19 Aug 2026 20:04:52 +0000</pubDate>
      <description>&lt;p&gt;New open-weight release.&lt;/p&gt;</description>
      <category>models</category>
    </item>
    <item>
      <title>Heap overflow in llama.cpp</title>
      <link>https://example.test/cve</link>
      <guid>gid-2</guid>
      <pubDate>Tue, 18 Aug 2026 09:00:00 +0000</pubDate>
      <content:encoded>&lt;p&gt;Parser bug.&lt;/p&gt;</content:encoded>
    </item>
  </channel>
</rss>
"""


def _cfg(**over) -> SourceConfig:
    base = dict(id="t", name="Test", connector="rss", tier="community", url="https://example.test/f")
    base.update(over)
    return SourceConfig(**base)


def test_rss_parses_items():
    obs = list(RssConnector()._parse(RSS_FIXTURE, _cfg()))
    assert len(obs) == 2
    first = obs[0]
    assert first.title == "Qwen3 released under Apache 2.0"
    assert first.url == "https://example.test/qwen3"
    assert first.published_at is not None and first.published_at.startswith("2026-08-19")
    assert first.summary == "New open-weight release."
    assert first.payload["categories"] == ["models"]


def test_rss_uses_content_encoded_when_no_description():
    obs = list(RssConnector()._parse(RSS_FIXTURE, _cfg()))
    assert obs[1].summary == "Parser bug."


def test_observation_hash_changes_with_content():
    a = Observation(external_id="x", kind="k", title="one", url="u")
    b = Observation(external_id="x", kind="k", title="two", url="u")
    assert a.hash() != b.hash()
    assert a.hash() == Observation(external_id="x", kind="k", title="one", url="u").hash()


# --------------------------------------------------- llm-stats flight extraction


def test_balanced_objects_finds_nested_and_skips_non_matching():
    blob = (
        'prefix{"name":"A","organization":"OrgA","license":"mit","meta":{"a":1}}'
        'junk{"name":"B","other":1}'
        '{"name":"C","organization":"OrgC","license":"apache_2_0"}'
    )
    found = list(_balanced_objects(blob, ("license", "organization")))
    assert len(found) == 2
    parsed = [json.loads(f) for f in found]
    assert parsed[0]["meta"] == {"a": 1}
    assert [p["name"] for p in parsed] == ["A", "C"]


def test_balanced_objects_handles_braces_inside_strings():
    blob = '{"organization":"Org","license":"mit","note":"a } brace {"}'
    found = list(_balanced_objects(blob, ("license", "organization")))
    assert len(found) == 1
    assert json.loads(found[0])["note"] == "a } brace {"


# ----------------------------------------------------------- severity derivation


@pytest.mark.parametrize(
    "score,expected",
    [(9.8, "critical"), (7.5, "high"), (5.0, "moderate"), (2.1, "low")],
)
def test_severity_from_numeric_score(score, expected):
    assert _severity_from_cvss(None, score) == expected


def test_severity_from_vector_only():
    full = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    assert _severity_from_cvss(full) == "critical"
    partial = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert _severity_from_cvss(partial) in ("high", "moderate")


def test_severity_unknown_when_no_data():
    assert _severity_from_cvss(None, None) is None


# ------------------------------------------------------------------ store upserts


def test_upsert_reports_new_then_seen_then_changed(tmp_path):
    store = Store(tmp_path / "s.db")
    run = store.start_run(["t"])
    rec = {
        "source_id": "t", "tier": "community", "external_id": "e1", "kind": "article",
        "title": "First", "url": "u", "summary": None, "published_at": None,
        "family_key": None, "runtime_key": None, "payload": {}, "content_hash": "h1",
    }
    assert store.upsert_observation(run, rec) == "new"
    assert store.upsert_observation(run, rec) == "seen"
    assert store.upsert_observation(run, {**rec, "content_hash": "h2", "title": "Second"}) == "changed"
    row = store.query("SELECT revision, title FROM observations WHERE external_id='e1'")[0]
    assert row["revision"] == 2 and row["title"] == "Second"
    store.close()


def test_artefact_licence_change_is_reported_distinctly(tmp_path):
    """Section 6.2: a licence change is a full-reassessment trigger, not a bump."""
    store = Store(tmp_path / "s.db")
    run = store.start_run(["hf"])
    rec = {
        "source_id": "hf", "artefact_id": "org/model", "family_key": "fam",
        "publisher": "org", "license": "apache-2.0", "model_type": "llm",
        "gated": False, "downloads": 10, "version_label": "1.0",
        "url": "u", "modified_at": "2026-01-01T00:00:00+00:00", "payload": {},
    }
    assert store.upsert_artefact(run, rec) == "new"
    assert store.upsert_artefact(run, rec) == "seen"
    assert store.upsert_artefact(run, {**rec, "license": "cc-by-nc"}) == "license_changed"
    store.close()


def test_health_tracks_consecutive_failures(tmp_path):
    store = Store(tmp_path / "s.db")
    store.record_health("s1", ok=False, error="boom")
    store.record_health("s1", ok=False, error="boom again")
    row = store.health()[0]
    assert row["consecutive_failures"] == 2
    store.record_health("s1", ok=True, item_count=5)
    row = store.health()[0]
    assert row["consecutive_failures"] == 0 and row["last_item_count"] == 5
    store.close()


# ------------------------------------------------------------------- config wiring


def test_source_options_capture_unknown_keys():
    cfg = SourceConfig.from_dict(
        {
            "id": "osv", "name": "OSV", "connector": "osv", "tier": "authoritative",
            "packages": [{"ecosystem": "PyPI", "name": "vllm"}],
            "custom_thing": 42,
        }
    )
    assert cfg.options["packages"][0]["name"] == "vllm"
    assert cfg.options["custom_thing"] == 42


def test_enabled_sources_rejects_unknown_id():
    from lomst import config as config_mod

    cfg = config_mod.Config(paths=config_mod.Paths(root=__import__("pathlib").Path(".")), raw={
        "sources": [{"id": "a", "name": "A", "connector": "rss", "tier": "community"}]
    })
    with pytest.raises(KeyError, match="unknown source"):
        cfg.enabled_sources(["nope"])


def test_explicit_selection_overrides_disabled_flag():
    from lomst import config as config_mod

    cfg = config_mod.Config(paths=config_mod.Paths(root=__import__("pathlib").Path(".")), raw={
        "sources": [
            {"id": "a", "name": "A", "connector": "rss", "tier": "community", "enabled": False}
        ]
    })
    assert cfg.enabled_sources() == []
    assert [s.id for s in cfg.enabled_sources(["a"])] == ["a"]
