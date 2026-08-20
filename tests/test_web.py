"""Smoke tests for the dashboard API.

These run against a temporary LOMST_HOME with an empty database, so they also
cover the first-run path a new user hits: no data, no registry entries, and the
UI still has to render rather than error.
"""

from __future__ import annotations

import importlib
import json

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    (tmp_path / "config").mkdir()
    (tmp_path / "registry" / "families").mkdir(parents=True)
    (tmp_path / "registry" / "runtimes").mkdir(parents=True)
    (tmp_path / "config" / "sources.yaml").write_text(
        "sources:\n"
        "  - id: radarai\n"
        "    name: RadarAI\n"
        "    connector: rss\n"
        "    tier: aggregator\n"
        "    url: https://radarai.top/feed.xml\n"
    )
    monkeypatch.setenv("LOMST_HOME", str(tmp_path))
    monkeypatch.setenv("LOMST_WEB_READONLY", "1")

    from lomst import web

    importlib.reload(web)
    with TestClient(web.app) as c:
        yield c


def test_index_serves_the_ui(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Model Security Tracker" in r.text
    # The status palette must ship icon + label, never colour alone.
    assert "badge" in r.text


def test_overview_on_an_empty_install(client):
    r = client.get("/api/overview")
    assert r.status_code == 200
    d = r.json()
    assert d["has_data"] is False
    assert d["families"] == 0
    assert d["readonly"] is True
    assert d["registry_error"] is None


def test_vocabulary_exposes_the_controlled_terms(client):
    d = client.get("/api/vocabulary").json()
    cats = [c["value"] for c in d["usage_categories"]]
    assert cats[0] == "research_experimentation"
    assert cats[-1] == "autonomous_decision_support"
    assert len(d["condition_codes"]) == 9
    assert any(c["code"] == "C9" for c in d["condition_codes"])


@pytest.mark.parametrize(
    "path",
    ["/api/actions", "/api/registry", "/api/advisories", "/api/families",
     "/api/intelligence", "/api/sources", "/api/digest", "/api/ingest/status"],
)
def test_read_endpoints_return_json(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert isinstance(r.json(), dict)


def test_check_blocks_an_unregistered_family(client):
    r = client.post(
        "/api/check",
        json={"family": "nope", "usage_category": "internal_productivity"},
    )
    assert r.status_code == 200
    d = r.json()
    assert d["verdict"] == "blocked"
    assert any(b["section"] == "9" for b in d["blockers"])


def test_check_rejects_a_bad_usage_category(client):
    r = client.post("/api/check", json={"family": "x", "usage_category": "nonsense"})
    assert r.status_code == 400
    assert "usage_category" in r.json()["error"]


def test_check_requires_a_family(client):
    r = client.post("/api/check", json={"usage_category": "internal_productivity"})
    assert r.status_code == 400


def test_assess_works_without_a_registry_entry(client):
    d = client.get("/api/assess/qwen").json()
    # No evidence yet, so the honest answer is Deferred - never an approval.
    assert d["recommended_outcome"] == "deferred"
    assert "Recommendation only" in d["disclaimer"]


def test_readonly_blocks_ingest_and_decisions(client):
    assert client.post("/api/ingest", json={}).status_code == 403
    r = client.post(
        "/api/decide",
        json={"family": "x", "outcome": "approved", "authority": "A", "rationale": "B"},
    )
    assert r.status_code == 403


def test_decision_requires_authority_and_rationale(tmp_path, monkeypatch):
    """Appendix A.5 / D.6 - and it must be enforced at the API, not just the form."""
    (tmp_path / "config").mkdir()
    fam = tmp_path / "registry" / "families"
    fam.mkdir(parents=True)
    (tmp_path / "registry" / "runtimes").mkdir(parents=True)
    (tmp_path / "config" / "sources.yaml").write_text("sources: []\n")
    (fam / "testfam.yaml").write_text(
        "key: testfam\nname: Test\nkind: model_family\n"
        "approval_status: pending_evaluation\nlifecycle_status: active\n"
    )
    monkeypatch.setenv("LOMST_HOME", str(tmp_path))
    monkeypatch.delenv("LOMST_WEB_READONLY", raising=False)

    from lomst import web

    importlib.reload(web)
    with TestClient(web.app) as c:
        missing_authority = c.post(
            "/api/decide",
            json={"family": "testfam", "outcome": "approved", "rationale": "why"},
        )
        assert missing_authority.status_code == 400
        assert "authority" in missing_authority.json()["error"].lower()

        missing_rationale = c.post(
            "/api/decide",
            json={"family": "testfam", "outcome": "approved", "authority": "AI Governance"},
        )
        assert missing_rationale.status_code == 400
        assert "rationale" in missing_rationale.json()["error"].lower()

        ok = c.post(
            "/api/decide",
            json={
                "family": "testfam",
                "outcome": "approved_with_conditions",
                "authority": "AI Governance",
                "rationale": "Evidence reviewed.",
                "approved_uses": ["internal_productivity"],
                "conditions": ["C2"],
            },
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["approval_status"] == "approved_with_conditions"

    # The decision must be durable in the git-tracked YAML (Section 9.1).
    text = (fam / "testfam.yaml").read_text()
    assert "AI Governance" in text
    assert "decision_history" in text


def test_ingest_status_shape(client):
    d = client.get("/api/ingest/status").json()
    assert d["running"] is False
    assert "sources" in d and isinstance(d["sources"], list)
