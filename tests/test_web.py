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


def test_scaffold_drafts_from_evidence_but_approves_nothing(tmp_path, monkeypatch):
    """The missing step between "61 families observed" and "3 decided".

    Drafting must never be an approval: the entry lands as pending_evaluation,
    which the usage gate treats as no permission at all.
    """
    (tmp_path / "config").mkdir()
    fam = tmp_path / "registry" / "families"
    fam.mkdir(parents=True)
    (tmp_path / "registry" / "runtimes").mkdir(parents=True)
    (tmp_path / "config" / "sources.yaml").write_text("sources: []\n")
    monkeypatch.setenv("LOMST_HOME", str(tmp_path))
    monkeypatch.delenv("LOMST_WEB_READONLY", raising=False)

    from lomst import config as cfgmod, db as dbmod, web

    importlib.reload(web)
    cfg = cfgmod.load(tmp_path)
    store = dbmod.Store(cfg.paths.db)
    run = store.start_run(["hf"])
    # Two generations under different licences, the newer one more downloaded.
    for repo, lic, dl in [
        ("google/gemma-4-31b-it", "apache-2.0", 9_000_000),
        ("google/gemma-3-1b-it", "gemma", 5_000_000),
    ]:
        store.upsert_artefact(
            run,
            {
                "source_id": "huggingface", "artefact_id": repo, "family_key": "gemma",
                "publisher": "google", "license": lic, "model_type": "llm",
                "gated": False, "downloads": dl, "version_label": None,
                "url": f"https://huggingface.co/{repo}",
                "modified_at": "2026-01-01T00:00:00+00:00",
                "payload": {"attribution_method": "name"},
            },
        )
    store.close()

    with TestClient(web.app) as c:
        r = c.post("/api/scaffold", json={"family": "gemma"})
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["approval_status"] == "pending_evaluation"
        assert d["drafted_from"] == 2

        # Drafting grants nothing.
        gate = c.post(
            "/api/check",
            json={"family": "gemma", "usage_category": "internal_productivity"},
        ).json()
        assert gate["verdict"] == "blocked"

        # A second attempt is a conflict, not a silent overwrite of a decision.
        assert c.post("/api/scaffold", json={"family": "gemma"}).status_code == 409

    text = (fam / "gemma.yaml").read_text()
    # Download-weighted pick, with the other generation's terms recorded.
    assert "license: apache-2.0" in text
    assert "gemma (5,000,000 downloads)" in text


def test_scaffold_refuses_without_evidence(client, monkeypatch):
    monkeypatch.delenv("LOMST_WEB_READONLY", raising=False)
    import importlib as il

    from lomst import web

    il.reload(web)
    with TestClient(web.app) as c:
        r = c.post("/api/scaffold", json={"family": "nothing_observed"})
        assert r.status_code == 400
        assert "nothing to draft" in r.json()["error"]
