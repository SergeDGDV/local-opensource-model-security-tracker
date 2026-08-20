"""Local web dashboard.

Buttons and tables for people who should not have to touch a terminal. Every
endpoint is a thin wrapper over the same governance code the CLI and the MCP
server use, so there is exactly one implementation of the rules.

The ingest runs on a worker thread because the connectors are synchronous; each
run opens its own SQLite connection, since connections cannot cross threads.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import threading
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from . import config, db, digest as digest_mod, ingest as ingest_mod
from .governance import review
from .governance.classify import Classifier, OFFICIAL_PUBLISHERS, publisher_matches
from .governance.registry import Entry, Registry, RegistryError
from .governance.usage import UsageGate
from .extract import FAMILY_NAMES
from .governance.vocab import (
    CONDITION_REQUIREMENTS,
    USAGE_RANK,
    ApprovalOutcome,
    ComponentKind,
    ConditionCode,
    InformationClass,
    LifecycleStatus,
    ModelType,
    UsageCategory,
)

log = logging.getLogger(__name__)

UI_DIR = Path(__file__).parent / "webui"


# --------------------------------------------------------------- ingest worker


class IngestJob:
    """Tracks the one-at-a-time background ingest."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: dict[str, Any] = {
            "running": False,
            "started_at": None,
            "finished_at": None,
            "run_id": None,
            "status": None,
            "new": 0,
            "changed": 0,
            "sources": [],
            "error": None,
            "current": None,
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._state)

    def start(self, only: list[str] | None = None) -> tuple[bool, str]:
        with self._lock:
            if self._state["running"]:
                return False, "An ingest is already running."
            self._state.update(
                running=True,
                started_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                finished_at=None,
                run_id=None,
                status=None,
                new=0,
                changed=0,
                sources=[],
                error=None,
                current="starting",
            )
        threading.Thread(target=self._run, args=(only,), daemon=True).start()
        return True, "Ingest started."

    def _run(self, only: list[str] | None) -> None:
        cfg = config.load()
        try:
            # A fresh Store: SQLite connections must not cross threads.
            with db.Store(cfg.paths.db) as store:
                report = ingest_mod.ingest(cfg, store, only=only)
            with self._lock:
                self._state.update(
                    run_id=report.run_id,
                    status=report.status,
                    new=report.new_total,
                    changed=report.changed_total,
                    sources=[
                        {
                            "id": o.source_id, "ok": o.ok, "new": o.new,
                            "changed": o.changed, "seen": o.seen, "error": o.error,
                        }
                        for o in report.outcomes
                    ],
                )
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            log.exception("ingest failed")
            with self._lock:
                self._state.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        finally:
            with self._lock:
                self._state.update(
                    running=False,
                    current=None,
                    finished_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                )


JOB = IngestJob()


# ------------------------------------------------------------------- helpers


def _ctx() -> tuple[config.Config, db.Store, Registry]:
    cfg = config.load()
    return cfg, db.Store(cfg.paths.db), Registry(cfg.paths.families, cfg.paths.runtimes)


def _readonly() -> bool:
    import os

    return os.environ.get("LOMST_WEB_READONLY", "").strip().lower() in ("1", "true", "yes")


def _err(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


# -------------------------------------------------------------------- routes


async def index(request: Request):
    return FileResponse(UI_DIR / "index.html")


async def api_overview(request: Request):
    cfg, store, registry = _ctx()
    try:
        try:
            entries = list(registry.load().values())
            registry_error = None
        except RegistryError as exc:
            entries, registry_error = [], str(exc)

        counts = {
            t: store.query(f"SELECT COUNT(*) c FROM {t}")[0]["c"]
            for t in ("observations", "advisories", "artefacts")
        }
        counts["artefacts_unclassified"] = store.query(
            "SELECT COUNT(*) c FROM artefacts WHERE family_key IS NULL"
        )[0]["c"]
        counts["families_observed"] = store.query(
            "SELECT COUNT(DISTINCT family_key) c FROM artefacts WHERE family_key IS NOT NULL"
        )[0]["c"]
        counts["actively_exploited"] = store.query(
            "SELECT COUNT(*) c FROM advisories WHERE source_id = 'kev' AND withdrawn_at IS NULL"
        )[0]["c"]
        last = store.last_run()
        actions = review.all_actions(store, registry) if not registry_error else []
        by_urgency: dict[str, int] = {}
        for a in actions:
            by_urgency[a.urgency.value] = by_urgency.get(a.urgency.value, 0) + 1

        families = [e for e in entries if e.kind is ComponentKind.MODEL_FAMILY]
        runtimes = [e for e in entries if e.kind is ComponentKind.RUNTIME]
        health = store.health()

        return JSONResponse(
            {
                "has_data": counts["observations"] > 0,
                "registry_error": registry_error,
                "counts": counts,
                "last_run": (
                    {
                        "id": last["id"],
                        "status": last["status"],
                        "finished_at": last["finished_at"],
                    }
                    if last
                    else None
                ),
                "actions_by_urgency": by_urgency,
                "actions_total": len(actions),
                "families": len(families),
                "runtimes": len(runtimes),
                "families_usable": sum(1 for e in families if e.usable),
                "reviews_overdue": sum(1 for e in entries if e.review_overdue),
                "fallback_gaps": sum(len(e.dependency_gaps()) for e in entries),
                "sources_total": len(cfg.sources),
                "sources_healthy": sum(1 for h in health if h["consecutive_failures"] == 0),
                "sources_failing": [
                    h["source_id"] for h in health if h["consecutive_failures"] > 0
                ],
                "readonly": _readonly(),
            }
        )
    finally:
        store.close()


async def api_actions(request: Request):
    cfg, store, registry = _ctx()
    try:
        urgency = request.query_params.get("urgency")
        actions = review.all_actions(store, registry)
        if urgency and urgency != "all":
            actions = [a for a in actions if a.urgency.value == urgency]
        return JSONResponse({"actions": [a.to_dict() for a in actions]})
    except RegistryError as exc:
        return _err(str(exc), 500)
    finally:
        store.close()


async def api_registry(request: Request):
    cfg, store, registry = _ctx()
    try:
        rows = []
        for e in sorted(registry.load().values(), key=lambda x: (x.kind.value, x.key)):
            rows.append(
                {
                    "key": e.key,
                    "name": e.name,
                    "kind": e.kind.value,
                    "model_type": e.model_type.value,
                    "developer": e.developer,
                    "approval_status": e.approval_status.value,
                    "lifecycle_status": e.lifecycle_status.value,
                    "usable": e.usable,
                    "approved_versions": e.approved_versions,
                    "approved_uses": [u.value for u in e.approved_uses],
                    "conditions": [c.value for c in e.conditions],
                    "license": e.license,
                    "runtime_compatibility": e.runtime_compatibility,
                    "business_owner": e.business_owner,
                    "governance_owner": e.governance_owner,
                    "approval_date": str(e.approval_date) if e.approval_date else None,
                    "review_date": str(e.review_date) if e.review_date else None,
                    "review_overdue": e.review_overdue,
                    "days_to_review": e.days_to_review(),
                    "restrictions": e.restrictions,
                    "security_notes": e.security_notes,
                    "dependent_solutions": [
                        {
                            "name": d.name,
                            "usage_category": d.usage_category.value,
                            "owner": d.owner,
                            "fallback_kind": d.fallback.kind,
                            "fallback_description": d.fallback.description,
                            "fallback_tested": d.fallback.tested,
                            "gap": d.gap,
                        }
                        for d in e.dependent_solutions
                    ],
                    "decision_history": [
                        {
                            "date": str(h.date),
                            "outcome": h.outcome.value,
                            "authority": h.authority,
                            "rationale": h.rationale,
                        }
                        for h in e.decision_history
                    ],
                }
            )
        return JSONResponse({"entries": rows})
    except RegistryError as exc:
        return _err(str(exc), 500)
    finally:
        store.close()


async def api_assess(request: Request):
    family = request.path_params["family"]
    cfg, store, registry = _ctx()
    try:
        return JSONResponse(Classifier(store, registry).assess(family).to_dict())
    except RegistryError as exc:
        return _err(str(exc), 500)
    finally:
        store.close()


async def api_check(request: Request):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("invalid JSON body")

    family = (body.get("family") or "").strip()
    if not family:
        return _err("family is required")
    try:
        category = UsageCategory(body.get("usage_category"))
    except ValueError:
        return _err(
            "usage_category must be one of: " + ", ".join(u.value for u in UsageCategory)
        )
    try:
        info = [InformationClass(i) for i in (body.get("information_classes") or [])]
    except ValueError:
        return _err(
            "information_classes must be from: " + ", ".join(i.value for i in InformationClass)
        )

    cfg, store, registry = _ctx()
    try:
        decision = UsageGate(registry).check(
            family,
            category,
            information_classes=info,
            runtime=(body.get("runtime") or None),
            solution_name=(body.get("solution_name") or None),
            version=(body.get("version") or None),
        )
        out = decision.to_dict()
        out["summary"] = decision.summary()
        return JSONResponse(out)
    except RegistryError as exc:
        return _err(str(exc), 500)
    finally:
        store.close()


async def api_advisories(request: Request):
    cfg, store, registry = _ctx()
    try:
        runtime = request.query_params.get("runtime")
        severity = request.query_params.get("severity")
        clauses = ["withdrawn_at IS NULL"]
        params: list[Any] = []
        if runtime and runtime != "all":
            clauses.append("runtime_key = ?")
            params.append(runtime)
        if severity and severity != "all":
            clauses.append("LOWER(COALESCE(severity,'unknown')) = ?")
            params.append(severity.lower())

        rows = store.query(
            f"""SELECT advisory_id, aliases, ecosystem, package, runtime_key, severity,
                       cvss, summary, url, published_at
                FROM advisories WHERE {' AND '.join(clauses)}
                ORDER BY CASE LOWER(COALESCE(severity,'')) WHEN 'critical' THEN 0
                         WHEN 'high' THEN 1 WHEN 'moderate' THEN 2 WHEN 'low' THEN 3
                         ELSE 4 END, COALESCE(published_at, first_seen) DESC
                LIMIT 500""",
            tuple(params),
        )
        runtimes = [
            r["runtime_key"]
            for r in store.query(
                "SELECT DISTINCT runtime_key FROM advisories "
                "WHERE runtime_key IS NOT NULL ORDER BY runtime_key"
            )
        ]
        totals = {
            (r["severity"] or "unknown"): r["n"]
            for r in store.query(
                "SELECT COALESCE(severity,'unknown') severity, COUNT(*) n FROM advisories "
                "WHERE withdrawn_at IS NULL GROUP BY 1"
            )
        }
        return JSONResponse(
            {
                "advisories": [
                    {
                        "id": r["advisory_id"],
                        "aliases": json.loads(r["aliases"] or "[]"),
                        "package": r["package"],
                        "ecosystem": r["ecosystem"],
                        "runtime": r["runtime_key"],
                        "severity": (r["severity"] or "unknown").lower(),
                        "cvss": r["cvss"],
                        "summary": r["summary"],
                        "url": r["url"],
                        "published_at": r["published_at"],
                    }
                    for r in rows
                ],
                "runtimes": runtimes,
                "totals_by_severity": totals,
            }
        )
    finally:
        store.close()


async def api_families(request: Request):
    cfg, store, registry = _ctx()
    try:
        known = set(registry.families())
        rows = store.query(
            """SELECT family_key,
                      COUNT(*) AS artefacts,
                      SUM(COALESCE(downloads,0)) AS downloads,
                      GROUP_CONCAT(DISTINCT publisher) AS publishers,
                      GROUP_CONCAT(DISTINCT license) AS licenses
               FROM artefacts WHERE family_key IS NOT NULL
               GROUP BY family_key ORDER BY downloads DESC"""
        )
        return JSONResponse(
            {
                "families": [
                    {
                        "family_key": r["family_key"],
                        "in_registry": r["family_key"] in known,
                        "artefacts": r["artefacts"],
                        "downloads": r["downloads"] or 0,
                        "publishers": sorted(set((r["publishers"] or "").split(",")))[:5],
                        "licenses": sorted(set((r["licenses"] or "").split(",")))[:6],
                    }
                    for r in rows
                ]
            }
        )
    except RegistryError as exc:
        return _err(str(exc), 500)
    finally:
        store.close()


async def api_artefacts(request: Request):
    """Individual model artefacts.

    The families rollup answers "what do we govern"; this answers "what is
    actually out there". Those are different questions, and collapsing the second
    into the first is why a 9000-artefact inventory previously looked like 30
    rows. Anything without a family mapping is shown as unclassified rather than
    filtered out - an unrecognised model is a governance gap, not a non-event.
    """
    cfg, store, registry = _ctx()
    try:
        qp = request.query_params
        q = (qp.get("q") or "").strip()
        distribution = qp.get("distribution") or "all"
        family = qp.get("family") or "all"
        source = qp.get("source") or "all"
        weights = qp.get("weights") or "all"
        limit = max(1, min(500, int(qp.get("limit") or 100)))
        offset = max(0, int(qp.get("offset") or 0))

        clauses: list[str] = []
        params: list[Any] = []
        if q:
            clauses.append("(artefact_id LIKE ? OR publisher LIKE ? OR license LIKE ?)")
            like = f"%{q}%"
            params += [like, like, like]
        if distribution != "all":
            clauses.append("COALESCE(json_extract(payload,'$.distribution'),'') = ?")
            params.append(distribution)
        if family == "unclassified":
            clauses.append("family_key IS NULL")
        elif family != "all":
            clauses.append("family_key = ?")
            params.append(family)
        if source != "all":
            clauses.append("source_id = ?")
            params.append(source)
        if weights == "safetensors":
            clauses.append("json_extract(payload,'$.has_safetensors') = 1")
        elif weights == "pickle_only":
            # Section 7.4: loading pickle weights executes arbitrary code.
            clauses.append(
                "json_extract(payload,'$.has_pickle_weights') = 1 "
                "AND COALESCE(json_extract(payload,'$.has_safetensors'),0) = 0"
            )
        elif weights == "gguf":
            clauses.append("json_extract(payload,'$.has_gguf') = 1")
        elif weights == "gated":
            clauses.append("gated = 1")

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        total = store.query(f"SELECT COUNT(*) c FROM artefacts {where}", tuple(params))[0]["c"]
        rows = store.query(
            f"""SELECT artefact_id, family_key, publisher, license, model_type, gated,
                       downloads, version_label, url, modified_at, source_id, payload
                FROM artefacts {where}
                ORDER BY COALESCE(downloads,0) DESC, artefact_id
                LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        )

        out = []
        for r in rows:
            try:
                pl = json.loads(r["payload"] or "{}")
            except json.JSONDecodeError:
                pl = {}
            out.append(
                {
                    "artefact_id": r["artefact_id"],
                    "family": r["family_key"],
                    "publisher": r["publisher"],
                    "license": r["license"],
                    "model_type": r["model_type"],
                    "gated": bool(r["gated"]),
                    "downloads": r["downloads"] or 0,
                    "version": r["version_label"],
                    "url": r["url"],
                    "modified_at": r["modified_at"],
                    "source": r["source_id"],
                    "distribution": pl.get("distribution"),
                    "has_safetensors": pl.get("has_safetensors"),
                    "has_pickle_weights": pl.get("has_pickle_weights"),
                    "has_gguf": pl.get("has_gguf"),
                    "discovered_by": pl.get("discovered_by"),
                    "hosted_alternative_for": pl.get("hosted_alternative_for"),
                    "params_b": pl.get("params_b"),
                }
            )

        facets = {
            "distributions": [
                r["d"]
                for r in store.query(
                    "SELECT DISTINCT COALESCE(json_extract(payload,'$.distribution'),'') d "
                    "FROM artefacts WHERE d != '' ORDER BY d"
                )
            ],
            "sources": [
                r["source_id"]
                for r in store.query(
                    "SELECT DISTINCT source_id FROM artefacts ORDER BY source_id"
                )
            ],
            "families": [
                r["family_key"]
                for r in store.query(
                    "SELECT family_key, COUNT(*) n FROM artefacts "
                    "WHERE family_key IS NOT NULL GROUP BY family_key ORDER BY n DESC"
                )
            ],
        }
        return JSONResponse(
            {
                "total": total,
                "limit": limit,
                "offset": offset,
                "artefacts": out,
                "facets": facets,
            }
        )
    finally:
        store.close()


async def api_intelligence(request: Request):
    cfg, store, registry = _ctx()
    try:
        q = (request.query_params.get("q") or "").strip()
        tier = request.query_params.get("tier") or "all"
        family = request.query_params.get("family")
        clauses: list[str] = []
        params: list[Any] = []
        if q:
            clauses.append("(title LIKE ? OR summary LIKE ?)")
            params += [f"%{q}%", f"%{q}%"]
        if family and family != "all":
            clauses.append("family_key = ?")
            params.append(family)
        if tier == "citable":
            clauses.append("tier IN ('authoritative','community')")
        elif tier != "all":
            clauses.append("tier = ?")
            params.append(tier)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = store.query(
            f"""SELECT source_id, tier, kind, title, url, summary, published_at,
                       family_key, runtime_key
                FROM observations {where}
                ORDER BY COALESCE(published_at, first_seen) DESC LIMIT 300""",
            tuple(params),
        )
        return JSONResponse(
            {
                "results": [
                    {
                        "source": r["source_id"],
                        "tier": r["tier"],
                        "citable": r["tier"] != "aggregator",
                        "kind": r["kind"],
                        "title": r["title"],
                        "url": r["url"],
                        "summary": r["summary"],
                        "published_at": r["published_at"],
                        "family": r["family_key"],
                        "runtime": r["runtime_key"],
                    }
                    for r in rows
                ]
            }
        )
    finally:
        store.close()


async def api_sources(request: Request):
    cfg, store, registry = _ctx()
    try:
        health = {h["source_id"]: h for h in store.health()}
        rows = []
        for sc in cfg.sources:
            h = health.get(sc.id)
            rows.append(
                {
                    "id": sc.id,
                    "name": sc.name,
                    "tier": sc.tier,
                    "connector": sc.connector,
                    "enabled": sc.enabled,
                    "url": sc.url,
                    "notes": sc.notes,
                    "healthy": bool(h) and h["consecutive_failures"] == 0,
                    "ever_run": bool(h),
                    "last_success_at": h["last_success_at"] if h else None,
                    "items": h["last_item_count"] if h else None,
                    "consecutive_failures": h["consecutive_failures"] if h else 0,
                    "last_error": h["last_error"] if h else None,
                }
            )
        return JSONResponse({"sources": rows})
    finally:
        store.close()


async def api_digest(request: Request):
    cfg, store, registry = _ctx()
    try:
        d = digest_mod.build(store, registry)
        return JSONResponse(
            {"structured": d.to_dict(), "text": digest_mod.render_text(d)}
        )
    except RegistryError as exc:
        return _err(str(exc), 500)
    finally:
        store.close()


async def api_vocab(request: Request):
    return JSONResponse(
        {
            "usage_categories": [
                {"value": u.value, "rank": USAGE_RANK[u], "label": _label(u.value)}
                for u in sorted(UsageCategory, key=lambda x: USAGE_RANK[x])
            ],
            "information_classes": [
                {"value": i.value, "label": _label(i.value)} for i in InformationClass
            ],
            "approval_outcomes": [
                {"value": o.value, "label": _label(o.value), "permits_use": o.usable}
                for o in ApprovalOutcome
            ],
            "lifecycle_statuses": [
                {"value": s.value, "label": _label(s.value)} for s in LifecycleStatus
            ],
            "condition_codes": [
                {"code": c.value, "requirement": CONDITION_REQUIREMENTS[c]}
                for c in ConditionCode
            ],
        }
    )


def _label(value: str) -> str:
    return value.replace("_", " ").capitalize()


async def api_ingest_start(request: Request):
    if _readonly():
        return _err("This dashboard is running in read-only mode.", 403)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - empty body is fine
        body = {}
    ok, message = JOB.start(body.get("sources") or None)
    return JSONResponse({"started": ok, "message": message}, status_code=200 if ok else 409)


async def api_ingest_status(request: Request):
    return JSONResponse(JOB.snapshot())


async def api_scaffold(request: Request):
    """Create a `pending_evaluation` registry entry for an observed family.

    This is the missing step between "we can see 61 families in circulation" and
    "we have decided about 3 of them". It drafts the Appendix B entry from
    evidence already ingested - publisher, licence, model type, distribution
    source, and which approved runtimes can actually run it - so a human fills in
    a judgement rather than retyping facts.

    It deliberately does NOT approve anything. The entry lands as
    `pending_evaluation`, which `UsageGate` treats as "no use permitted", and it
    stays that way until an approving authority records a Section 6.3 outcome.
    """
    if _readonly():
        return _err("This dashboard is running in read-only mode.", 403)
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("invalid JSON body")

    key = (body.get("family") or "").strip().lower()
    if not key:
        return _err("family is required")

    cfg, store, registry = _ctx()
    try:
        kind = ComponentKind(body.get("kind") or "model_family")
        if registry.get(key, kind) is not None:
            return _err(f"{key!r} is already in the registry", 409)

        # --- draft from observed evidence --------------------------------------
        rows = store.query(
            """SELECT publisher, license, model_type, url, source_id,
                      COALESCE(downloads,0) AS downloads
               FROM artefacts WHERE family_key = ?
               ORDER BY downloads DESC""",
            (key,),
        )
        if not rows:
            return _err(
                f"no artefacts observed for {key!r}, so there is nothing to draft from. "
                f"Run a refresh first, or add the YAML file by hand."
            )

        official = OFFICIAL_PUBLISHERS.get(key, ())
        developer = next(
            (r["publisher"] for r in rows if publisher_matches(r["publisher"], official)),
            rows[0]["publisher"] or "",
        )
        # Licence: weight by downloads among artefacts from the publisher of
        # record, not "first row wins". Families span generations - Gemma 3 ships
        # under the Gemma licence while Gemma 4 moved to Apache-2.0 - so the
        # spread is recorded alongside the pick rather than collapsed silently
        # (Sections 6.2, 7.3).
        licence_weight: dict[str, int] = {}
        for r in rows:
            if not r["license"] or not publisher_matches(r["publisher"], official):
                continue
            licence_weight[r["license"]] = licence_weight.get(r["license"], 0) + (
                r["downloads"] or 0
            )
        if not licence_weight:
            for r in rows:
                if r["license"]:
                    licence_weight[r["license"]] = licence_weight.get(r["license"], 0) + (
                        r["downloads"] or 0
                    )
        ranked = sorted(licence_weight.items(), key=lambda kv: -kv[1])
        license_value = ranked[0][0] if ranked else ""
        licence_note = ""
        if len(ranked) > 1:
            others = ", ".join(f"{name} ({dl:,} downloads)" for name, dl in ranked[1:4])
            licence_note = (
                f" This family also publishes under {others}. Each release is licensed on "
                f"its own terms, so confirm which generation is being approved (Section 6.2)."
            )
        model_type = next((r["model_type"] for r in rows if r["model_type"]), "llm")
        hf = next((r for r in rows if r["source_id"] == "huggingface"), None)
        distribution_source = (
            f"https://huggingface.co/{developer}" if hf and developer else (rows[0]["url"] or "")
        )
        # Only runtimes that are themselves approved and can demonstrably run it.
        pullable = any(r["source_id"] == "ollama_library" for r in rows)
        runtimes = [
            rt.key
            for rt in registry.runtimes().values()
            if rt.usable and (rt.key != "ollama" or pullable)
        ]

        entry = Entry(
            key=key,
            name=FAMILY_NAMES.get(key, key.replace("_", " ").title()),
            kind=kind,
            model_type=ModelType(model_type) if model_type in {m.value for m in ModelType} else ModelType.LLM,
            developer=developer,
            approval_status=ApprovalOutcome.PENDING_EVALUATION,
            license=license_value or "",
            distribution_source=distribution_source,
            runtime_compatibility=runtimes,
            governance_owner="AI Governance",
            notes=(
                f"Drafted from {len(rows)} observed artefacts. Fields are evidence, not "
                f"judgements: no use is permitted while status is pending_evaluation. "
                f"Complete the Appendix A checklist, then record a Section 6.3 outcome."
                + licence_note
            ),
        )
        path = registry.save(entry)
        return JSONResponse(
            {
                "created": True,
                "key": entry.key,
                "name": entry.name,
                "file": str(path),
                "drafted_from": len(rows),
                "approval_status": entry.approval_status.value,
                "next_step": (
                    "Status is pending_evaluation, so nothing is permitted yet. Open Details "
                    "and record a decision with an approving authority and a rationale."
                ),
            }
        )
    except (ValueError, RegistryError) as exc:
        return _err(str(exc))
    finally:
        store.close()


async def api_decide(request: Request):
    if _readonly():
        return _err("This dashboard is running in read-only mode.", 403)
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("invalid JSON body")

    family = (body.get("family") or "").strip()
    authority = (body.get("authority") or "").strip()
    rationale = (body.get("rationale") or "").strip()
    if not family:
        return _err("family is required")
    if not authority:
        return _err(
            "An approving authority is required (Appendix A.5 / D.6). Section 6.3 "
            "outcomes cannot be recorded anonymously."
        )
    if not rationale:
        return _err(
            "A rationale is required so the decision is auditable under Section 9.1."
        )
    try:
        outcome = ApprovalOutcome(body.get("outcome"))
    except ValueError:
        return _err("outcome must be one of: " + ", ".join(o.value for o in ApprovalOutcome))

    cfg, store, registry = _ctx()
    try:
        uses = (
            [UsageCategory(u) for u in body["approved_uses"]]
            if body.get("approved_uses") is not None
            else None
        )
        conds = (
            [ConditionCode(c.upper()) for c in body["conditions"]]
            if body.get("conditions") is not None
            else None
        )
        review_date = (
            dt.date.fromisoformat(body["review_date"]) if body.get("review_date") else None
        )
        entry = review.record_decision(
            registry,
            family,
            outcome,
            authority,
            kind=ComponentKind(body.get("kind") or "model_family"),
            rationale=rationale,
            approved_uses=uses,
            conditions=conds,
            versions=body.get("versions") or None,
            review_date=review_date,
        )
        return JSONResponse(
            {
                "recorded": True,
                "key": entry.key,
                "approval_status": entry.approval_status.value,
                "review_date": str(entry.review_date),
                "file": str(registry.dir_for(entry.kind) / f"{entry.key}.yaml"),
            }
        )
    except (KeyError, ValueError, RegistryError) as exc:
        return _err(str(exc))
    finally:
        store.close()


routes = [
    Route("/", index),
    Route("/api/overview", api_overview),
    Route("/api/actions", api_actions),
    Route("/api/registry", api_registry),
    Route("/api/assess/{family}", api_assess),
    Route("/api/check", api_check, methods=["POST"]),
    Route("/api/advisories", api_advisories),
    Route("/api/families", api_families),
    Route("/api/artefacts", api_artefacts),
    Route("/api/intelligence", api_intelligence),
    Route("/api/sources", api_sources),
    Route("/api/digest", api_digest),
    Route("/api/vocabulary", api_vocab),
    Route("/api/ingest", api_ingest_start, methods=["POST"]),
    Route("/api/ingest/status", api_ingest_status),
    Route("/api/scaffold", api_scaffold, methods=["POST"]),
    Route("/api/decide", api_decide, methods=["POST"]),
]

app = Starlette(routes=routes)


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    """Run the dashboard.

    Binds to loopback by default. This surface has no authentication and can
    write approval decisions, so exposing it on a network would contradict
    Section 10.3's stance on unauthenticated shared services.
    """
    import uvicorn

    if open_browser:
        import threading
        import webbrowser

        threading.Timer(1.0, lambda: webbrowser.open(f"http://{host}:{port}/")).start()

    uvicorn.run(app, host=host, port=port, log_level="warning")
