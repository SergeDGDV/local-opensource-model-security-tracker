"""MCP server exposing the tracker to an AI assistant.

Design stance: **read-only by default.**

Every tool here answers questions. The one tool that writes an approval decision
(`record_decision`) is disabled unless `LOMST_ALLOW_DECISIONS=1` is set in the
server environment. Section 13 step 4 makes recording a Section 6.3 outcome a
human act by a named authority, and a tool that a model can call on its own
initiative is the wrong shape for that. Leaving it off by default means the
assistant can prepare a decision, explain it, and hand the exact command to a
person - which is the workflow the framework actually describes.

Run it with:
    lomst-mcp
or register it in a client as `{"command": "lomst-mcp"}` with `LOMST_HOME` set.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from typing import Annotated, Any, Literal

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from . import config, db, digest as digest_mod, ingest as ingest_mod
from .governance import review
from .governance.classify import Classifier
from .governance.registry import Registry
from .governance.usage import UsageGate
from .governance.vocab import (
    CONDITION_REQUIREMENTS,
    ApprovalOutcome,
    ComponentKind,
    ConditionCode,
    InformationClass,
    UsageCategory,
)

server = MCPServer(
    name="lomst",
    title="Local & Open-Source Model Security Tracker",
    version="0.1.0",
    instructions=(
        "Governance tracking for locally executed and open-source AI models, implementing "
        "the Paradox Interactive 'Governance of Local and Open-Source AI Models' framework "
        "(v1.1).\n\n"
        "Key rules this server enforces, which you should reflect when answering:\n"
        "- Model approval never authorises a use on its own. Call `check_usage` for any "
        "'can I use X for Y' question; do not infer permission from `get_model_family`.\n"
        "- Runtimes are governed separately from models (Sections 5, 10). An approved model "
        "on an unapproved runtime is not approved.\n"
        "- `assess_family` returns a RECOMMENDATION with evidence, never a decision. "
        "Decisions are recorded by a named approving authority (Section 13 step 4).\n"
        "- Sources tiered `aggregator` are leads only and are never citable as provenance, "
        "licensing or vulnerability evidence (Section 7.1). The server separates them for "
        "you; keep them separate when you summarise.\n"
        "- Absence of evidence is not a pass. 'unknown' findings push toward Deferred."
    ),
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)
MUTATING = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False)


def _ctx() -> tuple[config.Config, db.Store, Registry]:
    cfg = config.load()
    return cfg, db.Store(cfg.paths.db), Registry(cfg.paths.families, cfg.paths.runtimes)


def _decisions_enabled() -> bool:
    return os.environ.get("LOMST_ALLOW_DECISIONS", "").strip().lower() in ("1", "true", "yes")


# --------------------------------------------------------------------- registry


@server.tool(
    description=(
        "List registry entries (model families and runtimes) with their Section 6.3 approval "
        "status, Appendix E.5 lifecycle status, approved usage categories and review dates. "
        "This is the authoritative record of what may be used (Section 9). It does NOT tell "
        "you whether a specific use is permitted - use check_usage for that."
    ),
    annotations=READ_ONLY,
)
def list_registry(
    kind: Annotated[
        Literal["model_family", "runtime", "all"], "Restrict to families, runtimes, or both"
    ] = "all",
    usable_only: Annotated[bool, "Only entries that currently permit some use"] = False,
    review_overdue_only: Annotated[bool, "Only entries whose Section 9.2 review has lapsed"] = False,
) -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        entries = list(registry.load().values())
        if kind != "all":
            entries = [e for e in entries if e.kind.value == kind]
        if usable_only:
            entries = [e for e in entries if e.usable]
        if review_overdue_only:
            entries = [e for e in entries if e.review_overdue]

        return {
            "count": len(entries),
            "entries": [
                {
                    "key": e.key,
                    "name": e.name,
                    "kind": e.kind.value,
                    "model_type": e.model_type.value,
                    "developer": e.developer,
                    "approval_status": e.approval_status.value,
                    "lifecycle_status": e.lifecycle_status.value,
                    "approved_versions": e.approved_versions,
                    "approved_uses": [u.value for u in e.approved_uses],
                    "conditions": [c.value for c in e.conditions],
                    "license": e.license,
                    "runtime_compatibility": e.runtime_compatibility,
                    "review_date": str(e.review_date) if e.review_date else None,
                    "review_overdue": e.review_overdue,
                    "usable": e.usable,
                    "dependent_solution_count": len(e.dependent_solutions),
                    "dependency_gaps": [gap for _, gap in e.dependency_gaps()],
                }
                for e in sorted(entries, key=lambda x: (x.kind.value, x.key))
            ],
        }
    finally:
        store.close()


@server.tool(
    description=(
        "Full registry entry for one model family or runtime, including restrictions, "
        "security notes, dependent solutions with their Section 8.5 fallback status, and the "
        "complete decision history (Section 4.4 traceability)."
    ),
    annotations=READ_ONLY,
)
def get_registry_entry(
    key: Annotated[str, "Registry key, e.g. 'llama', 'mistral', 'ollama'"],
    kind: Annotated[Literal["model_family", "runtime"], "Component kind"] = "model_family",
) -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        entry = registry.get(key, ComponentKind(kind))
        if entry is None:
            known = sorted(
                e.key for e in registry.load().values() if e.kind.value == kind
            )
            return {
                "found": False,
                "error": f"no {kind} entry for {key!r}",
                "known_keys": known,
                "note": (
                    "Absence from the registry means no approval exists (Section 9). Submit "
                    "an Appendix D request via Section 13 step 1."
                ),
            }
        data = entry.to_dict()
        data["found"] = True
        data["dependency_gaps"] = [
            {"solution": s.name, "gap": gap} for s, gap in entry.dependency_gaps()
        ]
        return data
    finally:
        store.close()


# ------------------------------------------------------------------ the gate


@server.tool(
    description=(
        "THE authoritative answer to 'may I use model X on runtime Y for purpose Z with "
        "information of class W'. Applies four independent gates from Section 8: model "
        "approval and usage category (8.1/E.2), runtime approval (5/10), information "
        "classification (8.3/11.2), and business-continuity fallback (8.5/C9). Returns a "
        "verdict plus every check with its governing section, so the reasoning is auditable. "
        "Always prefer this over interpreting a registry entry yourself."
    ),
    annotations=READ_ONLY,
)
def check_usage(
    family: Annotated[str, "Model family key, e.g. 'llama'"],
    usage_category: Annotated[
        Literal[
            "research_experimentation",
            "internal_productivity",
            "internal_business_applications",
            "production_services",
            "customer_facing_applications",
            "sensitive_information_processing",
            "autonomous_decision_support",
        ],
        "Appendix E.2 usage category",
    ],
    runtime: Annotated[
        str | None, "Inference runtime key, e.g. 'ollama', 'vllm'. Governed separately."
    ] = None,
    information_classes: Annotated[
        list[Literal["public", "internal", "confidential", "personal", "customer", "source_code"]]
        | None,
        "Information classes the workflow processes (Appendix D.3)",
    ] = None,
    solution_name: Annotated[
        str | None, "Name of the dependent solution, for the Section 8.5 continuity check"
    ] = None,
    version: Annotated[str | None, "Specific model version, checked against Section 6.2"] = None,
) -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        decision = UsageGate(registry).check(
            family,
            UsageCategory(usage_category),
            information_classes=[InformationClass(i) for i in (information_classes or [])],
            runtime=runtime,
            solution_name=solution_name,
            version=version,
        )
        out = decision.to_dict()
        out["summary"] = decision.summary()
        return out
    finally:
        store.close()


# ---------------------------------------------------------------- assessment


@server.tool(
    description=(
        "Evaluate a model family against the five Section 7 criteria (provenance, "
        "distribution integrity, licensing, security, operational suitability) using "
        "evidence gathered from tracked sources. Returns per-criterion verdicts with cited "
        "evidence, an overall risk level, a RECOMMENDED Section 6.3 outcome, condition codes, "
        "and the ceiling of usage categories the evidence could support.\n\n"
        "This is a recommendation with evidence, NOT an approval. Aggregator-tier material is "
        "returned separately as 'leads_not_evidence' and must not be cited as provenance or "
        "licensing evidence (Section 7.1). Works for families with no registry entry too, "
        "which is how you triage a new request."
    ),
    annotations=READ_ONLY,
)
def assess_family(
    family: Annotated[str, "Family key, e.g. 'qwen', 'gemma', 'deepseek'"],
) -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        return Classifier(store, registry).assess(family).to_dict()
    finally:
        store.close()


@server.tool(
    description=(
        "Model families observed in the wild across tracked sources, with artefact counts, "
        "publishers, licences and whether each has a registry entry. Use this to find "
        "candidates for evaluation (Section 15.3 asks that emerging families be assessed "
        "proactively) or to check what a family is actually publishing."
    ),
    annotations=READ_ONLY,
)
def list_observed_families(
    registered: Annotated[
        Literal["all", "yes", "no"], "Filter by presence of a registry entry"
    ] = "all",
    min_downloads: Annotated[int, "Minimum total downloads across artefacts"] = 0,
    limit: Annotated[int, "Maximum rows"] = 40,
) -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        known = set(registry.families())
        rows = store.query(
            """SELECT family_key,
                      COUNT(*) AS artefacts,
                      SUM(COALESCE(downloads, 0)) AS downloads,
                      GROUP_CONCAT(DISTINCT publisher) AS publishers,
                      GROUP_CONCAT(DISTINCT license) AS licenses
               FROM artefacts
               WHERE family_key IS NOT NULL
               GROUP BY family_key
               HAVING downloads >= ?
               ORDER BY downloads DESC""",
            (min_downloads,),
        )
        out = []
        for r in rows:
            in_registry = r["family_key"] in known
            if registered == "yes" and not in_registry:
                continue
            if registered == "no" and in_registry:
                continue
            out.append(
                {
                    "family_key": r["family_key"],
                    "in_registry": in_registry,
                    "artefacts": r["artefacts"],
                    "downloads": r["downloads"],
                    "publishers": (r["publishers"] or "").split(",")[:6],
                    "licenses": (r["licenses"] or "").split(",")[:8],
                }
            )
            if len(out) >= limit:
                break
        return {"count": len(out), "families": out}
    finally:
        store.close()


# ------------------------------------------------------------------- security


@server.tool(
    description=(
        "Vulnerability advisories affecting the inference stack, from OSV and GitHub Security "
        "Advisories. Advisories attach to runtimes and libraries, not model weights, which is "
        "why Section 5 evaluates those components independently. Use this for Section 7.4 "
        "security evaluation and Section 11.4 vulnerability management."
    ),
    annotations=READ_ONLY,
)
def get_advisories(
    runtime: Annotated[str | None, "Runtime key, e.g. 'vllm', 'ollama', 'llama_cpp'"] = None,
    severity: Annotated[
        list[Literal["critical", "high", "moderate", "low"]] | None, "Severities to include"
    ] = None,
    since_days: Annotated[int | None, "Only advisories published within this many days"] = None,
    limit: Annotated[int, "Maximum rows"] = 30,
) -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        clauses = ["withdrawn_at IS NULL"]
        params: list[Any] = []
        if runtime:
            clauses.append("runtime_key = ?")
            params.append(runtime)
        if severity:
            clauses.append(f"LOWER(severity) IN ({','.join('?' * len(severity))})")
            params.extend(s.lower() for s in severity)
        if since_days:
            cutoff = (
                dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=since_days)
            ).isoformat()
            clauses.append("COALESCE(published_at, first_seen) >= ?")
            params.append(cutoff)

        rows = store.query(
            f"""SELECT advisory_id, aliases, ecosystem, package, runtime_key, severity, cvss,
                       summary, url, published_at
                FROM advisories WHERE {' AND '.join(clauses)}
                ORDER BY CASE LOWER(COALESCE(severity,'')) WHEN 'critical' THEN 0
                         WHEN 'high' THEN 1 WHEN 'moderate' THEN 2 WHEN 'low' THEN 3
                         ELSE 4 END, COALESCE(published_at, first_seen) DESC
                LIMIT ?""",
            (*params, limit),
        )
        totals = {
            r["severity"] or "unknown": r["n"]
            for r in store.query(
                "SELECT severity, COUNT(*) n FROM advisories WHERE withdrawn_at IS NULL"
                + (" AND runtime_key = ?" if runtime else "")
                + " GROUP BY severity",
                (runtime,) if runtime else (),
            )
        }
        return {
            "count": len(rows),
            "totals_by_severity": totals,
            "advisories": [
                {
                    "id": r["advisory_id"],
                    "aliases": json.loads(r["aliases"] or "[]"),
                    "package": r["package"],
                    "ecosystem": r["ecosystem"],
                    "runtime": r["runtime_key"],
                    "severity": r["severity"],
                    "cvss": r["cvss"],
                    "summary": r["summary"],
                    "url": r["url"],
                    "published_at": r["published_at"],
                }
                for r in rows
            ],
        }
    finally:
        store.close()


# ------------------------------------------------------------------ intelligence


@server.tool(
    description=(
        "Full-text search across everything ingested from tracked sources: OWASP GenAI "
        "guidance, curated AI-security tool lists, vendor and community posts, model release "
        "notes and news. Each hit carries its source tier - 'aggregator' results are LEADS "
        "ONLY and must not be cited as evidence for a governance conclusion (Section 7.1)."
    ),
    annotations=READ_ONLY,
)
def search_intelligence(
    query: Annotated[str, "Text to search for in titles and summaries"],
    family: Annotated[str | None, "Restrict to a family key"] = None,
    runtime: Annotated[str | None, "Restrict to a runtime key"] = None,
    tier: Annotated[
        Literal["all", "authoritative", "community", "aggregator", "citable"], "Source tier filter"
    ] = "all",
    since_days: Annotated[int | None, "Only items published within this many days"] = None,
    limit: Annotated[int, "Maximum rows"] = 25,
) -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        clauses: list[str] = []
        params: list[Any] = []
        if query.strip():
            clauses.append("(title LIKE ? OR summary LIKE ?)")
            like = f"%{query.strip()}%"
            params.extend([like, like])
        if family:
            clauses.append("family_key = ?")
            params.append(family)
        if runtime:
            clauses.append("runtime_key = ?")
            params.append(runtime)
        if tier == "citable":
            clauses.append("tier IN ('authoritative','community')")
        elif tier != "all":
            clauses.append("tier = ?")
            params.append(tier)
        if since_days:
            cutoff = (
                dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=since_days)
            ).isoformat()
            clauses.append("COALESCE(published_at, first_seen) >= ?")
            params.append(cutoff)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = store.query(
            f"""SELECT source_id, tier, kind, title, url, summary, published_at, family_key,
                       runtime_key
                FROM observations {where}
                ORDER BY COALESCE(published_at, first_seen) DESC LIMIT ?""",
            (*params, limit),
        )
        hits = [
            {
                "source": r["source_id"],
                "tier": r["tier"],
                "citable_as_evidence": r["tier"] != "aggregator",
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
        return {
            "count": len(hits),
            "results": hits,
            "note": (
                f"{sum(1 for h in hits if not h['citable_as_evidence'])} of {len(hits)} results "
                f"are from aggregator-tier sources and are leads only (Section 7.1)."
            ),
        }
    finally:
        store.close()


# -------------------------------------------------------------------- lifecycle


@server.tool(
    description=(
        "Every outstanding governance action, most urgent first: reviews overdue or falling "
        "due (9.2), dependencies with no tested fallback (8.5/C9), advisories on approved "
        "runtimes (11.4), unapproved versions observed (6.2), licence changes (6.2/7.3), "
        "expiring exceptions (14), and families seen in the wild with no registry entry. "
        "Each action names the responsible function and the governing section."
    ),
    annotations=READ_ONLY,
)
def governance_actions(
    urgency: Annotated[
        Literal["all", "immediate", "high", "scheduled", "informational"], "Filter by urgency"
    ] = "all",
    subject: Annotated[str | None, "Restrict to one registry key"] = None,
    horizon_days: Annotated[int, "Review lookahead window"] = 30,
) -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        actions = review.all_actions(store, registry, horizon_days=horizon_days)
        if urgency != "all":
            actions = [a for a in actions if a.urgency.value == urgency]
        if subject:
            actions = [a for a in actions if a.subject == subject]
        counts: dict[str, int] = {}
        for a in actions:
            counts[a.urgency.value] = counts.get(a.urgency.value, 0) + 1
        return {
            "count": len(actions),
            "counts_by_urgency": counts,
            "actions": [a.to_dict() for a in actions],
        }
    finally:
        store.close()


@server.tool(
    description=(
        "Digest of the most recent ingest: source health, new items per source, new advisories, "
        "licence changes, activity per model family, and the outstanding governance actions. "
        "Use this to answer 'what changed today'."
    ),
    annotations=READ_ONLY,
)
def daily_digest(
    run_id: Annotated[int | None, "Specific run id; omit for the most recent"] = None,
    format: Annotated[Literal["structured", "text"], "Output shape"] = "structured",
) -> dict[str, Any] | str:
    cfg, store, registry = _ctx()
    try:
        d = digest_mod.build(store, registry, run_id=run_id)
        return digest_mod.render_text(d) if format == "text" else d.to_dict()
    finally:
        store.close()


@server.tool(
    description=(
        "Freshness and failure state of every tracked source. Scrapers rot; a source with "
        "consecutive failures means the corresponding evidence is stale, which matters before "
        "relying on an assessment."
    ),
    annotations=READ_ONLY,
)
def source_health() -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        rows = store.health()
        configured = {s.id: s for s in cfg.sources}
        return {
            "count": len(rows),
            "sources": [
                {
                    "source_id": r["source_id"],
                    "tier": getattr(configured.get(r["source_id"]), "tier", None),
                    "healthy": r["consecutive_failures"] == 0,
                    "consecutive_failures": r["consecutive_failures"],
                    "last_success_at": r["last_success_at"],
                    "last_item_count": r["last_item_count"],
                    "last_error": r["last_error"],
                }
                for r in rows
            ],
            "never_run": sorted(set(configured) - {r["source_id"] for r in rows}),
        }
    finally:
        store.close()


@server.tool(
    description=(
        "Reference data for the framework: Section 6.3 approval outcomes, Appendix E.2 usage "
        "categories with their escalation order, Appendix E.4 condition codes C1-C9, Appendix "
        "E.5 lifecycle statuses, and which information classes require Sensitive Information "
        "Processing approval. Use this to phrase answers in the organisation's own vocabulary."
    ),
    annotations=READ_ONLY,
)
def governance_vocabulary() -> dict[str, Any]:
    from .governance.vocab import (
        FALLBACK_REQUIRED_RANK,
        RESTRICTED_USE_CATEGORIES,
        SENSITIVE_INFORMATION_CLASSES,
        USAGE_RANK,
        LifecycleStatus,
    )

    return {
        "approval_outcomes": {
            o.value: {"permits_use": o.usable} for o in ApprovalOutcome
        },
        "usage_categories": [
            {
                "category": u.value,
                "rank": USAGE_RANK[u],
                "restricted_use_section_8_2": u in RESTRICTED_USE_CATEGORIES,
                "requires_tested_fallback_section_8_5": USAGE_RANK[u] >= FALLBACK_REQUIRED_RANK,
            }
            for u in sorted(UsageCategory, key=lambda x: USAGE_RANK[x])
        ],
        "condition_codes": {c.value: CONDITION_REQUIREMENTS[c] for c in ConditionCode},
        "lifecycle_statuses": {
            s.value: {"allows_new_development": s.allows_new_development} for s in LifecycleStatus
        },
        "information_classes": {
            i.value: {"requires_sensitive_approval": i in SENSITIVE_INFORMATION_CLASSES}
            for i in InformationClass
        },
        "source_tiers": {
            "authoritative": "Publisher of record or official API. Citable as evidence.",
            "community": "Recognised community/industry project. Citable as evidence.",
            "aggregator": "News aggregation, possibly machine-generated. Leads only.",
        },
    }


# ------------------------------------------------------------------- mutating


@server.tool(
    description=(
        "Run the ingest now, refreshing all tracked sources. Normally unnecessary because the "
        "scheduled daily job handles it; use when data looks stale. Writes to the observation "
        "cache only, never to the registry."
    ),
    annotations=MUTATING,
)
def run_ingest(
    sources: Annotated[list[str] | None, "Source ids to refresh; omit for all enabled"] = None,
) -> dict[str, Any]:
    cfg, store, registry = _ctx()
    try:
        report = ingest_mod.ingest(cfg, store, only=sources)
        return {
            "run_id": report.run_id,
            "status": report.status,
            "new": report.new_total,
            "changed": report.changed_total,
            "sources": [
                {
                    "id": o.source_id, "ok": o.ok, "new": o.new,
                    "changed": o.changed, "seen": o.seen, "error": o.error,
                }
                for o in report.outcomes
            ],
        }
    finally:
        store.close()


@server.tool(
    description=(
        "Record a Section 6.3 approval outcome against a registry entry (Section 13 step 4). "
        "DISABLED unless LOMST_ALLOW_DECISIONS=1 is set in the server environment.\n\n"
        "When disabled it returns the exact `lomst decide` command for a human to run, which "
        "is the intended workflow: approval is an act by a named authority, and this server "
        "deliberately does not let a model grant approvals on its own initiative. Prepare the "
        "decision, explain the evidence from assess_family, and hand over the command."
    ),
    annotations=MUTATING,
)
def record_decision(
    family: Annotated[str, "Registry key"],
    outcome: Annotated[
        Literal[
            "approved", "approved_with_conditions", "deferred", "rejected", "withdrawn",
            "restricted", "pending_evaluation",
        ],
        "Section 6.3 outcome",
    ],
    authority: Annotated[str, "Approving authority - required by Appendix A.5 / D.6"],
    rationale: Annotated[str, "Why. Recorded in the decision history."] = "",
    approved_uses: Annotated[list[str] | None, "Appendix E.2 categories to grant"] = None,
    conditions: Annotated[list[str] | None, "Condition codes C1-C9"] = None,
    versions: Annotated[list[str] | None, "Approved versions (Section 6.2)"] = None,
    review_date: Annotated[str | None, "Next review date, ISO. Defaults to +12 months."] = None,
    kind: Annotated[Literal["model_family", "runtime"], "Component kind"] = "model_family",
) -> dict[str, Any]:
    parts = [f"lomst decide {family} {outcome} --authority {authority!r}"]
    if rationale:
        parts.append(f"--rationale {rationale!r}")
    for use in approved_uses or []:
        parts.append(f"--approved-use {use}")
    for cond in conditions or []:
        parts.append(f"--condition {cond}")
    for ver in versions or []:
        parts.append(f"--version {ver}")
    if review_date:
        parts.append(f"--review-date {review_date}")
    if kind != "model_family":
        parts.append(f"--kind {kind}")
    command = " ".join(parts)

    if not _decisions_enabled():
        return {
            "recorded": False,
            "reason": (
                "Decision recording is disabled on this server (LOMST_ALLOW_DECISIONS is not "
                "set). Section 13 step 4 records a Section 6.3 outcome as an act of a named "
                "approving authority."
            ),
            "run_this_command": command,
            "next_step": (
                "Present this command to the approving authority along with the assess_family "
                "evidence. Commit the changed registry YAML afterwards - git history is the "
                "Section 9.1 audit record."
            ),
        }

    cfg, store, registry = _ctx()
    try:
        entry = review.record_decision(
            registry,
            family,
            ApprovalOutcome(outcome),
            authority,
            kind=ComponentKind(kind),
            rationale=rationale,
            approved_uses=[UsageCategory(u) for u in approved_uses] if approved_uses else None,
            conditions=[ConditionCode(c.upper()) for c in conditions] if conditions else None,
            versions=versions,
            review_date=dt.date.fromisoformat(review_date) if review_date else None,
        )
        return {
            "recorded": True,
            "key": entry.key,
            "approval_status": entry.approval_status.value,
            "approving_authority": entry.approving_authority,
            "review_date": str(entry.review_date),
            "reminder": (
                "Commit the changed registry YAML - git history is the Section 9.1 audit record."
            ),
        }
    except (KeyError, ValueError) as exc:
        return {"recorded": False, "error": str(exc), "run_this_command": command}
    finally:
        store.close()


def run() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    run()
