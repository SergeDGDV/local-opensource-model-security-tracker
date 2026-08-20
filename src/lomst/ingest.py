"""Daily ingest orchestration.

One source failing must never lose the rest of the run: each connector is
isolated, its health recorded, and the run reported as partial rather than
failed. A tracker that goes dark because one news site changed its markup is
worse than one that says "9 of 11 sources fresh, radarai stale 3 days".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .config import Config, SourceConfig
from .db import Store
from .extract import RUNTIME_KEYS, attribute_hf_id, detect, version_label
from .sources import build
from .sources.base import Result

log = logging.getLogger(__name__)


@dataclass(slots=True)
class SourceOutcome:
    source_id: str
    ok: bool
    new: int = 0
    changed: int = 0
    seen: int = 0
    error: str | None = None
    attribution: str | None = None

    @property
    def total(self) -> int:
        return self.new + self.changed + self.seen


@dataclass(slots=True)
class RunReport:
    run_id: int
    outcomes: list[SourceOutcome] = field(default_factory=list)

    @property
    def failed(self) -> list[SourceOutcome]:
        return [o for o in self.outcomes if not o.ok]

    @property
    def new_total(self) -> int:
        return sum(o.new for o in self.outcomes)

    @property
    def changed_total(self) -> int:
        return sum(o.changed for o in self.outcomes)

    @property
    def status(self) -> str:
        if not self.failed:
            return "ok"
        return "failed" if len(self.failed) == len(self.outcomes) else "partial"


def _resolve_runtime(payload: dict[str, Any], *texts: str | None) -> str | None:
    explicit = payload.get("runtime_key")
    if explicit in RUNTIME_KEYS:
        return explicit
    return detect(*texts).primary_runtime


def ingest(cfg: Config, store: Store, only: list[str] | None = None) -> RunReport:
    sources = cfg.enabled_sources(only)
    run_id = store.start_run(s.id for s in sources)
    report = RunReport(run_id=run_id)

    for sc in sources:
        outcome = _ingest_one(cfg, store, run_id, sc)
        report.outcomes.append(outcome)

    store.finish_run(
        run_id,
        status=report.status,
        error="; ".join(f"{o.source_id}: {o.error}" for o in report.failed) or None,
    )
    return report


def _ingest_one(cfg: Config, store: Store, run_id: int, sc: SourceConfig) -> SourceOutcome:
    try:
        result: Result = build(sc.connector).fetch(sc)
    except Exception as exc:  # noqa: BLE001 - one bad source must not end the run
        log.warning("source %s failed: %s", sc.id, exc)
        store.record_health(sc.id, ok=False, error=f"{type(exc).__name__}: {exc}")
        store.log_change(run_id, "source_failed", ref=sc.id, detail=str(exc)[:400])
        return SourceOutcome(sc.id, ok=False, error=f"{type(exc).__name__}: {exc}")

    out = SourceOutcome(sc.id, ok=True, attribution=result.attribution)
    counts = {"new": 0, "changed": 0, "seen": 0, "license_changed": 0}

    # ------------------------------------------------------------- observations
    for obs in result.observations:
        hits = detect(obs.title, obs.summary)
        status = store.upsert_observation(
            run_id,
            {
                "source_id": sc.id,
                "tier": sc.tier,
                "external_id": obs.external_id,
                "kind": obs.kind,
                "title": obs.title,
                "url": obs.url,
                "summary": obs.summary,
                "published_at": obs.published_at,
                "family_key": hits.primary_family,
                "runtime_key": hits.primary_runtime,
                "payload": {**obs.payload, "families": list(hits.families),
                            "runtimes": list(hits.runtimes)},
                "content_hash": obs.hash(),
            },
        )
        counts[status] = counts.get(status, 0) + 1
        if status == "new" and hits.primary_family:
            store.log_change(
                run_id,
                "observation",
                ref=obs.url or obs.external_id,
                family_key=hits.primary_family,
                detail=f"[{sc.id}] {obs.title or ''}"[:400],
            )

    # ---------------------------------------------------------------- advisories
    for adv in result.advisories:
        runtime = _resolve_runtime(adv.payload, adv.summary, adv.package)
        status = store.upsert_advisory(
            run_id,
            {
                "source_id": sc.id,
                "advisory_id": adv.advisory_id,
                "aliases": adv.aliases,
                "ecosystem": adv.ecosystem,
                "package": adv.package,
                "runtime_key": runtime,
                "severity": adv.severity,
                "cvss": adv.cvss,
                "summary": adv.summary,
                "url": adv.url,
                "published_at": adv.published_at,
                "modified_at": adv.modified_at,
                "withdrawn_at": adv.withdrawn_at,
                "payload": adv.payload,
            },
        )
        counts[status] = counts.get(status, 0) + 1
        # Only advisories that land on a runtime we can name are worth waking
        # someone for; the rest are recorded but not escalated (Section 11.4).
        if status == "new" and runtime and (adv.severity or "").lower() in ("critical", "high"):
            store.log_change(
                run_id,
                "advisory",
                ref=adv.advisory_id,
                severity=(adv.severity or "").lower(),
                detail=f"{adv.package}: {(adv.summary or '')[:300]}",
            )

    # ----------------------------------------------------------------- artefacts
    for art in result.artefacts:
        # Attribution strength is recorded, not just the family: an author-only
        # match is a discovery hint and must not fire Section 6.2 triggers.
        family, method = attribute_hf_id(art.artefact_id)
        status = store.upsert_artefact(
            run_id,
            {
                "source_id": sc.id,
                "artefact_id": art.artefact_id,
                "family_key": family,
                "publisher": art.publisher,
                "license": art.license,
                "model_type": art.model_type,
                "gated": art.gated,
                "downloads": art.downloads,
                "version_label": art.version_label
                or version_label(art.artefact_id.split("/")[-1]),
                "url": art.url,
                "modified_at": art.modified_at,
                "payload": {**art.payload, "attribution_method": method},
            },
        )
        counts[status] = counts.get(status, 0) + 1
        if status == "new" and family:
            store.log_change(
                run_id, "artefact", ref=art.artefact_id, family_key=family,
                detail=f"new artefact from {art.publisher or sc.id}"
                       f"{f' (licence {art.license})' if art.license else ''}",
            )
        elif status == "license_changed":
            # Section 6.2: a licensing change triggers full reassessment.
            store.log_change(
                run_id, "license_changed", ref=art.artefact_id, family_key=family,
                severity="high",
                detail=f"licence now {art.license!r} - Section 6.2 full reassessment trigger",
            )

    out.new = counts["new"]
    out.changed = counts["changed"] + counts.get("license_changed", 0)
    out.seen = counts["seen"]

    store.record_health(sc.id, ok=True, item_count=len(result))
    return out
