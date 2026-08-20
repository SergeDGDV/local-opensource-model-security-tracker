"""Command-line interface.

    lomst ingest                     run the daily ingest
    lomst digest                     what changed and what it means
    lomst actions                    outstanding governance actions
    lomst assess <family>            Section 7 evaluation + Appendix A checklist
    lomst check <family> <category>   Section 8 usage gate
    lomst registry list|show|scaffold
    lomst decide <family> <outcome>   record a Section 6.3 decision
    lomst probe [source...]           verify sources still parse
    lomst health                      source freshness
    lomst serve                       open the web dashboard in a browser
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys
from typing import Any

from . import config, db, digest as digest_mod, ingest as ingest_mod
from .governance import review
from .governance.classify import Classifier
from .governance.registry import Entry, Registry, RegistryError
from .governance.usage import UsageGate
from .governance.vocab import (
    CONDITION_REQUIREMENTS,
    ApprovalOutcome,
    ComponentKind,
    ConditionCode,
    Criterion,
    InformationClass,
    ModelType,
    UsageCategory,
)
from .sources import build as build_connector

LOG = logging.getLogger("lomst")


def _ctx(args: argparse.Namespace) -> tuple[config.Config, db.Store, Registry]:
    cfg = config.load()
    store = db.Store(cfg.paths.db)
    registry = Registry(cfg.paths.families, cfg.paths.runtimes)
    return cfg, store, registry


def _emit(payload: Any, as_json: bool, text: str) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    else:
        print(text)


# --------------------------------------------------------------------- commands


def cmd_ingest(args: argparse.Namespace) -> int:
    cfg, store, registry = _ctx(args)
    try:
        report = ingest_mod.ingest(cfg, store, only=args.source or None)
        if args.json:
            print(
                json.dumps(
                    {
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
                    },
                    indent=2,
                )
            )
        else:
            print(
                f"run {report.run_id}: {report.status} - "
                f"{report.new_total} new, {report.changed_total} changed"
            )
            for o in report.outcomes:
                mark = "ok " if o.ok else "ERR"
                print(
                    f"  {mark} {o.source_id:<22} new={o.new:<5} changed={o.changed:<4} "
                    f"seen={o.seen:<5} {o.error or ''}"
                )
        # Partial runs are still useful; only a total failure is an error exit.
        return 1 if report.status == "failed" else 0
    finally:
        store.close()


def cmd_digest(args: argparse.Namespace) -> int:
    cfg, store, registry = _ctx(args)
    try:
        d = digest_mod.build(store, registry, run_id=args.run)
        _emit(d.to_dict(), args.json, digest_mod.render_text(d))
        return 0
    finally:
        store.close()


def cmd_actions(args: argparse.Namespace) -> int:
    cfg, store, registry = _ctx(args)
    try:
        actions = review.all_actions(store, registry, horizon_days=args.horizon)
        if args.urgency:
            actions = [a for a in actions if a.urgency.value == args.urgency]
        if args.json:
            print(json.dumps([a.to_dict() for a in actions], indent=2))
        else:
            if not actions:
                print("No outstanding governance actions.")
            for a in actions:
                print(f"[{a.urgency.value:<13}] [{a.section:<10}] {a.subject}: {a.detail}")
                if a.owner:
                    print(f"{'':17}owner: {a.owner} ({a.responsible_function})")
        # Exit 2 when something is immediate, so a cron wrapper can alert.
        return 2 if any(a.urgency is review.Urgency.IMMEDIATE for a in actions) else 0
    finally:
        store.close()


def cmd_assess(args: argparse.Namespace) -> int:
    cfg, store, registry = _ctx(args)
    try:
        assessment = Classifier(store, registry).assess(args.family)
        if args.json:
            print(json.dumps(assessment.to_dict(), indent=2, ensure_ascii=False))
            return 0

        a = assessment
        print(f"{a.family_name}  ({a.family_key})")
        print(f"  Overall risk        : {a.overall_risk.value}")
        print(f"  Recommended outcome : {a.recommended_outcome.value}   [recommendation only]")
        if a.recommended_conditions:
            print("  Conditions          :")
            for c in a.recommended_conditions:
                print(f"      {c.value}  {CONDITION_REQUIREMENTS[c]}")
        ceiling = a.eligible_uses[-1].value if a.eligible_uses else "none"
        print(f"  Eligible ceiling    : {ceiling}")
        print()
        print("  Section 7 criteria:")
        for f in a.findings:
            print(f"    [{f.section:<4}] {f.criterion.value:<24} {f.verdict.value.upper():<8} {f.summary}")
            for e in f.evidence[:2]:
                print(f"            evidence ({e.source_id}/{e.tier.value}): {e.statement[:130]}")
        if a.evidence_gaps:
            print()
            print("  Evidence gaps:")
            for g in a.evidence_gaps:
                print(f"    - {g}")
        if a.leads:
            print()
            print(f"  Leads from aggregator sources ({len(a.leads)}) - NOT citable as evidence:")
            for l in a.leads[:5]:
                print(f"    - [{l.source_id}] {l.statement[:120]}")
        print()
        print(
            "  Recommendation only. Section 6.3 outcomes are recorded by an approving\n"
            "  authority via `lomst decide` (Section 13 step 4)."
        )
        return 0
    finally:
        store.close()


def cmd_check(args: argparse.Namespace) -> int:
    cfg, store, registry = _ctx(args)
    try:
        try:
            category = UsageCategory(args.category)
        except ValueError:
            print(
                f"unknown usage category {args.category!r}; expected one of: "
                + ", ".join(u.value for u in UsageCategory),
                file=sys.stderr,
            )
            return 64
        info = []
        for raw in args.info or []:
            try:
                info.append(InformationClass(raw))
            except ValueError:
                print(
                    f"unknown information class {raw!r}; expected one of: "
                    + ", ".join(i.value for i in InformationClass),
                    file=sys.stderr,
                )
                return 64

        decision = UsageGate(registry).check(
            args.family,
            category,
            information_classes=info,
            runtime=args.runtime,
            solution_name=args.solution,
            version=args.version,
        )
        if args.json:
            print(json.dumps(decision.to_dict(), indent=2))
        else:
            print(f"{args.family} / {category.value}  ->  {decision.verdict.value.upper()}")
            print()
            for r in decision.reasons:
                mark = "PASS" if r.passed else "FAIL"
                print(f"  {mark}  [{r.section:<12}] {r.rule}")
                print(f"        {r.detail}")
            if decision.conditions:
                print()
                print("  Conditions:")
                for c in decision.conditions:
                    print(f"    {c.value}  {CONDITION_REQUIREMENTS[c]}")
            if decision.required_actions:
                print()
                print("  Required actions:")
                for act in decision.required_actions:
                    print(f"    - {act}")
        return 0 if decision.verdict.value != "blocked" else 3
    finally:
        store.close()


def cmd_registry(args: argparse.Namespace) -> int:
    cfg, store, registry = _ctx(args)
    try:
        if args.action == "list":
            entries = registry.load()
            if args.json:
                print(json.dumps([e.to_dict() for e in entries.values()], indent=2, default=str))
                return 0
            print(f"{'KEY':<20} {'KIND':<14} {'STATUS':<26} {'LIFECYCLE':<16} REVIEW")
            for e in sorted(entries.values(), key=lambda x: (x.kind.value, x.key)):
                overdue = " (OVERDUE)" if e.review_overdue else ""
                print(
                    f"{e.key:<20} {e.kind.value:<14} {e.approval_status.value:<26} "
                    f"{e.lifecycle_status.value:<16} {e.review_date or '-'}{overdue}"
                )
            return 0

        if args.action == "show":
            entry = registry.get(args.key, ComponentKind(args.kind))
            if entry is None:
                print(f"no {args.kind} entry {args.key!r}", file=sys.stderr)
                return 4
            print(json.dumps(entry.to_dict(), indent=2, default=str))
            return 0

        if args.action == "scaffold":
            kind = ComponentKind(args.kind)
            if registry.get(args.key, kind) is not None:
                print(f"{args.kind} {args.key!r} already exists", file=sys.stderr)
                return 4
            entry = Entry(
                key=args.key,
                name=args.name or args.key.replace("_", " ").title(),
                kind=kind,
                model_type=ModelType(args.model_type),
                approval_status=ApprovalOutcome.PENDING_EVALUATION,
                notes=(
                    "Scaffolded entry. Complete the Appendix A checklist and record a "
                    "Section 6.3 decision via `lomst decide` before any use."
                ),
            )
            path = registry.save(entry)
            print(f"created {path}")
            print("Status is pending_evaluation: no use is permitted until a decision is recorded.")
            return 0
        return 64
    except RegistryError as exc:
        print(f"registry error: {exc}", file=sys.stderr)
        return 65
    finally:
        store.close()


def cmd_decide(args: argparse.Namespace) -> int:
    cfg, store, registry = _ctx(args)
    try:
        try:
            outcome = ApprovalOutcome(args.outcome)
        except ValueError:
            print(
                f"unknown outcome {args.outcome!r}; expected one of: "
                + ", ".join(o.value for o in ApprovalOutcome),
                file=sys.stderr,
            )
            return 64

        uses = None
        if args.approved_use:
            uses = [UsageCategory(u) for u in args.approved_use]
        conditions = None
        if args.condition:
            conditions = [ConditionCode(c.upper()) for c in args.condition]
        review_date = (
            dt.date.fromisoformat(args.review_date) if args.review_date else None
        )

        entry = review.record_decision(
            registry,
            args.family,
            outcome,
            args.authority,
            kind=ComponentKind(args.kind),
            rationale=args.rationale or "",
            approved_uses=uses,
            conditions=conditions,
            versions=args.version or None,
            review_date=review_date,
        )
        print(
            f"recorded {outcome.value} for {entry.key} by {entry.approving_authority}; "
            f"next review {entry.review_date}"
        )
        print(f"registry file updated - commit it to preserve the Section 9.1 audit record.")
        return 0
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 65
    finally:
        store.close()


def cmd_probe(args: argparse.Namespace) -> int:
    """Verify each source still fetches and parses, without writing anything.

    Scrapers rot. This is the command to run when a digest looks thin.
    """
    cfg, store, registry = _ctx(args)
    try:
        sources = cfg.enabled_sources(args.source or None)
        failures = 0
        for sc in sources:
            try:
                result = build_connector(sc.connector).fetch(sc)
                print(
                    f"ok   {sc.id:<22} tier={sc.tier:<14} obs={len(result.observations):<5} "
                    f"adv={len(result.advisories):<5} art={len(result.artefacts)}"
                )
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"FAIL {sc.id:<22} {type(exc).__name__}: {exc}")
        return 1 if failures else 0
    finally:
        store.close()


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the local web dashboard.

    Loopback-only by default. The dashboard has no authentication and can write
    approval decisions, so binding it to a network interface would contradict
    Section 10.3's stance on unauthenticated shared services. `--host` exists for
    deliberate, reviewed deployments behind a real access layer.
    """
    from .web import serve

    print(f"Model Security Tracker: http://{args.host}:{args.port}/")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "  WARNING: binding beyond loopback exposes an unauthenticated surface "
            "that can record approval decisions (Section 10.3).",
            file=sys.stderr,
        )
    print("  Press Ctrl+C to stop.")
    try:
        serve(host=args.host, port=args.port, open_browser=not args.no_browser)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    cfg, store, registry = _ctx(args)
    try:
        rows = store.health()
        if args.json:
            print(json.dumps([dict(r) for r in rows], indent=2, default=str))
            return 0
        if not rows:
            print("no ingest has run yet; try `lomst ingest`")
            return 0
        print(f"{'SOURCE':<24} {'OK':<4} {'ITEMS':<7} LAST SUCCESS")
        for r in rows:
            ok = "yes" if r["consecutive_failures"] == 0 else f"no({r['consecutive_failures']})"
            print(
                f"{r['source_id']:<24} {ok:<4} {str(r['last_item_count'] or '-'):<7} "
                f"{r['last_success_at'] or 'never'}"
            )
            if r["last_error"]:
                print(f"{'':24} last error: {r['last_error'][:120]}")
        return 0
    finally:
        store.close()


# ----------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lomst",
        description=(
            "Local & Open-Source Model Security Tracker - daily ingest and governance "
            "classification for the AI Governance Framework (v1.1)."
        ),
    )
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="command", required=True)

    def add_json(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--json", action="store_true", help="machine-readable output")

    sp = sub.add_parser("ingest", help="run the daily ingest")
    sp.add_argument("--source", action="append", help="limit to a source id (repeatable)")
    add_json(sp)
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("digest", help="what changed and what it means")
    sp.add_argument("--run", type=int, help="run id (default: most recent)")
    add_json(sp)
    sp.set_defaults(func=cmd_digest)

    sp = sub.add_parser("actions", help="outstanding governance actions")
    sp.add_argument("--horizon", type=int, default=30, help="review lookahead in days")
    sp.add_argument(
        "--urgency", choices=[u.value for u in review.Urgency], help="filter by urgency"
    )
    add_json(sp)
    sp.set_defaults(func=cmd_actions)

    sp = sub.add_parser("assess", help="Section 7 evaluation of a model family")
    sp.add_argument("family")
    add_json(sp)
    sp.set_defaults(func=cmd_assess)

    sp = sub.add_parser("check", help="Section 8 usage gate")
    sp.add_argument("family")
    sp.add_argument("category", choices=[u.value for u in UsageCategory])
    sp.add_argument("--runtime", help="inference runtime (governed separately, Section 10)")
    sp.add_argument(
        "--info", action="append", choices=[i.value for i in InformationClass],
        help="information class processed (repeatable)",
    )
    sp.add_argument("--solution", help="name of the dependent solution (Section 8.5)")
    sp.add_argument("--version", help="specific model version (Section 6.2)")
    add_json(sp)
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("registry", help="inspect or scaffold registry entries")
    sp.add_argument("action", choices=["list", "show", "scaffold"])
    sp.add_argument("key", nargs="?")
    sp.add_argument("--kind", default="model_family", choices=[k.value for k in ComponentKind])
    sp.add_argument("--name")
    sp.add_argument("--model-type", default="llm", choices=[m.value for m in ModelType])
    add_json(sp)
    sp.set_defaults(func=cmd_registry)

    sp = sub.add_parser("decide", help="record a Section 6.3 approval outcome")
    sp.add_argument("family")
    sp.add_argument("outcome", choices=[o.value for o in ApprovalOutcome])
    sp.add_argument(
        "--authority", required=True,
        help="approving authority (required: Appendix A.5 / D.6)",
    )
    sp.add_argument("--kind", default="model_family", choices=[k.value for k in ComponentKind])
    sp.add_argument("--rationale", help="why - recorded in the decision history")
    sp.add_argument(
        "--approved-use", action="append", choices=[u.value for u in UsageCategory],
        help="approved usage category (repeatable)",
    )
    sp.add_argument("--condition", action="append", help="condition code C1..C9 (repeatable)")
    sp.add_argument("--version", action="append", help="approved version (repeatable)")
    sp.add_argument("--review-date", help="next review date (ISO); defaults to +12 months")
    sp.set_defaults(func=cmd_decide)

    sp = sub.add_parser("probe", help="verify sources still fetch and parse")
    sp.add_argument("source", nargs="*", help="source ids (default: all enabled)")
    sp.set_defaults(func=cmd_probe, json=False)

    sp = sub.add_parser("health", help="source freshness")
    add_json(sp)
    sp.set_defaults(func=cmd_health)

    sp = sub.add_parser("serve", help="open the web dashboard")
    sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--host", default="127.0.0.1", help="loopback by default; see Section 10.3")
    sp.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    sp.set_defaults(func=cmd_serve, json=False)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except RegistryError as exc:
        print(f"registry error: {exc}", file=sys.stderr)
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
