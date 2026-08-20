"""Lifecycle governance: Sections 6.2, 8.5, 9.2, 9.3, 11.4 and 14.

Section 4.5 is the premise here - approval is not a permanent decision. These
functions turn the registry plus the day's ingest into the specific list of
things that now need a human: reviews falling due, licences that moved, versions
that appeared, advisories that landed on an approved runtime, dependencies with
no tested fallback, and exceptions about to lapse.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..db import Store
from ..extract import compare_release, versions_equivalent
from .classify import OFFICIAL_PUBLISHERS, publisher_matches
from .licensing import assess as assess_license
from .registry import Decision, Entry, Registry, today
from .vocab import ApprovalOutcome, ComponentKind, ConditionCode, UsageCategory, USAGE_RANK


class Urgency(str, Enum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    SCHEDULED = "scheduled"
    INFORMATIONAL = "informational"


_URGENCY_ORDER = {
    Urgency.IMMEDIATE: 0,
    Urgency.HIGH: 1,
    Urgency.SCHEDULED: 2,
    Urgency.INFORMATIONAL: 3,
}


@dataclass(slots=True)
class Action:
    """Something a named function has to do, with the section that requires it."""

    urgency: Urgency
    section: str
    subject: str
    kind: str
    detail: str
    owner: str = ""
    responsible_function: str = "AI Governance"

    def to_dict(self) -> dict[str, Any]:
        return {
            "urgency": self.urgency.value,
            "section": self.section,
            "subject": self.subject,
            "kind": self.kind,
            "detail": self.detail,
            "owner": self.owner,
            "responsible_function": self.responsible_function,
        }


def _sort(actions: list[Action]) -> list[Action]:
    return sorted(actions, key=lambda a: (_URGENCY_ORDER[a.urgency], a.subject, a.kind))


# --------------------------------------------------------------------- reviewers


def reviews_due(registry: Registry, horizon_days: int = 30) -> list[Action]:
    """Section 9.2 - scheduled review dates, overdue first."""
    out: list[Action] = []
    for entry in registry.load().values():
        days = entry.days_to_review()
        if days is None:
            out.append(
                Action(
                    Urgency.HIGH,
                    "9 / B",
                    entry.key,
                    "missing_review_date",
                    "No review date recorded. Appendix B requires one, and Section 9.2 "
                    "reviews are triggered by it.",
                    owner=entry.governance_owner,
                )
            )
            continue
        if days < 0:
            out.append(
                Action(
                    Urgency.IMMEDIATE,
                    "9.2",
                    entry.key,
                    "review_overdue",
                    f"Review was due {entry.review_date} ({abs(days)} days ago).",
                    owner=entry.governance_owner,
                )
            )
        elif days <= horizon_days:
            out.append(
                Action(
                    Urgency.SCHEDULED,
                    "9.2",
                    entry.key,
                    "review_upcoming",
                    f"Review due {entry.review_date} (in {days} days).",
                    owner=entry.governance_owner,
                )
            )
    return _sort(out)


def dependency_gaps(registry: Registry) -> list[Action]:
    """Section 8.5 / Appendix E.4 C9 - dependencies without a tested fallback."""
    out: list[Action] = []
    for entry in registry.load().values():
        for solution, gap in entry.dependency_gaps():
            immediate = USAGE_RANK[solution.usage_category] >= USAGE_RANK[
                UsageCategory.PRODUCTION_SERVICES
            ]
            out.append(
                Action(
                    Urgency.IMMEDIATE if immediate else Urgency.HIGH,
                    "8.5",
                    entry.key,
                    "fallback_gap",
                    f"{solution.name} ({solution.usage_category.value}): {gap}. "
                    f"A withdrawal under Section 6.3 would become an operational incident "
                    f"rather than a managed migration.",
                    owner=solution.owner or entry.business_owner,
                    responsible_function="Solution Owner",
                )
            )

        # Section 9: production-weight approvals with no recorded dependency at
        # all. Appendix E.2 says the Dependent Solutions entry should be complete
        # before the family is marked approved for those categories.
        production_uses = [
            u
            for u in entry.approved_uses
            if USAGE_RANK[u] >= USAGE_RANK[UsageCategory.INTERNAL_BUSINESS_APPLICATIONS]
        ]
        if production_uses and not entry.dependent_solutions:
            out.append(
                Action(
                    Urgency.HIGH,
                    "8.5 / E.2",
                    entry.key,
                    "dependent_solutions_empty",
                    f"Approved for {', '.join(u.value for u in production_uses)} but no "
                    f"dependent solutions recorded. Appendix E.2 expects a completed entry "
                    f"before that approval stands.",
                    owner=entry.governance_owner,
                )
            )
    return _sort(out)


def exception_status(registry: Registry, horizon_days: int = 14) -> list[Action]:
    """Section 14 - temporary approvals lapsing or already lapsed."""
    out: list[Action] = []
    for entry in registry.load().values():
        exc = entry.exception
        if exc is None:
            continue
        if exc.expired:
            out.append(
                Action(
                    Urgency.IMMEDIATE,
                    "14.3",
                    entry.key,
                    "exception_expired",
                    f"{exc.kind} exception expired ({exc.expires or 'no expiry recorded'}). "
                    f"Continued use must cease unless a new approval has been granted.",
                    owner=exc.owner,
                )
            )
        elif exc.expires and (exc.expires - today()).days <= horizon_days:
            out.append(
                Action(
                    Urgency.HIGH,
                    "14.1",
                    entry.key,
                    "exception_expiring",
                    f"{exc.kind} exception expires {exc.expires}.",
                    owner=exc.owner,
                )
            )
    return _sort(out)


def advisory_impacts(
    store: Store, registry: Registry, since_days: int = 7
) -> list[Action]:
    """Section 11.4 - new advisories touching an approved runtime."""
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=since_days)).isoformat()
    runtimes = registry.runtimes()
    if not runtimes:
        return []

    rows = store.query(
        """SELECT advisory_id, severity, package, runtime_key, summary, url, published_at
           FROM advisories
           WHERE withdrawn_at IS NULL
             AND runtime_key IS NOT NULL
             AND COALESCE(published_at, first_seen) >= ?
           ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END""",
        (cutoff,),
    )

    out: list[Action] = []
    for r in rows:
        rt = runtimes.get(r["runtime_key"])
        if rt is None or not rt.usable:
            continue
        severity = (r["severity"] or "unknown").lower()
        urgency = (
            Urgency.IMMEDIATE
            if severity == "critical"
            else Urgency.HIGH
            if severity == "high"
            else Urgency.INFORMATIONAL
        )
        out.append(
            Action(
                urgency,
                "11.4",
                rt.key,
                "advisory",
                f"{r['advisory_id']} ({severity}) affects {r['package']}, the runtime "
                f"{rt.name} depends on: {(r['summary'] or '')[:160]} {r['url'] or ''}".strip(),
                owner=rt.business_owner,
                responsible_function="Information Security",
            )
        )
    return _sort(out)


def version_drift(store: Store, registry: Registry) -> list[Action]:
    """Section 6.2 - releases observed that are not approved versions."""
    out: list[Action] = []
    families = registry.families()
    if not families:
        return out

    # Only artefacts published by the family's publisher of record, and only
    # where the repository name itself identifies the family. An author-only
    # attribution means the publisher ships several families (mistralai ships
    # Voxtral, Pixtral, Ministral) and a release of one is not a release of
    # another.
    rows = store.query(
        """SELECT family_key, artefact_id, version_label, url, modified_at, publisher,
                  json_extract(payload, '$.attribution_method') AS method
           FROM artefacts
           WHERE family_key IS NOT NULL AND version_label IS NOT NULL
           ORDER BY modified_at DESC"""
    )

    seen: set[tuple[str, str]] = set()
    for r in rows:
        entry = families.get(r["family_key"])
        if entry is None or not entry.usable:
            continue
        if r["method"] != "name":
            continue
        official = OFFICIAL_PUBLISHERS.get(entry.key, ())
        if official and not publisher_matches(r["publisher"], official):
            continue
        version = str(r["version_label"])
        # "4" and "4.0" are the same release; compare numerically.
        if any(versions_equivalent(version, av) for av in entry.approved_versions):
            continue
        dedupe = (entry.key, version)
        if dedupe in seen:
            continue
        seen.add(dedupe)

        newest_approved = entry.approved_versions[-1] if entry.approved_versions else None
        relation = compare_release(newest_approved, version)
        if relation == "major":
            urgency, route = Urgency.HIGH, "full reassessment (major release)"
        elif relation == "minor":
            urgency, route = Urgency.SCHEDULED, "expedited review (minor release)"
        elif relation == "older":
            # A superseded release still in circulation is a different question
            # from a new one: Section 9.3 covers whether it should be retired.
            urgency, route = (
                Urgency.INFORMATIONAL,
                "no action unless still in use; consider retirement under Section 9.3",
            )
        else:
            urgency, route = Urgency.SCHEDULED, "review to determine major/minor"

        descriptor = "Superseded version" if relation == "older" else "Version"
        out.append(
            Action(
                urgency,
                "6.2",
                entry.key,
                "superseded_version" if relation == "older" else "unapproved_version",
                f"{descriptor} {version} observed ({r['artefact_id']}) but approved versions "
                f"are {', '.join(entry.approved_versions) or 'none'}. Route through {route}.",
                owner=entry.governance_owner,
            )
        )
    return _sort(out)


def license_drift(store: Store, registry: Registry) -> list[Action]:
    """Section 6.2 / 7.3 - observed licence differs from the approved record.

    Three constraints keep this signal honest rather than merely loud:

    * Only artefacts from the family's **publisher of record** count. A
      third-party fine-tune under a different licence is not the family changing
      its terms; Section 6.2 treats it as an independent artefact, reported
      separately below.
    * An ``unknown`` licence class is an *evidence gap*, not a change. Hugging
      Face's ``other`` tag means "read the repository", which cannot support a
      claim that the licence moved.
    * Findings are deduplicated per licence class, because one relicensing event
      shows up across every artefact in the family.
    """
    out: list[Action] = []
    for key, entry in registry.families().items():
        if not entry.license or not entry.usable:
            continue
        recorded = assess_license(entry.license)
        official = OFFICIAL_PUBLISHERS.get(key, ())

        rows = store.query(
            """SELECT DISTINCT license, source_id, artefact_id, publisher FROM artefacts
               WHERE family_key = ? AND license IS NOT NULL AND license != ''""",
            (key,),
        )

        seen_classes: set[str] = set()
        third_party: list[str] = []
        unknown_licence: list[str] = []

        for r in rows:
            observed = assess_license(r["license"])
            if observed.klass is recorded.klass:
                continue

            from_official = publisher_matches(r["publisher"], official)
            if not from_official:
                third_party.append(f"{r['artefact_id']} ({observed.normalised})")
                continue
            if observed.klass.value == "unknown":
                unknown_licence.append(r["artefact_id"])
                continue
            if observed.klass.value in seen_classes:
                continue
            seen_classes.add(observed.klass.value)

            out.append(
                Action(
                    Urgency.IMMEDIATE,
                    "6.2 / 7.3",
                    key,
                    "license_drift",
                    f"Registry records {recorded.normalised!r} ({recorded.klass.value}) but "
                    f"the publisher of record reports {observed.normalised!r} "
                    f"({observed.klass.value}) via {r['source_id']}, e.g. "
                    f"{r['artefact_id']}. A licensing change requires full reassessment.",
                    owner=entry.governance_owner,
                    responsible_function="Legal",
                )
            )

        if unknown_licence:
            out.append(
                Action(
                    Urgency.HIGH,
                    "7.3",
                    key,
                    "license_unverified",
                    f"{len(unknown_licence)} artefact(s) from the publisher of record carry a "
                    f"non-specific licence tag (e.g. {unknown_licence[0]}), so the terms cannot "
                    f"be confirmed from metadata alone. Section 7.3 requires the conditions be "
                    f"evaluated before approval; read the repository licence directly.",
                    owner=entry.governance_owner,
                    responsible_function="Legal",
                )
            )

        if third_party:
            out.append(
                Action(
                    Urgency.INFORMATIONAL,
                    "6.2",
                    key,
                    "third_party_variant",
                    f"{len(third_party)} third-party redistribution(s) of this family carry a "
                    f"different licence (e.g. {third_party[0]}). These are independent "
                    f"artefacts and are not covered by the family's approval.",
                    owner=entry.governance_owner,
                )
            )
    return _sort(out)


def unregistered_families(store: Store, registry: Registry, min_downloads: int = 100_000) -> list[Action]:
    """Families visible in the wild with no registry entry at all.

    Not a compliance failure - Section 6 is explicit that approval lists are not
    exhaustive - but it is what turns the tracker into something proactive rather
    than a record of past decisions.
    """
    known = set(registry.families())
    rows = store.query(
        """SELECT family_key, COUNT(*) n, SUM(COALESCE(downloads,0)) dl,
                  GROUP_CONCAT(DISTINCT publisher) publishers
           FROM artefacts
           WHERE family_key IS NOT NULL
           GROUP BY family_key
           HAVING dl >= ?
           ORDER BY dl DESC""",
        (min_downloads,),
    )
    out: list[Action] = []
    for r in rows:
        if r["family_key"] in known:
            continue
        out.append(
            Action(
                Urgency.INFORMATIONAL,
                "13.1 / 15.3",
                r["family_key"],
                "unregistered_family",
                f"{r['n']} artefacts observed ({r['dl']:,} downloads) from "
                f"{r['publishers']}, with no registry entry. Section 15.3 asks that emerging "
                f"families be evaluated proactively.",
            )
        )
    return _sort(out)


def all_actions(store: Store, registry: Registry, *, horizon_days: int = 30) -> list[Action]:
    """Every outstanding governance action, most urgent first."""
    return _sort(
        reviews_due(registry, horizon_days)
        + dependency_gaps(registry)
        + exception_status(registry)
        + advisory_impacts(store, registry)
        + version_drift(store, registry)
        + license_drift(store, registry)
        + unregistered_families(store, registry)
    )


# ---------------------------------------------------------------- decision write


def record_decision(
    registry: Registry,
    family_key: str,
    outcome: ApprovalOutcome,
    authority: str,
    *,
    kind: ComponentKind = ComponentKind.MODEL_FAMILY,
    rationale: str = "",
    approved_uses: list[UsageCategory] | None = None,
    conditions: list[ConditionCode] | None = None,
    versions: list[str] | None = None,
    review_date: dt.date | None = None,
    restrictions: list[str] | None = None,
) -> Entry:
    """Record a Section 6.3 outcome against a registry entry (Section 13 step 4).

    `authority` is mandatory and must be a real name or body. The classifier
    produces recommendations; only this function writes an approval, and it
    refuses to do so anonymously - Appendix A.5 and Appendix D.6 both require an
    approving authority, and an unattributable approval is not auditable under
    Section 9.1.
    """
    if not authority.strip():
        raise ValueError(
            "an approving authority is required (Appendix A.5 / D.6); Section 6.3 outcomes "
            "cannot be recorded anonymously"
        )

    entry = registry.get(family_key, kind)
    if entry is None:
        raise KeyError(f"no registry entry for {kind.value} {family_key!r}")

    when = today()
    entry.approval_status = outcome
    entry.approving_authority = authority.strip()
    entry.last_review = when

    if outcome.usable and entry.approval_date is None:
        entry.approval_date = when
    if approved_uses is not None:
        entry.approved_uses = list(approved_uses)
    if conditions is not None:
        entry.conditions = list(conditions)
    if restrictions is not None:
        entry.restrictions = list(restrictions)
    if versions is not None:
        entry.approved_versions = list(versions)

    # Section 9.2 relies on a forward review date existing; default to 12 months
    # rather than silently leaving the entry unreviewable.
    entry.review_date = review_date or when.replace(year=when.year + 1)

    # Section 6.3: withdrawal removes the grant. Lifecycle status is left alone
    # deliberately - retirement is a separate Section 9.3 decision, and a
    # withdrawn family may still be pending a migration rather than retired.
    if outcome is ApprovalOutcome.WITHDRAWN:
        entry.approved_uses = []

    entry.decision_history.append(
        Decision(
            date=when,
            outcome=outcome,
            authority=authority.strip(),
            rationale=rationale,
            versions=list(versions or entry.approved_versions),
        )
    )
    registry.save(entry)
    return entry
