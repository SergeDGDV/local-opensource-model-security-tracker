"""Section 8 - Model usage and deployment gating.

Answers the question an employee actually asks: *may I use model X, on runtime Y,
for purpose Z, with information of class W?*

Section 8 is emphatic that model approval alone never answers this. Four
independent gates apply, and this module refuses to collapse them:

1. Model approval        - Section 6.3 status and Appendix E.2 category grant.
2. Runtime approval      - Sections 5 and 10; approving a model approves no runtime.
3. Information class     - Sections 8.3 and 11.2; the Information Classification
                           Policy takes precedence over the model's approval.
4. Continuity            - Section 8.5 and code C9; a tested fallback is
                           production-readiness evidence, not paperwork.

A "restricted use" under Section 8.2 can therefore never come back as a clean
"allowed": the most it can return is allowed-with-conditions plus the additional
governance the broader framework requires.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .registry import DependentSolution, Entry, Registry
from .vocab import (
    CONDITION_REQUIREMENTS,
    humanise,
    humanise_all,
    FALLBACK_REQUIRED_RANK,
    RESTRICTED_USE_CATEGORIES,
    SENSITIVE_INFORMATION_CLASSES,
    USAGE_RANK,
    ApprovalOutcome,
    ComponentKind,
    ConditionCode,
    InformationClass,
    LifecycleStatus,
    UsageCategory,
)


class Verdict(str, Enum):
    ALLOWED = "allowed"
    ALLOWED_WITH_CONDITIONS = "allowed_with_conditions"
    BLOCKED = "blocked"


@dataclass(slots=True)
class Reason:
    """One gate result, always traceable to a section."""

    section: str
    rule: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section,
            "rule": self.rule,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass(slots=True)
class UsageDecision:
    verdict: Verdict
    family_key: str
    usage_category: UsageCategory
    reasons: list[Reason] = field(default_factory=list)
    conditions: list[ConditionCode] = field(default_factory=list)
    required_actions: list[str] = field(default_factory=list)

    @property
    def blockers(self) -> list[Reason]:
        return [r for r in self.reasons if not r.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "family_key": self.family_key,
            "usage_category": self.usage_category.value,
            "blockers": [r.to_dict() for r in self.blockers],
            "checks": [r.to_dict() for r in self.reasons],
            "conditions": [
                {"code": c.value, "requirement": CONDITION_REQUIREMENTS[c]}
                for c in self.conditions
            ],
            "required_actions": self.required_actions,
        }

    def summary(self) -> str:
        if self.verdict is Verdict.BLOCKED:
            return "; ".join(f"[{r.section}] {r.detail}" for r in self.blockers)
        if self.verdict is Verdict.ALLOWED_WITH_CONDITIONS:
            codes = ", ".join(c.value for c in self.conditions)
            return f"Permitted subject to {codes or 'documented conditions'}."
        return "Permitted within the approved scope."


class UsageGate:
    def __init__(self, registry: Registry):
        self.registry = registry

    def check(
        self,
        family_key: str,
        usage_category: UsageCategory,
        *,
        information_classes: list[InformationClass] | None = None,
        runtime: str | None = None,
        solution_name: str | None = None,
        version: str | None = None,
    ) -> UsageDecision:
        info = information_classes or []
        reasons: list[Reason] = []
        conditions: list[ConditionCode] = []
        actions: list[str] = []

        entry = self.registry.get(family_key, ComponentKind.MODEL_FAMILY)

        # ------------------------------------------------ gate 1: model approval
        if entry is None:
            return UsageDecision(
                verdict=Verdict.BLOCKED,
                family_key=family_key,
                usage_category=usage_category,
                reasons=[
                    Reason(
                        "9",
                        "a decision exists for this model",
                        False,
                        f"Nobody has evaluated {family_key} yet, so no decision permits its "
                        f"use. This is not a judgement about the model - it simply has not "
                        f"been through the process. The registry is the record of what may "
                        f"be used (Section 9).",
                    )
                ],
                required_actions=[
                    f"Ask for it to be evaluated: fill in the \u201cRequest a new model\u201d "
                    f"questionnaire (Appendix D), or add {family_key} to the registry from the "
                    f"All models tab and have AI Governance record a decision.",
                    "Meanwhile, check whether an already-approved model does the same job - "
                    "that is the first thing AI Governance will ask (Section 13 step 2).",
                ],
            )

        reasons.append(
            Reason(
                "6.3",
                "approval status permits use",
                entry.approval_status.usable,
                f"Approval status is \u201c{humanise(entry.approval_status)}\u201d.",
            )
        )

        reasons.append(
            Reason(
                "9.3 / E.5",
                "lifecycle status permits new development",
                entry.lifecycle_status.allows_new_development,
                f"Lifecycle status is \u201c{humanise(entry.lifecycle_status)}\u201d."
                + (
                    " Retired models are not used for new solutions absent a documented "
                    "exception."
                    if entry.lifecycle_status is LifecycleStatus.RETIRED
                    else ""
                ),
            )
        )
        if entry.lifecycle_status is LifecycleStatus.DEPRECATED:
            actions.append(
                "Family is deprecated (Appendix E.5): plan a replacement before expanding use."
            )
        elif entry.lifecycle_status is LifecycleStatus.LIMITED_SUPPORT:
            actions.append(
                "Family is on limited support: prefer a newer approved alternative for new work."
            )

        granted = entry.approves(usage_category)
        reasons.append(
            Reason(
                "8.1 / E.2",
                "usage category is within the approved scope",
                granted,
                (
                    f"{humanise(usage_category).capitalize()} is an approved use."
                    if granted
                    else f"This model is not approved for {humanise(usage_category)}. "
                    f"It is approved for: {humanise_all(entry.approved_uses)}."
                ),
            )
        )

        # ------------------------------------------------------ Section 6.2 version
        if version:
            ok = version in entry.approved_versions
            reasons.append(
                Reason(
                    "6.2",
                    "version is an approved release",
                    ok,
                    (
                        f"Version {version} is approved."
                        if ok
                        else f"Version {version} is not in the approved list "
                        f"({', '.join(entry.approved_versions) or 'none'}). Family approval "
                        f"does not imply approval of every release."
                    ),
                )
            )
            if not ok:
                actions.append(
                    f"Route version {version} through Section 6.2 review (expedited for a "
                    f"minor release, full reassessment for a major one)."
                )

        # ------------------------------------------------ gate 2: runtime approval
        if runtime:
            reasons.extend(self._runtime_gate(entry, runtime, actions))
        elif USAGE_RANK[usage_category] >= FALLBACK_REQUIRED_RANK:
            reasons.append(
                Reason(
                    "5 / 10",
                    "runtime identified and separately approved",
                    False,
                    "No runtime specified. Runtimes are governed as independent components; "
                    "at this usage level the execution runtime must be named and approved.",
                )
            )
            actions.append("Specify the inference runtime and confirm its Section 10 approval.")

        # ------------------------------- gate 3: information classification (8.3/11.2)
        sensitive = [c for c in info if c in SENSITIVE_INFORMATION_CLASSES]
        if sensitive:
            approved_for_sensitive = entry.approves(
                UsageCategory.SENSITIVE_INFORMATION_PROCESSING
            )
            reasons.append(
                Reason(
                    "8.3 / 11.2",
                    "approved for the information classes involved",
                    approved_for_sensitive,
                    f"Processing {humanise_all(sensitive)} requires approval for handling "
                    f"sensitive information. "
                    + (
                        "That approval is present."
                        if approved_for_sensitive
                        else "That approval is absent; local execution does not by itself "
                        "permit processing confidential, personal or customer information."
                    ),
                )
            )
            conditions.append(ConditionCode.C1)
            actions.append(
                "Confirm the intended use against the Information Classification Policy, "
                "which takes precedence over this framework (Section 8.3)."
            )

        if InformationClass.SOURCE_CODE in info:
            conditions.append(ConditionCode.C1)
            actions.append(
                "Source code in scope: Section 8.4 treats repository access as an enterprise "
                "integration requiring its own governance."
            )

        # ---------------------------------------- gate 4: continuity (8.5 / C9)
        if USAGE_RANK[usage_category] >= FALLBACK_REQUIRED_RANK:
            reasons.append(self._continuity_gate(entry, solution_name, actions))
            conditions.append(ConditionCode.C9)

        # ------------------------------------------- Section 8.2 restricted uses
        if usage_category in RESTRICTED_USE_CATEGORIES:
            conditions.extend([ConditionCode.C3, ConditionCode.C8])
            actions.append(
                f"{humanise(usage_category).capitalize()} is a higher-risk use: additional "
                f"security, legal or architectural review applies whichever model you pick "
                f"(Section 8.2)."
            )
        if usage_category is UsageCategory.AUTONOMOUS_DECISION_SUPPORT:
            conditions.append(ConditionCode.C5)
            actions.append(
                "Because it can act on its own, a person must review output before "
                "production use and usage must be monitored more closely (Section 8.2)."
            )
            conditions.append(ConditionCode.C7)

        # ------------------------------------------------- Section 14 exceptions
        if entry.exception is not None:
            expired = entry.exception.expired
            reasons.append(
                Reason(
                    "14.1",
                    "temporary exception still valid",
                    not expired,
                    (
                        f"Operating under a {entry.exception.kind} exception expiring "
                        f"{entry.exception.expires}."
                        if not expired
                        else f"The {entry.exception.kind} exception has expired "
                        f"({entry.exception.expires or 'no expiry recorded'}); Section 14.3 "
                        f"requires use to cease until a new approval is granted."
                    ),
                )
            )

        # ------------------------------------------------------ Section 9.2 review
        if entry.review_overdue:
            conditions.append(ConditionCode.C3)
            actions.append(
                f"Scheduled review date {entry.review_date} has passed (Section 9.2): "
                f"reassess before relying on this approval."
            )

        # Carry the registry's own standing conditions through.
        conditions.extend(entry.conditions)

        deduped = sorted(set(conditions), key=lambda c: c.value)
        if any(not r.passed for r in reasons):
            verdict = Verdict.BLOCKED
        elif deduped or actions:
            verdict = Verdict.ALLOWED_WITH_CONDITIONS
        else:
            verdict = Verdict.ALLOWED

        return UsageDecision(
            verdict=verdict,
            family_key=family_key,
            usage_category=usage_category,
            reasons=reasons,
            conditions=deduped,
            required_actions=actions,
        )

    # ------------------------------------------------------------------ helpers
    def _runtime_gate(
        self, entry: Entry, runtime: str, actions: list[str]
    ) -> list[Reason]:
        """Sections 5 and 10: the runtime is a separate approval."""
        listed = runtime in entry.runtime_compatibility
        reasons = [
            Reason(
                "5 / B",
                "runtime is recorded as compatible with this family",
                listed,
                (
                    f"{runtime} is listed under runtime_compatibility."
                    if listed
                    else f"{runtime} is not listed as an approved runtime for this family "
                    f"({', '.join(entry.runtime_compatibility) or 'none recorded'})."
                ),
            )
        ]

        rt_entry = self.registry.get(runtime, ComponentKind.RUNTIME)
        if rt_entry is None:
            reasons.append(
                Reason(
                    "10 / 10.1",
                    "runtime has its own registry approval",
                    False,
                    f"Runtime {runtime!r} has no registry entry. Approval of a model does not "
                    f"imply approval of any runtime capable of executing it (Section 10).",
                )
            )
            actions.append(
                f"Submit an Appendix C runtime evaluation for {runtime!r} "
                f"(owner: Infra / Platform / IT per Appendix E.5)."
            )
        else:
            reasons.append(
                Reason(
                    "10",
                    "runtime approval permits use",
                    rt_entry.usable,
                    f"Runtime {rt_entry.name} is \u201c{humanise(rt_entry.approval_status)}\u201d "
                    f"and \u201c{humanise(rt_entry.lifecycle_status)}\u201d.",
                )
            )
            if rt_entry.review_overdue:
                actions.append(
                    f"Runtime {rt_entry.name} review date {rt_entry.review_date} has passed "
                    f"(Sections 9.2, 10.3)."
                )
        return reasons

    def _continuity_gate(
        self, entry: Entry, solution_name: str | None, actions: list[str]
    ) -> Reason:
        """Section 8.5: a documented, tested fallback at IBA and above."""
        matches: list[DependentSolution] = [
            d
            for d in entry.dependent_solutions
            if solution_name is None or d.name.lower() == solution_name.lower()
        ]

        if solution_name and not matches:
            actions.append(
                f"Record {solution_name!r} under dependent_solutions for {entry.key!r} with its "
                f"fallback, so a future withdrawal is visible before it happens (Sections 8.5, 9)."
            )
            return Reason(
                "8.5",
                "dependent solution registered with a tested fallback",
                False,
                f"{solution_name!r} is not recorded as a dependent solution of {entry.key!r}. "
                f"Section 9 requires the dependency be visible in the registry before a "
                f"withdrawal, not discovered afterward.",
            )

        if not matches:
            actions.append(
                f"Record this workflow under dependent_solutions for {entry.key!r} with an "
                f"alternate model, alternate provider or defined manual process."
            )
            return Reason(
                "8.5",
                "dependent solution registered with a tested fallback",
                False,
                "No dependent solution is recorded for this family at production weight. "
                "Section 8.5 requires the dependency and its fallback be documented before "
                "the workflow becomes business-critical.",
            )

        untested = [d for d in matches if d.gap]
        if untested:
            detail = "; ".join(f"{d.name}: {d.gap}" for d in untested)
            actions.append(
                "Test the documented fallback and record tested: true with a date. An "
                "untested assumption that a model keeps behaving as it did in testing is "
                "itself a risk (Section 8.5, citing 7.4)."
            )
            return Reason(
                "8.5 / E.4 C9", "dependent solution registered with a tested fallback", False, detail
            )

        names = ", ".join(f"{d.name} -> {d.fallback.kind}" for d in matches)
        return Reason(
            "8.5",
            "dependent solution registered with a tested fallback",
            True,
            f"Tested fallback on file: {names}.",
        )
