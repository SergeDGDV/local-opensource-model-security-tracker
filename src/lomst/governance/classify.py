"""Section 7 - Model evaluation criteria, applied to ingested evidence.

What this module does and does not do matters.

It **gathers and weighs evidence** against the five Section 7 criteria and
produces a *recommendation* plus a populated Appendix A checklist. It does
**not** approve anything. Section 6.3 outcomes are recorded by an approving
authority through Section 13 step 4; `governance.decide` is the only path that
writes an approval, and it demands a named authority. A classifier that could
approve its own findings would defeat the point of the framework.

Two rules are enforced structurally rather than left to the caller:

* Section 4.2 (Technology Neutrality) - origin country, vendor identity and
  "open vs commercial" never contribute to a score. Only the five criteria do.
* Section 7.1 (Provenance) - `SourceTier.AGGREGATOR` material cannot be cited as
  evidence. It is reported separately as leads to investigate.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..db import Store
from ..extract import FAMILY_NAMES
from .licensing import LicenseAssessment, LicenseClass, assess as assess_license
from .registry import Entry, Registry
from .vocab import (
    CONDITION_REQUIREMENTS,
    CRITERION_SECTIONS,
    USAGE_RANK,
    ApprovalOutcome,
    ConditionCode,
    Criterion,
    RiskLevel,
    SourceTier,
    UsageCategory,
)


class Verdict(str, Enum):
    """Per-criterion outcome."""

    PASS = "pass"
    CONCERN = "concern"
    FAIL = "fail"
    #: Section 7 weighs an overall risk profile; missing evidence is explicitly
    #: not a pass. UNKNOWN drives the recommendation toward Deferred (6.3).
    UNKNOWN = "unknown"


_VERDICT_WEIGHT = {
    Verdict.PASS: 0,
    Verdict.CONCERN: 1,
    Verdict.UNKNOWN: 2,
    Verdict.FAIL: 4,
}


@dataclass(slots=True)
class Evidence:
    """A single citable fact, with the source that produced it."""

    source_id: str
    tier: SourceTier
    statement: str
    url: str | None = None
    observed_at: str | None = None

    @property
    def citable(self) -> bool:
        return self.tier.citable_as_evidence


@dataclass(slots=True)
class Finding:
    criterion: Criterion
    verdict: Verdict
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    conditions: list[ConditionCode] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    @property
    def section(self) -> str:
        return CRITERION_SECTIONS[self.criterion]

    def to_dict(self) -> dict[str, Any]:
        return {
            "criterion": self.criterion.value,
            "section": self.section,
            "verdict": self.verdict.value,
            "summary": self.summary,
            "conditions": [c.value for c in self.conditions],
            "gaps": self.gaps,
            "evidence": [
                {
                    "source": e.source_id,
                    "tier": e.tier.value,
                    "statement": e.statement,
                    "url": e.url,
                }
                for e in self.evidence
            ],
        }


@dataclass(slots=True)
class Assessment:
    family_key: str
    family_name: str
    findings: list[Finding]
    overall_risk: RiskLevel
    recommended_outcome: ApprovalOutcome
    recommended_conditions: list[ConditionCode]
    eligible_uses: list[UsageCategory]
    leads: list[Evidence] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)
    license: LicenseAssessment | None = None
    registry_entry: Entry | None = None

    @property
    def is_recommendation_only(self) -> bool:
        """Always true. Present so callers cannot mistake this for a decision."""
        return True

    def finding(self, criterion: Criterion) -> Finding | None:
        return next((f for f in self.findings if f.criterion is criterion), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "family_key": self.family_key,
            "family_name": self.family_name,
            "overall_risk": self.overall_risk.value,
            "recommended_outcome": self.recommended_outcome.value,
            "recommended_conditions": [
                {"code": c.value, "requirement": CONDITION_REQUIREMENTS[c]}
                for c in self.recommended_conditions
            ],
            "eligible_uses": [u.value for u in self.eligible_uses],
            "findings": [f.to_dict() for f in self.findings],
            "evidence_gaps": self.evidence_gaps,
            "leads_not_evidence": [
                {"source": l.source_id, "statement": l.statement, "url": l.url}
                for l in self.leads
            ],
            "license": (
                {
                    "raw": self.license.raw,
                    "class": self.license.klass.value,
                    "commercial_use": self.license.commercial_use,
                    "redistribution": self.license.redistribution,
                    "fine_tuning": self.license.fine_tuning,
                    "acceptable_use_policy": self.license.acceptable_use_policy,
                    "rationale": self.license.rationale,
                }
                if self.license
                else None
            ),
            "disclaimer": (
                "Recommendation only. Section 6.3 outcomes are recorded by an approving "
                "authority via the Section 13 decision step; this assessment is the "
                "evidence that supports that decision, not the decision itself."
            ),
        }


# ---------------------------------------------------------------------- helpers

#: Publishers we treat as the official channel for a family (Section 7.1
#: "Preference goes to models obtained directly from official distribution
#: channels"). Membership is about being the publisher of record, not about the
#: organisation's country or commercial status (Section 4.2).
OFFICIAL_PUBLISHERS: dict[str, tuple[str, ...]] = {
    "llama": ("meta-llama", "Meta", "Meta AI"),
    "mistral": ("mistralai", "Mistral", "Mistral AI"),
    "mixtral": ("mistralai", "Mistral AI"),
    "magistral": ("mistralai", "Mistral AI"),
    "devstral": ("mistralai", "Mistral AI"),
    "gemma": ("google", "Google", "Google DeepMind"),
    "phi": ("microsoft", "Microsoft"),
    "qwen": ("Qwen", "Alibaba", "Alibaba Cloud"),
    "deepseek": ("deepseek-ai", "DeepSeek"),
    "glm": ("zai-org", "Zhipu AI", "Z.ai"),
    "granite": ("ibm-granite", "IBM"),
    "olmo": ("allenai", "Allen Institute for AI", "Ai2"),
    "smollm": ("HuggingFaceTB", "Hugging Face"),
    "nemotron": ("nvidia", "NVIDIA"),
    "falcon": ("tiiuae", "TII"),
    "command_r": ("CohereLabs", "Cohere"),
    "kimi": ("moonshotai", "Moonshot AI"),
    "minimax": ("MiniMaxAI", "MiniMax"),
    "gpt_oss": ("openai", "OpenAI"),
    "whisper": ("openai", "OpenAI"),
    "stable_diffusion": ("stabilityai", "Stability AI"),
    "flux": ("black-forest-labs", "Black Forest Labs"),
    "bge": ("BAAI",),
    "nomic_embed": ("nomic-ai", "Nomic AI"),
}

_STALE_DAYS = 270  # Section 7.5 "maintenance activity" / 9.2 review triggers


def _norm_publisher(value: str) -> str:
    return "".join(ch for ch in (value or "").lower() if ch.isalnum())


def publisher_matches(publisher: str | None, official: tuple[str, ...]) -> bool:
    """Whether `publisher` is the publisher of record.

    Sources spell the same organisation differently: Hugging Face says ``Qwen``,
    llm-stats says ``Alibaba Cloud / Qwen Team``. Exact matching would silently
    treat official releases as third-party redistributions, which inverts the
    Section 6.2 distinction this function exists to protect.
    """
    if not publisher or not official:
        return False
    got = _norm_publisher(publisher)
    if not got:
        return False
    return any(
        (want := _norm_publisher(name)) and (want in got or got in want)
        for name in official
    )


def _tier(raw: str) -> SourceTier:
    try:
        return SourceTier(raw)
    except ValueError:
        return SourceTier.COMMUNITY


def _days_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        when = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = dt.datetime.now(dt.timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return (now - when).days


# -------------------------------------------------------------------- classifier


class Classifier:
    def __init__(self, store: Store, registry: Registry):
        self.store = store
        self.registry = registry

    def assess(self, family_key: str) -> Assessment:
        entry = self.registry.get(family_key)
        artefacts = self._artefacts(family_key)
        leads, citable = self._observations(family_key)

        license_assessment, license_notes = self._pick_license(artefacts, entry)

        findings = [
            self._provenance(family_key, artefacts),
            self._distribution_integrity(artefacts),
            self._licensing(license_assessment, license_notes),
            self._security(artefacts, entry, citable),
            self._operational(artefacts),
        ]

        risk = self._risk(findings)
        conditions = sorted(
            {c for f in findings for c in f.conditions}, key=lambda c: c.value
        )
        outcome = self._recommend(findings, risk, license_assessment)
        eligible = self._eligible_uses(license_assessment, findings)
        gaps = [g for f in findings for g in f.gaps]

        return Assessment(
            family_key=family_key,
            family_name=(entry.name if entry else FAMILY_NAMES.get(family_key, family_key)),
            findings=findings,
            overall_risk=risk,
            recommended_outcome=outcome,
            recommended_conditions=conditions,
            eligible_uses=eligible,
            leads=leads,
            evidence_gaps=gaps,
            license=license_assessment,
            registry_entry=entry,
        )

    # ------------------------------------------------------------ data loading
    def _artefacts(self, family_key: str) -> list[dict[str, Any]]:
        rows = self.store.query(
            """SELECT a.*, sh.source_id AS _sid FROM artefacts a
               LEFT JOIN source_health sh ON sh.source_id = a.source_id
               WHERE a.family_key = ?
               ORDER BY COALESCE(a.downloads, 0) DESC""",
            (family_key,),
        )
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d.get("payload") or "{}")
            except json.JSONDecodeError:
                d["payload"] = {}
            out.append(d)
        return out

    def _observations(self, family_key: str) -> tuple[list[Evidence], list[Evidence]]:
        """Split observations into leads (aggregator) and citable evidence."""
        rows = self.store.query(
            """SELECT source_id, tier, title, url, summary, published_at
               FROM observations WHERE family_key = ?
               ORDER BY COALESCE(published_at, first_seen) DESC LIMIT 60""",
            (family_key,),
        )
        leads: list[Evidence] = []
        citable: list[Evidence] = []
        for r in rows:
            ev = Evidence(
                source_id=r["source_id"],
                tier=_tier(r["tier"]),
                statement=(r["title"] or r["summary"] or "")[:220],
                url=r["url"],
                observed_at=r["published_at"],
            )
            (citable if ev.citable else leads).append(ev)
        return leads, citable

    def _pick_license(
        self, artefacts: list[dict[str, Any]], entry: Entry | None
    ) -> tuple[LicenseAssessment, list[str]]:
        """Choose the licence to assess, and report licence spread across the family.

        A family is not a single licence. Llama alone publishes a dozen distinct
        licence strings across its releases, and Mistral mixes Apache-2.0 with
        research-only terms. Section 6.2 is explicit that approving a family does
        not approve every release, so the licence assessed must be the one
        attached to the *approved versions* where we know them - not simply the
        most-downloaded artefact, which skews to whatever is popular rather than
        what is approved.

        Returns the chosen assessment plus notes describing any divergence, so
        heterogeneity surfaces instead of being silently collapsed.
        """
        authoritative = [
            a for a in artefacts if a.get("source_id") == "huggingface" and a.get("license")
        ]
        licensed = authoritative or [a for a in artefacts if a.get("license")]

        notes: list[str] = []
        if not licensed:
            if entry and entry.license:
                return assess_license(entry.license), [
                    "No licence observed at a distribution source; using the registry's "
                    "recorded licence, which is unverified against the publisher."
                ]
            return assess_license(None), []

        # Group observed licences by class to detect real divergence (spelling
        # differences between sources are not governance events).
        by_class: dict[str, set[str]] = {}
        for a in licensed:
            la = assess_license(a["license"])
            by_class.setdefault(la.klass.value, set()).add(la.normalised)

        chosen: dict[str, Any] | None = None
        approved_versions = set(entry.approved_versions) if entry else set()
        if approved_versions:
            chosen = next(
                (a for a in licensed if str(a.get("version_label")) in approved_versions),
                None,
            )
            if chosen is None:
                notes.append(
                    f"No artefact matching the approved version(s) "
                    f"{', '.join(sorted(approved_versions))} carries a licence tag; the "
                    f"licence below is taken from another release of the same family and "
                    f"may not govern the approved one (Section 6.2)."
                )

        if chosen is None:
            chosen = licensed[0]  # ordered by downloads desc

        if len(by_class) > 1:
            spread = "; ".join(
                f"{klass}: {', '.join(sorted(names))}" for klass, names in sorted(by_class.items())
            )
            notes.append(
                f"Family publishes releases under {len(by_class)} different licence classes "
                f"({spread}). Each release must be licensed on its own terms; a family-level "
                f"licence statement would be misleading (Sections 6.2, 7.3)."
            )

        return assess_license(chosen["license"]), notes

    # -------------------------------------------------------------- criteria
    def _provenance(self, family_key: str, artefacts: list[dict[str, Any]]) -> Finding:
        official = OFFICIAL_PUBLISHERS.get(family_key, ())
        evidence: list[Evidence] = []
        matched: str | None = None

        for a in artefacts:
            publisher = a.get("publisher") or ""
            if publisher_matches(publisher, official):
                matched = publisher
                evidence.append(
                    Evidence(
                        source_id=a["source_id"],
                        tier=_tier("authoritative" if a["source_id"] in ("huggingface", "ollama_library") else "community"),
                        statement=f"{a['artefact_id']} published by {publisher}, the publisher of record for this family",
                        url=a.get("url"),
                    )
                )
                break

        if matched:
            return Finding(
                Criterion.PROVENANCE,
                Verdict.PASS,
                f"Official publisher identified ({matched}) and artefacts retrieved from its "
                f"official channel.",
                evidence=evidence,
            )

        if not official:
            return Finding(
                Criterion.PROVENANCE,
                Verdict.UNKNOWN,
                f"No publisher of record is registered for {family_key!r}, so authenticity "
                f"cannot be confirmed automatically.",
                gaps=[
                    f"Add {family_key!r} to OFFICIAL_PUBLISHERS, or verify the publisher "
                    f"manually per Section 7.1."
                ],
                conditions=[ConditionCode.C8],
            )

        if artefacts:
            publishers = sorted({a.get("publisher") or "?" for a in artefacts})
            return Finding(
                Criterion.PROVENANCE,
                Verdict.CONCERN,
                f"Artefacts found, but none from the expected publisher "
                f"({', '.join(official)}). Observed: {', '.join(publishers[:5])}. "
                f"Section 6.2 treats third-party redistributions as independent artefacts.",
                gaps=["Verify chain of custody before approval (Section 7.2)."],
                conditions=[ConditionCode.C1, ConditionCode.C8],
            )

        return Finding(
            Criterion.PROVENANCE,
            Verdict.UNKNOWN,
            "No artefacts observed at any authoritative distribution source.",
            gaps=["Run `lomst ingest` or confirm the family is actually published."],
        )

    def _distribution_integrity(self, artefacts: list[dict[str, Any]]) -> Finding:
        hf = [a for a in artefacts if a.get("source_id") == "huggingface"]
        if not hf:
            return Finding(
                Criterion.DISTRIBUTION_INTEGRITY,
                Verdict.UNKNOWN,
                "No artefact manifest available; weight format and integrity unverified.",
                gaps=["Section 7.2 requires integrity verification wherever practical."],
                conditions=[ConditionCode.C1],
            )

        safetensors = sum(1 for a in hf if a["payload"].get("has_safetensors"))
        pickled = [a for a in hf if a["payload"].get("has_pickle_weights")]
        gated = sum(1 for a in hf if a.get("gated"))
        evidence = [
            Evidence(
                "huggingface",
                SourceTier.AUTHORITATIVE,
                f"{len(hf)} artefacts inspected; {safetensors} publish .safetensors weights; "
                f"{len(pickled)} additionally ship pickle-format weights; {gated} are gated.",
                url=hf[0].get("url"),
            )
        ]

        # Pickle deserialisation executes arbitrary code at load time. Section 7.4
        # declines models "requiring insecure execution practices"; the safe read
        # is that pickle weights are acceptable only if safetensors also exist.
        if pickled and safetensors == 0:
            return Finding(
                Criterion.DISTRIBUTION_INTEGRITY,
                Verdict.FAIL,
                "Only pickle-format weights (.bin/.pt/.ckpt) are published. Loading these "
                "executes arbitrary code, an insecure execution practice under Section 7.4.",
                evidence=evidence,
                conditions=[ConditionCode.C1, ConditionCode.C6],
                gaps=["Require a .safetensors distribution or an approved conversion process."],
            )

        conditions = [ConditionCode.C2] if gated else []
        verdict = Verdict.PASS if safetensors else Verdict.CONCERN
        note = (
            "safetensors weights available; commit SHAs recorded for integrity checking."
            if safetensors
            else "No safetensors weights observed; integrity relies on repository trust alone."
        )
        if gated:
            note += (
                f" {gated} artefact(s) are gated, so access requires accepting additional "
                f"terms (Section 7.3)."
            )
        if pickled:
            note += (
                f" {len(pickled)} artefact(s) also ship pickle weights; restrict loading to "
                f"safetensors."
            )
            conditions.append(ConditionCode.C6)

        return Finding(
            Criterion.DISTRIBUTION_INTEGRITY, verdict, note,
            evidence=evidence, conditions=conditions,
        )

    def _licensing(self, la: LicenseAssessment, notes: list[str] | None = None) -> Finding:
        notes = notes or []
        verdict = {
            LicenseClass.PERMISSIVE: Verdict.PASS,
            LicenseClass.COPYLEFT: Verdict.CONCERN,
            LicenseClass.COMMUNITY: Verdict.CONCERN,
            LicenseClass.RESEARCH_ONLY: Verdict.FAIL,
            LicenseClass.PROPRIETARY: Verdict.FAIL,
            LicenseClass.UNKNOWN: Verdict.UNKNOWN,
        }[la.klass]

        gaps = list(notes)
        if la.klass is LicenseClass.UNKNOWN:
            gaps.append("Licence not determinable; Section 6.3 Deferred until clarified.")
        if la.klass is LicenseClass.RESEARCH_ONLY:
            gaps.append("Non-commercial terms cap this family at Research & Experimentation.")

        # Divergent licences across releases mean the family-level answer cannot
        # be a clean pass, even when the assessed release is permissive.
        if notes and verdict is Verdict.PASS:
            verdict = Verdict.CONCERN

        summary = f"Licence {la.normalised!r} classified as {la.klass.value}. {la.rationale}"
        if notes:
            summary += " " + notes[0]

        return Finding(
            Criterion.LICENSING,
            verdict,
            summary,
            evidence=(
                [Evidence("huggingface", SourceTier.AUTHORITATIVE, f"license tag: {la.raw}")]
                if la.raw
                else []
            ),
            conditions=list(la.conditions),
            gaps=gaps,
        )

    def _security(
        self,
        artefacts: list[dict[str, Any]],
        entry: Entry | None,
        citable: list[Evidence],
    ) -> Finding:
        # Section 5/7.4: vulnerabilities land on the runtime, so security is
        # assessed against the runtimes this family is actually run on.
        runtimes = (entry.runtime_compatibility if entry else []) or []
        if runtimes:
            placeholders = ",".join("?" * len(runtimes))
            rows = self.store.query(
                f"""SELECT severity, COUNT(*) n FROM advisories
                    WHERE withdrawn_at IS NULL AND runtime_key IN ({placeholders})
                    GROUP BY severity""",
                tuple(runtimes),
            )
        else:
            rows = []

        counts = {(r["severity"] or "unknown"): r["n"] for r in rows}
        critical = counts.get("critical", 0)
        high = counts.get("high", 0)

        evidence = [
            Evidence(
                "osv",
                SourceTier.AUTHORITATIVE,
                f"Open advisories on approved runtimes ({', '.join(runtimes) or 'none recorded'}): "
                + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"),
                url="https://osv.dev",
            )
        ]
        evidence.extend(e for e in citable if e.source_id in ("owasp_genai", "ghsa"))

        pickled = any(a["payload"].get("has_pickle_weights") for a in artefacts)
        conditions: list[ConditionCode] = []
        gaps: list[str] = []

        if not runtimes:
            gaps.append(
                "No runtime_compatibility recorded, so runtime CVE exposure is unassessed. "
                "Section 10 governs runtimes independently."
            )
            return Finding(
                Criterion.SECURITY,
                Verdict.UNKNOWN,
                "Runtime exposure cannot be assessed until approved runtimes are recorded "
                "for this family (Sections 5 and 10).",
                evidence=evidence,
                conditions=[ConditionCode.C1],
                gaps=gaps,
            )

        if critical:
            verdict = Verdict.FAIL
            summary = (
                f"{critical} critical advisory/advisories affect the runtimes this family is "
                f"approved on. Section 11.4 requires an organisational risk assessment before "
                f"continued use."
            )
            conditions += [ConditionCode.C1, ConditionCode.C7]
        elif high:
            verdict = Verdict.CONCERN
            summary = (
                f"{high} high-severity advisory/advisories affect approved runtimes; patching "
                f"status must be confirmed (Sections 10.3, 11.4)."
            )
            conditions += [ConditionCode.C1]
        else:
            verdict = Verdict.PASS
            summary = "No open critical or high advisories on the approved runtimes."

        if pickled:
            conditions.append(ConditionCode.C6)
            summary += " Pickle-format weights present; restrict loading to safetensors."

        return Finding(
            Criterion.SECURITY, verdict, summary,
            evidence=evidence, conditions=sorted(set(conditions), key=lambda c: c.value),
            gaps=gaps,
        )

    def _operational(self, artefacts: list[dict[str, Any]]) -> Finding:
        pullable = [a for a in artefacts if a.get("source_id") == "ollama_library"]
        hf = [a for a in artefacts if a.get("source_id") == "huggingface"]

        freshest = None
        for a in hf:
            d = _days_since(a.get("modified_at"))
            if d is not None and (freshest is None or d < freshest):
                freshest = d

        evidence = []
        if pullable:
            evidence.append(
                Evidence(
                    "ollama_library",
                    SourceTier.AUTHORITATIVE,
                    f"Available for local execution via Ollama: "
                    f"{', '.join(a['artefact_id'] for a in pullable[:4])}",
                    url=pullable[0].get("url"),
                )
            )
        if freshest is not None:
            evidence.append(
                Evidence(
                    "huggingface",
                    SourceTier.AUTHORITATIVE,
                    f"Most recent publisher update {freshest} days ago.",
                )
            )

        params = [
            a["payload"].get("params_b")
            for a in artefacts
            if isinstance(a["payload"].get("params_b"), (int, float))
        ]
        gaps: list[str] = []
        conditions: list[ConditionCode] = []

        if freshest is None:
            gaps.append("No publisher update timestamps observed; maintenance activity unknown.")
            verdict = Verdict.UNKNOWN
            summary = "Operational sustainability cannot be judged without maintenance signals."
        elif freshest > _STALE_DAYS:
            verdict = Verdict.CONCERN
            summary = (
                f"No publisher update in {freshest} days. Section 7.5 asks whether maintenance "
                f"activity is acceptable, and 9.3 covers discontinued support."
            )
            conditions.append(ConditionCode.C8)
        else:
            verdict = Verdict.PASS
            summary = f"Actively maintained (last publisher update {freshest} days ago)."

        if pullable:
            summary += " Runs on Ollama, so deployment on a managed workstation is practical."
        else:
            gaps.append(
                "Not present in the Ollama library; confirm a supported runtime exists "
                "(Section 7.5 / 10.1)."
            )

        if params:
            biggest = max(params)
            summary += f" Largest observed variant ~{biggest:g}B parameters."
            if biggest >= 70:
                conditions.append(ConditionCode.C6)
                summary += (
                    " At this size local workstation execution is unlikely; restrict to "
                    "approved execution environments."
                )

        return Finding(
            Criterion.OPERATIONAL_SUITABILITY, verdict, summary,
            evidence=evidence, conditions=conditions, gaps=gaps,
        )

    # ------------------------------------------------------------- aggregation
    def _risk(self, findings: list[Finding]) -> RiskLevel:
        if any(f.verdict is Verdict.FAIL for f in findings):
            return RiskLevel.HIGH
        score = sum(_VERDICT_WEIGHT[f.verdict] for f in findings)
        unknowns = sum(1 for f in findings if f.verdict is Verdict.UNKNOWN)
        # Thin evidence is not low risk (Section 7: weigh the overall profile).
        if unknowns >= 3:
            return RiskLevel.UNKNOWN
        if score == 0:
            return RiskLevel.LOW
        if score <= 3:
            return RiskLevel.MEDIUM
        return RiskLevel.HIGH

    def _recommend(
        self, findings: list[Finding], risk: RiskLevel, la: LicenseAssessment
    ) -> ApprovalOutcome:
        """Map findings to a recommended Section 6.3 outcome.

        Never returns APPROVED unqualified when any condition applies, and never
        returns anything at all as a decision - see the module docstring.
        """
        if la.klass is LicenseClass.PROPRIETARY:
            return ApprovalOutcome.REJECTED
        if any(f.verdict is Verdict.FAIL for f in findings):
            # A failing criterion is not automatically a rejection: Section 7
            # says no single criterion decides. It is a Deferred pending review,
            # except where the licence forecloses use outright.
            if la.klass is LicenseClass.RESEARCH_ONLY:
                return ApprovalOutcome.APPROVED_WITH_CONDITIONS
            return ApprovalOutcome.DEFERRED
        if risk is RiskLevel.UNKNOWN or any(f.verdict is Verdict.UNKNOWN for f in findings):
            return ApprovalOutcome.DEFERRED
        if any(f.conditions for f in findings):
            return ApprovalOutcome.APPROVED_WITH_CONDITIONS
        return ApprovalOutcome.APPROVED

    def _eligible_uses(
        self, la: LicenseAssessment, findings: list[Finding]
    ) -> list[UsageCategory]:
        """The highest usage categories this family *could* be approved for.

        This is a ceiling derived from the evidence, not a grant. Section 8.5
        gating for production categories is applied at request time by
        `governance.usage`, because it depends on the specific workflow.
        """
        if la.klass is LicenseClass.PROPRIETARY:
            return []
        if la.klass is LicenseClass.RESEARCH_ONLY:
            return [UsageCategory.RESEARCH_EXPERIMENTATION]

        ceiling = UsageCategory.AUTONOMOUS_DECISION_SUPPORT
        if any(f.verdict is Verdict.FAIL for f in findings):
            ceiling = UsageCategory.RESEARCH_EXPERIMENTATION
        elif any(f.verdict is Verdict.UNKNOWN for f in findings):
            ceiling = UsageCategory.INTERNAL_PRODUCTIVITY
        elif any(f.verdict is Verdict.CONCERN for f in findings):
            ceiling = UsageCategory.INTERNAL_BUSINESS_APPLICATIONS

        limit = USAGE_RANK[ceiling]
        return [u for u, rank in USAGE_RANK.items() if rank <= limit]
