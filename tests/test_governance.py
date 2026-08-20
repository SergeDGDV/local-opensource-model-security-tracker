"""Tests for the governance rules.

These assert policy behaviour, not implementation detail. If a test here fails,
either the framework changed or the tracker stopped implementing it faithfully -
both worth a hard failure.
"""

from __future__ import annotations

import datetime as dt

import pytest

from lomst.db import Store
from lomst.extract import attribute_hf_id, detect, is_major_change, version_label
from lomst.governance.licensing import LicenseClass, assess
from lomst.governance.registry import Entry, Fallback, Registry, RegistryError
from lomst.governance.usage import UsageGate, Verdict
from lomst.governance.vocab import (
    ApprovalOutcome,
    ComponentKind,
    ConditionCode,
    InformationClass,
    LifecycleStatus,
    UsageCategory,
)
from lomst.governance import review


# --------------------------------------------------------------------- fixtures


@pytest.fixture()
def registry(tmp_path):
    fam = tmp_path / "families"
    run = tmp_path / "runtimes"
    fam.mkdir()
    run.mkdir()
    return Registry(fam, run)


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


def approved_family(**over) -> Entry:
    defaults = dict(
        key="testfam",
        name="Test Family",
        kind=ComponentKind.MODEL_FAMILY,
        approval_status=ApprovalOutcome.APPROVED,
        lifecycle_status=LifecycleStatus.ACTIVE,
        approved_versions=["1.0"],
        approved_uses=[
            UsageCategory.RESEARCH_EXPERIMENTATION,
            UsageCategory.INTERNAL_PRODUCTIVITY,
        ],
        runtime_compatibility=["testrt"],
        license="apache-2.0",
        review_date=dt.date.today() + dt.timedelta(days=200),
    )
    defaults.update(over)
    return Entry(**defaults)


def approved_runtime(**over) -> Entry:
    defaults = dict(
        key="testrt",
        name="Test Runtime",
        kind=ComponentKind.RUNTIME,
        approval_status=ApprovalOutcome.APPROVED,
        lifecycle_status=LifecycleStatus.ACTIVE,
        review_date=dt.date.today() + dt.timedelta(days=200),
    )
    defaults.update(over)
    return Entry(**defaults)


# ------------------------------------------------------- Section 8 usage gating


def test_unregistered_family_is_blocked(registry):
    """Section 9: the registry is the authoritative record of what may be used."""
    d = UsageGate(registry).check("nope", UsageCategory.INTERNAL_PRODUCTIVITY)
    assert d.verdict is Verdict.BLOCKED
    assert any(r.section == "9" for r in d.blockers)


def test_approved_use_within_scope_is_permitted(registry):
    registry.save(approved_family())
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam", UsageCategory.INTERNAL_PRODUCTIVITY, runtime="testrt"
    )
    assert d.verdict in (Verdict.ALLOWED, Verdict.ALLOWED_WITH_CONDITIONS)
    assert not d.blockers


def test_usage_category_outside_approved_scope_is_blocked(registry):
    """Section 8.1 / Appendix E.2: approval is per usage category."""
    registry.save(approved_family())
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam", UsageCategory.CUSTOMER_FACING_APPLICATIONS, runtime="testrt"
    )
    assert d.verdict is Verdict.BLOCKED
    assert any("8.1" in r.section for r in d.blockers)


def test_model_approval_does_not_approve_a_runtime(registry):
    """Sections 5 and 10 - the central separation this tracker must not blur."""
    registry.save(approved_family(runtime_compatibility=["testrt", "unapproved_rt"]))
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam", UsageCategory.INTERNAL_PRODUCTIVITY, runtime="unapproved_rt"
    )
    assert d.verdict is Verdict.BLOCKED
    assert any(r.section.startswith("10") for r in d.blockers)


def test_confidential_information_requires_sensitive_approval(registry):
    """Sections 8.3 / 11.2 - local execution is not itself permission."""
    registry.save(approved_family())
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam",
        UsageCategory.INTERNAL_PRODUCTIVITY,
        runtime="testrt",
        information_classes=[InformationClass.CONFIDENTIAL],
    )
    assert d.verdict is Verdict.BLOCKED
    assert any("8.3" in r.section for r in d.blockers)


def test_public_information_does_not_trigger_sensitive_gate(registry):
    registry.save(approved_family())
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam",
        UsageCategory.INTERNAL_PRODUCTIVITY,
        runtime="testrt",
        information_classes=[InformationClass.PUBLIC, InformationClass.INTERNAL],
    )
    assert d.verdict is not Verdict.BLOCKED


@pytest.mark.parametrize(
    "category,needs_fallback",
    [
        (UsageCategory.RESEARCH_EXPERIMENTATION, False),
        (UsageCategory.INTERNAL_PRODUCTIVITY, False),
        (UsageCategory.INTERNAL_BUSINESS_APPLICATIONS, True),
        (UsageCategory.PRODUCTION_SERVICES, True),
    ],
)
def test_fallback_required_only_at_business_weight(registry, category, needs_fallback):
    """Section 8.5 is proportionate: a prototype needs no fallback plan."""
    registry.save(
        approved_family(
            approved_uses=list(UsageCategory),  # grant everything so 8.1 is not the blocker
        )
    )
    registry.save(approved_runtime())
    d = UsageGate(registry).check("testfam", category, runtime="testrt")
    triggered = any("8.5" in r.section for r in d.blockers)
    assert triggered is needs_fallback


def test_untested_fallback_blocks_production(registry):
    """Section 8.5: 'has the fallback actually been tested, or only assumed?'"""
    from lomst.governance.registry import DependentSolution

    entry = approved_family(
        approved_uses=[UsageCategory.INTERNAL_BUSINESS_APPLICATIONS],
        dependent_solutions=[
            DependentSolution(
                name="Widget pipeline",
                usage_category=UsageCategory.INTERNAL_BUSINESS_APPLICATIONS,
                fallback=Fallback(
                    kind="manual_process", description="do it by hand", tested=False
                ),
            )
        ],
    )
    registry.save(entry)
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam",
        UsageCategory.INTERNAL_BUSINESS_APPLICATIONS,
        runtime="testrt",
        solution_name="Widget pipeline",
    )
    assert d.verdict is Verdict.BLOCKED
    assert any("not tested" in r.detail for r in d.blockers)


def test_tested_fallback_permits_production(registry):
    from lomst.governance.registry import DependentSolution

    registry.save(
        approved_family(
            approved_uses=[UsageCategory.INTERNAL_BUSINESS_APPLICATIONS],
            dependent_solutions=[
                DependentSolution(
                    name="Widget pipeline",
                    usage_category=UsageCategory.INTERNAL_BUSINESS_APPLICATIONS,
                    fallback=Fallback(
                        kind="manual_process",
                        description="Documented manual triage runbook",
                        tested=True,
                        tested_date=dt.date.today(),
                    ),
                )
            ],
        )
    )
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam",
        UsageCategory.INTERNAL_BUSINESS_APPLICATIONS,
        runtime="testrt",
        solution_name="Widget pipeline",
    )
    assert d.verdict is Verdict.ALLOWED_WITH_CONDITIONS
    assert ConditionCode.C9 in d.conditions


def test_retired_family_blocks_new_use(registry):
    """Section 9.3 / Appendix E.5."""
    registry.save(approved_family(lifecycle_status=LifecycleStatus.RETIRED))
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam", UsageCategory.INTERNAL_PRODUCTIVITY, runtime="testrt"
    )
    assert d.verdict is Verdict.BLOCKED


def test_unapproved_version_is_flagged(registry):
    """Section 6.2: family approval is not release approval."""
    registry.save(approved_family())
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam", UsageCategory.INTERNAL_PRODUCTIVITY, runtime="testrt", version="2.0"
    )
    assert d.verdict is Verdict.BLOCKED
    assert any(r.section == "6.2" for r in d.blockers)


def test_expired_exception_blocks_use(registry):
    """Section 14.3."""
    from lomst.governance.registry import Exception_

    registry.save(
        approved_family(
            exception=Exception_(
                kind="temporary_research",
                owner="R&D",
                scope="benchmarking",
                expires=dt.date.today() - dt.timedelta(days=1),
            )
        )
    )
    registry.save(approved_runtime())
    d = UsageGate(registry).check(
        "testfam", UsageCategory.INTERNAL_PRODUCTIVITY, runtime="testrt"
    )
    assert d.verdict is Verdict.BLOCKED
    assert any("14" in r.section for r in d.blockers)


def test_exception_without_expiry_is_treated_as_expired(registry):
    """Section 14.1 requires an expiry date; a missing one must not mean forever."""
    from lomst.governance.registry import Exception_

    exc = Exception_(kind="temporary_research", owner="R&D", scope="x", expires=None)
    assert exc.expired is True


def test_restricted_use_never_returns_clean_allowed(registry):
    """Section 8.2: restricted uses always carry additional governance."""
    registry.save(approved_family(approved_uses=list(UsageCategory)))
    registry.save(approved_runtime())
    from lomst.governance.registry import DependentSolution

    entry = registry.get("testfam")
    entry.dependent_solutions = [
        DependentSolution(
            name="svc",
            usage_category=UsageCategory.PRODUCTION_SERVICES,
            fallback=Fallback(kind="manual_process", description="manual", tested=True),
        )
    ]
    registry.save(entry)
    d = UsageGate(registry).check(
        "testfam", UsageCategory.PRODUCTION_SERVICES, runtime="testrt", solution_name="svc"
    )
    assert d.verdict is not Verdict.ALLOWED  # never a bare "yes"
    assert ConditionCode.C3 in d.conditions


# ------------------------------------------------------------ Section 7.3 licences


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("apache-2.0", LicenseClass.PERMISSIVE),
        ("apache_2_0", LicenseClass.PERMISSIVE),
        ("mit", LicenseClass.PERMISSIVE),
        ("llama_4_community_license_agreement", LicenseClass.COMMUNITY),
        ("llama3.2", LicenseClass.COMMUNITY),
        ("gemma", LicenseClass.COMMUNITY),
        ("tongyi_qianwen", LicenseClass.COMMUNITY),
        ("mistral_research_license", LicenseClass.RESEARCH_ONLY),
        ("cc_by_nc", LicenseClass.RESEARCH_ONLY),
        ("proprietary", LicenseClass.PROPRIETARY),
        ("agpl-3.0", LicenseClass.COPYLEFT),
        (None, LicenseClass.UNKNOWN),
        ("other", LicenseClass.UNKNOWN),
    ],
)
def test_license_classification(raw, expected):
    assert assess(raw).klass is expected


def test_research_license_blocks_business_use():
    a = assess("mistral_research_license")
    assert a.commercial_use is False
    assert a.blocks_business_use is True


def test_community_license_requires_legal_review():
    """Section 7.3: acceptable use policies are a Legal question (C2)."""
    a = assess("llama_4_community_license_agreement")
    assert ConditionCode.C2 in a.conditions
    assert a.acceptable_use_policy is True


def test_unknown_license_is_not_treated_as_permissive():
    a = assess("other")
    assert a.commercial_use is None
    assert ConditionCode.C2 in a.conditions


# ----------------------------------------------------------------- extraction


def test_llama_cpp_is_a_runtime_not_the_llama_family():
    """The trap Section 5 warns about: a runtime CVE is not a model finding."""
    hits = detect("Heap overflow in llama.cpp GGUF parser")
    assert "llama_cpp" in hits.runtimes
    assert "llama" not in hits.families


def test_third_party_derivative_is_not_attributed_to_the_base_family():
    """Section 6.2: variants are independent artefacts."""
    family, method = attribute_hf_id("deepseek-ai/DeepSeek-R1-Distill-Llama-70B")
    assert family == "deepseek"
    assert method == "name"


def test_publisher_hint_does_not_override_an_explicit_name():
    assert attribute_hf_id("google/siglip-base-patch16")[0] != "gemma"
    assert attribute_hf_id("google/gemma-3-4b-it")[0] == "gemma"


def test_author_only_attribution_is_marked_weak():
    family, method = attribute_hf_id("mistralai/Some-Unknown-Thing")
    assert family == "mistral"
    assert method == "author"  # must not drive Section 6.2 triggers


@pytest.mark.parametrize(
    "name,expected",
    [
        ("Mistral-Small-3.2-24B-Instruct-2506", "3.2"),
        ("Llama-4-Scout-17B", "4"),
        ("Pixtral-12B-2409", None),        # 2409 is a date code, not a version
        ("Voxtral-Small-24B-2507", None),  # ditto
        ("Ministral-3-14B-Instruct-2512", "3"),
    ],
)
def test_version_label_ignores_date_codes(name, expected):
    assert version_label(name) == expected


def test_major_change_detection_is_conservative():
    assert is_major_change("3.1", "4.0") is True
    assert is_major_change("3.1", "3.2") is False
    assert is_major_change(None, "4.0") is None  # unknown, not False


# ------------------------------------------------------------ registry integrity


def test_registry_rejects_bad_key(registry):
    with pytest.raises(RegistryError):
        Entry.from_dict({"key": "Bad-Key", "name": "x"})


def test_registry_rejects_unknown_condition_code(registry):
    with pytest.raises(RegistryError):
        Entry.from_dict({"key": "k", "name": "x", "conditions": ["C99"]})


def test_condition_codes_are_case_insensitive():
    e = Entry.from_dict({"key": "k", "name": "x", "conditions": ["c2", "C9"]})
    assert e.conditions == [ConditionCode.C2, ConditionCode.C9]


def test_fallback_marked_tested_needs_a_description():
    with pytest.raises(RegistryError):
        Fallback(kind="manual_process", description="  ", tested=True)


def test_entry_round_trips_through_yaml(registry):
    from lomst.governance.registry import DependentSolution

    original = approved_family(
        dependent_solutions=[
            DependentSolution(
                name="Thing",
                usage_category=UsageCategory.PRODUCTION_SERVICES,
                owner="Team",
                fallback=Fallback(kind="alternate_model", description="use other", tested=True),
            )
        ],
        conditions=[ConditionCode.C2, ConditionCode.C9],
    )
    registry.save(original)
    reloaded = Registry(registry.families_dir, registry.runtimes_dir).get("testfam")
    assert reloaded is not None
    assert reloaded.conditions == original.conditions
    assert reloaded.dependent_solutions[0].fallback.tested is True
    assert reloaded.dependent_solutions[0].usage_category is UsageCategory.PRODUCTION_SERVICES


# --------------------------------------------------------------- decision write


def test_decision_requires_a_named_authority(registry):
    """Appendix A.5 / D.6: an unattributable approval is not auditable."""
    registry.save(approved_family())
    with pytest.raises(ValueError, match="authority"):
        review.record_decision(registry, "testfam", ApprovalOutcome.APPROVED, "   ")


def test_decision_appends_history_and_sets_review_date(registry):
    registry.save(approved_family(review_date=None))
    entry = review.record_decision(
        registry,
        "testfam",
        ApprovalOutcome.APPROVED_WITH_CONDITIONS,
        "AI Governance",
        rationale="because",
        conditions=[ConditionCode.C2],
    )
    assert entry.review_date is not None and entry.review_date > dt.date.today()
    assert entry.decision_history[-1].authority == "AI Governance"
    assert entry.decision_history[-1].rationale == "because"


def test_withdrawal_removes_approved_uses(registry):
    """Section 6.3: withdrawal removes the grant."""
    registry.save(approved_family())
    entry = review.record_decision(
        registry, "testfam", ApprovalOutcome.WITHDRAWN, "AI Governance"
    )
    assert entry.approved_uses == []
    assert not entry.usable


# ---------------------------------------------------------------- review engine


def test_overdue_review_is_immediate(registry):
    registry.save(approved_family(review_date=dt.date.today() - dt.timedelta(days=5)))
    actions = review.reviews_due(registry)
    assert any(a.kind == "review_overdue" and a.urgency is review.Urgency.IMMEDIATE
               for a in actions)


def test_missing_review_date_is_reported(registry):
    registry.save(approved_family(review_date=None))
    assert any(a.kind == "missing_review_date" for a in review.reviews_due(registry))


def test_production_approval_without_dependent_solutions_is_flagged(registry):
    """Appendix E.2 note: the Dependent Solutions entry precedes the approval."""
    registry.save(
        approved_family(approved_uses=[UsageCategory.PRODUCTION_SERVICES], dependent_solutions=[])
    )
    assert any(a.kind == "dependent_solutions_empty" for a in review.dependency_gaps(registry))


# ------------------------------------------------- Section 6.2 version handling


@pytest.mark.parametrize(
    "a,b,same",
    [
        ("4", "4.0", True),
        ("4.0", "4.0.0", True),
        ("4.0", "4.1", False),
        ("3", "4", False),
        ("weird", "weird", True),
    ],
)
def test_versions_equivalent(a, b, same):
    from lomst.extract import versions_equivalent

    assert versions_equivalent(a, b) is same


@pytest.mark.parametrize(
    "approved,observed,expected",
    [
        ("4.0", "5.0", "major"),
        ("4.0", "4.1", "minor"),
        ("4.0", "3.2", "older"),
        ("4.0", "4", "same"),
        ("4.0", None, "unknown"),
    ],
)
def test_compare_release(approved, observed, expected):
    from lomst.extract import compare_release

    assert compare_release(approved, observed) == expected


def test_equivalent_version_is_not_flagged_as_unapproved(registry, store):
    """Regression: Llama-4-* must not be flagged when 4.0 is approved."""
    registry.save(approved_family(key="llama", name="Llama", approved_versions=["4.0"]))
    run = store.start_run(["hf"])
    store.upsert_artefact(
        run,
        {
            "source_id": "huggingface", "artefact_id": "meta-llama/Llama-4-Scout",
            "family_key": "llama", "publisher": "meta-llama", "license": "apache-2.0",
            "model_type": "llm", "gated": False, "downloads": 1, "version_label": "4",
            "url": "u", "modified_at": "2026-01-01T00:00:00+00:00",
            "payload": {"attribution_method": "name"},
        },
    )
    actions = review.version_drift(store, registry)
    assert not [a for a in actions if a.kind == "unapproved_version"]


def test_older_release_is_informational_not_a_minor_release(registry, store):
    registry.save(approved_family(key="llama", name="Llama", approved_versions=["4.0"]))
    run = store.start_run(["hf"])
    store.upsert_artefact(
        run,
        {
            "source_id": "huggingface", "artefact_id": "meta-llama/Meta-Llama-3-8B",
            "family_key": "llama", "publisher": "meta-llama", "license": "apache-2.0",
            "model_type": "llm", "gated": False, "downloads": 1, "version_label": "3",
            "url": "u", "modified_at": "2026-01-01T00:00:00+00:00",
            "payload": {"attribution_method": "name"},
        },
    )
    actions = review.version_drift(store, registry)
    superseded = [a for a in actions if a.kind == "superseded_version"]
    assert superseded and superseded[0].urgency is review.Urgency.INFORMATIONAL


def test_author_attributed_artefact_does_not_trigger_version_drift(registry, store):
    """An author-only attribution must not fire a Section 6.2 trigger."""
    registry.save(approved_family(key="mistral", name="Mistral", approved_versions=["0.3"]))
    run = store.start_run(["hf"])
    store.upsert_artefact(
        run,
        {
            "source_id": "huggingface", "artefact_id": "mistralai/Unrelated-Thing-9",
            "family_key": "mistral", "publisher": "mistralai", "license": "apache-2.0",
            "model_type": "llm", "gated": False, "downloads": 1, "version_label": "9",
            "url": "u", "modified_at": "2026-01-01T00:00:00+00:00",
            "payload": {"attribution_method": "author"},
        },
    )
    assert not review.version_drift(store, registry)
