"""Tests for the plain-language guide and the questionnaires.

The completeness tests are the point of this file: adding a member to any
governed enum must fail here until somebody explains it, otherwise the UI
silently starts showing a raw snake_case value again.
"""

from __future__ import annotations

import pytest

from lomst.governance import guide, surveys
from lomst.governance.vocab import (
    ApprovalOutcome,
    ComponentKind,
    ConditionCode,
    Criterion,
    InformationClass,
    LifecycleStatus,
    RiskLevel,
    SourceTier,
    UsageCategory,
    humanise,
    humanise_all,
)


# ------------------------------------------------------------- completeness


@pytest.mark.parametrize(
    "enum_cls,mapping,name",
    [
        (ApprovalOutcome, guide.APPROVAL_OUTCOMES, "APPROVAL_OUTCOMES"),
        (UsageCategory, guide.USAGE_CATEGORIES, "USAGE_CATEGORIES"),
        (InformationClass, guide.INFORMATION_CLASSES, "INFORMATION_CLASSES"),
        (LifecycleStatus, guide.LIFECYCLE_STATUSES, "LIFECYCLE_STATUSES"),
        (Criterion, guide.CRITERIA, "CRITERIA"),
        (RiskLevel, guide.RISK_LEVELS, "RISK_LEVELS"),
        (SourceTier, guide.SOURCE_TIERS, "SOURCE_TIERS"),
        (ComponentKind, guide.COMPONENT_KINDS, "COMPONENT_KINDS"),
        (ConditionCode, guide.CONDITION_PLAIN, "CONDITION_PLAIN"),
    ],
)
def test_every_enum_member_is_explained(enum_cls, mapping, name):
    missing = [m.value for m in enum_cls if m not in mapping]
    assert not missing, f"{name} does not explain: {missing}"


def test_explanations_avoid_the_jargon_they_describe():
    """A plain-language sentence must not just restate the snake_case value."""
    for term in list(guide.USAGE_CATEGORIES.values()) + list(
        guide.APPROVAL_OUTCOMES.values()
    ):
        assert "_" not in term.plain, term.plain
        assert term.plain.endswith((".", "?")), term.plain
        # A real sentence rather than the label echoed back. Brevity is fine -
        # "Assessed and not allowed." is a better explanation than a paragraph -
        # so this only catches a stub, not a short sentence.
        assert len(term.plain.split()) >= 4, term.plain
        assert term.plain.lower() != term.label.lower(), term.plain


def test_guide_builds_and_carries_computed_flags():
    g = guide.build()
    assert g["intro"]["paragraphs"]
    by_value = {u["key"]: u for u in g["usage_categories"]}
    # Section 8.5's threshold has to be visible, not just described in prose.
    assert by_value["internal_productivity"]["needs_tested_fallback"] is False
    assert by_value["internal_business_applications"]["needs_tested_fallback"] is True
    assert by_value["production_services"]["needs_extra_governance"] is True
    # Ordered lightest to heaviest.
    ranks = [u["rank"] for u in g["usage_categories"]]
    assert ranks == sorted(ranks)


def test_guide_marks_which_statuses_permit_use():
    g = guide.build()
    by = {o["key"]: o for o in g["approval_outcomes"]}
    assert by["approved"]["permits_use"] is True
    assert by["pending_evaluation"]["permits_use"] is False
    assert by["withdrawn"]["permits_use"] is False


def test_conditions_have_both_plain_and_formal_wording():
    g = guide.build()
    assert len(g["conditions"]) == 9
    for c in g["conditions"]:
        assert c["label"] and c["plain"] and c["formal"]
        assert c["label"] != c["formal"], c["code"]


# --------------------------------------------------------------- humanising


@pytest.mark.parametrize(
    "value,expected",
    [
        (UsageCategory.CUSTOMER_FACING_APPLICATIONS, "customer-facing applications"),
        (UsageCategory.INTERNAL_PRODUCTIVITY, "internal productivity"),
        (ApprovalOutcome.APPROVED_WITH_CONDITIONS, "approved with conditions"),
        (LifecycleStatus.LIMITED_SUPPORT, "limited support"),
        (InformationClass.SOURCE_CODE, "source code"),
        ("some_unmapped_value", "some unmapped value"),
    ],
)
def test_humanise(value, expected):
    assert humanise(value) == expected


def test_humanise_all_handles_empty():
    assert humanise_all([]) == "none"
    assert humanise_all(None) == "none"
    assert humanise_all([UsageCategory.INTERNAL_PRODUCTIVITY]) == "internal productivity"


def test_no_snake_case_leaks_into_gate_messages(tmp_path):
    """Regression: verdict text used to read 'customer_facing_applications'."""
    import datetime as dt

    from lomst.governance.registry import Entry, Registry
    from lomst.governance.usage import UsageGate
    from lomst.governance.vocab import ComponentKind as CK

    fam, run = tmp_path / "f", tmp_path / "r"
    fam.mkdir(); run.mkdir()
    reg = Registry(fam, run)
    reg.save(
        Entry(
            key="testfam", name="Test", kind=CK.MODEL_FAMILY,
            approval_status=ApprovalOutcome.APPROVED,
            approved_uses=[UsageCategory.INTERNAL_PRODUCTIVITY],
            review_date=dt.date.today() + dt.timedelta(days=90),
        )
    )
    d = UsageGate(reg).check("testfam", UsageCategory.CUSTOMER_FACING_APPLICATIONS)
    blob = " ".join(r.detail for r in d.reasons) + " ".join(d.required_actions)
    for leak in ("customer_facing_applications", "internal_productivity",
                 "approved_with_conditions", "pending_evaluation"):
        assert leak not in blob, f"{leak} leaked into user-facing text: {blob}"


# ------------------------------------------------------------------ surveys


def test_catalogue_lists_every_survey():
    cat = surveys.catalogue()
    ids = [s["id"] for s in cat]
    assert ids[0] == "permission", "the permission check is what most people need"
    assert set(ids) == set(surveys.SURVEYS)
    for s in cat:
        assert s["title"] and s["purpose"] and s["outcome"]
        assert s["steps"], s["id"]
        for step in s["steps"]:
            assert step["questions"], f"{s['id']}/{step['id']} has no questions"


def test_only_the_permission_survey_decides_permission():
    deciding = [s["id"] for s in surveys.catalogue() if s["decides_permission"]]
    assert deciding == ["permission"]


def test_every_choice_question_offers_options():
    for s in surveys.catalogue():
        for step in s["steps"]:
            for q in step["questions"]:
                if q["type"] in ("single", "multi"):
                    assert q["options"], f"{s['id']}/{q['id']}"
                if q["type"] == "yesno":
                    assert q["good_answer"] in ("yes", "no"), f"{s['id']}/{q['id']}"


def test_score_reports_unanswered_required_questions():
    sv = surveys.get("model_evaluation")
    res = surveys.score(sv, {})
    assert res["complete"] is False
    assert res["recommendation"] == "incomplete"
    assert res["unanswered"]


def test_score_flags_pickle_only_as_blocking():
    """Section 7.4: only-pickle weights is a blocker, not a note."""
    sv = surveys.get("model_evaluation")
    answers = {q.id: (q.good_answer or "x")
               for st in sv.steps for q in st.questions if q.required}
    answers.update({
        "model_family": "Foo", "developer": "Acme", "distribution_source": "https://x",
        "intended_use": "t", "business_owner": "me", "license_name": "MIT",
        "intended_categories": ["internal_productivity"],
        "safetensors_available": "no",
    })
    res = surveys.score(sv, answers)
    assert res["recommendation"] == "deferred"
    assert "safetensors" in res["headline"]


def test_score_returns_clean_when_nothing_is_wrong():
    sv = surveys.get("model_evaluation")
    answers = {q.id: (q.good_answer or "x")
               for st in sv.steps for q in st.questions if q.required}
    answers.update({
        "model_family": "Foo", "developer": "Acme", "distribution_source": "https://x",
        "intended_use": "t", "business_owner": "me", "license_name": "Apache-2.0",
        "intended_categories": ["internal_productivity"],
    })
    res = surveys.score(sv, answers)
    assert res["complete"] is True
    assert res["recommendation"] == "approved"
    assert not res["gaps"]


def test_production_use_pulls_in_the_fallback_condition():
    sv = surveys.get("model_evaluation")
    answers = {q.id: (q.good_answer or "x")
               for st in sv.steps for q in st.questions if q.required}
    answers.update({
        "model_family": "Foo", "developer": "Acme", "distribution_source": "https://x",
        "intended_use": "t", "business_owner": "me", "license_name": "Apache-2.0",
        "intended_categories": ["production_services"],
    })
    res = surveys.score(sv, answers)
    codes = {c["code"] for c in res["conditions"]}
    assert "C9" in codes, "production use must require a tested fallback"


def test_scoring_never_claims_to_approve():
    sv = surveys.get("model_evaluation")
    res = surveys.score(sv, {})
    assert "not an approval" in res["disclaimer"]
