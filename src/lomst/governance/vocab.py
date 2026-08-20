"""Controlled vocabulary from *Governance of Local and Open-Source AI Models* v1.1.

Every term here is traceable to a section of the governance document. Section
references in docstrings are load-bearing: they are surfaced to the user in
explanations so a decision can always be tied back to the policy that produced
it.
"""

from __future__ import annotations

from enum import Enum


#: Display labels for the enum members whose snake_case value would otherwise
#: leak into user-facing text. Governance vocabulary is precise; "you cannot use
#: this for customer_facing_applications" is precise and unreadable.
_LABELS: dict[str, str] = {
    "research_experimentation": "research and experimentation",
    "internal_productivity": "internal productivity",
    "internal_business_applications": "internal business applications",
    "production_services": "production services",
    "customer_facing_applications": "customer-facing applications",
    "sensitive_information_processing": "handling sensitive information",
    "autonomous_decision_support": "acting or deciding on its own",
    "approved_with_conditions": "approved with conditions",
    "pending_evaluation": "pending evaluation",
    "limited_support": "limited support",
    "source_code": "source code",
    "model_family": "model family",
}


def humanise(value: object) -> str:
    """Render an enum member or raw value as readable text."""
    raw = getattr(value, "value", value)
    text = str(raw)
    return _LABELS.get(text, text.replace("_", " "))


def humanise_all(values: object) -> str:
    """Comma-joined readable list, or 'none' when empty."""
    items = [humanise(v) for v in (values or [])]
    return ", ".join(items) if items else "none"


class ApprovalOutcome(str, Enum):
    """Section 6.3 - Approval outcomes."""

    APPROVED = "approved"
    APPROVED_WITH_CONDITIONS = "approved_with_conditions"
    DEFERRED = "deferred"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    #: Appendix E.1 adds two states the 6.3 table does not carry.
    RESTRICTED = "restricted"
    PENDING_EVALUATION = "pending_evaluation"

    @property
    def usable(self) -> bool:
        """Whether the outcome permits any use at all."""
        return self in {
            ApprovalOutcome.APPROVED,
            ApprovalOutcome.APPROVED_WITH_CONDITIONS,
            ApprovalOutcome.RESTRICTED,
        }


class LifecycleStatus(str, Enum):
    """Appendix E.5 - Lifecycle status."""

    ACTIVE = "active"
    LIMITED_SUPPORT = "limited_support"
    DEPRECATED = "deprecated"
    RETIRED = "retired"

    @property
    def allows_new_development(self) -> bool:
        """Section 9.3: retired models are not used for new solutions absent an
        approved exception; deprecated models require a replacement plan."""
        return self in {LifecycleStatus.ACTIVE, LifecycleStatus.LIMITED_SUPPORT}


class UsageCategory(str, Enum):
    """Appendix E.2 - Usage categories, ordered by escalating governance weight."""

    RESEARCH_EXPERIMENTATION = "research_experimentation"
    INTERNAL_PRODUCTIVITY = "internal_productivity"
    INTERNAL_BUSINESS_APPLICATIONS = "internal_business_applications"
    PRODUCTION_SERVICES = "production_services"
    CUSTOMER_FACING_APPLICATIONS = "customer_facing_applications"
    SENSITIVE_INFORMATION_PROCESSING = "sensitive_information_processing"
    AUTONOMOUS_DECISION_SUPPORT = "autonomous_decision_support"


#: Escalation rank. Section 8.5 keys the fallback requirement off "Internal
#: Business Applications, Production Services, or higher (Appendix E)", so the
#: ordering is a governance rule, not a display preference.
USAGE_RANK: dict[UsageCategory, int] = {
    UsageCategory.RESEARCH_EXPERIMENTATION: 0,
    UsageCategory.INTERNAL_PRODUCTIVITY: 1,
    UsageCategory.INTERNAL_BUSINESS_APPLICATIONS: 2,
    UsageCategory.PRODUCTION_SERVICES: 3,
    UsageCategory.CUSTOMER_FACING_APPLICATIONS: 4,
    UsageCategory.SENSITIVE_INFORMATION_PROCESSING: 5,
    UsageCategory.AUTONOMOUS_DECISION_SUPPORT: 6,
}

#: Section 8.5 / Appendix E.2 note: the threshold at which a documented, tested
#: fallback becomes part of the production-readiness evidence.
FALLBACK_REQUIRED_RANK = USAGE_RANK[UsageCategory.INTERNAL_BUSINESS_APPLICATIONS]

#: Section 8.2 - Restricted uses. Presence of any of these means the broader AI
#: Governance Framework applies regardless of which model is chosen, so the
#: tracker must never answer "allowed" on model approval alone.
RESTRICTED_USE_CATEGORIES: frozenset[UsageCategory] = frozenset(
    {
        UsageCategory.PRODUCTION_SERVICES,
        UsageCategory.CUSTOMER_FACING_APPLICATIONS,
        UsageCategory.SENSITIVE_INFORMATION_PROCESSING,
        UsageCategory.AUTONOMOUS_DECISION_SUPPORT,
    }
)


class ConditionCode(str, Enum):
    """Appendix E.4 - Conditional approval codes."""

    C1 = "C1"
    C2 = "C2"
    C3 = "C3"
    C4 = "C4"
    C5 = "C5"
    C6 = "C6"
    C7 = "C7"
    C8 = "C8"
    C9 = "C9"


CONDITION_REQUIREMENTS: dict[ConditionCode, str] = {
    ConditionCode.C1: "Information Security review required",
    ConditionCode.C2: "Legal review required",
    ConditionCode.C3: "AI Governance approval required for deployment",
    ConditionCode.C4: "Enterprise Architecture review required",
    ConditionCode.C5: "Human review required before production use",
    ConditionCode.C6: "Restricted to approved execution environments",
    ConditionCode.C7: "Enhanced monitoring required",
    ConditionCode.C8: "Additional risk assessment required",
    ConditionCode.C9: "Documented, tested fallback required before production use (Section 8.5)",
}


class Criterion(str, Enum):
    """Section 7 - Model evaluation criteria."""

    PROVENANCE = "provenance"
    DISTRIBUTION_INTEGRITY = "distribution_integrity"
    LICENSING = "licensing"
    SECURITY = "security"
    OPERATIONAL_SUITABILITY = "operational_suitability"


CRITERION_SECTIONS: dict[Criterion, str] = {
    Criterion.PROVENANCE: "7.1",
    Criterion.DISTRIBUTION_INTEGRITY: "7.2",
    Criterion.LICENSING: "7.3",
    Criterion.SECURITY: "7.4",
    Criterion.OPERATIONAL_SUITABILITY: "7.5",
}


class RiskLevel(str, Enum):
    """Appendix A.5 - Overall risk."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    #: Used when evidence is too thin to place the model on the scale at all.
    #: Section 7 weighs an overall risk profile; absent evidence is not "low".
    UNKNOWN = "unknown"


class InformationClass(str, Enum):
    """Section 8.3 / 11.2 and Appendix D.3 - information types processed.

    The Information Classification Policy is the authoritative source and takes
    precedence over this document (Section 8.3); these are the buckets Appendix
    D.3 asks a requestor to declare.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PERSONAL = "personal"
    CUSTOMER = "customer"
    SOURCE_CODE = "source_code"


#: Section 8.3 / 11.2: these classes cannot be processed unless the family is
#: approved for Sensitive Information Processing (Appendix E.2).
SENSITIVE_INFORMATION_CLASSES: frozenset[InformationClass] = frozenset(
    {
        InformationClass.CONFIDENTIAL,
        InformationClass.PERSONAL,
        InformationClass.CUSTOMER,
    }
)


class SourceTier(str, Enum):
    """Trust tier for an ingest source.

    Not from the governance document - this is the tracker's own control, added
    because Section 7.1 requires provenance evidence to come from reputable,
    preferably official channels. An AI-generated news aggregator can legitimately
    raise a *lead* worth investigating but must not be the evidence a licensing
    or provenance conclusion rests on.
    """

    #: Publisher-of-record or official API: Hugging Face, OSV, GitHub, Ollama.
    AUTHORITATIVE = "authoritative"
    #: Recognised community/industry project with named maintainers: OWASP,
    #: curated awesome-lists, vendor security blogs.
    COMMUNITY = "community"
    #: News aggregation, partly or wholly machine-generated, or with no stated
    #: editorial verification. Leads only - never citable as evidence.
    AGGREGATOR = "aggregator"

    @property
    def citable_as_evidence(self) -> bool:
        return self is not SourceTier.AGGREGATOR


class ModelType(str, Enum):
    """Section 3 scope / Appendix A.1 - Model Type."""

    LLM = "llm"
    VISION = "vision"
    SPEECH = "speech"
    EMBEDDING = "embedding"
    MULTIMODAL = "multimodal"
    DIFFUSION = "diffusion"
    REASONING = "reasoning"
    OTHER = "other"


class ComponentKind(str, Enum):
    """Section 5 - Governance scope.

    Components are evaluated independently: approving a family does not approve a
    runtime, and vice versa.
    """

    MODEL_FAMILY = "model_family"
    RUNTIME = "runtime"
