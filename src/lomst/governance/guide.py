"""Plain-language explanations of every governed term.

The dashboard previously assumed the reader had the governance document open.
"C9", "approved_with_conditions" and "Section 8.5" are precise and completely
opaque to anyone who has not read it, which is most people who will use this.

Everything here is keyed to the enums in `vocab.py` rather than written as free
prose, so an explanation cannot silently drift from the rule it describes: add a
member to `UsageCategory` and the completeness test in this module's test file
fails until it is explained.

Wording rules followed throughout:

* Lead with what it means for the reader, not what the document calls it.
* Say what is *permitted* or *required*, not what is "in scope".
* Keep the section reference, but as a citation rather than the explanation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .vocab import (
    CONDITION_REQUIREMENTS,
    RESTRICTED_USE_CATEGORIES,
    SENSITIVE_INFORMATION_CLASSES,
    USAGE_RANK,
    ApprovalOutcome,
    ComponentKind,
    ConditionCode,
    Criterion,
    InformationClass,
    LifecycleStatus,
    RiskLevel,
    SourceTier,
    UsageCategory,
)


@dataclass(slots=True)
class Term:
    """One explained term."""

    key: str
    label: str
    #: One sentence a non-specialist can act on.
    plain: str
    #: What follows from it in practice.
    means: str = ""
    #: Governance document citation.
    section: str = ""
    #: Concrete illustration.
    example: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v}


# ------------------------------------------------------------ approval outcomes

APPROVAL_OUTCOMES: dict[ApprovalOutcome, Term] = {
    ApprovalOutcome.APPROVED: Term(
        "approved", "Approved",
        "You can use it for the purposes listed, without extra permission.",
        means="Still only for the listed purposes. Anything beyond them needs a new decision.",
        section="6.3",
    ),
    ApprovalOutcome.APPROVED_WITH_CONDITIONS: Term(
        "approved_with_conditions", "Approved with conditions",
        "You can use it, but specific requirements must be met first.",
        means="The conditions are mandatory, not advice. Each one names who has to sign off "
              "or what has to be in place.",
        section="6.3",
        example="Approved for internal productivity, but Legal must review the licence first.",
    ),
    ApprovalOutcome.RESTRICTED: Term(
        "restricted", "Restricted",
        "Only certain teams, environments or use cases are allowed.",
        means="If your team or your machine is not on the list, this is a no for you even "
              "though it says approved for someone else.",
        section="E.1",
    ),
    ApprovalOutcome.DEFERRED: Term(
        "deferred", "Deferred",
        "Not decided yet because information is missing.",
        means="This is not a soft yes. No use is permitted until the gap is filled - usually "
              "an unclear licence, an unverified publisher, or untested security behaviour.",
        section="6.3",
    ),
    ApprovalOutcome.PENDING_EVALUATION: Term(
        "pending_evaluation", "Pending evaluation",
        "Someone has asked about it; nobody has assessed it yet.",
        means="No use is permitted. This is the state a newly drafted entry starts in.",
        section="E.1",
    ),
    ApprovalOutcome.REJECTED: Term(
        "rejected", "Rejected",
        "Assessed and not allowed.",
        means="Can be reconsidered if something changes - a relicensing, a fixed "
              "vulnerability, a new distribution channel. The reason is recorded.",
        section="6.3",
    ),
    ApprovalOutcome.WITHDRAWN: Term(
        "withdrawn", "Withdrawn",
        "It was allowed before, and now it is not.",
        means="Existing deployments must follow a migration or retirement plan. This is "
              "exactly the event a fallback plan exists for.",
        section="6.3",
    ),
}

# ------------------------------------------------------------- usage categories

USAGE_CATEGORIES: dict[UsageCategory, Term] = {
    UsageCategory.RESEARCH_EXPERIMENTATION: Term(
        "research_experimentation", "Research and experimentation",
        "You are learning, benchmarking or building a throwaway proof of concept.",
        means="The lightest level of oversight. No fallback plan needed.",
        section="E.2",
        example="Downloading a model to see whether it summarises patch notes well.",
    ),
    UsageCategory.INTERNAL_PRODUCTIVITY: Term(
        "internal_productivity", "Internal productivity",
        "It helps you do your own work: coding help, summarising, translating, drafting.",
        means="Output is reviewed by a person before it goes anywhere. Still no fallback "
              "plan needed.",
        section="E.2",
        example="A coding assistant on your workstation.",
    ),
    UsageCategory.INTERNAL_BUSINESS_APPLICATIONS: Term(
        "internal_business_applications", "Internal business applications",
        "Colleagues depend on it as part of a process, not just you.",
        means="This is the threshold where a tested fallback becomes mandatory. If the model "
              "went away, someone's job would stop working.",
        section="E.2, 8.5",
        example="A tool that enriches localisation glossaries for the whole team.",
    ),
    UsageCategory.PRODUCTION_SERVICES: Term(
        "production_services", "Production services",
        "A business-critical system depends on it.",
        means="Extra security, legal and architectural review on top of model approval. "
              "Tested fallback required.",
        section="E.2, 8.2",
    ),
    UsageCategory.CUSTOMER_FACING_APPLICATIONS: Term(
        "customer_facing_applications", "Customer-facing applications",
        "Players or customers interact with the output.",
        means="Highest scrutiny. Reputational and contractual exposure, so approval for "
              "internal use never carries over to this.",
        section="E.2, 8.2",
    ),
    UsageCategory.SENSITIVE_INFORMATION_PROCESSING: Term(
        "sensitive_information_processing", "Handling sensitive information",
        "It will process confidential, personal, customer or regulated information.",
        means="Needs its own approval. Running a model on your own laptop does not by itself "
              "make it acceptable to feed it confidential data.",
        section="E.2, 8.3, 11.2",
    ),
    UsageCategory.AUTONOMOUS_DECISION_SUPPORT: Term(
        "autonomous_decision_support", "Acting or deciding on its own",
        "It can influence or trigger business decisions without a person approving each one.",
        means="The most heavily governed category. Human review before production use and "
              "enhanced monitoring are expected.",
        section="E.2, 8.2",
    ),
}

# --------------------------------------------------------------- condition codes

#: Plain-language gloss for each code. The formal requirement text stays in
#: `vocab.CONDITION_REQUIREMENTS`; this says who does what and why.
CONDITION_PLAIN: dict[ConditionCode, tuple[str, str]] = {
    ConditionCode.C1: (
        "Information Security has to review it",
        "Someone from InfoSec checks the security implications before you proceed.",
    ),
    ConditionCode.C2: (
        "Legal has to review the licence",
        "The licence has terms that need a lawyer's read - typically an acceptable use "
        "policy, or restrictions on commercial use.",
    ),
    ConditionCode.C3: (
        "AI Governance has to approve the deployment",
        "Approval of the model is not approval of your specific deployment of it.",
    ),
    ConditionCode.C4: (
        "Enterprise Architecture has to review it",
        "How it fits the wider system landscape needs checking.",
    ),
    ConditionCode.C5: (
        "A person must review the output before production use",
        "No unreviewed model output reaching production.",
    ),
    ConditionCode.C6: (
        "Only in approved environments",
        "Not on any machine you like - a managed workstation, a specific server, or a "
        "container, as specified.",
    ),
    ConditionCode.C7: (
        "Extra monitoring required",
        "Usage has to be logged and watched more closely than normal.",
    ),
    ConditionCode.C8: (
        "A further risk assessment is needed",
        "Something about the case does not fit the standard evaluation.",
    ),
    ConditionCode.C9: (
        "A tested fallback must exist before production use",
        "You must be able to say what happens if this model disappears - and have actually "
        "tried it, not just written it down.",
    ),
}

# ---------------------------------------------------------- information classes

INFORMATION_CLASSES: dict[InformationClass, Term] = {
    InformationClass.PUBLIC: Term(
        "public", "Public information",
        "Already published, or fine to publish.",
        section="D.3",
        example="Marketing copy that is already live, public documentation.",
    ),
    InformationClass.INTERNAL: Term(
        "internal", "Internal information",
        "Ordinary company material, not secret but not public.",
        section="D.3",
        example="Meeting notes, internal wiki pages, sprint plans.",
    ),
    InformationClass.CONFIDENTIAL: Term(
        "confidential", "Confidential information",
        "Damaging if it leaked. Needs explicit approval to process.",
        means="Requires approval for handling sensitive information, whatever the model.",
        section="D.3, 8.3",
        example="Unreleased titles, financials, contracts, security findings.",
    ),
    InformationClass.PERSONAL: Term(
        "personal", "Personal data",
        "Information about identifiable people. Data protection law applies.",
        means="Requires approval for handling sensitive information, and the Information "
              "Classification Policy overrides anything this tool says.",
        section="D.3, 11.2",
        example="Employee records, player accounts, support tickets with names.",
    ),
    InformationClass.CUSTOMER: Term(
        "customer", "Customer or player information",
        "Data belonging to the people who buy from or play our games.",
        means="Requires approval for handling sensitive information. Contractual duties "
              "usually apply too.",
        section="D.3",
    ),
    InformationClass.SOURCE_CODE: Term(
        "source_code", "Source code",
        "Our code, in any form, including snippets pasted into a prompt.",
        means="Connecting a model to a repository counts as an enterprise integration and "
              "needs its own governance.",
        section="D.3, 8.4",
    ),
}

# -------------------------------------------------------------------- lifecycle

LIFECYCLE_STATUSES: dict[LifecycleStatus, Term] = {
    LifecycleStatus.ACTIVE: Term(
        "active", "Active",
        "Fine to use for new work.",
        section="E.5",
    ),
    LifecycleStatus.LIMITED_SUPPORT: Term(
        "limited_support", "Limited support",
        "Existing uses can continue, but start new work on something newer.",
        section="E.5",
    ),
    LifecycleStatus.DEPRECATED: Term(
        "deprecated", "Deprecated",
        "On its way out. Plan a replacement now.",
        section="E.5",
    ),
    LifecycleStatus.RETIRED: Term(
        "retired", "Retired",
        "No longer allowed for new solutions.",
        means="Using it anyway needs a documented exception.",
        section="E.5, 9.3",
    ),
}

# --------------------------------------------------------- evaluation criteria

CRITERIA: dict[Criterion, Term] = {
    Criterion.PROVENANCE: Term(
        "provenance", "Where it came from",
        "Is this genuinely from the organisation that claims to have made it?",
        means="A model published by the real Meta account is not the same artefact as a "
              "copy uploaded by a stranger, even if the files look identical.",
        section="7.1",
    ),
    Criterion.DISTRIBUTION_INTEGRITY: Term(
        "distribution_integrity", "Whether the download can be trusted",
        "Can we verify the files have not been tampered with, and are they in a safe format?",
        means="Weight files in the older pickle format run arbitrary code the moment you "
              "load them. The safetensors format does not, which is why it is preferred.",
        section="7.2",
    ),
    Criterion.LICENSING: Term(
        "licensing", "What the licence lets us do",
        "Can we use it commercially, fine-tune it, and redistribute it?",
        means="Open weights do not mean unrestricted. Several popular models forbid "
              "commercial use or attach an acceptable use policy.",
        section="7.3",
    ),
    Criterion.SECURITY: Term(
        "security", "Known security problems",
        "Are there unpatched vulnerabilities in the software needed to run it?",
        means="Vulnerabilities almost always sit in the runtime rather than the model file, "
              "so this is assessed against the software you would run it on.",
        section="7.4",
    ),
    Criterion.OPERATIONAL_SUITABILITY: Term(
        "operational_suitability", "Whether we can actually run and keep running it",
        "Does the hardware exist, and is the model still being maintained?",
        means="A model nobody has updated in a year is a support problem waiting to happen.",
        section="7.5",
    ),
}

# ------------------------------------------------------------------ risk levels

RISK_LEVELS: dict[RiskLevel, Term] = {
    RiskLevel.LOW: Term("low", "Low risk", "Nothing of concern found across the five checks."),
    RiskLevel.MEDIUM: Term(
        "medium", "Medium risk", "Some concerns, none of them blocking on their own."
    ),
    RiskLevel.HIGH: Term(
        "high", "High risk", "At least one check failed outright, or several raised concerns."
    ),
    RiskLevel.UNKNOWN: Term(
        "unknown", "Not enough information",
        "Too little evidence to judge.",
        means="Deliberately not treated as low risk. Missing information is a reason to "
              "wait, not to proceed.",
    ),
}

# ---------------------------------------------------------------- source tiers

SOURCE_TIERS: dict[SourceTier, Term] = {
    SourceTier.AUTHORITATIVE: Term(
        "authoritative", "Authoritative",
        "Straight from the publisher or an official database.",
        means="Can be cited as evidence for a decision.",
        section="7.1",
        example="The Hugging Face API, the CISA vulnerability catalogue.",
    ),
    SourceTier.COMMUNITY: Term(
        "community", "Community",
        "A recognised project or industry group with named maintainers.",
        means="Can be cited as evidence.",
        section="7.1",
        example="The OWASP GenAI Security Project.",
    ),
    SourceTier.AGGREGATOR: Term(
        "aggregator", "Leads only",
        "News aggregation, sometimes machine-generated, with no stated fact-checking.",
        means="Useful for spotting something worth investigating. Never used as the evidence "
              "a decision rests on.",
        section="7.1",
    ),
}

# ------------------------------------------------------------- component kinds

COMPONENT_KINDS: dict[ComponentKind, Term] = {
    ComponentKind.MODEL_FAMILY: Term(
        "model_family", "Model family",
        "A set of related models released by one organisation - Llama, Qwen, Gemma.",
        means="Decisions are made per family, not per file, otherwise nothing would keep up. "
              "But approving a family does not approve every future version of it.",
        section="6.1, 6.2",
    ),
    ComponentKind.RUNTIME: Term(
        "runtime", "Runtime",
        "The software that loads and runs a model - Ollama, vLLM, LM Studio.",
        means="Approved separately from models, because this is where the security "
              "vulnerabilities actually are. An approved model on an unapproved runtime is "
              "not approved.",
        section="5, 10",
    ),
}

# ----------------------------------------------------------------- who decides

@dataclass(slots=True)
class Role:
    name: str
    does: str
    section: str = "12"


ROLES: list[Role] = [
    Role("AI Governance",
         "Owns the approval process and the registry. Decides whether a model may be used "
         "at all - but does not own your solution."),
    Role("Information Security",
         "Judges the security side: supply chain, vulnerabilities, what controls are needed. "
         "Can ask for a model to be restricted or withdrawn."),
    Role("Legal",
         "Reads the licence and the obligations that come with it. Not every model needs a "
         "fresh legal review; it depends on what actually changed."),
    Role("IT and Platform teams",
         "Run the approved environments and deploy the runtimes. They do not decide which "
         "models are allowed."),
    Role("Solution owners",
         "Accountable for their own solution staying inside its approved scope - including "
         "keeping the fallback plan current. Model approval does not transfer this."),
    Role("Everyone else",
         "Use approved models and runtimes, ask before introducing something new, and report "
         "anything that looks wrong."),
]

# -------------------------------------------------------------------- glossary

GLOSSARY: list[Term] = [
    Term("open_weights", "Open weights",
         "The model files can be downloaded and run on your own hardware.",
         means="Not the same as open source, and not the same as unrestricted - the licence "
               "still decides what you may do with it."),
    Term("hosted_only", "Hosted only",
         "You can only reach it through somebody else's API; there are no files to download.",
         means="Outside the scope of this framework, which covers models run locally.",
         section="3"),
    Term("safetensors", "safetensors",
         "A weight file format that only holds numbers.",
         means="Preferred, because loading it cannot execute code."),
    Term("pickle_weights", "Pickle weights (.bin, .pt, .ckpt)",
         "An older weight format that can run arbitrary code when loaded.",
         means="A model published only in this format is treated as failing the "
               "download-integrity check.",
         section="7.4"),
    Term("gguf", "GGUF",
         "A compact single-file format used by desktop tools like Ollama and llama.cpp.",
         means="Usually produced by a third party rather than the original publisher, which "
               "makes it a separate artefact for governance purposes.",
         section="6.2"),
    Term("gated", "Gated",
         "The publisher makes you accept terms or request access before downloading.",
         means="Somebody has to agree to those terms on the company's behalf, which is a "
               "legal question, not a technical one.",
         section="7.3"),
    Term("quantised", "Quantised variant",
         "A shrunk version of a model, made to run on smaller hardware.",
         means="Almost always repackaged by someone other than the original publisher, so it "
               "is not covered by the original's approval.",
         section="6.2"),
    Term("fallback", "Fallback",
         "What you would do if this model became unavailable tomorrow.",
         means="Must be one of three things: another approved model, another provider, or a "
               "defined manual process. \"We would work something out\" does not count.",
         section="8.5"),
    Term("dependent_solution", "Dependent solution",
         "A workflow that relies on a particular model.",
         means="Recorded against the model so that if it is ever withdrawn, everyone can see "
               "immediately what breaks.",
         section="8.5, 9"),
    Term("exception", "Temporary exception",
         "Time-limited permission to use something that has not been through full approval.",
         means="Must have an owner, a scope and an expiry date. When it expires, use stops.",
         section="14"),
    Term("registry", "The registry",
         "The list of everything that has been decided, and on what terms.",
         means="If it is not in there, no decision has been made - which means no permission.",
         section="9"),
    Term("advisory", "Security advisory",
         "A published report of a vulnerability in a piece of software.",
         means="Rated by severity. \"Actively exploited\" means attackers are using it right "
               "now, which outranks any severity score.",
         section="11.4"),
]

# ------------------------------------------------------------------ assembly


def build() -> dict[str, Any]:
    """The whole reference, ready to render."""
    return {
        "intro": {
            "title": "How model governance works here",
            "paragraphs": [
                "Running an AI model on your own machine is not automatically safer than "
                "using a cloud service. It moves the responsibility to us: where the model "
                "came from, what its licence allows, what software is needed to run it, and "
                "what happens when it is withdrawn.",
                "Three things are approved separately, and this trips people up most often. "
                "The model is one decision. The runtime that executes it is another. What "
                "you build with them is a third. An approved model on an unapproved runtime "
                "is not approved.",
                "Approval is never permanent. Licences change, vulnerabilities are found, "
                "publishers stop maintaining things. Everything here has a review date.",
            ],
            "key_rule": (
                "Approval of a model never authorises a particular use of it. Use the "
                "permission questionnaire for that."
            ),
        },
        "component_kinds": [t.to_dict() for t in COMPONENT_KINDS.values()],
        "approval_outcomes": [
            {**APPROVAL_OUTCOMES[o].to_dict(), "permits_use": o.usable}
            for o in ApprovalOutcome
        ],
        "usage_categories": [
            {
                **USAGE_CATEGORIES[u].to_dict(),
                "rank": USAGE_RANK[u],
                "needs_extra_governance": u in RESTRICTED_USE_CATEGORIES,
                "needs_tested_fallback": USAGE_RANK[u]
                >= USAGE_RANK[UsageCategory.INTERNAL_BUSINESS_APPLICATIONS],
            }
            for u in sorted(UsageCategory, key=lambda x: USAGE_RANK[x])
        ],
        "conditions": [
            {
                "code": c.value,
                "label": CONDITION_PLAIN[c][0],
                "plain": CONDITION_PLAIN[c][1],
                "formal": CONDITION_REQUIREMENTS[c],
            }
            for c in ConditionCode
        ],
        "information_classes": [
            {
                **INFORMATION_CLASSES[i].to_dict(),
                "needs_sensitive_approval": i in SENSITIVE_INFORMATION_CLASSES,
            }
            for i in InformationClass
        ],
        "lifecycle_statuses": [
            {**LIFECYCLE_STATUSES[s].to_dict(), "allows_new_work": s.allows_new_development}
            for s in LifecycleStatus
        ],
        "criteria": [CRITERIA[c].to_dict() for c in Criterion],
        "risk_levels": [RISK_LEVELS[r].to_dict() for r in RiskLevel],
        "source_tiers": [SOURCE_TIERS[t].to_dict() for t in SourceTier],
        "roles": [asdict(r) for r in ROLES],
        "glossary": sorted((t.to_dict() for t in GLOSSARY), key=lambda d: d["label"].lower()),
    }
