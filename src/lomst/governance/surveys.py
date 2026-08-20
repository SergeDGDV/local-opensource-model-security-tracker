"""Questionnaires, defined as data so the UI can render them generically.

The governance document is largely made of checklists - Appendix A evaluates a
model, Appendix C evaluates a runtime, Appendix D requests approval, and Section
8.5 asks four questions about continuity. On paper they are tables of blank
boxes. Here they are answerable, and where an answer has a consequence the
consequence is computed rather than left to the reader to look up.

Two things this module refuses to do:

* It does not approve anything. Appendix A is explicit that completing the
  checklist "does not automatically imply approval, it provides the information
  required to support a governance decision". Every result is a recommendation
  with the reasoning shown.
* It does not hide the reasoning behind a score. Each answer that triggers a
  condition says which condition and why, in plain language.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .guide import CONDITION_PLAIN
from .vocab import (
    CONDITION_REQUIREMENTS,
    ConditionCode,
    InformationClass,
    UsageCategory,
    USAGE_RANK,
)


@dataclass(slots=True)
class Option:
    value: str
    label: str
    help: str = ""
    #: Conditions this answer brings with it.
    conditions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Question:
    id: str
    prompt: str
    #: "single" | "multi" | "yesno" | "text" | "longtext" | "family" | "runtime" | "date"
    type: str
    help: str = ""
    options: list[Option] = field(default_factory=list)
    required: bool = True
    section: str = ""
    #: For yes/no items: which answer is the reassuring one. A "no" on a question
    #: whose good answer is "yes" becomes a gap rather than a silent pass.
    good_answer: str | None = None
    #: Conditions implied when the answer is *not* the good one.
    conditions_if_bad: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Step:
    id: str
    title: str
    intro: str = ""
    questions: list[Question] = field(default_factory=list)


@dataclass(slots=True)
class Survey:
    id: str
    title: str
    purpose: str
    #: What the reader gets at the end.
    outcome: str
    steps: list[Step] = field(default_factory=list)
    section: str = ""
    #: Set when the survey produces a permit/deny answer rather than a summary.
    decides_permission: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _yesno(
    qid: str,
    prompt: str,
    *,
    good: str = "yes",
    help: str = "",
    section: str = "",
    conditions: list[str] | None = None,
    required: bool = True,
) -> Question:
    return Question(
        id=qid,
        prompt=prompt,
        type="yesno",
        help=help,
        section=section,
        good_answer=good,
        conditions_if_bad=conditions or [],
        required=required,
    )


# ============================================================ permission check


def permission_survey() -> Survey:
    """The one most people need: may I use this, for this, with this data?

    Options are described by what the reader is doing, not by the category name,
    because "internal business applications" is not how anyone describes their own
    work. The category is still returned so the answer is traceable.
    """
    from .guide import INFORMATION_CLASSES, USAGE_CATEGORIES

    usage_options = [
        Option(
            value=u.value,
            label=USAGE_CATEGORIES[u].label,
            help=USAGE_CATEGORIES[u].plain,
            conditions=(
                [ConditionCode.C9.value]
                if USAGE_RANK[u] >= USAGE_RANK[UsageCategory.INTERNAL_BUSINESS_APPLICATIONS]
                else []
            ),
        )
        for u in sorted(UsageCategory, key=lambda x: USAGE_RANK[x])
    ]
    info_options = [
        Option(
            value=i.value,
            label=INFORMATION_CLASSES[i].label,
            help=INFORMATION_CLASSES[i].plain,
            conditions=[ConditionCode.C1.value] if i in {
                InformationClass.CONFIDENTIAL,
                InformationClass.PERSONAL,
                InformationClass.CUSTOMER,
            } else [],
        )
        for i in InformationClass
    ]

    return Survey(
        id="permission",
        title="Can I use this model?",
        purpose=(
            "Five questions. You get a yes, a yes-with-conditions, or a no - with the "
            "reason for each check spelled out."
        ),
        outcome="A permission decision you can act on, and the reasoning behind it.",
        section="8",
        decides_permission=True,
        steps=[
            Step(
                id="what",
                title="Which model?",
                intro="Pick the model family you want to use.",
                questions=[
                    Question(
                        id="family",
                        prompt="Which model family?",
                        type="family",
                        help="If it is not in the list, nobody has assessed it yet - which "
                             "means the answer is no until someone does.",
                        section="9",
                    ),
                    Question(
                        id="version",
                        prompt="A specific version, if you know it",
                        type="text",
                        help="Approving a family does not approve every release of it. Leave "
                             "blank if you are not sure.",
                        required=False,
                        section="6.2",
                    ),
                ],
            ),
            Step(
                id="purpose",
                title="What will you use it for?",
                intro="Pick the closest description of what you are actually doing.",
                questions=[
                    Question(
                        id="usage_category",
                        prompt="What is the use?",
                        type="single",
                        options=usage_options,
                        section="8.1, E.2",
                    ),
                ],
            ),
            Step(
                id="data",
                title="What information will it see?",
                intro=(
                    "Include anything you would paste into a prompt, not just what it is "
                    "formally connected to."
                ),
                questions=[
                    Question(
                        id="information_classes",
                        prompt="Tick everything that applies",
                        type="multi",
                        options=info_options,
                        required=False,
                        section="8.3, D.3",
                    ),
                ],
            ),
            Step(
                id="where",
                title="Where will it run?",
                intro=(
                    "The software that runs the model is approved separately from the model "
                    "itself, and this is the check people miss most often."
                ),
                questions=[
                    Question(
                        id="runtime",
                        prompt="Which runtime will execute it?",
                        type="runtime",
                        help="Ollama, vLLM, LM Studio and similar. If you do not know, ask "
                             "before proceeding.",
                        required=False,
                        section="5, 10",
                    ),
                ],
            ),
            Step(
                id="continuity",
                title="How much will depend on it?",
                intro=(
                    "This only matters once colleagues rely on it. A prototype needs no "
                    "fallback plan."
                ),
                questions=[
                    Question(
                        id="solution_name",
                        prompt="What is this solution called?",
                        type="text",
                        help="Name it so the dependency can be recorded against the model. "
                             "If the model were withdrawn, this is how anyone knows what "
                             "breaks. Leave blank for experiments.",
                        required=False,
                        section="8.5, 9",
                    ),
                ],
            ),
        ],
    )


# ====================================================== Appendix A - evaluation


def model_evaluation_survey() -> Survey:
    """Appendix A, as a form.

    Grouped the way the document groups it, but each item says why it is being
    asked. A "no" is not a failure - it is a gap with a named consequence.
    """
    return Survey(
        id="model_evaluation",
        title="Evaluate a model (Appendix A)",
        purpose=(
            "The structured assessment behind an approval decision. Work through it with "
            "the model's documentation open."
        ),
        outcome=(
            "A completed checklist, the conditions your answers imply, and a recommended "
            "decision. Completing it is not itself an approval."
        ),
        section="A",
        steps=[
            Step(
                id="general",
                title="What are we looking at?",
                questions=[
                    Question("model_family", "Model family", "text", section="A.1"),
                    Question("version", "Version", "text", required=False, section="A.1"),
                    Question("developer", "Who published it?", "text", section="A.1"),
                    Question(
                        "distribution_source", "Where would we download it from?", "text",
                        help="A URL. The official publisher's page, ideally.", section="A.1",
                    ),
                    Question(
                        "intended_use", "What do we want it for?", "longtext", section="A.1"
                    ),
                    Question(
                        "business_owner", "Who owns this on the business side?", "text",
                        help="A named person or team who stays accountable for it.",
                        section="A.1",
                    ),
                ],
            ),
            Step(
                id="provenance",
                title="Where it came from",
                intro="Establishing we are getting the real thing from the real publisher.",
                questions=[
                    _yesno("official_publisher_identified",
                           "Do we know which organisation actually published this?",
                           section="7.1", conditions=[ConditionCode.C8.value]),
                    _yesno("official_download_source",
                           "Would we download it from that organisation's own channel?",
                           help="Rather than a mirror or a re-upload by a third party.",
                           section="7.2", conditions=[ConditionCode.C1.value]),
                    _yesno("checksums_verified",
                           "Can we verify the files are unmodified (checksums or signatures)?",
                           section="7.2", conditions=[ConditionCode.C1.value]),
                    _yesno("documentation_available",
                           "Is there real documentation - a model card, known limitations?",
                           section="7.1", conditions=[ConditionCode.C8.value]),
                    _yesno("developer_reputable",
                           "Is the publisher an organisation we can reasonably rely on?",
                           help="About track record and maintenance, not about which country "
                                "they are in - origin is explicitly not a factor.",
                           section="4.2, 7.1", conditions=[ConditionCode.C8.value]),
                ],
            ),
            Step(
                id="licensing",
                title="What the licence allows",
                intro="Open weights do not mean unrestricted. Read the actual licence.",
                questions=[
                    Question("license_name", "What licence is it under?", "text",
                             help="For example Apache-2.0, MIT, or a bespoke community licence.",
                             section="7.3"),
                    _yesno("commercial_use_permitted",
                           "Does it permit commercial use?",
                           section="7.3", conditions=[ConditionCode.C2.value]),
                    _yesno("internal_business_use_permitted",
                           "Does it permit internal business use?",
                           section="7.3", conditions=[ConditionCode.C2.value]),
                    _yesno("finetuning_permitted",
                           "Does it permit fine-tuning?",
                           help="Only matters if we intend to.", required=False,
                           section="7.3"),
                    _yesno("acceptable_use_policy",
                           "Does it come with an acceptable use policy?",
                           good="no",
                           help="Many community licences do. Not a problem in itself, but it "
                                "creates obligations someone has to accept on our behalf.",
                           section="7.3", conditions=[ConditionCode.C2.value]),
                    _yesno("gated_access",
                           "Do you have to accept terms or request access to download it?",
                           good="no", section="7.3", conditions=[ConditionCode.C2.value]),
                ],
            ),
            Step(
                id="security",
                title="Security and running it",
                questions=[
                    _yesno("safetensors_available",
                           "Are the weights available in safetensors format?",
                           help="If only .bin/.pt/.ckpt exist, loading the model runs "
                                "arbitrary code. That is treated as a failure, not a niggle.",
                           section="7.4", conditions=[ConditionCode.C1.value,
                                                      ConditionCode.C6.value]),
                    _yesno("vulnerabilities_reviewed",
                           "Have known vulnerabilities in the required software been checked?",
                           section="7.4", conditions=[ConditionCode.C1.value]),
                    _yesno("network_behaviour_understood",
                           "Do we know what it talks to over the network?",
                           help="Some runtimes phone home, auto-update, or download models "
                                "unprompted.",
                           section="7.4, 10.2", conditions=[ConditionCode.C1.value]),
                    _yesno("elevated_privileges_required",
                           "Does it need admin rights or unrestricted file access?",
                           good="no", section="11.3",
                           conditions=[ConditionCode.C1.value, ConditionCode.C6.value]),
                    _yesno("hardware_available",
                           "Do we have hardware that can actually run it?",
                           section="7.5", conditions=[ConditionCode.C8.value]),
                    _yesno("actively_maintained",
                           "Is the publisher still updating it?",
                           section="7.5", conditions=[ConditionCode.C8.value]),
                    _yesno("runtime_approved",
                           "Is the runtime we would use already approved?",
                           help="Approving a model never approves the software that runs it.",
                           section="5, 10", conditions=[ConditionCode.C6.value]),
                ],
            ),
            Step(
                id="usage",
                title="What it will be used for",
                questions=[
                    Question(
                        "intended_categories",
                        "Which of these apply?",
                        "multi",
                        options=[
                            Option("research_experimentation", "Research and experimentation"),
                            Option("internal_productivity", "Internal productivity"),
                            Option("internal_business_applications",
                                   "Internal business applications",
                                   conditions=[ConditionCode.C9.value]),
                            Option("production_services", "Production services",
                                   conditions=[ConditionCode.C9.value,
                                               ConditionCode.C3.value]),
                            Option("customer_facing_applications", "Customer-facing",
                                   conditions=[ConditionCode.C9.value,
                                               ConditionCode.C3.value,
                                               ConditionCode.C5.value]),
                            Option("sensitive_information_processing",
                                   "Handling sensitive information",
                                   conditions=[ConditionCode.C1.value]),
                            Option("autonomous_decision_support", "Acting on its own",
                                   conditions=[ConditionCode.C5.value,
                                               ConditionCode.C7.value]),
                        ],
                        section="A.4, E.2",
                    ),
                ],
            ),
            Step(
                id="continuity",
                title="If it went away tomorrow",
                intro=(
                    "Section 8.5. Skip this if it is an experiment; answer it properly if "
                    "anyone will come to rely on it."
                ),
                questions=[
                    _yesno("single_point_of_failure",
                           "Would this workflow depend on this one model with no alternative?",
                           good="no", required=False, section="8.5",
                           conditions=[ConditionCode.C9.value]),
                    Question(
                        "fallback_kind", "If it were withdrawn, what would you do?", "single",
                        options=[
                            Option("alternate_model", "Switch to another approved model"),
                            Option("alternate_provider", "Use a hosted provider instead"),
                            Option("manual_process", "Fall back to doing it manually"),
                            Option("none", "No plan yet",
                                   help="An honest answer, and the reason this question exists.",
                                   conditions=[ConditionCode.C9.value]),
                        ],
                        required=False, section="8.5",
                    ),
                    _yesno("fallback_tested",
                           "Has that fallback actually been tried?",
                           required=False,
                           help="Assuming a swap will work is itself a risk. Untested counts "
                                "as no fallback for production purposes.",
                           section="8.5", conditions=[ConditionCode.C9.value]),
                ],
            ),
        ],
    )


# ==================================================== Appendix C - runtime


def runtime_evaluation_survey() -> Survey:
    return Survey(
        id="runtime_evaluation",
        title="Evaluate a runtime (Appendix C)",
        purpose=(
            "Runtimes are assessed separately from models. This is where security "
            "vulnerabilities usually live, so it is not a formality."
        ),
        outcome="A completed checklist and the conditions your answers imply.",
        section="C, 10",
        steps=[
            Step(
                id="general",
                title="Which runtime?",
                questions=[
                    Question("runtime", "Name", "text", section="C.1"),
                    Question("version", "Version", "text", required=False, section="C.1"),
                    Question("publisher", "Who publishes it?", "text", section="C.1"),
                    Question(
                        "operating_systems", "Which operating systems would we run it on?",
                        "text", required=False, section="C.1",
                    ),
                ],
            ),
            Step(
                id="governance",
                title="Software governance",
                questions=[
                    _yesno("official_distribution",
                           "Would we install it from the official source?",
                           section="10.2", conditions=[ConditionCode.C1.value]),
                    _yesno("license_reviewed", "Has its licence been reviewed?",
                           section="10.1", conditions=[ConditionCode.C2.value]),
                    _yesno("active_maintenance", "Is it actively maintained?",
                           help="The organisation avoids deploying runtimes the developers "
                                "have abandoned.",
                           section="10.3", conditions=[ConditionCode.C8.value]),
                    _yesno("vulnerability_review", "Has a vulnerability review been done?",
                           section="10.1", conditions=[ConditionCode.C1.value]),
                ],
            ),
            Step(
                id="security",
                title="Access and exposure",
                intro=(
                    "Several popular runtimes serve an unauthenticated API by default. That "
                    "is fine on loopback and not fine on a shared network."
                ),
                questions=[
                    _yesno("authentication_supported",
                           "Can it require authentication?",
                           section="10.3", conditions=[ConditionCode.C1.value,
                                                       ConditionCode.C6.value]),
                    _yesno("authorisation_supported",
                           "Can it distinguish who is allowed to do what?",
                           section="10.3", conditions=[ConditionCode.C1.value]),
                    _yesno("audit_logging",
                           "Does it produce usable logs?",
                           section="10.3", conditions=[ConditionCode.C7.value]),
                    _yesno("network_exposure_controlled",
                           "Would it be reachable only from where it should be?",
                           help="An unauthenticated service reachable across the "
                                "organisation's network is not deployed without explicit "
                                "approval.",
                           section="10.3", conditions=[ConditionCode.C1.value,
                                                       ConditionCode.C6.value]),
                    _yesno("auto_update_understood",
                           "Do we know when and how it updates itself?",
                           section="10.2", conditions=[ConditionCode.C1.value]),
                    _yesno("telemetry_documented",
                           "Do we know what usage data it sends out?",
                           section="10.2", conditions=[ConditionCode.C1.value]),
                ],
            ),
            Step(
                id="enterprise",
                title="Running it properly",
                questions=[
                    _yesno("central_deployment", "Can IT deploy it centrally?",
                           required=False, section="C.3"),
                    _yesno("container_support", "Does it run in a container?",
                           required=False, section="C.3"),
                    _yesno("monitoring", "Can we monitor it?",
                           required=False, section="C.3",
                           conditions=[ConditionCode.C7.value]),
                    _yesno("identity_integration", "Can it use our identity provider?",
                           required=False, section="C.3"),
                ],
            ),
        ],
    )


# =================================================== Appendix D - request


def approval_request_survey() -> Survey:
    return Survey(
        id="approval_request",
        title="Request a new model (Appendix D)",
        purpose=(
            "The intake form. Enough information for an informed evaluation, and no more."
        ),
        outcome=(
            "A request summary to send to AI Governance. Check the registry first - if an "
            "approved model already does the job, you may not need this at all."
        ),
        section="D, 13",
        steps=[
            Step(
                id="who",
                title="Who is asking?",
                questions=[
                    Question("requestor", "Your name", "text", section="D.1"),
                    Question("department", "Team or department", "text", section="D.1"),
                    Question("business_owner", "Who will own this if approved?", "text",
                             help="A named person or team accountable for it afterwards.",
                             section="D.1"),
                ],
            ),
            Step(
                id="what",
                title="Which model?",
                questions=[
                    Question("model_family", "Model family", "text", section="D.1"),
                    Question("version", "Version", "text", required=False, section="D.1"),
                    Question("developer", "Who publishes it?", "text", section="D.1"),
                    Question("download_source", "Official download source", "text",
                             section="D.1"),
                    Question("required_runtime", "Which runtime does it need?", "runtime",
                             help="Approved separately. If it needs something new, that gets "
                                  "its own evaluation.",
                             required=False, section="D.1"),
                ],
            ),
            Step(
                id="why",
                title="Why do you need it?",
                questions=[
                    Question("business_use", "What will you use it for?", "longtext",
                             section="D.2"),
                    Question("business_value", "What do we get out of it?", "longtext",
                             section="D.2"),
                    Question("why_not_existing",
                             "Why will an already-approved model not do?", "longtext",
                             help="The first thing AI Governance checks. A good answer here "
                                  "speeds everything up.",
                             section="D.2, 13"),
                ],
            ),
            Step(
                id="data",
                title="What information will it process?",
                questions=[
                    Question(
                        "information_classes", "Tick everything that applies", "multi",
                        options=[
                            Option("public", "Public information"),
                            Option("internal", "Internal information"),
                            Option("confidential", "Confidential information",
                                   conditions=[ConditionCode.C1.value]),
                            Option("personal", "Personal data",
                                   conditions=[ConditionCode.C1.value,
                                               ConditionCode.C2.value]),
                            Option("customer", "Customer or player information",
                                   conditions=[ConditionCode.C1.value]),
                            Option("source_code", "Source code",
                                   conditions=[ConditionCode.C1.value]),
                        ],
                        required=False, section="D.3",
                    ),
                ],
            ),
            Step(
                id="how",
                title="How will it be deployed?",
                questions=[
                    Question(
                        "deployment", "Where will it run?", "single",
                        options=[
                            Option("local_workstation", "My own workstation"),
                            Option("shared_workstation", "A shared machine"),
                            Option("server", "A server",
                                   conditions=[ConditionCode.C4.value]),
                            Option("cloud", "Cloud infrastructure",
                                   conditions=[ConditionCode.C4.value]),
                        ],
                        section="D.4",
                    ),
                    _yesno("integrates_with_systems",
                           "Will it connect to any of our existing systems?",
                           good="no",
                           help="Repositories, databases, ticketing, chat. Connecting a model "
                                "to these changes its risk profile substantially.",
                           section="8.4, D.4",
                           conditions=[ConditionCode.C3.value, ConditionCode.C4.value]),
                    Question(
                        "requested_approval", "What level of approval are you asking for?",
                        "single",
                        options=[
                            Option("research_experimentation", "Experimentation only"),
                            Option("internal_productivity", "Internal productivity"),
                            Option("internal_business_applications", "A business application",
                                   conditions=[ConditionCode.C9.value]),
                            Option("production_services", "A production service",
                                   conditions=[ConditionCode.C9.value,
                                               ConditionCode.C3.value]),
                        ],
                        section="D.5",
                    ),
                    Question("known_concerns",
                             "Anything about it that already worries you?", "longtext",
                             help="Raising it now is faster than having it found later.",
                             required=False, section="D.4"),
                ],
            ),
        ],
    )


# =================================================== Section 8.5 - continuity


def continuity_survey() -> Survey:
    return Survey(
        id="continuity",
        title="Continuity check (Section 8.5)",
        purpose=(
            "Four questions about what happens if a model you depend on is withdrawn. "
            "Withdrawal is routine governance activity, not a disaster - unless nobody "
            "planned for it."
        ),
        outcome="Whether your dependency is adequately planned for, and what is missing.",
        section="8.5",
        steps=[
            Step(
                id="dependency",
                title="The dependency",
                questions=[
                    Question("solution_name", "What is the solution called?", "text",
                             section="8.5"),
                    Question("family", "Which model does it depend on?", "family",
                             section="8.5"),
                    Question(
                        "usage_category", "How much does the business rely on it?", "single",
                        options=[
                            Option("research_experimentation",
                                   "It is an experiment",
                                   help="No fallback plan needed."),
                            Option("internal_productivity",
                                   "It helps individuals work",
                                   help="No fallback plan needed."),
                            Option("internal_business_applications",
                                   "A team's process depends on it",
                                   conditions=[ConditionCode.C9.value]),
                            Option("production_services",
                                   "A business-critical system depends on it",
                                   conditions=[ConditionCode.C9.value]),
                        ],
                        section="8.5, E.2",
                    ),
                ],
            ),
            Step(
                id="plan",
                title="The four questions",
                questions=[
                    _yesno("single_point_of_failure",
                           "Does this depend on one specific model family with no approved "
                           "alternative?",
                           good="no", section="8.5",
                           conditions=[ConditionCode.C9.value]),
                    Question(
                        "fallback_kind",
                        "If it were withdrawn or changed materially, what is the fallback?",
                        "single",
                        options=[
                            Option("alternate_model", "Another approved model"),
                            Option("alternate_provider", "The same model from a hosted provider"),
                            Option("manual_process", "A defined manual process"),
                            Option("none", "Nothing defined yet",
                                   conditions=[ConditionCode.C9.value]),
                        ],
                        section="8.5",
                    ),
                    Question("fallback_description",
                             "Describe it concretely", "longtext",
                             help="Specific enough that someone else could execute it. "
                                  "\"We would figure it out\" is the answer this question "
                                  "exists to catch.",
                             section="8.5"),
                    Question("business_as_usual",
                             "How would the team keep working during the switch?", "longtext",
                             help="This is what separates a managed migration from an "
                                  "incident.",
                             required=False, section="8.5"),
                    _yesno("fallback_tested",
                           "Has the fallback actually been tested?",
                           section="8.5", conditions=[ConditionCode.C9.value]),
                    Question("tested_date", "When was it last tested?", "date",
                             required=False, section="8.5"),
                ],
            ),
        ],
    )


SURVEYS: dict[str, Any] = {
    "permission": permission_survey,
    "model_evaluation": model_evaluation_survey,
    "runtime_evaluation": runtime_evaluation_survey,
    "approval_request": approval_request_survey,
    "continuity": continuity_survey,
}


def catalogue() -> list[dict[str, Any]]:
    """Every survey, in the order most people need them."""
    order = ["permission", "approval_request", "model_evaluation", "runtime_evaluation",
             "continuity"]
    return [SURVEYS[k]().to_dict() for k in order]


def get(survey_id: str) -> Survey | None:
    factory = SURVEYS.get(survey_id)
    return factory() if factory else None


# ------------------------------------------------------------------- scoring


def score(survey: Survey, answers: dict[str, Any]) -> dict[str, Any]:
    """Summarise a completed checklist.

    Deliberately not a pass/fail. Appendix A says completing the checklist
    provides the information for a decision rather than making one, so the output
    is: what is missing, what conditions the answers imply, and a recommendation.
    """
    gaps: list[dict[str, Any]] = []
    conditions: set[str] = set()
    unanswered: list[str] = []

    for step in survey.steps:
        for q in step.questions:
            raw = answers.get(q.id)
            given = raw not in (None, "", [], {})
            if q.required and not given:
                unanswered.append(q.prompt)
                continue
            if not given:
                continue

            if q.type == "yesno" and q.good_answer:
                if str(raw).lower() != q.good_answer:
                    gaps.append(
                        {
                            "question": q.prompt,
                            "answer": str(raw),
                            "section": q.section,
                            "conditions": q.conditions_if_bad,
                        }
                    )
                    conditions.update(q.conditions_if_bad)
            elif q.type in ("single", "multi"):
                chosen = raw if isinstance(raw, list) else [raw]
                for opt in q.options:
                    if opt.value in chosen:
                        conditions.update(opt.conditions)

    codes = [c for c in ConditionCode if c.value in conditions]
    complete = not unanswered

    if not complete:
        recommendation = "incomplete"
        headline = f"{len(unanswered)} required question(s) still to answer."
    elif not gaps and not codes:
        recommendation = "approved"
        headline = "Nothing of concern. A clean approval is defensible on this evidence."
    elif gaps and any(
        g["question"].startswith("Are the weights available in safetensors")
        for g in gaps
    ):
        recommendation = "deferred"
        headline = (
            "One answer is a blocker: without safetensors weights, loading the model runs "
            "arbitrary code. Resolve that before approving."
        )
    elif len(gaps) >= 4:
        recommendation = "deferred"
        headline = (
            f"{len(gaps)} gaps. Too much is unresolved for an approval to stand up; get the "
            f"answers first."
        )
    else:
        recommendation = "approved_with_conditions"
        headline = (
            f"Usable, but {len(codes)} condition(s) must be met first."
            if codes
            else f"{len(gaps)} gap(s) to note, none of them blocking."
        )

    return {
        "survey": survey.id,
        "complete": complete,
        "unanswered": unanswered,
        "gaps": gaps,
        "conditions": [
            {
                "code": c.value,
                "label": CONDITION_PLAIN[c][0],
                "plain": CONDITION_PLAIN[c][1],
                "formal": CONDITION_REQUIREMENTS[c],
            }
            for c in codes
        ],
        "recommendation": recommendation,
        "headline": headline,
        "disclaimer": (
            "This is a summary of what you answered, not an approval. A named approving "
            "authority records the decision (Section 13 step 4)."
        ),
    }
