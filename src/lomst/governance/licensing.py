"""Section 7.3 - Licensing evaluation.

Licence identifiers are normalised from the several spellings our sources emit
(llm-stats uses `llama_3_1_community_license`, Hugging Face uses `llama3.1`) and
mapped to the legal conditions Section 7.3 actually asks about: commercial use,
redistribution, fine-tuning, and whether an acceptable use policy applies.

The classes below are an engineering aid for triage, not a legal opinion. Where a
licence carries an acceptable-use policy or bespoke terms, the correct output is
"Legal review required" (C2), which is what this module returns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .vocab import ConditionCode


class LicenseClass(str, Enum):
    #: Apache-2.0, MIT, BSD: commercial use, redistribution and fine-tuning all
    #: permitted with attribution only.
    PERMISSIVE = "permissive"
    #: GPL/AGPL family: permitted but imposes obligations on downstream users,
    #: which Section 7.3 explicitly calls out.
    COPYLEFT = "copyleft"
    #: Llama/Gemma/Qwen-style community licences: commercial use generally
    #: permitted but subject to an acceptable use policy and sometimes a user
    #: threshold or naming obligation.
    COMMUNITY = "community"
    #: Research/non-commercial only. Cannot support internal business use.
    RESEARCH_ONLY = "research_only"
    #: Closed weights. Out of scope for this framework (Section 3 covers locally
    #: executed models); recorded so the registry can say why it was excluded.
    PROPRIETARY = "proprietary"
    #: Not determinable from available evidence -> Deferred (Section 6.3).
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class LicenseAssessment:
    raw: str | None
    normalised: str
    klass: LicenseClass
    commercial_use: bool | None
    redistribution: bool | None
    fine_tuning: bool | None
    acceptable_use_policy: bool
    conditions: tuple[ConditionCode, ...]
    rationale: str

    @property
    def blocks_business_use(self) -> bool:
        """Whether internal business use is impossible under this licence."""
        return self.klass in (LicenseClass.RESEARCH_ONLY, LicenseClass.PROPRIETARY)


# Ordered patterns; first match wins, so specific families precede generic words.
_RULES: list[tuple[str, LicenseClass]] = [
    # Research / non-commercial - checked first because several contain a
    # permissive-sounding token ("mit + model license", "cc-by-nc").
    (r"non[\s_-]?commercial|[\s_-]nc\b|cc[\s_-]?by[\s_-]?nc|research[\s_-]?(?:only|license|licence)|mrl", LicenseClass.RESEARCH_ONLY),
    (r"proprietary|closed|api[\s_-]?only", LicenseClass.PROPRIETARY),
    # Community / bespoke open-weight licences with an AUP.
    (r"llama[\s_\-.]?\d|llama[\s_-]?\d?[\s_-]?community|meta[\s_-]?llama", LicenseClass.COMMUNITY),
    (r"gemma|health_ai_developer_foundations", LicenseClass.COMMUNITY),
    (r"tongyi|qwen", LicenseClass.COMMUNITY),
    (r"deepseek", LicenseClass.COMMUNITY),
    (r"nvidia[\s_-]?open[\s_-]?model|jamba[\s_-]?open|openmdw|lfm\d|mnpl|falcon[\s_-]?llm", LicenseClass.COMMUNITY),
    (r"open[\s_-]?rail|rail[\s_-]?m|creativeml", LicenseClass.COMMUNITY),
    (r"modified[\s_-]?mit", LicenseClass.COMMUNITY),
    # Copyleft.
    (r"agpl|gpl|lgpl|mpl[\s_-]?2|eupl", LicenseClass.COPYLEFT),
    # Permissive.
    (r"apache([\s_-]?2)?|^mit$|\bmit\b|bsd|isc|unlicense|cc[\s_-]?by([\s_-]?4)?(?:[\s_-]?0)?$|cc0", LicenseClass.PERMISSIVE),
]

_PROFILES: dict[LicenseClass, tuple[bool | None, bool | None, bool | None, bool, tuple[ConditionCode, ...], str]] = {
    #                      commercial, redistrib, finetune, aup,  conditions,              rationale
    LicenseClass.PERMISSIVE: (True, True, True, False, (), "Permissive licence: commercial use, redistribution and fine-tuning permitted with attribution."),
    LicenseClass.COPYLEFT: (True, True, True, False, (ConditionCode.C2,), "Copyleft licence imposes obligations on downstream users (Section 7.3); Legal review required."),
    LicenseClass.COMMUNITY: (True, True, True, True, (ConditionCode.C2,), "Community/bespoke licence with an acceptable use policy and possible bespoke obligations; Legal review required (Section 7.3)."),
    LicenseClass.RESEARCH_ONLY: (False, None, None, True, (ConditionCode.C2, ConditionCode.C6), "Non-commercial/research licence: cannot support internal business use. Restrict to Research & Experimentation."),
    LicenseClass.PROPRIETARY: (None, False, False, True, (ConditionCode.C2,), "Closed weights: outside the scope of local/open-source model governance (Section 3)."),
    LicenseClass.UNKNOWN: (None, None, None, True, (ConditionCode.C2,), "Licence could not be determined from available evidence; Section 6.3 outcome is Deferred until clarified."),
}


def normalise(raw: str | None) -> str:
    if not raw:
        return "unknown"
    return re.sub(r"[\s_]+", "-", raw.strip().lower()).strip("-") or "unknown"


def assess(raw: str | None) -> LicenseAssessment:
    """Classify a licence string into Section 7.3 terms."""
    norm = normalise(raw)
    klass = LicenseClass.UNKNOWN
    if norm != "unknown":
        for pattern, candidate in _RULES:
            if re.search(pattern, norm, re.I):
                klass = candidate
                break

    commercial, redistribution, fine_tuning, aup, conditions, rationale = _PROFILES[klass]
    return LicenseAssessment(
        raw=raw,
        normalised=norm,
        klass=klass,
        commercial_use=commercial,
        redistribution=redistribution,
        fine_tuning=fine_tuning,
        acceptable_use_policy=aup,
        conditions=conditions,
        rationale=rationale,
    )
