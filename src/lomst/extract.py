"""Map free text and artefact ids onto registry family and runtime keys.

Section 6.1 performs governance at model-family level, so every ingested item
must be attributable to a family before it can inform a governance decision.
Section 5 keeps runtimes as independent components, which creates a trap worth
being explicit about: "llama.cpp" contains "llama", and a llama.cpp CVE says
nothing about the Llama model family. Runtime mentions are therefore masked out
of the text before family matching runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .governance.vocab import ModelType

# --------------------------------------------------------------------- runtimes
# Ordered longest-pattern-first so "llama.cpp" wins over any "llama" alias.
RUNTIME_PATTERNS: list[tuple[str, str]] = [
    ("llama_cpp", r"llama[.\s_-]?cpp"),
    ("lm_studio", r"lm[\s_-]?studio"),
    ("text_generation_inference", r"text[\s-]generation[\s-]inference|\bTGI\b"),
    ("onnxruntime", r"onnx[\s_-]?runtime"),
    ("ollama", r"\bollama\b"),
    ("vllm", r"\bvllm\b"),
    ("sglang", r"\bsglang\b"),
    ("mlx", r"\bmlx(?:-lm)?\b"),
    ("transformers", r"\bhugging\s?face\s+transformers\b|\btransformers\s+librar"),
    ("triton", r"\btriton\s+inference\s+server\b"),
    ("localai", r"\blocal\.?ai\b"),
    ("llamafile", r"\bllamafile\b"),
]

# ---------------------------------------------------------------------- families
# key -> (display name, alias regex, default model type)
# Only families with a recognised publishing organisation are listed, matching
# the Section 6.1 definition of a family.
FAMILY_PATTERNS: list[tuple[str, str, str, ModelType]] = [
    ("llama",     "Llama",       r"\bllama[\s-]?\d(?:\.\d+)?\b|\bllama\b(?!\s*[.\s_-]?cpp)|\bcode\s?llama\b", ModelType.LLM),
    ("mistral",   "Mistral",     r"\bmistral(?:[\s-]?(?:small|large|nemo|7b))?\b", ModelType.LLM),
    ("mixtral",   "Mixtral",     r"\bmixtral\b", ModelType.LLM),
    ("magistral", "Magistral",   r"\bmagistral\b", ModelType.REASONING),
    ("devstral",  "Devstral",    r"\bdevstral\b", ModelType.LLM),
    # Distinct product lines from the same publisher are distinct families under
    # Section 6.1, not versions of Mistral. Without these they collapse into
    # `mistral` via the publisher fallback and pollute its version history.
    ("voxtral",   "Voxtral",     r"\bvoxtral\b", ModelType.SPEECH),
    ("pixtral",   "Pixtral",     r"\bpixtral\b", ModelType.MULTIMODAL),
    ("shieldstral", "Shieldstral", r"\bshieldstral\b", ModelType.LLM),
    ("ministral", "Ministral",   r"\bministral\b", ModelType.LLM),
    ("gemma",     "Gemma",       r"\bgemma[\s-]?\d?\b|\bcodegemma\b|\bpaligemma\b", ModelType.LLM),
    ("phi",       "Phi",         r"\bphi[\s-]?[\d]\b|\bphi[\s-]?(?:mini|small|medium|silica)\b", ModelType.LLM),
    ("qwen",      "Qwen",        r"\bqwen[\s-]?\d?(?:\.\d+)?\b|\bqwq\b|\bqvq\b", ModelType.LLM),
    ("deepseek",  "DeepSeek",    r"\bdeepseek(?:[\s-]?(?:v?\d|r\d|coder|math|vl))?\b", ModelType.LLM),
    ("glm",       "GLM",         r"\bglm[\s-]?\d(?:\.\d+)?\b|\bchatglm\b", ModelType.LLM),
    ("granite",   "Granite",     r"\bgranite[\s-]?\d?(?:\.\d+)?\b", ModelType.LLM),
    ("olmo",      "OLMo",        r"\bolmo[\s-]?\d?\b|\bmolmo\b", ModelType.LLM),
    ("smollm",    "SmolLM",      r"\bsmol(?:lm|vlm)[\s-]?\d?\b", ModelType.LLM),
    ("nemotron",  "Nemotron",    r"\bnemotron\b", ModelType.LLM),
    ("falcon",    "Falcon",      r"\bfalcon[\s-]?\d?\b", ModelType.LLM),
    ("yi",        "Yi",          r"\byi[\s-]?(?:\d+b|coder|vl|large)\b", ModelType.LLM),
    ("command_r", "Command R",   r"\bcommand[\s-]?r\+?\b|\baya\b", ModelType.LLM),
    ("kimi",      "Kimi",        r"\bkimi(?:[\s-]?k\d)?\b", ModelType.LLM),
    ("minimax",   "MiniMax",     r"\bminimax[\s-]?\w*\b", ModelType.MULTIMODAL),
    ("gpt_oss",   "gpt-oss",     r"\bgpt[\s-]?oss\b", ModelType.LLM),
    ("whisper",   "Whisper",     r"\bwhisper(?:[\s-]?(?:large|turbo|v\d))?\b", ModelType.SPEECH),
    ("stable_diffusion", "Stable Diffusion", r"\bstable[\s-]diffusion\b|\bsdxl\b|\bsd[\s-]?3(?:\.\d)?\b", ModelType.DIFFUSION),
    ("flux",      "FLUX",        r"\bflux(?:\.\d)?[\s-]?(?:dev|schnell|pro)?\b", ModelType.DIFFUSION),
    ("clip",      "CLIP",        r"\bclip\b(?=\s+(?:model|embed|vision))|\bsiglip\b", ModelType.VISION),
    ("bge",       "BGE",         r"\bbge[\s-]?(?:m3|large|base|small|reranker)\b", ModelType.EMBEDDING),
    ("e5",        "E5",          r"\b(?:multilingual-)?e5[\s-]?(?:large|base|small)\b", ModelType.EMBEDDING),
    ("nomic_embed", "Nomic Embed", r"\bnomic[\s-]?embed\b", ModelType.EMBEDDING),
]

#: Hugging Face author -> family hint, used when the repo id alone is ambiguous.
HF_AUTHOR_FAMILY: dict[str, str] = {
    "meta-llama": "llama",
    "mistralai": "mistral",
    "google": "gemma",
    "microsoft": "phi",
    "Qwen": "qwen",
    "deepseek-ai": "deepseek",
    "allenai": "olmo",
    "HuggingFaceTB": "smollm",
    "nvidia": "nemotron",
    "openai": "whisper",
    "ibm-granite": "granite",
    "tiiuae": "falcon",
    "CohereLabs": "command_r",
    "stabilityai": "stable_diffusion",
    "black-forest-labs": "flux",
    "BAAI": "bge",
    "nomic-ai": "nomic_embed",
    "moonshotai": "kimi",
    "zai-org": "glm",
    "MiniMaxAI": "minimax",
}

_RUNTIME_RE = [(k, re.compile(p, re.I)) for k, p in RUNTIME_PATTERNS]
_FAMILY_RE = [(k, n, re.compile(p, re.I), t) for k, n, p, t in FAMILY_PATTERNS]

FAMILY_NAMES: dict[str, str] = {k: n for k, n, _, _ in FAMILY_PATTERNS}
FAMILY_TYPES: dict[str, ModelType] = {k: t for k, _, _, t in FAMILY_PATTERNS}
RUNTIME_KEYS: tuple[str, ...] = tuple(k for k, _ in RUNTIME_PATTERNS)


@dataclass(frozen=True, slots=True)
class Mentions:
    families: tuple[str, ...]
    runtimes: tuple[str, ...]

    @property
    def primary_family(self) -> str | None:
        return self.families[0] if self.families else None

    @property
    def primary_runtime(self) -> str | None:
        return self.runtimes[0] if self.runtimes else None


def detect(*texts: str | None) -> Mentions:
    """Find family and runtime mentions across the given text fragments.

    Runtime matches are replaced with a sentinel before family matching so that
    e.g. a llama.cpp advisory is not attributed to the Llama family.
    """
    blob = " \n ".join(t for t in texts if t)
    if not blob.strip():
        return Mentions((), ())

    runtimes: list[str] = []
    masked = blob
    for key, rx in _RUNTIME_RE:
        masked, n = rx.subn(" \x00RUNTIME\x00 ", masked)
        if n:
            runtimes.append(key)

    families: list[str] = []
    for key, _name, rx, _t in _FAMILY_RE:
        if rx.search(masked):
            families.append(key)

    return Mentions(tuple(families), tuple(runtimes))


def attribute_hf_id(artefact_id: str) -> tuple[str | None, str]:
    """Resolve a Hugging Face repo id to ``(family_key, method)``.

    ``method`` is ``"name"`` when the repository name itself identifies the
    family, ``"author"`` when only the publisher hint matched, and ``"none"``
    when nothing did. The distinction matters: publishers ship multiple families
    (``mistralai`` publishes Voxtral, Pixtral and Ministral; ``google`` publishes
    far more than Gemma), so an author-only attribution is a discovery hint and
    must not drive Section 6.2 version triggers.
    """
    author, _, name = artefact_id.partition("/")
    detected = detect(name.replace("-", " ").replace("_", " ")).families
    author_family = HF_AUTHOR_FAMILY.get(author)

    if author_family and author_family in detected:
        return author_family, "name"
    if detected:
        return detected[0], "name"
    if author_family:
        return author_family, "author"
    return None, "none"


def family_from_hf_id(artefact_id: str) -> str | None:
    """Resolve a Hugging Face repo id (``author/name``) to a family key.

    The publisher is weighted above the name, because model names routinely
    mention another family. ``deepseek-ai/DeepSeek-R1-Distill-Llama-70B`` is a
    DeepSeek artefact that fine-tunes Llama; attributing it to Llama would let a
    third-party derivative contaminate the governance record of the family it was
    derived from, which Section 6.2 explicitly separates ("although based on an
    approved family, these variants are independent software artefacts").

    The publisher does not simply win outright, though: ``google`` publishes far
    more than Gemma, so the author hint is only used when the name corroborates
    it or names nothing else.
    """
    return attribute_hf_id(artefact_id)[0]


_VERSION_RE = re.compile(
    r"""(?:^|[\s\-_/])            # boundary
        v?(\d+(?:\.\d+){0,2})     # 3, 3.1, 2.5.1
        (?=[\s\-_/]|$)""",
    re.X,
)

#: Mistral, Qwen and others suffix release date codes (``-2409``, ``-2602``)
#: which look exactly like integer versions. Treating them as versions produced
#: a flood of bogus Section 6.2 "major release" triggers.
_DATE_CODE_RE = re.compile(r"^(?:19|20)?\d{2}(?:0[1-9]|1[0-2])$")


def version_label(*texts: str | None) -> str | None:
    """Best-effort version extraction.

    Deliberately conservative: Section 6.2 distinguishes minor from major
    releases, and a wrong guess would mis-route a release to an expedited review
    when it needs a full reassessment. Returning None means "ask a human".
    """
    for text in texts:
        if not text:
            continue
        for m in _VERSION_RE.finditer(text):
            candidate = m.group(1)
            if "." not in candidate:
                # A bare integer that parses as YYMM/YYYYMM is a build stamp, and
                # anything above 100 is not a model version either.
                if _DATE_CODE_RE.match(candidate) or int(candidate) > 100:
                    continue
            return candidate
    return None


def version_tuple(value: str | None) -> tuple[int, ...] | None:
    """Parse a dotted version into a comparable tuple, or None if unparseable."""
    if not value:
        return None
    try:
        return tuple(int(part) for part in str(value).strip().split("."))
    except ValueError:
        return None


def versions_equivalent(a: str | None, b: str | None) -> bool:
    """Whether two version strings denote the same release.

    ``"4"`` and ``"4.0"`` are the same release. Comparing the raw strings marks
    every ``Llama-4-*`` artefact as an unapproved version when ``4.0`` is
    approved, which buries the real Section 6.2 signal in false positives.
    """
    ta, tb = version_tuple(a), version_tuple(b)
    if ta is None or tb is None:
        return (a or "").strip() == (b or "").strip()
    width = max(len(ta), len(tb))
    return ta + (0,) * (width - len(ta)) == tb + (0,) * (width - len(tb))


def compare_release(approved: str | None, observed: str | None) -> str:
    """Classify observed relative to approved for Section 6.2 routing.

    Returns one of ``"major"``, ``"minor"``, ``"older"``, ``"same"`` or
    ``"unknown"``. ``"unknown"`` means a human must classify it - Section 6.2
    routes major and minor releases differently, so guessing has consequences.
    """
    ta, tb = version_tuple(approved), version_tuple(observed)
    if ta is None or tb is None:
        return "unknown"
    if versions_equivalent(approved, observed):
        return "same"
    if tb[0] > ta[0]:
        return "major"
    if tb[0] < ta[0]:
        return "older"
    return "minor" if tb > ta else "older"


def is_major_change(previous: str | None, current: str | None) -> bool | None:
    """Whether moving previous -> current is a major release (Section 6.2).

    Returns None when it cannot be determined, which callers must treat as
    "requires human classification" rather than as False.
    """
    result = compare_release(previous, current)
    if result == "unknown":
        return None
    return result == "major"


def guess_model_type(family_key: str | None, *texts: str | None) -> ModelType:
    if family_key and family_key in FAMILY_TYPES:
        return FAMILY_TYPES[family_key]
    blob = " ".join(t for t in texts if t).lower()
    for needle, mt in (
        ("embedding", ModelType.EMBEDDING),
        ("speech", ModelType.SPEECH),
        ("text-to-speech", ModelType.SPEECH),
        ("whisper", ModelType.SPEECH),
        ("diffusion", ModelType.DIFFUSION),
        ("image generation", ModelType.DIFFUSION),
        ("multimodal", ModelType.MULTIMODAL),
        ("vision", ModelType.VISION),
        ("reasoning", ModelType.REASONING),
    ):
        if needle in blob:
            return mt
    return ModelType.LLM if blob else ModelType.OTHER
