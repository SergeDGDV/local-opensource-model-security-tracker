"""Model-tracker connectors: llm-stats.com, Evertune, Ollama library."""

from __future__ import annotations

import codecs
import json
import re
from typing import Any, Iterator

from ..config import SourceConfig
from ..http import fetch
from .base import Artefact, Observation, Result, iso_date, strip_html

# ------------------------------------------------------------------- llm-stats

_FLIGHT_RE = re.compile(r'self\.__next_f\.push\(\[1,\s*"((?:[^"\\]|\\.)*)"\]\)')


def _balanced_objects(text: str, required: tuple[str, ...], max_len: int = 4000) -> Iterator[str]:
    """Yield balanced ``{...}`` substrings containing every required key.

    The page is a Next.js app whose model table arrives inside the RSC flight
    payload rather than as HTML, so there is no DOM to select against. Scanning
    for balanced objects is resilient to key reordering and to new fields being
    added, which a positional regex would not be.
    """
    for match in re.finditer(r'\{"', text):
        start = match.start()
        depth = 0
        in_string = False
        escaped = False
        for i in range(start, min(len(text), start + max_len)):
            ch = text[i]
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : i + 1]
                    if all(f'"{k}"' in candidate for k in required):
                        yield candidate
                    break


class LlmStatsConnector:
    """llm-stats.com leaderboard.

    robots.txt disallows /api/, so the public page is parsed instead of the JSON
    API. That constraint is honoured centrally by `http.fetch`, which will raise
    RobotsDenied rather than fetch a disallowed path.
    """

    name = "llm_stats"

    def fetch(self, cfg: SourceConfig) -> Result:
        base = (cfg.url or "https://llm-stats.com/").rstrip("/")
        resp = fetch(f"{base}/models")

        chunks = _FLIGHT_RE.findall(resp.text)
        if not chunks:
            raise RuntimeError(
                "llm-stats: RSC flight payload not found - page structure changed, "
                "re-verify with `lomst probe llm_stats`"
            )
        blob = "".join(_unescape(c) for c in chunks)

        seen: set[str] = set()
        artefacts: list[Artefact] = []
        observations: list[Observation] = []

        for raw in _balanced_objects(blob, ("license", "organization")):
            try:
                rec: dict[str, Any] = json.loads(raw)
            except json.JSONDecodeError:
                continue
            name = rec.get("name")
            org = rec.get("organization")
            if not name or not org:
                continue
            key = f"{org}/{name}"
            if key in seen:
                continue
            seen.add(key)

            license_raw = (rec.get("license") or "unknown").strip()
            artefacts.append(
                Artefact(
                    artefact_id=key,
                    publisher=org,
                    license=license_raw,
                    model_type="multimodal" if rec.get("multimodal") else None,
                    version_label=None,
                    url=f"{base}/models",
                    modified_at=iso_date(rec.get("release_date")),
                    payload={
                        # llm-stats reports an absolute parameter count
                        # (32500000000), not billions. Normalise here so
                        # downstream sizing logic reads in familiar units.
                        "params_b": (
                            rec["params"] / 1e9
                            if isinstance(rec.get("params"), (int, float))
                            else None
                        ),
                        "params_count": rec.get("params"),
                        "context": rec.get("context"),
                        "is_moe": rec.get("is_moe"),
                        "multimodal": rec.get("multimodal"),
                        "knowledge_cutoff": rec.get("knowledge_cutoff"),
                        "release_date": rec.get("release_date"),
                        "announcement_date": rec.get("announcement_date"),
                        "model_id": rec.get("model_id"),
                        "canonical_model_id": rec.get("canonical_model_id"),
                        # Section 4.2 (Technology Neutrality): origin country is
                        # recorded for traceability but is never an input to any
                        # score or recommendation. See governance/classify.py.
                        "organization_country": rec.get("organization_country"),
                        "_neutrality_note": (
                            "organization_country is metadata only; Section 4.2 forbids "
                            "approving or rejecting a model based on origin"
                        ),
                    },
                )
            )

        observations.append(
            Observation(
                external_id="llm_stats:snapshot",
                kind="leaderboard_snapshot",
                title=f"llm-stats.com leaderboard: {len(artefacts)} models",
                url=f"{base}/models",
                summary=(
                    f"{len(artefacts)} models tracked; "
                    f"{sum(1 for a in artefacts if a.license != 'proprietary')} with a non-proprietary licence."
                ),
                payload={"model_count": len(artefacts)},
            )
        )
        return Result(observations=observations, artefacts=artefacts)


def _unescape(chunk: str) -> str:
    try:
        return codecs.decode(chunk, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return chunk


# -------------------------------------------------------------------- Evertune


class EvertuneConnector:
    """Evertune AI Model Release Tracker (curated JSON).

    The payload declares its own `license` and `attribution`; both are preserved
    and re-surfaced in digests so downstream use stays within the terms the
    source sets.
    """

    name = "evertune"

    def fetch(self, cfg: SourceConfig) -> Result:
        url = cfg.url or "https://models.evertune.ai/ai-model-tracker.json"
        doc: dict[str, Any] = fetch(url).json()

        attribution = " | ".join(
            str(doc[k]) for k in ("attribution", "license", "source") if doc.get(k)
        ) or None

        observations = []
        for rec in doc.get("models", []):
            rid = rec.get("id")
            if not rid:
                continue
            provider = rec.get("provider") or "unknown"
            model = rec.get("model") or ""
            observations.append(
                Observation(
                    external_id=f"evertune:{rid}",
                    kind="model_release",
                    title=f"{provider}: {model}".strip(": "),
                    url=rec.get("link"),
                    summary=strip_html(rec.get("notes")),
                    published_at=iso_date(rec.get("releaseDate")),
                    payload={
                        "provider": provider,
                        "model": model,
                        "release_date": rec.get("releaseDate"),
                        "source_name": cfg.name,
                    },
                )
            )

        observations.append(
            Observation(
                external_id="evertune:meta",
                kind="tracker_meta",
                title=f"Evertune tracker: {doc.get('count')} releases",
                url=doc.get("url"),
                summary=strip_html(doc.get("description")),
                published_at=iso_date(doc.get("lastUpdated")),
                payload={"attribution": attribution, "count": doc.get("count")},
            )
        )
        return Result(observations=observations, attribution=attribution)


# ---------------------------------------------------------------------- Ollama

_OLLAMA_LINK_RE = re.compile(r'href="/library/([A-Za-z0-9._\-]+)"')


class OllamaConnector:
    """Ollama model library index.

    Records what is actually pullable onto a workstation. This is the practical
    distribution-source evidence for Section 7.2, and the set an employee can
    realistically reach for, so gaps between it and the registry are worth seeing.
    """

    name = "ollama"

    def fetch(self, cfg: SourceConfig) -> Result:
        url = cfg.url or "https://ollama.com/library"
        html = fetch(url).text
        names = sorted(set(_OLLAMA_LINK_RE.findall(html)))
        if not names:
            raise RuntimeError(
                "ollama: no /library/ entries found - page structure changed, "
                "re-verify with `lomst probe ollama_library`"
            )

        artefacts = [
            Artefact(
                artefact_id=f"ollama/{n}",
                publisher="ollama-library",
                url=f"https://ollama.com/library/{n}",
                payload={"pullable": True, "name": n},
            )
            for n in names
        ]
        observations = [
            Observation(
                external_id="ollama:library_snapshot",
                kind="registry_snapshot",
                title=f"Ollama library: {len(names)} models pullable",
                url=url,
                summary="Models available via `ollama pull` at time of scan.",
                payload={"count": len(names), "names": names},
            )
        ]
        return Result(observations=observations, artefacts=artefacts)
