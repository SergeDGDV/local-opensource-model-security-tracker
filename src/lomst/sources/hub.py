"""Hugging Face Hub connector.

This is the source that makes Appendix A.2 answerable rather than guessed. For a
given repo the Hub reports the publishing organisation, the licence tag, whether
the release is gated, the file manifest and the last modification time - i.e.
direct evidence for Section 7.1 (provenance), 7.2 (distribution integrity) and
7.3 (licensing).

Discovery runs four strategies rather than one allowlist, because each answers a
different governance question:

* ``publishers``  - the official orgs behind governed families. This is the
  provenance backbone: Section 7.1 prefers artefacts obtained directly from the
  publisher of record.
* ``top``         - the most-downloaded models across the whole Hub. What people
  will actually ask for, whether or not we have evaluated it.
* ``trending``    - what is about to be asked for. Section 15.3 wants emerging
  families evaluated proactively, not reactively.
* ``quantisers``  - third-party redistributors (GGUF/AWQ repackagers). Section
  6.2 treats these as independent artefacts that are *not* covered by a family's
  approval, so they have to be visible to be governed at all.

An earlier version watched ten hand-listed organisations, which capped coverage
at a couple of hundred repos out of roughly two million. The Hub serves 1000
records per page in well under a second, so the narrow scope bought nothing.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from ..config import SourceConfig
from ..extract import version_label
from ..http import fetch
from .base import Artefact, Observation, Result, iso_date

_NEXT_LINK = re.compile(r'<([^>]+)>;\s*rel="next"')

#: Pipelines worth governing, mapped to the Appendix A.1 model types. Anything
#: outside this set (tabular regression, RL policies, and so on) is out of scope
#: for the families this framework is concerned with.
PIPELINE_MODEL_TYPES: dict[str, str] = {
    "text-generation": "llm",
    "text2text-generation": "llm",
    "feature-extraction": "embedding",
    "sentence-similarity": "embedding",
    "automatic-speech-recognition": "speech",
    "text-to-speech": "speech",
    "text-to-audio": "speech",
    "image-text-to-text": "multimodal",
    "any-to-any": "multimodal",
    "visual-question-answering": "multimodal",
    "text-to-image": "diffusion",
    "image-to-image": "diffusion",
    "text-to-video": "diffusion",
    "image-classification": "vision",
    "object-detection": "vision",
    "image-segmentation": "vision",
    "zero-shot-image-classification": "vision",
    "fill-mask": "llm",
    "token-classification": "llm",
    "text-classification": "llm",
    "translation": "llm",
    "summarization": "llm",
}

#: Weight formats whose loader executes arbitrary code (Python pickle). Section
#: 7.4 declines models requiring insecure execution practices, so the presence
#: or absence of a safetensors alternative is recorded per artefact.
PICKLE_SUFFIXES = (".bin", ".pt", ".pth", ".ckpt", ".pkl")


def _license_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        if tag.startswith("license:"):
            return tag.split(":", 1)[1]
    return None


def _to_artefact(m: dict[str, Any], strategy: str) -> Artefact | None:
    repo_id = m.get("id") or m.get("modelId")
    if not repo_id:
        return None
    author = repo_id.split("/")[0] if "/" in repo_id else ""
    tags = m.get("tags") or []
    pipeline = m.get("pipeline_tag")

    files = [
        (s.get("rfilename") or "")
        for s in (m.get("siblings") or [])
        if isinstance(s, dict)
    ]
    has_safetensors = any(f.endswith(".safetensors") for f in files)
    has_pickle = any(f.endswith(PICKLE_SUFFIXES) for f in files)
    has_gguf = any(f.endswith(".gguf") for f in files)

    return Artefact(
        artefact_id=repo_id,
        publisher=author,
        license=_license_from_tags(tags),
        model_type=PIPELINE_MODEL_TYPES.get(pipeline or ""),
        gated=bool(m.get("gated")),
        downloads=m.get("downloads") or 0,
        version_label=version_label(repo_id.split("/")[-1]),
        url=f"https://huggingface.co/{repo_id}",
        modified_at=iso_date(m.get("lastModified")),
        payload={
            # Everything on the Hub ships downloadable weights, so these are
            # open-weight artefacts by construction. Recorded explicitly so the
            # registry can separate them from hosted-only models, which are out
            # of scope under Section 3.
            "distribution": "open_weights",
            "discovered_by": strategy,
            "likes": m.get("likes"),
            "trending_score": m.get("trendingScore"),
            "library_name": m.get("library_name"),
            "pipeline_tag": pipeline,
            "created_at": iso_date(m.get("createdAt")),
            "sha": m.get("sha"),
            "private": m.get("private"),
            "has_safetensors": has_safetensors,
            "has_pickle_weights": has_pickle,
            "has_gguf": has_gguf,
            "file_count": len(files),
            "tags": [t for t in tags if not t.startswith("license:")][:30],
        },
    )


class HuggingFaceConnector:
    name = "huggingface"

    def fetch(self, cfg: SourceConfig) -> Result:
        base = (cfg.url or "https://huggingface.co/api").rstrip("/")
        opts = cfg.options

        # Deduplicated by repo id across strategies; first finder keeps the label.
        seen: dict[str, Artefact] = {}
        stats: dict[str, int] = {}

        # --- strategy 1: official publishers (provenance backbone) -----------
        for author in opts.get("publishers") or []:
            self._sweep(
                base, seen, stats, "publisher",
                {"author": author, "sort": "lastModified", "direction": -1},
                int(opts.get("per_publisher", 100)),
            )

        # --- strategy 2: most-downloaded across the Hub ----------------------
        cap_top = int(opts.get("top_downloads", 0))
        if cap_top:
            for pipeline in opts.get("pipelines") or ["text-generation"]:
                self._sweep(
                    base, seen, stats, "top_downloads",
                    {"filter": pipeline, "sort": "downloads", "direction": -1},
                    cap_top,
                )

        # --- strategy 3: trending (Section 15.3, look ahead) -----------------
        cap_trend = int(opts.get("trending", 0))
        if cap_trend:
            self._sweep(
                base, seen, stats, "trending",
                {"sort": "trendingScore", "direction": -1}, cap_trend,
            )

        # --- strategy 4: third-party redistributors (Section 6.2) ------------
        for author in opts.get("quantisers") or []:
            self._sweep(
                base, seen, stats, "quantiser",
                {"author": author, "sort": "downloads", "direction": -1},
                int(opts.get("per_quantiser", 100)),
            )

        artefacts = list(seen.values())
        gated = sum(1 for a in artefacts if a.gated)
        pickle_only = sum(
            1
            for a in artefacts
            if a.payload.get("has_pickle_weights") and not a.payload.get("has_safetensors")
        )
        observations = [
            Observation(
                external_id="hf:summary",
                kind="hub_snapshot",
                title=f"Hugging Face: {len(artefacts)} model repositories inspected",
                url="https://huggingface.co",
                summary=(
                    f"Discovered via " + ", ".join(f"{k}={v}" for k, v in sorted(stats.items()))
                    + f". {gated} gated (extra terms apply - Section 7.3); "
                    f"{pickle_only} publish only pickle-format weights, which execute code "
                    f"on load (Section 7.4)."
                ),
                payload={"strategies": stats, "gated": gated, "pickle_only": pickle_only},
            )
        ]
        return Result(observations=observations, artefacts=artefacts)

    # ------------------------------------------------------------------ paging
    def _sweep(
        self,
        base: str,
        seen: dict[str, Artefact],
        stats: dict[str, int],
        strategy: str,
        params: dict[str, Any],
        cap: int,
    ) -> None:
        """Page through a model query until `cap` records or the pages run out."""
        if cap <= 0:
            return
        added = 0
        for m in self._paginate(base, params, cap):
            art = _to_artefact(m, strategy)
            if art is None:
                continue
            # First strategy to find a repo wins, so the provenance sweep keeps
            # its label rather than being relabelled by a later popularity pass.
            if art.artefact_id in seen:
                continue
            seen[art.artefact_id] = art
            added += 1
        stats[strategy] = stats.get(strategy, 0) + added

    def _paginate(
        self, base: str, params: dict[str, Any], cap: int
    ) -> Iterator[dict[str, Any]]:
        page_size = min(1000, cap)
        url: str | None = f"{base}/models"
        query: dict[str, Any] | None = {**params, "limit": page_size, "full": "true"}
        yielded = 0

        while url and yielded < cap:
            resp = fetch(url, params=query, check_robots=False)
            batch = resp.json()
            if not isinstance(batch, list) or not batch:
                return
            for m in batch:
                yield m
                yielded += 1
                if yielded >= cap:
                    return
            # The Hub paginates by opaque cursor in the Link header; the cursor
            # already encodes the original filters, so params must not be resent.
            match = _NEXT_LINK.search(resp.headers.get("Link", ""))
            url, query = (match.group(1) if match else None), None
