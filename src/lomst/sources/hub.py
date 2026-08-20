"""Hugging Face Hub connector.

This is the source that makes Appendix A.2 answerable rather than guessed. For a
given repo the Hub reports the publishing organisation, the licence tag, whether
the release is gated, the file manifest and the last modification time - i.e.
direct evidence for Section 7.1 (provenance), 7.2 (distribution integrity) and
7.3 (licensing).
"""

from __future__ import annotations

from typing import Any

from ..config import SourceConfig
from ..extract import family_from_hf_id, version_label
from ..http import fetch
from .base import Artefact, Observation, Result, iso_date


def _license_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        if tag.startswith("license:"):
            return tag.split(":", 1)[1]
    return None


def _pipeline_to_model_type(pipeline: str | None) -> str | None:
    if not pipeline:
        return None
    mapping = {
        "text-generation": "llm",
        "text2text-generation": "llm",
        "feature-extraction": "embedding",
        "sentence-similarity": "embedding",
        "automatic-speech-recognition": "speech",
        "text-to-speech": "speech",
        "text-to-audio": "speech",
        "image-text-to-text": "multimodal",
        "visual-question-answering": "multimodal",
        "text-to-image": "diffusion",
        "image-classification": "vision",
        "object-detection": "vision",
        "zero-shot-image-classification": "vision",
    }
    return mapping.get(pipeline)


class HuggingFaceConnector:
    """Watch the official publishers of the families we govern."""

    name = "huggingface"

    def fetch(self, cfg: SourceConfig) -> Result:
        base = (cfg.url or "https://huggingface.co/api").rstrip("/")
        authors: list[str] = cfg.options.get("watch_authors") or []
        min_downloads = int(cfg.options.get("min_downloads", 0))
        limit = int(cfg.options.get("limit", 50))

        artefacts: list[Artefact] = []
        observations: list[Observation] = []
        gated_count = 0

        for author in authors:
            resp = fetch(
                f"{base}/models",
                params={
                    "author": author,
                    "sort": "lastModified",
                    "direction": -1,
                    "limit": limit,
                    "full": "true",
                },
                check_robots=False,  # documented public API
            )
            models: list[dict[str, Any]] = resp.json()

            for m in models:
                repo_id = m.get("id") or m.get("modelId")
                if not repo_id:
                    continue
                downloads = m.get("downloads") or 0
                if downloads < min_downloads:
                    continue

                tags = m.get("tags") or []
                gated = bool(m.get("gated"))
                if gated:
                    gated_count += 1

                # Section 7.2: the presence of a .safetensors manifest is
                # meaningful. Pickle-based .bin weights execute arbitrary code on
                # load, which is exactly the "insecure execution practice" 7.4
                # says not to approve.
                files = [
                    (s.get("rfilename") or "")
                    for s in (m.get("siblings") or [])
                    if isinstance(s, dict)
                ]
                has_safetensors = any(f.endswith(".safetensors") for f in files)
                has_pickle = any(f.endswith((".bin", ".pt", ".pth", ".ckpt")) for f in files)

                artefacts.append(
                    Artefact(
                        artefact_id=repo_id,
                        publisher=author,
                        license=_license_from_tags(tags),
                        model_type=_pipeline_to_model_type(m.get("pipeline_tag")),
                        gated=gated,
                        downloads=downloads,
                        version_label=version_label(repo_id.split("/")[-1]),
                        url=f"https://huggingface.co/{repo_id}",
                        modified_at=iso_date(m.get("lastModified")),
                        payload={
                            "family_key": family_from_hf_id(repo_id),
                            "likes": m.get("likes"),
                            "library_name": m.get("library_name"),
                            "pipeline_tag": m.get("pipeline_tag"),
                            "created_at": iso_date(m.get("createdAt")),
                            "sha": m.get("sha"),
                            "private": m.get("private"),
                            "has_safetensors": has_safetensors,
                            "has_pickle_weights": has_pickle,
                            "file_count": len(files),
                            "tags": [t for t in tags if not t.startswith("license:")][:40],
                        },
                    )
                )

        observations.append(
            Observation(
                external_id="hf:summary",
                kind="hub_snapshot",
                title=f"Hugging Face: {len(artefacts)} artefacts across {len(authors)} publishers",
                url="https://huggingface.co",
                summary=(
                    f"{gated_count} gated releases (gating implies acceptance of "
                    f"additional terms - Section 7.3)."
                ),
                payload={"authors": authors, "gated": gated_count},
            )
        )
        return Result(observations=observations, artefacts=artefacts)
