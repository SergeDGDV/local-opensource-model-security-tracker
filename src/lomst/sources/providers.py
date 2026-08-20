"""Hosted-provider catalogues.

Why a tracker for *local* models cares about hosted providers: Section 8.5 asks
what the fallback is if a model is withdrawn, and names "an alternate provider"
as one of three acceptable answers. Knowing that an open-weight family is also
served by a commercial API turns that question from speculation into a fact on
file, and knowing it is *not* served anywhere means the fallback has to be an
alternate model or a manual process.

These catalogues also cross-check Section 7.3: a provider serving a model
commercially is evidence, though not proof, that its licence permits commercial
use.
"""

from __future__ import annotations

from typing import Any

from ..config import SourceConfig
from ..http import fetch
from .base import Artefact, Observation, Result, iso_date, strip_html


class OpenRouterConnector:
    """OpenRouter model catalogue.

    Entries carrying `hugging_face_id` are open-weight models with a hosted
    endpoint - exactly the "alternate provider" fallback Section 8.5 describes.
    Entries without one are hosted-only and therefore outside the scope of this
    framework (Section 3 covers locally executed models); they are recorded so
    the registry can say why they were excluded rather than silently omitting them.
    """

    name = "openrouter"

    def fetch(self, cfg: SourceConfig) -> Result:
        url = cfg.url or "https://openrouter.ai/api/v1/models"
        doc: dict[str, Any] = fetch(url, check_robots=False).json()
        models = doc.get("data") or []

        artefacts: list[Artefact] = []
        open_weight = 0

        for m in models:
            mid = m.get("id")
            if not mid:
                continue
            hf_id = m.get("hugging_face_id") or None
            if hf_id:
                open_weight += 1

            pricing = m.get("pricing") or {}
            arch = m.get("architecture") or {}
            # Free-tier variants are priced at zero; a paid endpoint is the more
            # meaningful signal that this is a real commercial fallback.
            try:
                prompt_price = float(pricing.get("prompt") or 0)
            except (TypeError, ValueError):
                prompt_price = 0.0

            artefacts.append(
                Artefact(
                    artefact_id=f"openrouter/{mid}",
                    publisher=mid.split("/")[0] if "/" in mid else "openrouter",
                    # OpenRouter does not publish licence terms, so this stays
                    # empty rather than inventing a value the classifier would
                    # then treat as evidence.
                    license=None,
                    model_type=(arch.get("modality") or None),
                    url=f"https://openrouter.ai/models/{mid}",
                    modified_at=(
                        iso_date(str(m["created"])) if isinstance(m.get("created"), (int, float))
                        else None
                    ),
                    payload={
                        "distribution": "open_weights_hosted" if hf_id else "hosted_only",
                        "hosted_alternative_for": hf_id,
                        "context_length": m.get("context_length"),
                        "display_name": m.get("name"),
                        "prompt_price_per_token": prompt_price,
                        "is_free_tier": prompt_price == 0.0,
                        "description": strip_html(m.get("description"), 300),
                        "in_scope_note": (
                            "Open-weight model with a hosted endpoint: a valid Section 8.5 "
                            "alternate provider."
                            if hf_id
                            else "Hosted-only: outside Section 3 scope for local execution."
                        ),
                    },
                )
            )

        observations = [
            Observation(
                external_id="openrouter:summary",
                kind="provider_catalogue",
                title=f"OpenRouter: {open_weight} open-weight models available as a hosted fallback",
                url="https://openrouter.ai/models",
                summary=(
                    f"{len(models)} models served; {open_weight} map to open weights on "
                    f"Hugging Face and can therefore serve as a Section 8.5 alternate "
                    f"provider. {len(models) - open_weight} are hosted-only and out of scope "
                    f"for local execution."
                ),
                payload={"total": len(models), "open_weight": open_weight},
            )
        ]
        return Result(observations=observations, artefacts=artefacts)
