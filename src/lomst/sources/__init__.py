"""Connector registry."""

from __future__ import annotations

from .base import Advisory, Artefact, Connector, Observation, Result
from .feeds import RssConnector, WordPressConnector
from .hub import HuggingFaceConnector
from .providers import OpenRouterConnector
from .security import (
    GhsaConnector,
    GithubAwesomeConnector,
    KevConnector,
    OsvConnector,
)
from .trackers import EvertuneConnector, LlmStatsConnector, OllamaConnector

CONNECTORS: dict[str, type] = {
    "rss": RssConnector,
    "wordpress": WordPressConnector,
    "evertune": EvertuneConnector,
    "llm_stats": LlmStatsConnector,
    "ollama": OllamaConnector,
    "huggingface": HuggingFaceConnector,
    "osv": OsvConnector,
    "ghsa": GhsaConnector,
    "github_awesome": GithubAwesomeConnector,
    "kev": KevConnector,
    "openrouter": OpenRouterConnector,
}


def build(connector: str) -> Connector:
    try:
        return CONNECTORS[connector]()  # type: ignore[return-value]
    except KeyError:
        raise KeyError(
            f"unknown connector {connector!r}; known: {', '.join(sorted(CONNECTORS))}"
        ) from None


__all__ = [
    "CONNECTORS",
    "build",
    "Advisory",
    "Artefact",
    "Connector",
    "Observation",
    "Result",
]
