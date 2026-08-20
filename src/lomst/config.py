"""Paths and configuration loading."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

import yaml


def _root() -> Path:
    """Project root.

    Overridable with LOMST_HOME so the CLI, the launchd job and the MCP server
    (which starts with an arbitrary cwd) all resolve the same tree.
    """
    env = os.environ.get("LOMST_HOME")
    if env:
        return Path(env).expanduser().resolve()
    # src/lomst/config.py -> project root
    return Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class SourceConfig:
    id: str
    name: str
    connector: str
    tier: str
    enabled: bool = True
    url: str | None = None
    notes: str | None = None
    robots: str | None = None
    options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SourceConfig":
        known = {"id", "name", "connector", "tier", "enabled", "url", "notes", "robots"}
        return cls(
            id=raw["id"],
            name=raw["name"],
            connector=raw["connector"],
            tier=raw.get("tier", "community"),
            enabled=bool(raw.get("enabled", True)),
            url=raw.get("url"),
            notes=raw.get("notes"),
            robots=raw.get("robots"),
            options={k: v for k, v in raw.items() if k not in known},
        )


@dataclass(frozen=True, slots=True)
class Paths:
    root: Path

    @property
    def config(self) -> Path:
        return self.root / "config"

    @property
    def registry(self) -> Path:
        return self.root / "registry"

    @property
    def families(self) -> Path:
        return self.registry / "families"

    @property
    def runtimes(self) -> Path:
        return self.registry / "runtimes"

    @property
    def var(self) -> Path:
        return self.root / "var"

    @property
    def db(self) -> Path:
        return Path(os.environ.get("LOMST_DB") or self.var / "tracker.db")

    @property
    def logs(self) -> Path:
        return self.var / "logs"


# No slots here: cached_property needs a __dict__ to memoise into.
@dataclass(frozen=True)
class Config:
    paths: Paths
    raw: dict[str, Any]

    @cached_property
    def sources(self) -> list[SourceConfig]:
        return [SourceConfig.from_dict(s) for s in self.raw.get("sources", [])]

    @cached_property
    def runtime_defs(self) -> list[dict[str, Any]]:
        return list(self.raw.get("runtimes", []))

    def enabled_sources(self, only: list[str] | None = None) -> list[SourceConfig]:
        picked = [s for s in self.sources if s.enabled]
        if only:
            wanted = set(only)
            unknown = wanted - {s.id for s in self.sources}
            if unknown:
                raise KeyError(f"unknown source id(s): {', '.join(sorted(unknown))}")
            # An explicit selection overrides `enabled`, so a disabled source can
            # still be probed on demand.
            picked = [s for s in self.sources if s.id in wanted]
        return picked

    def source(self, source_id: str) -> SourceConfig:
        for s in self.sources:
            if s.id == source_id:
                return s
        raise KeyError(f"unknown source: {source_id}")


def load(root: Path | None = None) -> Config:
    paths = Paths(root=root or _root())
    cfg_file = paths.config / "sources.yaml"
    raw = yaml.safe_load(cfg_file.read_text()) if cfg_file.exists() else {}
    paths.var.mkdir(parents=True, exist_ok=True)
    paths.logs.mkdir(parents=True, exist_ok=True)
    return Config(paths=paths, raw=raw or {})
