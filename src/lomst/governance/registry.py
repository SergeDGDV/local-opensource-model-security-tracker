"""Section 9 / Appendix B - the model registry.

Registry entries are git-tracked YAML. That is a deliberate choice: Section 9.1
requires historical decisions be retained for an auditable record, and git gives
that for free with reviewable diffs, authorship and timestamps that a database
row update would quietly overwrite.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

from .vocab import (
    USAGE_RANK,
    ApprovalOutcome,
    ComponentKind,
    ConditionCode,
    LifecycleStatus,
    ModelType,
    UsageCategory,
)


class RegistryError(ValueError):
    """Invalid registry content."""


def today() -> dt.date:
    return dt.date.today()


def _as_date(value: Any, field_name: str) -> dt.date | None:
    if value in (None, ""):
        return None
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value)[:10])
    except ValueError as exc:
        raise RegistryError(f"{field_name}: not an ISO date: {value!r}") from exc


def _as_enum(enum_cls: type, value: Any, field_name: str, default: Any = None) -> Any:
    if value in (None, ""):
        if default is not None:
            return default
        raise RegistryError(f"{field_name} is required")
    raw = str(value).strip()
    # Most vocabularies are lowercase snake_case, but the Appendix E.4 condition
    # codes are uppercase (C1..C9). Try the value as written before folding case
    # so both spellings round-trip from YAML.
    for candidate in (raw, raw.lower(), raw.upper()):
        try:
            return enum_cls(candidate)
        except ValueError:
            continue
    allowed = ", ".join(sorted(m.value for m in enum_cls))
    raise RegistryError(f"{field_name}: {value!r} not one of: {allowed}")


# ------------------------------------------------------------------- structures


@dataclass(slots=True)
class Fallback:
    """Section 8.5 - the fallback for a model dependency."""

    kind: str = "none"  # alternate_model | alternate_provider | manual_process | none
    description: str = ""
    tested: bool = False
    tested_date: dt.date | None = None

    KINDS = ("alternate_model", "alternate_provider", "manual_process", "none")

    def __post_init__(self) -> None:
        if self.kind not in self.KINDS:
            raise RegistryError(
                f"fallback.kind {self.kind!r} not one of: {', '.join(self.KINDS)}"
            )
        # Section 8.5: "not 'we would figure it out'". A fallback asserted as
        # tested must say what was tested.
        if self.tested and not self.description.strip():
            raise RegistryError("fallback marked tested but has no description")

    @property
    def is_real(self) -> bool:
        return self.kind != "none" and bool(self.description.strip())

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Fallback":
        return cls(
            kind=str(raw.get("kind", "none")),
            description=str(raw.get("description", "") or ""),
            tested=bool(raw.get("tested", False)),
            tested_date=_as_date(raw.get("tested_date"), "fallback.tested_date"),
        )


@dataclass(slots=True)
class DependentSolution:
    """Section 8.5 / 9 - a workflow depending on this family."""

    name: str
    usage_category: UsageCategory
    owner: str = ""
    description: str = ""
    fallback: Fallback = field(default_factory=Fallback)

    @property
    def requires_fallback(self) -> bool:
        """Section 8.5: applies at Internal Business Applications or higher."""
        return USAGE_RANK[self.usage_category] >= USAGE_RANK[
            UsageCategory.INTERNAL_BUSINESS_APPLICATIONS
        ]

    @property
    def gap(self) -> str | None:
        """Why this solution fails Section 8.5, or None if it is compliant."""
        if not self.requires_fallback:
            return None
        if not self.fallback.is_real:
            return "no documented fallback"
        if not self.fallback.tested:
            return "fallback documented but not tested"
        return None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DependentSolution":
        if not raw.get("name"):
            raise RegistryError("dependent_solutions[].name is required")
        return cls(
            name=str(raw["name"]),
            usage_category=_as_enum(
                UsageCategory, raw.get("usage_category"), "dependent_solutions[].usage_category"
            ),
            owner=str(raw.get("owner", "") or ""),
            description=str(raw.get("description", "") or ""),
            fallback=Fallback.from_dict(raw.get("fallback") or {}),
        )


@dataclass(slots=True)
class Decision:
    """One entry in the Section 4.4 decision history."""

    date: dt.date
    outcome: ApprovalOutcome
    authority: str
    rationale: str = ""
    versions: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Decision":
        return cls(
            date=_as_date(raw.get("date"), "decision.date") or today(),
            outcome=_as_enum(ApprovalOutcome, raw.get("outcome"), "decision.outcome"),
            authority=str(raw.get("authority", "") or ""),
            rationale=str(raw.get("rationale", "") or ""),
            versions=[str(v) for v in (raw.get("versions") or [])],
        )


@dataclass(slots=True)
class Exception_:
    """Section 14 - temporary research approval or emergency review."""

    kind: str  # temporary_research | emergency
    owner: str
    scope: str
    expires: dt.date | None = None

    @property
    def expired(self) -> bool:
        # Section 14.1 requires an expiry date. An exception with no expiry is
        # treated as expired rather than perpetual, so the omission surfaces.
        return self.expires is None or self.expires < today()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Exception_":
        return cls(
            kind=str(raw.get("kind", "temporary_research")),
            owner=str(raw.get("owner", "") or ""),
            scope=str(raw.get("scope", "") or ""),
            expires=_as_date(raw.get("expires"), "exception.expires"),
        )


@dataclass(slots=True)
class Entry:
    """A registry entry for a model family or a runtime (Section 5, Appendix B)."""

    key: str
    name: str
    kind: ComponentKind = ComponentKind.MODEL_FAMILY
    model_type: ModelType = ModelType.LLM
    developer: str = ""
    approval_status: ApprovalOutcome = ApprovalOutcome.PENDING_EVALUATION
    lifecycle_status: LifecycleStatus = LifecycleStatus.ACTIVE
    approved_versions: list[str] = field(default_factory=list)
    approved_uses: list[UsageCategory] = field(default_factory=list)
    conditions: list[ConditionCode] = field(default_factory=list)
    restrictions: list[str] = field(default_factory=list)
    license: str = ""
    distribution_source: str = ""
    runtime_compatibility: list[str] = field(default_factory=list)
    business_owner: str = ""
    governance_owner: str = ""
    approving_authority: str = ""
    approval_date: dt.date | None = None
    review_date: dt.date | None = None
    last_review: dt.date | None = None
    security_notes: str = ""
    documentation: list[str] = field(default_factory=list)
    dependent_solutions: list[DependentSolution] = field(default_factory=list)
    decision_history: list[Decision] = field(default_factory=list)
    exception: Exception_ | None = None
    notes: str = ""

    # ------------------------------------------------------------- derived
    @property
    def usable(self) -> bool:
        """Whether any use is permitted right now."""
        if not self.approval_status.usable:
            return False
        if self.lifecycle_status is LifecycleStatus.RETIRED:
            return False
        return True

    @property
    def review_overdue(self) -> bool:
        """Section 9.2 - scheduled review date has passed."""
        return self.review_date is not None and self.review_date < today()

    def days_to_review(self) -> int | None:
        if self.review_date is None:
            return None
        return (self.review_date - today()).days

    def approves(self, category: UsageCategory) -> bool:
        return category in self.approved_uses

    def dependency_gaps(self) -> list[tuple[DependentSolution, str]]:
        """Section 8.5 non-compliances among dependent solutions."""
        return [(d, gap) for d in self.dependent_solutions if (gap := d.gap)]

    # ------------------------------------------------------------- (de)serialise
    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, key: str | None = None) -> "Entry":
        key = str(raw.get("key") or key or "").strip()
        if not key:
            raise RegistryError("entry requires a `key`")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_]*", key):
            raise RegistryError(
                f"key {key!r} must be lowercase snake_case (it is used as a filename and a join key)"
            )

        return cls(
            key=key,
            name=str(raw.get("name") or key),
            kind=_as_enum(ComponentKind, raw.get("kind"), "kind", ComponentKind.MODEL_FAMILY),
            model_type=_as_enum(ModelType, raw.get("model_type"), "model_type", ModelType.LLM),
            developer=str(raw.get("developer", "") or ""),
            approval_status=_as_enum(
                ApprovalOutcome, raw.get("approval_status"), "approval_status",
                ApprovalOutcome.PENDING_EVALUATION,
            ),
            lifecycle_status=_as_enum(
                LifecycleStatus, raw.get("lifecycle_status"), "lifecycle_status",
                LifecycleStatus.ACTIVE,
            ),
            approved_versions=[str(v) for v in (raw.get("approved_versions") or [])],
            approved_uses=[
                _as_enum(UsageCategory, u, "approved_uses[]")
                for u in (raw.get("approved_uses") or [])
            ],
            conditions=[
                _as_enum(ConditionCode, c, "conditions[]")
                for c in (raw.get("conditions") or [])
            ],
            restrictions=[str(r) for r in (raw.get("restrictions") or [])],
            license=str(raw.get("license", "") or ""),
            distribution_source=str(raw.get("distribution_source", "") or ""),
            runtime_compatibility=[str(r) for r in (raw.get("runtime_compatibility") or [])],
            business_owner=str(raw.get("business_owner", "") or ""),
            governance_owner=str(raw.get("governance_owner", "") or ""),
            approving_authority=str(raw.get("approving_authority", "") or ""),
            approval_date=_as_date(raw.get("approval_date"), "approval_date"),
            review_date=_as_date(raw.get("review_date"), "review_date"),
            last_review=_as_date(raw.get("last_review"), "last_review"),
            security_notes=str(raw.get("security_notes", "") or ""),
            documentation=[str(d) for d in (raw.get("documentation") or [])],
            dependent_solutions=[
                DependentSolution.from_dict(d) for d in (raw.get("dependent_solutions") or [])
            ],
            decision_history=[
                Decision.from_dict(d) for d in (raw.get("decision_history") or [])
            ],
            exception=Exception_.from_dict(raw["exception"]) if raw.get("exception") else None,
            notes=str(raw.get("notes", "") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        def convert(value: Any) -> Any:
            if isinstance(value, dt.date):
                return value.isoformat()
            if hasattr(value, "value"):  # Enum
                return value.value
            if isinstance(value, dict):
                return {k: convert(v) for k, v in value.items() if v not in (None, [], "")}
            if isinstance(value, list):
                return [convert(v) for v in value]
            return value

        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if value in (None, [], ""):
                continue
            if f.name == "exception" and value is not None:
                out[f.name] = convert(asdict(value))
            elif f.name in ("dependent_solutions", "decision_history"):
                out[f.name] = [convert(asdict(v)) for v in value]
            else:
                out[f.name] = convert(value)
        return out


# --------------------------------------------------------------------- registry


class Registry:
    """Loads and saves registry entries from git-tracked YAML."""

    def __init__(self, families_dir: Path, runtimes_dir: Path):
        self.families_dir = families_dir
        self.runtimes_dir = runtimes_dir
        self._cache: dict[str, Entry] | None = None

    def dir_for(self, kind: ComponentKind) -> Path:
        return self.families_dir if kind is ComponentKind.MODEL_FAMILY else self.runtimes_dir

    def load(self, *, refresh: bool = False) -> dict[str, Entry]:
        if self._cache is not None and not refresh:
            return self._cache

        entries: dict[str, Entry] = {}
        for directory, kind in (
            (self.families_dir, ComponentKind.MODEL_FAMILY),
            (self.runtimes_dir, ComponentKind.RUNTIME),
        ):
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.yaml")):
                raw = yaml.safe_load(path.read_text()) or {}
                raw.setdefault("kind", kind.value)
                try:
                    entry = Entry.from_dict(raw, key=path.stem)
                except RegistryError as exc:
                    raise RegistryError(f"{path}: {exc}") from exc
                composite = self._composite(entry.kind, entry.key)
                if composite in entries:
                    raise RegistryError(f"duplicate registry key {composite!r} at {path}")
                entries[composite] = entry

        self._cache = entries
        return entries

    @staticmethod
    def _composite(kind: ComponentKind, key: str) -> str:
        return f"{kind.value}:{key}"

    def families(self) -> dict[str, Entry]:
        return {
            e.key: e
            for e in self.load().values()
            if e.kind is ComponentKind.MODEL_FAMILY
        }

    def runtimes(self) -> dict[str, Entry]:
        return {
            e.key: e for e in self.load().values() if e.kind is ComponentKind.RUNTIME
        }

    def get(self, key: str, kind: ComponentKind = ComponentKind.MODEL_FAMILY) -> Entry | None:
        return self.load().get(self._composite(kind, key))

    def save(self, entry: Entry) -> Path:
        directory = self.dir_for(entry.kind)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{entry.key}.yaml"
        header = (
            f"# {entry.name} - registry entry (Appendix B)\n"
            f"# Governance of Local and Open-Source AI Models v1.1\n"
            f"# Edit deliberately: git history is the Section 9.1 audit record.\n"
        )
        body = yaml.safe_dump(
            entry.to_dict(), sort_keys=False, allow_unicode=True, width=100
        )
        path.write_text(header + body)
        self._cache = None
        return path
