"""Connector contract shared by every ingest source."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Protocol

from ..config import SourceConfig
from ..http import content_hash


@dataclass(slots=True)
class Observation:
    """A dated item of interest: a post, release note, list entry, news item."""

    external_id: str
    kind: str
    title: str | None = None
    url: str | None = None
    summary: str | None = None
    published_at: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def hash(self) -> str:
        return content_hash(self.title, self.url, self.summary, self.published_at)


@dataclass(slots=True)
class Advisory:
    """A vulnerability record (Section 7.4 / 11.4)."""

    advisory_id: str
    summary: str | None = None
    aliases: list[str] = field(default_factory=list)
    ecosystem: str | None = None
    package: str | None = None
    severity: str | None = None
    cvss: str | None = None
    url: str | None = None
    published_at: str | None = None
    modified_at: str | None = None
    withdrawn_at: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Artefact:
    """A concrete distributable model artefact at an authoritative source.

    Supplies the provenance and licensing facts Appendix A.2 asks for.
    """

    artefact_id: str
    publisher: str | None = None
    license: str | None = None
    model_type: str | None = None
    gated: bool = False
    downloads: int | None = None
    version_label: str | None = None
    url: str | None = None
    modified_at: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Result:
    """Everything one connector produced in one run."""

    observations: list[Observation] = field(default_factory=list)
    advisories: list[Advisory] = field(default_factory=list)
    artefacts: list[Artefact] = field(default_factory=list)
    #: Attribution/licence text a source requires us to reproduce (Evertune's
    #: payload carries its own `license` and `attribution` fields).
    attribution: str | None = None

    def __len__(self) -> int:
        return len(self.observations) + len(self.advisories) + len(self.artefacts)


class Connector(Protocol):
    """A source connector.

    Implementations must be side-effect free apart from network reads; all
    persistence happens in ingest so that `probe` can exercise a source without
    writing anything.
    """

    name: str

    def fetch(self, cfg: SourceConfig) -> Result: ...


# ------------------------------------------------------------------ text helpers

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_ENTITIES = {
    "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"',
    "&#039;": "'", "&#39;": "'", "&apos;": "'", "&nbsp;": " ",
    "&hellip;": "...", "&#8217;": "’", "&#8216;": "‘",
    "&#8220;": "“", "&#8221;": "”", "&#8211;": "–",
    "&#8212;": "—",
}


def strip_html(value: str | None, limit: int = 600) -> str | None:
    """Flatten an HTML fragment to plain text.

    WordPress and RSS bodies arrive as HTML; the tracker stores readable text so
    family detection and digests operate on prose, not markup.
    """
    if not value:
        return None
    text = _TAG_RE.sub(" ", value)
    for ent, char in _ENTITIES.items():
        text = text.replace(ent, char)
    text = _WS_RE.sub(" ", text).strip()
    if not text:
        return None
    return text[:limit].rstrip() + "…" if len(text) > limit else text


def iso_date(value: str | None) -> str | None:
    """Normalise the several date formats our sources emit to ISO-8601 UTC."""
    if not value:
        return None
    raw = value.strip()

    # RFC 2822 (RSS pubDate)
    if "," in raw and any(d in raw for d in ("GMT", "UTC", "+", "-")):
        try:
            dt = parsedate_to_datetime(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
        except (TypeError, ValueError):
            pass

    candidate = raw.replace("Z", "+00:00")
    for parser in (
        lambda s: datetime.fromisoformat(s),
        lambda s: datetime.strptime(s, "%Y-%m-%d"),
        lambda s: datetime.strptime(s, "%b %d, %Y"),
        lambda s: datetime.strptime(s, "%d %b %Y"),
    ):
        try:
            dt = parser(candidate)
        except (TypeError, ValueError):
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
    return None
