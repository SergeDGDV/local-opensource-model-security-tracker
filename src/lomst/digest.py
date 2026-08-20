"""Daily change digest.

The digest answers "what changed, and what does it mean for us" rather than
dumping the day's feed. Anything that is not tied to an approved family, an
approved runtime or an outstanding governance action is summarised as a count,
not enumerated.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from typing import Any

from .db import Store
from .governance.registry import Registry
from .governance.review import Action, Urgency, all_actions


@dataclass(slots=True)
class Digest:
    run_id: int
    generated_at: str
    source_health: list[dict[str, Any]] = field(default_factory=list)
    new_by_source: dict[str, int] = field(default_factory=dict)
    advisories: list[dict[str, Any]] = field(default_factory=list)
    license_changes: list[dict[str, Any]] = field(default_factory=list)
    family_activity: list[dict[str, Any]] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    attributions: list[str] = field(default_factory=list)

    @property
    def urgent(self) -> list[Action]:
        return [a for a in self.actions if a.urgency in (Urgency.IMMEDIATE, Urgency.HIGH)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "source_health": self.source_health,
            "new_by_source": self.new_by_source,
            "advisories": self.advisories,
            "license_changes": self.license_changes,
            "family_activity": self.family_activity,
            "actions": [a.to_dict() for a in self.actions],
            "attributions": self.attributions,
        }


def build(store: Store, registry: Registry, run_id: int | None = None) -> Digest:
    if run_id is None:
        last = store.last_run()
        run_id = int(last["id"]) if last else 0

    changes = store.changes_for_run(run_id) if run_id else []

    advisories = [
        {
            "id": c["ref"],
            "severity": c["severity"],
            "detail": c["detail"],
        }
        for c in changes
        if c["kind"] == "advisory"
    ]
    license_changes = [
        {"artefact": c["ref"], "family": c["family_key"], "detail": c["detail"]}
        for c in changes
        if c["kind"] == "license_changed"
    ]

    # Group observation/artefact activity by family so the digest reads by
    # governance subject rather than by source.
    activity: dict[str, dict[str, Any]] = {}
    for c in changes:
        fam = c["family_key"]
        if not fam or c["kind"] not in ("observation", "artefact"):
            continue
        bucket = activity.setdefault(
            fam, {"family": fam, "observations": 0, "artefacts": 0, "examples": []}
        )
        bucket["observations" if c["kind"] == "observation" else "artefacts"] += 1
        if len(bucket["examples"]) < 3 and c["detail"]:
            bucket["examples"].append(c["detail"][:160])

    known = set(registry.families())
    family_activity = sorted(
        (
            {**v, "in_registry": v["family"] in known}
            for v in activity.values()
        ),
        key=lambda d: (not d["in_registry"], -(d["observations"] + d["artefacts"])),
    )

    health = [
        {
            "source_id": r["source_id"],
            "ok": r["consecutive_failures"] == 0,
            "last_success": r["last_success_at"],
            "consecutive_failures": r["consecutive_failures"],
            "items": r["last_item_count"],
            "error": r["last_error"],
        }
        for r in store.health()
    ]

    new_by_source = {
        r["source_id"]: r["n"]
        for r in store.query(
            "SELECT source_id, COUNT(*) n FROM observations WHERE first_run_id = ? "
            "GROUP BY source_id ORDER BY n DESC",
            (run_id,),
        )
    }

    # Sources that require attribution get it reproduced here rather than
    # silently consumed (Evertune publishes under CC-BY-4.0).
    attributions: list[str] = []
    for r in store.query(
        "SELECT payload FROM observations WHERE kind IN ('tracker_meta', 'hub_snapshot')"
    ):
        try:
            value = json.loads(r["payload"] or "{}").get("attribution")
        except json.JSONDecodeError:
            continue
        if value and value not in attributions:
            attributions.append(str(value))

    return Digest(
        run_id=run_id,
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        source_health=health,
        new_by_source=new_by_source,
        advisories=advisories,
        license_changes=license_changes,
        family_activity=family_activity,
        actions=all_actions(store, registry),
        attributions=[a for a in attributions if a],
    )


def render_text(d: Digest, *, max_actions: int = 25) -> str:
    """Human-readable digest for the terminal or a log file."""
    lines: list[str] = []
    add = lines.append

    add(f"Local & Open-Source Model Security Tracker - digest for run {d.run_id}")
    add(f"Generated {d.generated_at}")
    add("")

    stale = [h for h in d.source_health if not h["ok"]]
    add(f"SOURCES: {len(d.source_health) - len(stale)}/{len(d.source_health)} healthy")
    for h in stale:
        add(f"  ! {h['source_id']}: {h['consecutive_failures']} consecutive failures - {h['error']}")
    if d.new_by_source:
        top = ", ".join(f"{k}={v}" for k, v in list(d.new_by_source.items())[:8])
        add(f"  new items: {top}")
    add("")

    urgent = d.urgent
    add(f"GOVERNANCE ACTIONS: {len(d.actions)} outstanding ({len(urgent)} urgent)")
    shown = 0
    for a in d.actions:
        if shown >= max_actions:
            add(f"  ... and {len(d.actions) - shown} more (see `lomst actions`)")
            break
        marker = {
            Urgency.IMMEDIATE: "!!",
            Urgency.HIGH: "! ",
            Urgency.SCHEDULED: "> ",
            Urgency.INFORMATIONAL: "  ",
        }[a.urgency]
        add(f"  {marker} [{a.section}] {a.subject}: {a.detail}")
        if a.owner:
            add(f"        owner: {a.owner} ({a.responsible_function})")
        shown += 1
    add("")

    if d.license_changes:
        add(f"LICENCE CHANGES (Section 6.2 full reassessment trigger): {len(d.license_changes)}")
        for lc in d.license_changes:
            add(f"  * {lc['artefact']} [{lc['family']}]: {lc['detail']}")
        add("")

    if d.advisories:
        add(f"NEW ADVISORIES ON TRACKED PACKAGES: {len(d.advisories)}")
        for adv in d.advisories[:12]:
            add(f"  * [{adv['severity']}] {adv['id']}: {(adv['detail'] or '')[:120]}")
        if len(d.advisories) > 12:
            add(f"  ... and {len(d.advisories) - 12} more")
        add("")

    if d.family_activity:
        registered = [f for f in d.family_activity if f["in_registry"]]
        other = [f for f in d.family_activity if not f["in_registry"]]
        add(f"ACTIVITY: {len(registered)} registered families, {len(other)} unregistered")
        for f in registered[:10]:
            add(f"  - {f['family']}: {f['observations']} items, {f['artefacts']} artefacts")
        if other:
            add(
                "  unregistered with activity: "
                + ", ".join(f"{f['family']}({f['observations'] + f['artefacts']})" for f in other[:12])
            )
        add("")

    for attribution in d.attributions:
        add(f"Attribution: {attribution}")

    return "\n".join(lines)
