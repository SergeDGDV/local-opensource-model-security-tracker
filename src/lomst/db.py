"""SQLite observation store.

This database is a *cache of what the world said*, rebuildable by re-running
ingest. It is deliberately not the audit record: Section 9.1 requires historical
decisions be retained auditably, and those live in git-tracked registry YAML
where they produce reviewable diffs.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    sources     TEXT,
    error       TEXT
);

-- One row per distinct item ever seen from a source. Re-seeing an item updates
-- last_seen; a changed content_hash bumps revision so the digest can report
-- "changed" separately from "new".
CREATE TABLE IF NOT EXISTS observations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id    TEXT NOT NULL,
    tier         TEXT NOT NULL,
    external_id  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    title        TEXT,
    url          TEXT,
    summary      TEXT,
    published_at TEXT,
    family_key   TEXT,
    runtime_key  TEXT,
    payload      TEXT NOT NULL DEFAULT '{}',
    content_hash TEXT NOT NULL,
    revision     INTEGER NOT NULL DEFAULT 1,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    first_run_id INTEGER,
    UNIQUE (source_id, external_id)
);
CREATE INDEX IF NOT EXISTS ix_obs_family    ON observations (family_key);
CREATE INDEX IF NOT EXISTS ix_obs_runtime   ON observations (runtime_key);
CREATE INDEX IF NOT EXISTS ix_obs_published ON observations (published_at DESC);
CREATE INDEX IF NOT EXISTS ix_obs_firstrun  ON observations (first_run_id);

-- Vulnerability records kept separate from observations: they are queried by
-- package/runtime and carry severity semantics the generic table cannot express.
CREATE TABLE IF NOT EXISTS advisories (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id    TEXT NOT NULL,
    advisory_id  TEXT NOT NULL,
    aliases      TEXT NOT NULL DEFAULT '[]',
    ecosystem    TEXT,
    package      TEXT,
    runtime_key  TEXT,
    severity     TEXT,
    cvss         TEXT,
    summary      TEXT,
    url          TEXT,
    published_at TEXT,
    modified_at  TEXT,
    withdrawn_at TEXT,
    payload      TEXT NOT NULL DEFAULT '{}',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    first_run_id INTEGER,
    UNIQUE (source_id, advisory_id, package)
);
CREATE INDEX IF NOT EXISTS ix_adv_runtime  ON advisories (runtime_key);
CREATE INDEX IF NOT EXISTS ix_adv_severity ON advisories (severity);

-- Model artefacts observed at an authoritative distribution source. Supplies
-- Appendix A.2 provenance/licensing facts and Section 6.2 new-version detection.
CREATE TABLE IF NOT EXISTS artefacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id     TEXT NOT NULL,
    artefact_id   TEXT NOT NULL,
    family_key    TEXT,
    publisher     TEXT,
    license       TEXT,
    model_type    TEXT,
    gated         INTEGER NOT NULL DEFAULT 0,
    downloads     INTEGER,
    version_label TEXT,
    url           TEXT,
    modified_at   TEXT,
    payload       TEXT NOT NULL DEFAULT '{}',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    first_run_id  INTEGER,
    UNIQUE (source_id, artefact_id)
);
CREATE INDEX IF NOT EXISTS ix_art_family ON artefacts (family_key);

-- Append-only log of what a run changed, so the digest is a query rather than a
-- diff recomputation.
CREATE TABLE IF NOT EXISTS changes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL,
    at         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    ref        TEXT,
    family_key TEXT,
    severity   TEXT,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS ix_chg_run ON changes (run_id);

CREATE TABLE IF NOT EXISTS source_health (
    source_id            TEXT PRIMARY KEY,
    last_attempt_at      TEXT,
    last_success_at      TEXT,
    last_error           TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_item_count      INTEGER
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # ------------------------------------------------------------------ runs
    def start_run(self, sources: Iterable[str]) -> int:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO runs (started_at, sources) VALUES (?, ?)",
                (utcnow(), ",".join(sources)),
            )
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str = "ok", error: str | None = None) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE runs SET finished_at = ?, status = ?, error = ? WHERE id = ?",
                (utcnow(), status, error, run_id),
            )

    def last_run(self) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM runs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()

    # ---------------------------------------------------------------- upserts
    def upsert_observation(self, run_id: int, rec: dict[str, Any]) -> str:
        """Insert or update one observation.

        Returns "new", "changed" or "seen" so callers can log a change without a
        second query.
        """
        now = utcnow()
        row = self.conn.execute(
            "SELECT id, content_hash FROM observations WHERE source_id = ? AND external_id = ?",
            (rec["source_id"], rec["external_id"]),
        ).fetchone()

        payload = json.dumps(rec.get("payload") or {}, ensure_ascii=False, sort_keys=True)
        if row is None:
            with self.tx() as c:
                c.execute(
                    """INSERT INTO observations
                       (source_id, tier, external_id, kind, title, url, summary,
                        published_at, family_key, runtime_key, payload, content_hash,
                        first_seen, last_seen, first_run_id)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        rec["source_id"], rec["tier"], rec["external_id"], rec["kind"],
                        rec.get("title"), rec.get("url"), rec.get("summary"),
                        rec.get("published_at"), rec.get("family_key"), rec.get("runtime_key"),
                        payload, rec["content_hash"], now, now, run_id,
                    ),
                )
            return "new"

        if row["content_hash"] != rec["content_hash"]:
            with self.tx() as c:
                c.execute(
                    """UPDATE observations SET kind=?, title=?, url=?, summary=?,
                       published_at=?, family_key=?, runtime_key=?, payload=?,
                       content_hash=?, revision=revision+1, last_seen=? WHERE id=?""",
                    (
                        rec["kind"], rec.get("title"), rec.get("url"), rec.get("summary"),
                        rec.get("published_at"), rec.get("family_key"), rec.get("runtime_key"),
                        payload, rec["content_hash"], now, row["id"],
                    ),
                )
            return "changed"

        with self.tx() as c:
            c.execute("UPDATE observations SET last_seen=? WHERE id=?", (now, row["id"]))
        return "seen"

    def upsert_advisory(self, run_id: int, rec: dict[str, Any]) -> str:
        now = utcnow()
        key = (rec["source_id"], rec["advisory_id"], rec.get("package"))
        row = self.conn.execute(
            "SELECT id, modified_at FROM advisories WHERE source_id=? AND advisory_id=? AND package IS ?",
            key,
        ).fetchone()
        payload = json.dumps(rec.get("payload") or {}, ensure_ascii=False, sort_keys=True)
        if row is None:
            with self.tx() as c:
                c.execute(
                    """INSERT INTO advisories
                       (source_id, advisory_id, aliases, ecosystem, package, runtime_key,
                        severity, cvss, summary, url, published_at, modified_at,
                        withdrawn_at, payload, first_seen, last_seen, first_run_id)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        rec["source_id"], rec["advisory_id"],
                        json.dumps(rec.get("aliases") or []),
                        rec.get("ecosystem"), rec.get("package"), rec.get("runtime_key"),
                        rec.get("severity"), rec.get("cvss"), rec.get("summary"),
                        rec.get("url"), rec.get("published_at"), rec.get("modified_at"),
                        rec.get("withdrawn_at"), payload, now, now, run_id,
                    ),
                )
            return "new"

        changed = row["modified_at"] != rec.get("modified_at")
        with self.tx() as c:
            c.execute(
                """UPDATE advisories SET aliases=?, severity=?, cvss=?, summary=?, url=?,
                   modified_at=?, withdrawn_at=?, payload=?, last_seen=? WHERE id=?""",
                (
                    json.dumps(rec.get("aliases") or []), rec.get("severity"), rec.get("cvss"),
                    rec.get("summary"), rec.get("url"), rec.get("modified_at"),
                    rec.get("withdrawn_at"), payload, now, row["id"],
                ),
            )
        return "changed" if changed else "seen"

    def upsert_artefact(self, run_id: int, rec: dict[str, Any]) -> str:
        now = utcnow()
        row = self.conn.execute(
            "SELECT id, modified_at, license FROM artefacts WHERE source_id=? AND artefact_id=?",
            (rec["source_id"], rec["artefact_id"]),
        ).fetchone()
        payload = json.dumps(rec.get("payload") or {}, ensure_ascii=False, sort_keys=True)
        if row is None:
            with self.tx() as c:
                c.execute(
                    """INSERT INTO artefacts
                       (source_id, artefact_id, family_key, publisher, license, model_type,
                        gated, downloads, version_label, url, modified_at, payload,
                        first_seen, last_seen, first_run_id)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        rec["source_id"], rec["artefact_id"], rec.get("family_key"),
                        rec.get("publisher"), rec.get("license"), rec.get("model_type"),
                        int(bool(rec.get("gated"))), rec.get("downloads"),
                        rec.get("version_label"), rec.get("url"), rec.get("modified_at"),
                        payload, now, now, run_id,
                    ),
                )
            return "new"

        # A licence change on an already-approved family is a Section 6.2 full
        # reassessment trigger, so it is reported distinctly from a content bump.
        if row["license"] != rec.get("license"):
            outcome = "license_changed"
        elif row["modified_at"] != rec.get("modified_at"):
            outcome = "changed"
        else:
            outcome = "seen"
        with self.tx() as c:
            c.execute(
                """UPDATE artefacts SET family_key=?, publisher=?, license=?, model_type=?,
                   gated=?, downloads=?, version_label=?, url=?, modified_at=?, payload=?,
                   last_seen=? WHERE id=?""",
                (
                    rec.get("family_key"), rec.get("publisher"), rec.get("license"),
                    rec.get("model_type"), int(bool(rec.get("gated"))), rec.get("downloads"),
                    rec.get("version_label"), rec.get("url"), rec.get("modified_at"),
                    payload, now, row["id"],
                ),
            )
        return outcome

    def log_change(
        self,
        run_id: int,
        kind: str,
        ref: str | None = None,
        family_key: str | None = None,
        severity: str | None = None,
        detail: str | None = None,
    ) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO changes (run_id, at, kind, ref, family_key, severity, detail)"
                " VALUES (?,?,?,?,?,?,?)",
                (run_id, utcnow(), kind, ref, family_key, severity, detail),
            )

    def record_health(
        self,
        source_id: str,
        ok: bool,
        error: str | None = None,
        item_count: int | None = None,
    ) -> None:
        now = utcnow()
        with self.tx() as c:
            c.execute(
                """INSERT INTO source_health
                     (source_id, last_attempt_at, last_success_at, last_error,
                      consecutive_failures, last_item_count)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET
                     last_attempt_at = excluded.last_attempt_at,
                     last_success_at = COALESCE(excluded.last_success_at, source_health.last_success_at),
                     last_error      = excluded.last_error,
                     consecutive_failures = CASE WHEN ? THEN 0
                                                 ELSE source_health.consecutive_failures + 1 END,
                     last_item_count = COALESCE(excluded.last_item_count, source_health.last_item_count)
                """,
                (source_id, now, now if ok else None, error, 0 if ok else 1, item_count, ok),
            )

    # ---------------------------------------------------------------- queries
    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def changes_for_run(self, run_id: int) -> list[sqlite3.Row]:
        return self.query(
            "SELECT * FROM changes WHERE run_id = ? ORDER BY "
            " CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            " WHEN 'moderate' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, kind, ref",
            (run_id,),
        )

    def health(self) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM source_health ORDER BY source_id")
