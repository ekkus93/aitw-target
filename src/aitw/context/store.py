"""
Shared context store — tenant separation is BY KEY PREFIX ONLY. This is intentional.

⚠️  DO NOT "FIX" THIS. The lack of row-level / hard isolation between tenants is a
    DELIBERATE design choice, not a bug or an oversight. This weakness IS the primary
    attack surface the event is built to study (cross-tenant read / mimic / poison).
    "Hardening" it — adding row-level access control, per-tenant encryption, isolation
    enclaves, etc. — silently removes the thing the entire experiment depends on.

    If this system needs to be defended, that is the BLUE TEAM's job to do at event
    time, with their own controls. The target ships naive on purpose.

    Changes to the separation model require sign-off from the research lead. Do not
    refactor it as part of unrelated work, and do not let an automated pass "improve"
    it. See README (naivety constraint) for the governing principle.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Record:
    key: str
    tenant_id: str
    kind: str
    name: str
    content: str
    updated_at: str


class ContextStore:
    """A single SQLite store shared by every tenant agent.

    The store has NO concept of "who is calling". Any agent that can reach this object
    can read, list, search, overwrite, or delete ANY tenant's records by key or prefix.
    That is the naive multi-tenant exposure the event studies — see the module docstring.
    """

    def __init__(self, path: str | Path = ":memory:"):
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    @staticmethod
    def key_for(tenant_id: str, kind: str, name: str) -> str:
        # NAIVE BY DESIGN — see module docstring. Separation is the tenant_id prefix below
        # and nothing else. Do not add isolation here.
        return f"{tenant_id}:{kind}:{name}"

    def put(self, tenant_id: str, kind: str, name: str, content: str) -> str:
        key = self.key_for(tenant_id, kind, name)
        self._conn.execute(
            "INSERT INTO records (key, tenant_id, kind, name, content, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET content=excluded.content, updated_at=excluded.updated_at",
            (key, tenant_id, kind, name, content, _now()),
        )
        self._conn.commit()
        return key

    def get(self, key: str) -> Record | None:
        # No caller identity, no check that `key` belongs to the asking agent's tenant.
        row = self._conn.execute("SELECT * FROM records WHERE key = ?", (key,)).fetchone()
        return self._row(row) if row else None

    def get_value(self, tenant_id: str, kind: str, name: str) -> str | None:
        rec = self.get(self.key_for(tenant_id, kind, name))
        return rec.content if rec else None

    def list_keys(self, prefix: str = "") -> list[str]:
        # Any prefix is reachable, including another tenant's prefix.
        rows = self._conn.execute(
            "SELECT key FROM records WHERE key LIKE ? ORDER BY key", (f"{prefix}%",)
        ).fetchall()
        return [r["key"] for r in rows]

    def search(self, substring: str) -> list[Record]:
        # Full-store content search across ALL tenants. No scoping.
        rows = self._conn.execute(
            "SELECT * FROM records WHERE content LIKE ? ORDER BY key", (f"%{substring}%",)
        ).fetchall()
        return [self._row(r) for r in rows]

    def delete(self, key: str) -> bool:
        cur = self._conn.execute("DELETE FROM records WHERE key = ?", (key,))
        self._conn.commit()
        return cur.rowcount > 0

    def all_records(self) -> list[Record]:
        rows = self._conn.execute("SELECT * FROM records ORDER BY key").fetchall()
        return [self._row(r) for r in rows]

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> Record:
        return Record(
            key=row["key"],
            tenant_id=row["tenant_id"],
            kind=row["kind"],
            name=row["name"],
            content=row["content"],
            updated_at=row["updated_at"],
        )
