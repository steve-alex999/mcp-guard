"""SQLite storage: the schema for all three tables, and the audit log of tool calls.

`calls` gets one row per tool call, blocked or not, and is append-only: nothing here updates
or deletes a row, and triggers make SQLite refuse to. Every gateway process and the admin API
open the same file (data/guard.db, or MCP_GUARD_DB).
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "guard.db"

Decision = Literal[
    "ALLOW",
    "ALLOW_REDACTED",
    "BLOCK_NOT_ALLOWED",
    "BLOCK_SCHEMA",
    "BLOCK_RULE",
    "BLOCK_RATE",
    "BLOCK_DENIED",
    "BLOCK_TIMEOUT",
    "BLOCK_ERROR",  # the policy check raised or misbehaved, so the gateway failed closed
]

# approvals carries client_id, tool and args_json on top of SPEC.md's columns: the calls row is
# only written once the call finishes, and the approver needs to see what they are approving.
SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    client_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_json TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    output_json TEXT,
    findings_json TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    approval_id TEXT
);
CREATE INDEX IF NOT EXISTS calls_client_ts ON calls (client_id, ts);
CREATE TRIGGER IF NOT EXISTS calls_no_update BEFORE UPDATE ON calls
BEGIN SELECT RAISE(ABORT, 'calls is append-only'); END;
CREATE TRIGGER IF NOT EXISTS calls_no_delete BEFORE DELETE ON calls
BEGIN SELECT RAISE(ABORT, 'calls is append-only'); END;

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL,
    created_ts TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'timeout')),
    resolved_ts TEXT,
    resolved_by TEXT,
    note TEXT,
    client_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS approvals_status ON approvals (status, created_ts);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    reason TEXT NOT NULL
);
"""


def db_path() -> Path:
    return Path(os.environ.get("MCP_GUARD_DB", DEFAULT_DB))


def timestamp(at: datetime | None = None) -> str:
    """UTC ISO 8601 with milliseconds, so timestamps sort as strings."""
    return (at or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="milliseconds")


def new_id() -> str:
    return uuid.uuid4().hex


def init_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")  # readers don't block the writer across processes
        conn.executescript(SCHEMA)


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    """A short-lived autocommit connection: each statement is its own transaction."""
    conn = sqlite3.connect(path, timeout=5, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


class CallRecord(BaseModel):
    id: str
    ts: str
    client_id: str
    tool: str
    args: Any = Field(description="Arguments as the client sent them, valid or not")
    decision: Decision
    reason: str
    output: Any = None
    findings: list[dict[str, Any]] = []
    latency_ms: float
    approval_id: str | None = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> CallRecord:
        return cls(
            id=row["id"], ts=row["ts"], client_id=row["client_id"], tool=row["tool"],
            args=json.loads(row["args_json"]), decision=row["decision"], reason=row["reason"],
            output=json.loads(row["output_json"]) if row["output_json"] is not None else None,
            findings=json.loads(row["findings_json"]), latency_ms=row["latency_ms"],
            approval_id=row["approval_id"],
        )


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        init_db(path)

    def record(self, call: CallRecord) -> None:
        with connect(self.path) as conn:
            conn.execute(
                "INSERT INTO calls (id, ts, client_id, tool, args_json, decision, reason, output_json,"
                " findings_json, latency_ms, approval_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    call.id, call.ts, call.client_id, call.tool, json.dumps(call.args, default=str),
                    call.decision, call.reason,
                    json.dumps(call.output, default=str) if call.output is not None else None,
                    json.dumps(call.findings), call.latency_ms, call.approval_id,
                ),
            )

    def get(self, call_id: str) -> CallRecord | None:
        with connect(self.path) as conn:
            row = conn.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()
        return CallRecord.from_row(row) if row else None

    def recent(self, limit: int = 100, *, decision: str | None = None,
               client_id: str | None = None) -> list[CallRecord]:
        """Newest first, optionally filtered by decision and client."""
        where, params = [], []
        if decision:
            where.append("decision = ?")
            params.append(decision)
        if client_id:
            where.append("client_id = ?")
            params.append(client_id)
        sql = "SELECT * FROM calls" + (f" WHERE {' AND '.join(where)}" if where else "")
        with connect(self.path) as conn:
            rows = conn.execute(f"{sql} ORDER BY ts DESC, rowid DESC LIMIT ?", (*params, limit)).fetchall()
        return [CallRecord.from_row(r) for r in rows]

    def count_since(self, client_id: str, seconds: float) -> int:
        """Calls `client_id` made in the last `seconds`, blocked ones included."""
        since = timestamp(datetime.now(UTC) - timedelta(seconds=seconds))
        with connect(self.path) as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM calls WHERE client_id = ? AND ts >= ?", (client_id, since)
            ).fetchone()[0]
