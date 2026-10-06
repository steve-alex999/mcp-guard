"""Pending-approval queue for high-risk tool calls, kept in SQLite so any process can resolve it.

The gateway process holding the call creates a row and polls it; the admin API, possibly in
another process, flips its status. A resolution only lands on a row that is still pending, so a
late approve cannot race a timeout.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal

import anyio
from pydantic import BaseModel

from gateway.audit import connect, init_db, new_id, timestamp

Status = Literal["pending", "approved", "denied", "timeout"]


class Approval(BaseModel):
    id: str
    call_id: str
    created_ts: str
    status: Status
    resolved_ts: str | None = None
    resolved_by: str | None = None
    note: str | None = None
    client_id: str
    tool: str
    args: Any


class UnknownApproval(LookupError):
    pass


class ApprovalClosed(Exception):
    """The approval was already resolved."""

    def __init__(self, approval: Approval):
        super().__init__(f"Approval {approval.id} is already {approval.status}")
        self.approval = approval


class ApprovalQueue:
    def __init__(self, path: Path, poll_interval_s: float = 0.5):
        self.path = path
        self.poll_interval_s = poll_interval_s
        init_db(path)

    def create(self, call_id: str, client_id: str, tool: str, args: Any) -> Approval:
        approval = Approval(id=new_id(), call_id=call_id, created_ts=timestamp(), status="pending",
                            client_id=client_id, tool=tool, args=args)
        with connect(self.path) as conn:
            conn.execute(
                "INSERT INTO approvals (id, call_id, created_ts, status, client_id, tool, args_json)"
                " VALUES (?, ?, ?, 'pending', ?, ?, ?)",
                (approval.id, call_id, approval.created_ts, client_id, tool, json.dumps(args, default=str)),
            )
        return approval

    def get(self, approval_id: str) -> Approval | None:
        with connect(self.path) as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return _from_row(row) if row else None

    def pending(self) -> list[Approval]:
        """Oldest first."""
        with connect(self.path) as conn:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_ts, rowid"
            ).fetchall()
        return [_from_row(r) for r in rows]

    def resolve(self, approval_id: str, status: Literal["approved", "denied", "timeout"], by: str,
                note: str | None = None) -> Approval:
        """Resolve a pending approval. Raises UnknownApproval or ApprovalClosed."""
        with connect(self.path) as conn:
            updated = conn.execute(
                "UPDATE approvals SET status = ?, resolved_ts = ?, resolved_by = ?, note = ?"
                " WHERE id = ? AND status = 'pending'",
                (status, timestamp(), by, note, approval_id),
            ).rowcount
        approval = self.get(approval_id)
        if approval is None:
            raise UnknownApproval(approval_id)
        if not updated:
            raise ApprovalClosed(approval)
        return approval

    async def wait(self, approval_id: str, timeout_s: float,
                   on_tick: Callable[[float], Awaitable[None]] | None = None) -> Approval:
        """Poll until the approval is resolved, and mark it timed out after `timeout_s`.

        `on_tick` gets the seconds waited so far, once per poll.
        """
        started = time.monotonic()
        while True:
            approval = self.get(approval_id)
            if approval is None:
                raise UnknownApproval(approval_id)
            if approval.status != "pending":
                return approval
            waited = time.monotonic() - started
            if waited >= timeout_s:
                try:
                    return self.resolve(approval_id, "timeout", by="gateway",
                                        note=f"No decision within {timeout_s:g} s")
                except ApprovalClosed as e:  # resolved just before the deadline
                    return e.approval
            if on_tick:
                await on_tick(waited)
            await anyio.sleep(min(self.poll_interval_s, timeout_s - waited))


def _from_row(row: Any) -> Approval:
    fields = {k: row[k] for k in row.keys() if k != "args_json"}
    return Approval(**fields, args=json.loads(row["args_json"]))
