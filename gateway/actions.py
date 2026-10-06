"""The simulated write tools: close_alert, disable_account, quarantine_host.

Each records its intent in the actions table and returns a confirmation. Nothing outside the
database changes.
"""

from __future__ import annotations

from collections.abc import Collection
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

from gateway.audit import connect, init_db, new_id, timestamp
from triage.tools import Args

Reason = Annotated[str, Field(min_length=1, max_length=500, description="Why, citing the evidence")]


class CloseAlertArgs(Args):
    alert_id: str = Field(max_length=64, description="Alert ID, e.g. ALR-12345")
    verdict: Literal["benign", "threat"]
    reason: Reason


class DisableAccountArgs(Args):
    account: str = Field(max_length=128, description="User or service account name")
    reason: Reason


class QuarantineHostArgs(Args):
    hostname: str = Field(max_length=128)
    reason: Reason


class Actions:
    def __init__(self, path: Path, alert_ids: Collection[str], accounts: Collection[str],
                 hosts: Collection[str]):
        self.path = path
        self.alert_ids, self.accounts, self.hosts = set(alert_ids), set(accounts), set(hosts)
        init_db(path)

    def close_alert(self, args: CloseAlertArgs) -> dict[str, Any]:
        if args.alert_id not in self.alert_ids:
            return {"error": f"No alert with ID {args.alert_id!r}"}
        return self._record("close_alert", args.alert_id, f"[{args.verdict}] {args.reason}")

    def disable_account(self, args: DisableAccountArgs) -> dict[str, Any]:
        if args.account not in self.accounts:
            return {"error": f"No account named {args.account!r}"}
        return self._record("disable_account", args.account, args.reason)

    def quarantine_host(self, args: QuarantineHostArgs) -> dict[str, Any]:
        if args.hostname not in self.hosts:
            return {"error": f"No asset named {args.hostname!r}"}
        return self._record("quarantine_host", args.hostname, args.reason)

    def _record(self, tool: str, target: str, reason: str) -> dict[str, Any]:
        action_id = new_id()
        with connect(self.path) as conn:
            conn.execute("INSERT INTO actions (id, ts, tool, target, reason) VALUES (?, ?, ?, ?, ?)",
                         (action_id, timestamp(), tool, target, reason))
        return {"action_id": action_id, "tool": tool, "target": target, "status": "done", "simulated": True}
