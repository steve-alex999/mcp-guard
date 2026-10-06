"""Admin API for the dashboard: the audit log, the approval queue and the policy.

    python -m gateway.admin_api --port 8766

It shares data/guard.db and policy.yaml with any number of gateway processes, so it can run on
its own (the usual setup next to Claude Desktop) or inside one gateway process with
`python -m gateway.server --admin-port 8766`. There is no authentication: it listens on
127.0.0.1 and is for local use only.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Literal

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from gateway.approvals import Approval, ApprovalClosed, ApprovalQueue, UnknownApproval
from gateway.audit import AuditLog, CallRecord, Decision, db_path
from gateway.config import PolicyConfig, PolicyFile, policy_path
from gateway.tools import TOOLS

DASHBOARD_ORIGINS = os.environ.get("MCP_GUARD_DASHBOARD_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")


class CallDetail(CallRecord):
    approval: Approval | None = None


class ToolInfo(BaseModel):
    name: str
    title: str
    risk: Literal["low", "medium", "high"]
    writes: bool


class Resolution(BaseModel):
    by: str = Field(default="dashboard", min_length=1, max_length=64)
    note: str | None = Field(default=None, max_length=500)


def create_app(db: Path, policy: Path) -> FastAPI:
    audit, approvals, policy_file = AuditLog(db), ApprovalQueue(db), PolicyFile(policy)
    app = FastAPI(title="MCP Guard admin API")
    app.add_middleware(CORSMiddleware, allow_origins=DASHBOARD_ORIGINS.split(","),
                       allow_methods=["GET", "POST", "PUT"], allow_headers=["content-type"])

    @app.get("/calls")
    def list_calls(limit: int = Query(100, ge=1, le=1000), decision: Decision | None = None,
                   client_id: str | None = None) -> list[CallRecord]:
        """Newest first."""
        return audit.recent(limit, decision=decision, client_id=client_id)

    @app.get("/calls/{call_id}")
    def get_call(call_id: str) -> CallDetail:
        call = audit.get(call_id)
        if call is None:
            raise HTTPException(404, f"No call {call_id}")
        approval = approvals.get(call.approval_id) if call.approval_id else None
        return CallDetail(**call.model_dump(), approval=approval)

    @app.get("/pending")
    def list_pending() -> list[Approval]:
        """Oldest first."""
        return approvals.pending()

    def resolve(approval_id: str, status: Literal["approved", "denied"], resolution: Resolution | None) -> Approval:
        resolution = resolution or Resolution()
        try:
            return approvals.resolve(approval_id, status, by=resolution.by, note=resolution.note)
        except UnknownApproval:
            raise HTTPException(404, f"No approval {approval_id}") from None
        except ApprovalClosed as e:
            raise HTTPException(409, str(e)) from None

    @app.post("/pending/{approval_id}/approve")
    def approve(approval_id: str, resolution: Resolution | None = None) -> Approval:
        return resolve(approval_id, "approved", resolution)

    @app.post("/pending/{approval_id}/deny")
    def deny(approval_id: str, resolution: Resolution | None = None) -> Approval:
        return resolve(approval_id, "denied", resolution)

    @app.get("/tools")
    def list_tools() -> list[ToolInfo]:
        return [ToolInfo(name=t.name, title=t.title, risk=t.risk, writes=t.writes) for t in TOOLS.values()]

    @app.get("/policy")
    def get_policy() -> PolicyConfig:
        return policy_file.current()

    @app.put("/policy")
    def put_policy(config: PolicyConfig) -> PolicyConfig:
        """Replace the policy. Gateways pick it up on their next call."""
        policy_file.save(config)
        return policy_file.current()

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--policy", type=Path, default=policy_path())
    parser.add_argument("--db", type=Path, default=db_path())
    args = parser.parse_args()
    uvicorn.run(create_app(args.db, args.policy), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
