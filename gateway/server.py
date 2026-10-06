"""MCP server for the gateway's tools. Every call goes through Gateway.guarded_call(): the policy
check, a human approval for high-risk writes, the tool itself, and an audit row.

    python -m gateway.server --transport stdio --client-id claude-desktop
    python -m gateway.server --transport http --port 8765 --admin-port 8766

The change-record index is built in memory at startup. EMBEDDING_PROVIDER=hash skips the
fastembed model, TRIAGE_DATA_DIR points at another copy of the triage data/ folder, and
MCP_GUARD_POLICY and MCP_GUARD_DB move policy.yaml and data/guard.db.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import uvicorn
from mcp.server.mcpserver import Context, MCPServer
from mcp_types import CallToolResult, TextContent, Tool
from pydantic import BaseModel
from qdrant_client import QdrantClient

from gateway.actions import Actions
from gateway.admin_api import create_app
from gateway.approvals import Approval, ApprovalClosed, ApprovalQueue
from gateway.audit import AuditLog, CallRecord, Decision, db_path, new_id, timestamp
from gateway.config import PolicyConfig, PolicyFile, policy_path
from gateway.policy import POLICY_DECISIONS, CallContext, PolicyResult, ToolCall
from gateway.policy import check as policy_check
from gateway.tools import TOOLS
from triage.data import DATA_DIR, load_alerts, load_assets, load_change_records, load_identities, load_threat_intel
from triage.embeddings import get_embedder
from triage.tools import Toolbox, ensure_index

log = logging.getLogger("gateway")

Check = Callable[[ToolCall, PolicyConfig, CallContext], PolicyResult]
OnWait = Callable[[float, float], Awaitable[None]]


@dataclass
class Gateway:
    """Everything a guarded call touches. Tests swap `check` for a stub."""

    toolbox: Toolbox
    actions: Actions
    policy: PolicyFile
    audit: AuditLog
    approvals: ApprovalQueue
    check: Check = policy_check

    async def guarded_call(self, client_id: str, tool: str, args: dict[str, Any],
                           on_wait: OnWait | None = None) -> CallRecord:
        """Run one tool call through the policy and audit it, whatever happens (SPEC.md section 5).

        `on_wait(seconds_waited, timeout_s)` is called while the call waits for approval.
        """
        started = time.monotonic()
        call_id, approval_id = new_id(), None
        config = self.policy.current()
        result = self._check(ToolCall(client_id, tool, args), config)
        decision, reason = result.decision, result.reason

        def record(decision: Decision, reason: str, output: Any = None) -> CallRecord:
            call = CallRecord(
                id=call_id, ts=timestamp(), client_id=client_id, tool=tool, args=args, decision=decision,
                reason=reason, output=output, latency_ms=round((time.monotonic() - started) * 1000, 1),
                approval_id=approval_id,
            )
            self.audit.record(call)
            log.info("%s %s -> %s in %.0f ms", client_id, tool, decision, call.latency_ms)
            return call

        if decision == "ALLOW" and result.needs_approval:
            approval = self.approvals.create(call_id, client_id, tool, args)
            approval_id = approval.id
            timeout_s = config.approval_timeout_s
            try:
                approval = await self.approvals.wait(
                    approval.id, timeout_s, (lambda waited: on_wait(waited, timeout_s)) if on_wait else None
                )
            except anyio.get_cancelled_exc_class():
                # No awaits below, so this still runs while the task is being cancelled.
                with suppress(ApprovalClosed):
                    self.approvals.resolve(approval_id, "timeout", by="gateway", note="The client cancelled the call")
                record("BLOCK_TIMEOUT", "The client cancelled the call while it waited for approval")
                raise
            decision, reason = _approval_outcome(approval)

        if decision != "ALLOW":
            return record(decision, reason)
        return record(decision, reason, await anyio.to_thread.run_sync(self._execute, tool, result.args))

    def _check(self, call: ToolCall, config: PolicyConfig) -> PolicyResult:
        """policy.check(), failing closed if it raises or returns something it should not."""
        context = CallContext(self.toolbox.identities, self.audit.count_since(call.client_id, 60))
        try:
            result = self.check(call, config, context)
        except Exception as e:
            log.exception("The policy check raised on %s", call.tool)
            return PolicyResult("BLOCK_ERROR", f"The policy check failed ({type(e).__name__}), so the call was blocked")
        if result.decision not in POLICY_DECISIONS:
            return PolicyResult("BLOCK_ERROR", f"The policy check returned {result.decision}, which only the gateway may")
        spec = TOOLS.get(call.tool)
        if result.decision == "ALLOW" and (spec is None or not isinstance(result.args, spec.args)):
            return PolicyResult("BLOCK_ERROR", "The policy check allowed the call without validated arguments")
        return result

    def _execute(self, tool: str, args: BaseModel) -> dict[str, Any]:
        handler = getattr(self.actions if TOOLS[tool].writes else self.toolbox, tool)
        try:
            return handler(args)
        except Exception:
            log.exception("%s raised", tool)
            return {"error": f"{tool} failed"}


def _approval_outcome(approval: Approval) -> tuple[Decision, str]:
    who = f"{approval.resolved_by}{': ' + approval.note if approval.note else ''}"
    if approval.status == "approved":
        return "ALLOW", f"Approved by {who}"
    if approval.status == "denied":
        return "BLOCK_DENIED", f"Denied by {who}"
    return "BLOCK_TIMEOUT", approval.note or "No decision in time"


class GuardServer(MCPServer):
    """An MCPServer that lists the gateway's tools itself and hands raw arguments to the gateway.

    MCPServer's tool registry derives schemas from function signatures and validates arguments
    before the tool body runs. The gateway needs the raw arguments, so that schema failures are
    blocked and audited like any other policy decision, so list_tools and call_tool are
    overridden instead.
    """

    def __init__(self, gateway: Gateway, client_id: str):
        super().__init__(
            name="mcp-guard",
            version="0.1.0",
            instructions="Tools for triaging security alerts against a synthetic dataset: lookups (change "
            "records, assets, identities, threat intel) and response actions (close an alert, disable an "
            "account, quarantine a host). A policy gateway checks every call; high-risk actions may wait "
            "for human approval.",
        )
        self.gateway = gateway
        self.client_id = client_id

    async def list_tools(self) -> list[Tool]:
        return [spec.mcp_tool() for spec in TOOLS.values()]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], context: Context[Any, Any] | None = None
    ) -> CallToolResult:
        async def on_wait(waited: float, timeout_s: float) -> None:
            if context is not None:
                await context.report_progress(waited, timeout_s, "Waiting for human approval")

        call = await self.gateway.guarded_call(self.client_id, name, arguments, on_wait)
        if call.decision.startswith("BLOCK"):
            output = {"error": f"Blocked by MCP Guard ({call.decision}): {call.reason}"}
        else:
            output = call.output
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(output))],
            structured_content=output,
            is_error="error" in output,
            meta={"mcp_guard": {"call_id": call.id, "decision": call.decision}},
        )


def load_toolbox(data_dir: Path) -> Toolbox:
    """Build triage's Toolbox with the change-record index in memory.

    triage.store.get_client() would default to embedded storage inside the triage repo,
    which locks that folder and writes into a project this one must not modify.
    """
    client, embedder = QdrantClient(":memory:"), get_embedder()
    ensure_index(client, embedder, load_change_records(data_dir))
    return Toolbox(client, embedder, load_assets(data_dir), load_identities(data_dir), load_threat_intel(data_dir))


def load_gateway(policy: Path, db: Path) -> Gateway:
    data_dir = Path(os.environ.get("TRIAGE_DATA_DIR", DATA_DIR))
    toolbox = load_toolbox(data_dir)
    actions = Actions(db, {a.alert.id for a in load_alerts(data_dir)}, toolbox.identities, toolbox.assets)
    return Gateway(toolbox, actions, PolicyFile(policy), AuditLog(db), ApprovalQueue(db))


async def serve(server: GuardServer, args: argparse.Namespace) -> None:
    """Run the MCP transport, plus the admin API with --admin-port, until the transport ends."""
    admin = None
    async with anyio.create_task_group() as tg:
        if args.admin_port:
            # log_config=None logs through the root logger, so to stderr.
            admin = uvicorn.Server(uvicorn.Config(create_app(args.db, args.policy), host=args.host,
                                                  port=args.admin_port, log_config=None))
            tg.start_soon(admin.serve)
        if args.transport == "stdio":
            await server.run_stdio_async()
        else:
            app = server.streamable_http_app(host=args.host)
            await uvicorn.Server(uvicorn.Config(app, host=args.host, port=args.port, log_config=None)).serve()
        if admin:
            admin.should_exit = True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--client-id", default=os.environ.get("MCP_GUARD_CLIENT_ID", "anonymous"),
                        help="Who is calling; the policy allowlist is keyed on this")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765, help="HTTP transport only")
    parser.add_argument("--admin-port", type=int, help="Also serve the admin API on this port")
    parser.add_argument("--policy", type=Path, default=policy_path())
    parser.add_argument("--db", type=Path, default=db_path())
    args = parser.parse_args()

    # stdout carries the stdio transport, so logs go to stderr.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(message)s")
    started = time.monotonic()
    gateway = load_gateway(args.policy, args.db)
    log.info("Indexed change records with %s in %.1f s", gateway.toolbox.embedder.name, time.monotonic() - started)
    with suppress(KeyboardInterrupt):  # uvicorn re-raises Ctrl-C after a clean shutdown, as uvicorn.run expects
        anyio.run(serve, GuardServer(gateway, args.client_id), args)


if __name__ == "__main__":
    main()
