"""The policy checks that run before every tool call (SPEC.md section 5, steps 2 to 5).

The gateway (Gateway.guarded_call in gateway/server.py) calls check() once per call, before
anything runs, and acts on the result:
- ALLOW: run the tool with `result.args`. If `result.needs_approval` is set, hold the call for a
  human first; a denial or timeout becomes BLOCK_DENIED or BLOCK_TIMEOUT.
- BLOCK_*: don't run it. The client sees `result.reason`.
If check() raises, returns a decision it should not, or returns ALLOW without validated args,
the gateway fails closed with BLOCK_ERROR. It writes the audit row in every case.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from gateway.actions import DisableAccountArgs
from gateway.audit import Decision
from gateway.config import PolicyConfig
from gateway.tools import TOOLS  # name -> ToolSpec; .args is the tool's argument model
from triage.models import Identity
from triage.tools import SearchArgs

# The decisions check() may return. The others are the gateway's.
POLICY_DECISIONS = {"ALLOW", "BLOCK_NOT_ALLOWED", "BLOCK_SCHEMA", "BLOCK_RULE", "BLOCK_RATE"}


@dataclass(frozen=True)
class ToolCall:
    client_id: str
    tool: str
    args: dict[str, Any]  # as the client sent them: unvalidated, possibly hostile


@dataclass(frozen=True)
class CallContext:
    identities: Mapping[str, Identity]  # account name -> identity, from identities.jsonl
    calls_last_minute: int  # calls this client made in the last 60 s, blocked ones included


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str  # shown to the client and in the audit log: say which rule fired, and why
    args: BaseModel | None = None  # the validated argument model; required with ALLOW
    needs_approval: bool = False


def check(call: ToolCall, config: PolicyConfig, context: CallContext) -> PolicyResult:
    """Decide whether `call` may run. Pure: no I/O, no clock, no globals beyond TOOLS.

    Checks in this order; the first that fails decides:
    1. Allowlist. The client is in config.clients and the tool is in its list. An unknown client
       or tool is BLOCK_NOT_ALLOWED.
    2. Schema. The args validate against TOOLS[call.tool].args (extra fields are forbidden), and
       their JSON is at most config.max_arg_chars long. Otherwise BLOCK_SCHEMA, with a reason
       that names the offending field.
    3. Argument rules, each BLOCK_RULE:
       - disable_account may not target an account that has any tag in
         config.protected_account_tags. An account's tags are its account_type (human, service
         or scanner) plus config.account_tags.get(name, []).
       - search_change_records may not ask for window_hours above config.max_window_hours.
    4. Rate. context.calls_last_minute >= config.rate_limit_per_minute is BLOCK_RATE.
    5. Otherwise ALLOW, with the validated args, and needs_approval set when the tool is in
       config.approval_required.
    """
    # 1. Allowlist. An unknown tool name is the client's text, so it is not repeated back.
    client = config.clients.get(call.client_id)
    if client is None:
        return PolicyResult("BLOCK_NOT_ALLOWED", f"Client {call.client_id!r} is not in the policy")
    spec = TOOLS.get(call.tool)
    if spec is None:
        return PolicyResult("BLOCK_NOT_ALLOWED", "No tool by that name")
    if call.tool not in client.tools:
        return PolicyResult("BLOCK_NOT_ALLOWED", f"Client {call.client_id!r} may not call {call.tool}")

    # 2. Schema. Size first: it is cheap, and it bounds what validation and the reason below see.
    size = len(json.dumps(call.args, ensure_ascii=False, separators=(",", ":")))
    if size > config.max_arg_chars:
        return PolicyResult("BLOCK_SCHEMA", f"Arguments are {size} characters as JSON; the limit is {config.max_arg_chars}")
    try:
        args = spec.args.model_validate(call.args)
    except ValidationError as e:
        return PolicyResult("BLOCK_SCHEMA", f"Invalid arguments for {call.tool}: {_describe(e)}")

    # 3. Argument rules, on the validated args: they carry defaults and coerced types.
    if isinstance(args, DisableAccountArgs):
        identity = context.identities.get(args.account)
        if identity is None:  # its tags can't be known, so fail closed
            return PolicyResult("BLOCK_RULE", f"disable_account: no account named {args.account!r}")
        tags = {identity.account_type, *config.account_tags.get(args.account, [])}
        if protected := sorted(tags & set(config.protected_account_tags)):
            return PolicyResult(
                "BLOCK_RULE", f"disable_account may not target {args.account!r}: it is tagged "
                f"{', '.join(protected)}, which the policy protects",
            )
    if isinstance(args, SearchArgs) and args.window_hours > config.max_window_hours:
        return PolicyResult(
            "BLOCK_RULE", f"window_hours is {args.window_hours:g}; the policy allows at most {config.max_window_hours:g}"
        )

    # 4. Rate. The count is of earlier calls, so the limit-th call is the last one allowed.
    if context.calls_last_minute >= config.rate_limit_per_minute:
        return PolicyResult(
            "BLOCK_RATE", f"Client {call.client_id!r} made {context.calls_last_minute} calls in the last "
            f"minute; the limit is {config.rate_limit_per_minute}",
        )

    # 5. Allow.
    needs_approval = call.tool in config.approval_required
    reason = "Allowed by the policy" + (", pending human approval" if needs_approval else "")
    return PolicyResult("ALLOW", reason, args=args, needs_approval=needs_approval)


def _describe(error: ValidationError) -> str:
    """Each failing field and what is wrong with it, without echoing the client's input."""
    return "; ".join(
        f"{'.'.join(map(str, e['loc'])) or 'arguments'}: {e['msg']}" for e in error.errors(include_url=False)
    )
