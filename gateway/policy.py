"""The policy checks that run before every tool call (SPEC.md section 5, steps 2 to 5).

The gateway (Gateway.guarded_call in gateway/server.py) calls check() once per call, before
anything runs, and acts on the result:
- ALLOW: run the tool with `result.args`. If `result.needs_approval` is set, hold the call for a
  human first; a denial or timeout becomes BLOCK_DENIED or BLOCK_TIMEOUT.
- BLOCK_*: don't run it. The client sees `result.reason`.
If check() raises, returns a decision it should not, or returns ALLOW without validated args,
the gateway fails closed with BLOCK_ERROR. It writes the audit row in every case.

TODO(Stephen): implement check(). tests/test_policy.py pins down the behaviour and fails until
then; until it passes, every call through the gateway is blocked with BLOCK_ERROR.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from gateway.audit import Decision
from gateway.config import PolicyConfig
from gateway.tools import TOOLS  # name -> ToolSpec; .args is the tool's argument model
from triage.models import Identity

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
    # TODO(Stephen)
    raise NotImplementedError("policy.check is not implemented yet: see the TODO in gateway/policy.py")
