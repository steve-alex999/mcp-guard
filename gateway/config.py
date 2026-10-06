"""policy.yaml: which client may call which tool, approval rules and limits.

PolicyFile re-reads the file whenever it changes on disk, so an edit, or a PUT /policy from the
admin API in this or another process, applies from the next tool call.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from gateway.tools import TOOLS

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policy.yaml"
HEADER = "# MCP Guard policy. Field reference: gateway/config.py. PUT /policy rewrites this file.\n"

log = logging.getLogger(__name__)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClientPolicy(Strict):
    tools: list[str] = Field(description="Tools this client may call; everything else is BLOCK_NOT_ALLOWED")


class ScannerPolicy(Strict):
    mode: Literal["redact", "envelope", "off"] = "redact"


class PolicyConfig(Strict):
    clients: dict[str, ClientPolicy]
    approval_required: list[str] = Field(default=[], description="Tools held for a human decision")
    approval_timeout_s: float = Field(default=120, gt=0)
    protected_account_tags: list[str] = Field(
        default=[], description="disable_account may not target an account with any of these tags"
    )
    account_tags: dict[str, list[str]] = Field(
        default={},
        description="Extra tags per account. An account is always tagged with its type (human, service or "
        "scanner); identities.jsonl has no admin flag, so admins are tagged here.",
    )
    rate_limit_per_minute: int = Field(default=30, gt=0, description="Calls per client per minute")
    max_window_hours: float = Field(default=168, gt=0, description="Cap on search_change_records window_hours")
    max_arg_chars: int = Field(default=2000, gt=0, description="Cap on the length of a call's arguments as JSON")
    scanner: ScannerPolicy = ScannerPolicy()

    @model_validator(mode="after")
    def _known_tools(self) -> PolicyConfig:
        named = {t for c in self.clients.values() for t in c.tools} | set(self.approval_required)
        if unknown := sorted(named - TOOLS.keys()):
            raise ValueError(f"Unknown tools: {', '.join(unknown)}")
        return self


def policy_path() -> Path:
    return Path(os.environ.get("MCP_GUARD_POLICY", DEFAULT_POLICY))


def load_policy(path: Path) -> PolicyConfig:
    return PolicyConfig.model_validate(yaml.safe_load(path.read_text()))


class PolicyFile:
    def __init__(self, path: Path):
        self.path = path
        self._config = load_policy(path)  # an invalid file at startup is an error
        self._mtime = path.stat().st_mtime_ns

    def current(self) -> PolicyConfig:
        """The policy as of the file's last valid version."""
        try:
            mtime = self.path.stat().st_mtime_ns
            if mtime != self._mtime:
                self._mtime = mtime
                self._config = load_policy(self.path)
                log.info("Reloaded %s", self.path)
        except (OSError, yaml.YAMLError, ValidationError):
            log.exception("Could not reload %s; keeping the previous policy", self.path)
        return self._config

    def save(self, config: PolicyConfig) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(HEADER + yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False))
        os.replace(tmp, self.path)
