"""The behaviour gateway/policy.py's check() must have. These fail until it is implemented."""

import copy
from datetime import UTC, datetime

import pytest

from gateway.config import PolicyConfig
from gateway.policy import CallContext, ToolCall, check
from triage.data import load_identities
from triage.tools import AssetArgs, SearchArgs

IDENTITIES = {i.name: i for i in load_identities()}
HUMAN, ADMIN, SERVICE, SCANNER = "aditi.gupta", "dana.oliveira", "svc-backup", "svc-vulnscan"


@pytest.fixture
def config():
    return PolicyConfig.model_validate({
        "clients": {
            "analyst": {"tools": ["search_change_records", "get_asset", "close_alert", "disable_account"]},
            "untrusted-agent": {"tools": ["get_asset"]},
        },
        "approval_required": ["disable_account"],
        "protected_account_tags": ["admin", "service"],
        "account_tags": {ADMIN: ["admin"]},
        "rate_limit_per_minute": 5,
        "max_window_hours": 72,
        "max_arg_chars": 500,
    })


def run(config, tool, args, client="analyst", calls_last_minute=0):
    return check(ToolCall(client, tool, args), config, CallContext(IDENTITIES, calls_last_minute))


def disable(account):
    return {"account": account, "reason": "Logged in from a known-bad IP"}


def test_identities_used_here_exist():
    assert IDENTITIES[HUMAN].account_type == "human"
    assert IDENTITIES[ADMIN].account_type == "human"
    assert IDENTITIES[SERVICE].account_type == "service"
    assert IDENTITIES[SCANNER].account_type == "scanner"


# ---- 1. allowlist ---------------------------------------------------------------------


def test_allows_a_listed_tool(config):
    result = run(config, "get_asset", {"hostname": "web-prod-01"})
    assert result.decision == "ALLOW"
    assert result.args == AssetArgs(hostname="web-prod-01")
    assert result.needs_approval is False
    assert result.reason


def test_blocks_a_tool_the_client_may_not_call(config):
    result = run(config, "disable_account", disable(HUMAN), client="untrusted-agent")
    assert result.decision == "BLOCK_NOT_ALLOWED"
    assert "disable_account" in result.reason


def test_blocks_an_unknown_client(config):
    assert run(config, "get_asset", {"hostname": "web-prod-01"}, client="nobody").decision == "BLOCK_NOT_ALLOWED"


def test_blocks_an_unknown_tool(config):
    assert run(config, "drop_tables", {}).decision == "BLOCK_NOT_ALLOWED"


def test_allowlist_comes_before_schema(config):
    result = run(config, "disable_account", {"bogus": 1}, client="untrusted-agent")
    assert result.decision == "BLOCK_NOT_ALLOWED"


# ---- 2. schema ------------------------------------------------------------------------


@pytest.mark.parametrize(("args", "field"), [
    ({"hostname": "web-prod-01", "extra": "x"}, "extra"),
    ({"hostname": 42}, "hostname"),
    ({}, "hostname"),
], ids=["extra-field", "wrong-type", "missing"])
def test_blocks_invalid_arguments(config, args, field):
    result = run(config, "get_asset", args)
    assert result.decision == "BLOCK_SCHEMA"
    assert field in result.reason


def test_blocks_oversized_arguments(config):
    assert run(config, "search_change_records", {"query": "x" * 1000}).decision == "BLOCK_SCHEMA"


def test_returns_the_validated_arguments(config):
    result = run(config, "search_change_records", {"query": "deploy", "around": "2026-08-10T12:00:00Z"})
    assert result.decision == "ALLOW"
    assert isinstance(result.args, SearchArgs)
    assert result.args.around == datetime(2026, 8, 10, 12, tzinfo=UTC)
    assert result.args.window_hours == 24


# ---- 3. argument rules ----------------------------------------------------------------


@pytest.mark.parametrize(("account", "tag"), [(SERVICE, "service"), (ADMIN, "admin")])
def test_protected_accounts_cannot_be_disabled(config, account, tag):
    result = run(config, "disable_account", disable(account))
    assert result.decision == "BLOCK_RULE"
    assert tag in result.reason


@pytest.mark.parametrize("account", [HUMAN, SCANNER])
def test_other_accounts_can_be_disabled_with_approval(config, account):
    result = run(config, "disable_account", disable(account))
    assert result.decision == "ALLOW"
    assert result.needs_approval is True


def test_protection_follows_the_policy(config):
    config = config.model_copy(update={"protected_account_tags": ["admin"]})
    assert run(config, "disable_account", disable(SERVICE)).decision == "ALLOW"
    assert run(config, "disable_account", disable(ADMIN)).decision == "BLOCK_RULE"


def test_window_hours_is_capped_by_the_policy(config):
    assert run(config, "search_change_records", {"query": "deploy", "window_hours": 72}).decision == "ALLOW"
    assert run(config, "search_change_records", {"query": "deploy", "window_hours": 100}).decision == "BLOCK_RULE"


# ---- 4. rate --------------------------------------------------------------------------


def test_blocks_a_client_over_its_rate_limit(config):
    assert run(config, "get_asset", {"hostname": "web-prod-01"}, calls_last_minute=4).decision == "ALLOW"
    assert run(config, "get_asset", {"hostname": "web-prod-01"}, calls_last_minute=5).decision == "BLOCK_RATE"


# ---- 5. approval ----------------------------------------------------------------------


def test_only_listed_tools_need_approval(config):
    close = {"alert_id": "ALR-1", "verdict": "benign", "reason": "Explained by a change record"}
    assert run(config, "close_alert", close).needs_approval is False
    config = config.model_copy(update={"approval_required": []})
    assert run(config, "disable_account", disable(HUMAN)).needs_approval is False


def test_does_not_modify_its_inputs(config):
    args = disable(HUMAN)
    args_before, config_before = copy.deepcopy(args), config.model_dump()
    run(config, "disable_account", args)
    assert args == args_before
    assert config.model_dump() == config_before
