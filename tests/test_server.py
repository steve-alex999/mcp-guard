import json
import sys
from typing import get_args

import anyio
import pytest
from fastapi.testclient import TestClient
from mcp import Client, StdioServerParameters

from gateway.admin_api import create_app
from gateway.audit import AuditLog, Decision, connect
from gateway.policy import PolicyResult
from gateway.server import GuardServer
from gateway.tools import TOOLS
from triage.data import load_alerts, load_assets, load_identities, load_threat_intel
from triage.tools import AssetArgs

pytestmark = pytest.mark.anyio

HUMAN = "aditi.gupta"
DISABLE = {"account": HUMAN, "reason": "Logged in from a known-bad IP"}


@pytest.fixture
async def client(gateway):
    async with Client(GuardServer(gateway, client_id="test")) as client:
        yield client


def actions_taken(gateway):
    with connect(gateway.actions.path) as conn:
        return [(r["tool"], r["target"]) for r in conn.execute("SELECT tool, target FROM actions")]


async def next_pending(gateway):
    with anyio.fail_after(5):
        while not (pending := gateway.approvals.pending()):
            await anyio.sleep(0.01)
    return pending[0]


# ---- tools ----------------------------------------------------------------------------


async def test_lists_every_tool(client):
    tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) == set(TOOLS)
    for name, tool in tools.items():
        assert tool.description
        assert tool.input_schema["additionalProperties"] is False
        assert tool.annotations.read_only_hint is not TOOLS[name].writes
    assert tools["disable_account"].annotations.destructive_hint is True
    assert tools["close_alert"].annotations.destructive_hint is False


async def test_search_schema_comes_from_the_triage_model(client):
    tools = {t.name: t for t in (await client.list_tools()).tools}
    schema = tools["search_change_records"].input_schema
    assert schema["required"] == ["query"]
    assert schema["properties"]["window_hours"]["maximum"] == 168
    assert "ISO 8601" in schema["properties"]["around"]["description"]


async def test_search_finds_the_named_case_record(client):
    item = next(a for a in load_alerts() if "named_case" in a.label.tags)
    alert = item.alert
    result = await client.call_tool("search_change_records", {
        "query": alert.raw_message, "host": alert.host, "account": alert.principal,
        "around": alert.timestamp.isoformat(),
    })
    assert not result.is_error
    assert result.structured_content["results"][0]["id"] == item.label.change_record_id


async def test_lookups(client):
    asset = load_assets()[0]
    identity = next(i for i in load_identities() if i.account_type == "service")
    bad = load_threat_intel()[0]
    assert (await client.call_tool("get_asset", {"hostname": asset.hostname})).structured_content \
        == asset.model_dump(mode="json")
    assert (await client.call_tool("get_identity", {"name": identity.name})).structured_content \
        == identity.model_dump(mode="json")
    assert (await client.call_tool("check_indicator", {"value": bad.value.upper()})).structured_content["listed"]
    assert not (await client.call_tool("check_indicator", {"value": "x.invalid"})).structured_content["listed"]


async def test_text_content_mirrors_structured_content(client):
    result = await client.call_tool("get_asset", {"hostname": load_assets()[0].hostname})
    assert json.loads(result.content[0].text) == result.structured_content


async def test_unknown_record_is_an_error(client):
    result = await client.call_tool("get_asset", {"hostname": "no-such-host"})
    assert result.is_error
    assert "No asset named 'no-such-host'" in result.content[0].text


async def test_write_tool_records_an_action(client, gateway, alert_ids):
    alert_id = sorted(alert_ids)[0]
    result = await client.call_tool("close_alert", {"alert_id": alert_id, "verdict": "benign", "reason": "Explained"})
    assert result.structured_content["simulated"] is True
    assert actions_taken(gateway) == [("close_alert", alert_id)]


# ---- gateway --------------------------------------------------------------------------


async def test_every_call_is_audited(client, gateway):
    result = await client.call_tool("get_asset", {"hostname": "web-prod-01"})
    [call] = gateway.audit.recent()
    assert result.meta["mcp_guard"] == {"call_id": call.id, "decision": "ALLOW"}
    assert (call.client_id, call.tool, call.decision) == ("test", "get_asset", "ALLOW")
    assert call.args == {"hostname": "web-prod-01"}
    assert call.output == result.structured_content
    assert call.latency_ms >= 0


async def test_blocked_calls_do_not_run(client, gateway, alert_ids):
    gateway.check = lambda call, config, context: PolicyResult("BLOCK_RULE", "Closing alerts is off today")
    args = {"alert_id": sorted(alert_ids)[0], "verdict": "benign", "reason": "Explained"}
    result = await client.call_tool("close_alert", args)
    assert result.is_error
    assert result.content[0].text == json.dumps(
        {"error": "Blocked by MCP Guard (BLOCK_RULE): Closing alerts is off today"}
    )
    [call] = gateway.audit.recent()
    assert (call.decision, call.args, call.output) == ("BLOCK_RULE", args, None)
    assert actions_taken(gateway) == []


def raises(call, config, context):
    raise RuntimeError("bug")


@pytest.mark.parametrize("check", [
    raises,
    lambda call, config, context: PolicyResult("ALLOW", "no args"),
    lambda call, config, context: PolicyResult("ALLOW", "wrong args", args=AssetArgs(hostname="web-prod-01")),
    lambda call, config, context: PolicyResult("BLOCK_DENIED", "only the gateway decides this"),
], ids=["raises", "no-args", "wrong-args", "gateway-decision"])
async def test_policy_misbehaviour_fails_closed(client, gateway, check):
    gateway.check = check
    result = await client.call_tool("disable_account", DISABLE)
    assert result.is_error
    assert gateway.audit.recent()[0].decision == "BLOCK_ERROR"
    assert gateway.approvals.pending() == []
    assert actions_taken(gateway) == []


async def test_check_sees_identities_and_recent_calls(client, gateway, toolbox):
    contexts = []

    def spy(call, config, context):
        contexts.append(context)
        return PolicyResult("BLOCK_RATE", "spying")

    gateway.check = spy
    for _ in range(3):
        await client.call_tool("get_asset", {"hostname": "web-prod-01"})
    assert [c.calls_last_minute for c in contexts] == [0, 1, 2]
    assert contexts[0].identities is toolbox.identities


# ---- approvals ------------------------------------------------------------------------


async def test_approved_call_runs(client, gateway, db, policy_path):
    admin = TestClient(create_app(db, policy_path))
    result = {}
    async with anyio.create_task_group() as tg:
        async def call():
            result["r"] = await client.call_tool("disable_account", DISABLE)

        tg.start_soon(call)
        approval = await next_pending(gateway)
        assert (approval.client_id, approval.tool, approval.args) == ("test", "disable_account", DISABLE)
        response = admin.post(f"/pending/{approval.id}/approve", json={"by": "stephen", "note": "Confirmed"})
        assert response.status_code == 200

    assert not result["r"].is_error
    assert actions_taken(gateway) == [("disable_account", HUMAN)]
    [call] = gateway.audit.recent()
    assert (call.decision, call.reason, call.approval_id) == ("ALLOW", "Approved by stephen: Confirmed", approval.id)


async def test_denied_call_does_not_run(client, gateway):
    async with anyio.create_task_group() as tg:
        async def call():
            result = await client.call_tool("disable_account", DISABLE)
            assert result.is_error
            assert "BLOCK_DENIED" in result.content[0].text

        tg.start_soon(call)
        approval = await next_pending(gateway)
        gateway.approvals.resolve(approval.id, "denied", by="stephen")

    assert gateway.audit.recent()[0].decision == "BLOCK_DENIED"
    assert actions_taken(gateway) == []


async def test_unanswered_approval_times_out(client, gateway):
    gateway.policy.save(gateway.policy.current().model_copy(update={"approval_timeout_s": 0.1}))
    result = await client.call_tool("disable_account", DISABLE)
    assert result.is_error
    [call] = gateway.audit.recent()
    assert call.decision == "BLOCK_TIMEOUT"
    assert gateway.approvals.get(call.approval_id).status == "timeout"
    assert actions_taken(gateway) == []


async def test_progress_is_reported_while_waiting(client, gateway):
    gateway.policy.save(gateway.policy.current().model_copy(update={"approval_timeout_s": 0.2}))
    updates = []

    async def on_progress(progress, total, message):
        updates.append((total, message))

    await client.call_tool("disable_account", DISABLE, progress_callback=on_progress)
    assert updates
    assert updates[0] == (0.2, "Waiting for human approval")


async def test_cancelled_wait_is_audited(gateway):
    async with anyio.create_task_group() as tg:
        tg.start_soon(gateway.guarded_call, "test", "disable_account", DISABLE)
        approval = await next_pending(gateway)
        tg.cancel_scope.cancel()

    assert gateway.approvals.get(approval.id).status == "timeout"
    [call] = gateway.audit.recent()
    assert (call.decision, call.approval_id) == ("BLOCK_TIMEOUT", approval.id)


# ---- entrypoint -----------------------------------------------------------------------


async def test_stdio_entrypoint(tmp_path):
    """The command from the Claude Desktop config, run from an unrelated working directory with the
    real policy. Whatever policy.check decides, the call is answered and audited."""
    db = tmp_path / "guard.db"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gateway.server", "--transport", "stdio", "--client-id", "claude-desktop"],
        env={"EMBEDDING_PROVIDER": "hash", "MCP_GUARD_DB": str(db)},
        cwd=tmp_path,
    )
    async with Client(params) as client:
        assert len((await client.list_tools()).tools) == len(TOOLS)
        result = await client.call_tool("get_asset", {"hostname": "web-prod-01"})
    meta = result.meta["mcp_guard"]
    assert meta["decision"] in get_args(Decision)
    assert AuditLog(db).get(meta["call_id"]).decision == meta["decision"]
