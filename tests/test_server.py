import json
import sys

import pytest
from mcp import Client, StdioServerParameters
from qdrant_client import QdrantClient

from gateway.server import READ_TOOLS, GuardServer
from triage.data import load_alerts, load_assets, load_identities, load_threat_intel
from triage.embeddings import HashEmbedder
from triage.tools import Toolbox

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
def toolbox():
    return Toolbox.load(QdrantClient(":memory:"), HashEmbedder())


@pytest.fixture
async def client(toolbox):
    async with Client(GuardServer(toolbox, client_id="test")) as client:
        yield client


async def test_lists_the_four_read_tools(client):
    tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) == set(READ_TOOLS)
    for tool in tools.values():
        assert tool.description
        assert tool.input_schema["additionalProperties"] is False
        assert tool.annotations.read_only_hint is True


async def test_search_schema_comes_from_the_triage_model(client):
    tools = {t.name: t for t in (await client.list_tools()).tools}
    schema = tools["search_change_records"].input_schema
    assert schema["required"] == ["query"]
    assert schema["properties"]["window_hours"]["maximum"] == 168
    assert schema["properties"]["window_hours"]["exclusiveMinimum"] == 0
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


async def test_get_asset(client):
    asset = load_assets()[0]
    result = await client.call_tool("get_asset", {"hostname": asset.hostname})
    assert not result.is_error
    assert result.structured_content == asset.model_dump(mode="json")


async def test_get_identity(client):
    identity = next(i for i in load_identities() if i.account_type == "service")
    result = await client.call_tool("get_identity", {"name": identity.name})
    assert not result.is_error
    assert result.structured_content == identity.model_dump(mode="json")


async def test_check_indicator(client):
    bad = load_threat_intel()[0]
    listed = await client.call_tool("check_indicator", {"value": bad.value.upper()})
    assert listed.structured_content == {
        "value": bad.value.upper(), "listed": True, "threat_type": bad.threat_type, "confidence": bad.confidence,
    }
    clean = await client.call_tool("check_indicator", {"value": "nothing-here.invalid"})
    assert clean.structured_content == {"value": "nothing-here.invalid", "listed": False}


async def test_text_content_mirrors_structured_content(client):
    result = await client.call_tool("get_asset", {"hostname": load_assets()[0].hostname})
    assert json.loads(result.content[0].text) == result.structured_content


async def test_unknown_record_is_an_error(client):
    result = await client.call_tool("get_asset", {"hostname": "no-such-host"})
    assert result.is_error
    assert "No asset named 'no-such-host'" in result.content[0].text


@pytest.mark.parametrize("arguments", [
    {"hostname": "web-prod-01", "extra": "field"},
    {"hostname": 42},
    {},
])
async def test_invalid_arguments_are_a_readable_error(client, arguments):
    result = await client.call_tool("get_asset", arguments)
    assert result.is_error
    assert "Invalid arguments for get_asset" in result.content[0].text


async def test_window_hours_is_capped(client):
    result = await client.call_tool("search_change_records", {"query": "deploy", "window_hours": 500})
    assert result.is_error
    assert "window_hours" in result.content[0].text


async def test_unknown_tool_is_an_error(client):
    result = await client.call_tool("disable_account", {"account": "svc-backup", "reason": "test"})
    assert result.is_error
    assert "Unknown tool 'disable_account'" in result.content[0].text


async def test_stdio_entrypoint(tmp_path):
    """The command from the Claude Desktop config, run from an unrelated working directory."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gateway.server", "--transport", "stdio", "--client-id", "claude-desktop"],
        env={"EMBEDDING_PROVIDER": "hash"},
        cwd=tmp_path,
    )
    asset = load_assets()[0]
    async with Client(params) as client:
        assert len((await client.list_tools()).tools) == len(READ_TOOLS)
        result = await client.call_tool("get_asset", {"hostname": asset.hostname})
    assert result.structured_content == asset.model_dump(mode="json")
