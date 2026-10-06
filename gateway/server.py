"""MCP server that exposes the triage lookup tools, routing every call through guarded_call().

    python -m gateway.server --transport stdio --client-id claude-desktop
    python -m gateway.server --transport http --port 8765

The change-record index is built in memory at startup. EMBEDDING_PROVIDER=hash skips the
fastembed model, and TRIAGE_DATA_DIR points at a different copy of the triage data/ folder.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import anyio
from mcp.server.mcpserver import Context, MCPServer
from mcp_types import CallToolResult, TextContent, Tool, ToolAnnotations
from pydantic import BaseModel
from qdrant_client import QdrantClient

from triage.data import DATA_DIR, load_assets, load_change_records, load_identities, load_threat_intel
from triage.embeddings import get_embedder
from triage.tools import LOOKUP_TOOLS, AssetArgs, IdentityArgs, IndicatorArgs, SearchArgs, Toolbox, ensure_index

log = logging.getLogger("gateway")

# name -> (title, argument model). The models are triage's own, with extra="forbid".
READ_TOOLS: dict[str, tuple[str, type[BaseModel]]] = {
    "search_change_records": ("Search change records", SearchArgs),
    "get_asset": ("Get asset", AssetArgs),
    "get_identity": ("Get identity", IdentityArgs),
    "check_indicator": ("Check indicator", IndicatorArgs),
}

_TRIAGE_FUNCTIONS = {t["function"]["name"]: t["function"] for t in LOOKUP_TOOLS}


def input_schema(name: str, model: type[BaseModel]) -> dict[str, Any]:
    """The argument model's JSON schema, with the field descriptions triage gives the model."""
    schema = model.model_json_schema()
    described = _TRIAGE_FUNCTIONS[name]["parameters"]["properties"]
    for field, prop in schema["properties"].items():
        if "description" in described.get(field, {}):
            prop["description"] = described[field]["description"]
    return schema


def mcp_tool(name: str) -> Tool:
    title, model = READ_TOOLS[name]
    return Tool(
        name=name,
        title=title,
        description=_TRIAGE_FUNCTIONS[name]["description"],
        input_schema=input_schema(name, model),
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
    )


class GuardServer(MCPServer):
    """An MCPServer that lists its tools itself and hands raw arguments to guarded_call().

    MCPServer's tool registry derives schemas from function signatures and validates arguments
    before the tool body runs. The gateway needs the raw arguments, so that schema failures are
    blocked and audited like any other policy decision, so list_tools and call_tool are
    overridden instead.
    """

    def __init__(self, toolbox: Toolbox, client_id: str):
        super().__init__(
            name="mcp-guard",
            version="0.1.0",
            instructions="Read-only lookups for triaging security alerts against a synthetic dataset: "
            "change records, assets, identities and threat intel.",
        )
        self.toolbox = toolbox
        self.client_id = client_id

    async def list_tools(self) -> list[Tool]:
        return [mcp_tool(name) for name in READ_TOOLS]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], context: Context[Any, Any] | None = None
    ) -> CallToolResult:
        output = await self.guarded_call(self.client_id, name, arguments)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(output))],
            structured_content=output,
            is_error="error" in output,
        )

    async def guarded_call(self, client_id: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        """Run one tool call for `client_id`.

        Milestone 1 runs the call as is: Toolbox.call validates the arguments against the
        triage models and answers unknown tools with an error. The policy checks, output scan
        and audit row from SPEC.md section 5 go here in milestone 2.
        """
        started = time.monotonic()
        output = await anyio.to_thread.run_sync(self.toolbox.call, tool, args)
        log.info("%s %s -> %s in %.0f ms", client_id, tool, "error" if "error" in output else "ok",
                 (time.monotonic() - started) * 1000)
        return output


def load_toolbox() -> Toolbox:
    """Build triage's Toolbox with the change-record index in memory.

    triage.store.get_client() would default to embedded storage inside the triage repo,
    which locks that folder and writes into a project this one must not modify.
    """
    data_dir = Path(os.environ.get("TRIAGE_DATA_DIR", DATA_DIR))
    client, embedder = QdrantClient(":memory:"), get_embedder()
    ensure_index(client, embedder, load_change_records(data_dir))
    return Toolbox(client, embedder, load_assets(data_dir), load_identities(data_dir), load_threat_intel(data_dir))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--client-id", default=os.environ.get("MCP_GUARD_CLIENT_ID", "anonymous"),
                        help="Who is calling; the policy allowlist is keyed on this")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP transport only")
    parser.add_argument("--port", type=int, default=8765, help="HTTP transport only")
    args = parser.parse_args()

    # stdout carries the stdio transport, so logs go to stderr.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(message)s")
    started = time.monotonic()
    toolbox = load_toolbox()
    log.info("Indexed change records with %s in %.1f s", toolbox.embedder.name, time.monotonic() - started)

    server = GuardServer(toolbox, args.client_id)
    if args.transport == "stdio":
        server.run("stdio")
    else:
        server.run("streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
