# MCP Guard

An MCP server that exposes security-triage lookup tools to any MCP client (Claude Desktop,
Claude Code), with a gateway that will check every tool call before it runs. The tools and the
synthetic data come from [alert-triage-agent](../alert-triage-agent), imported, not copied.
See [SPEC.md](SPEC.md) for the full design.

**Status: milestone 1 of 4.** The MCP server and its four read tools work over stdio and
Streamable HTTP. The gateway (allowlist, schema and argument rules, approvals, audit log),
the dashboard, the injection scanner and the eval come in milestones 2 to 4.

## Setup

Needs Python 3.12+ and the triage project checked out next to this one.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ../alert-triage-agent -e '.[dev]'
pytest
```

## Run it

```bash
python -m gateway.server --transport stdio --client-id claude-desktop   # what an MCP client launches
python -m gateway.server --transport http --port 8765                    # Streamable HTTP at http://127.0.0.1:8765/mcp
```

At startup the server indexes the 300 change records in an in-memory Qdrant. With the
default fastembed model this took about 12 s here; `EMBEDDING_PROVIDER=hash` makes it
near-instant at the cost of search quality.

| Env var | Default | Effect |
| --- | --- | --- |
| `EMBEDDING_PROVIDER` | `fastembed` | `hash` uses triage's deterministic bag-of-words embedder (no model download) |
| `TRIAGE_DATA_DIR` | `../alert-triage-agent/data` | Where the synthetic `*.jsonl` files are read from |
| `MCP_GUARD_CLIENT_ID` | `anonymous` | Default for `--client-id` |

## Use it from Claude Desktop

Add this to `~/Library/Application Support/Claude/claude_desktop_config.json`, then restart
Claude Desktop:

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "/Users/stephen/Reaper/mcp-guard/.venv/bin/python",
      "args": ["-m", "gateway.server", "--transport", "stdio", "--client-id", "claude-desktop"]
    }
  }
}
```

The command is the venv's Python by absolute path, because Claude Desktop does not launch
servers from your shell, so a bare `python` would not find the installed packages. Nothing
depends on the working directory.

Then ask something like *"Look up the asset db-prod-01 and any change records for it in
the last week."* Claude Desktop writes the server's stderr to
`~/Library/Logs/Claude/mcp-server-mcp-guard.log`, with one line per tool call.

## Use it from Claude Code

```bash
claude mcp add mcp-guard -- /Users/stephen/Reaper/mcp-guard/.venv/bin/python -m gateway.server --transport stdio --client-id claude-code
```

## Tools

The schemas are generated from triage's Pydantic argument models (`extra="forbid"`), and
the descriptions are the ones the triage agent uses. All four are annotated read-only.

| Tool | Arguments | Returns |
| --- | --- | --- |
| `search_change_records` | `query`, `host?`, `account?`, `around?` (ISO 8601), `window_hours` (0–168, default 24) | Up to 5 change tickets with scores |
| `get_asset` | `hostname` | Owner, criticality, environment, role, IP |
| `get_identity` | `name` | Account type, team, owner, credential-change history |
| `check_indicator` | `value` (IP or domain) | Whether it is on the threat-intel list, with type and confidence |

Each result comes back as JSON text plus `structuredContent`. Unknown records, invalid
arguments and unknown tools come back with `isError: true` and a readable message.

## Design notes

- `mcp` 2.x renamed `FastMCP` to `MCPServer`; this uses `MCPServer`.
- `GuardServer` overrides `MCPServer.list_tools` and `call_tool` instead of registering
  decorated functions. A decorated function's arguments are validated by the SDK before
  any of our code runs, so a schema violation could never be blocked and audited by the
  gateway. Here every call, valid or not, reaches `guarded_call()`.
- `search_change_records` returns text from change tickets. Milestone 4 scans it for
  injected instructions; until then it is passed through unchanged.

## Limitations

Everything is local and synthetic: no real SIEM, directory or threat feed. There is no
authentication. In HTTP mode, all connections share the process's `--client-id`.
