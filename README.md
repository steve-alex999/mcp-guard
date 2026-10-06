# MCP Guard

An MCP server that exposes security-triage tools to any MCP client (Claude Desktop, Claude
Code), with a gateway that checks every tool call before it runs: an allowlist per client,
schema and argument rules, a rate limit, human approval for high-risk writes, a
prompt-injection scan of tool outputs, and an append-only audit log. The lookup tools and the synthetic data come from
[alert-triage-agent](https://github.com/steve-alex999/alert-triage-agent), imported, not
copied. See [SPEC.md](SPEC.md) for the full design.

**Status: milestone 4 of 4, apart from the demo GIF.** The MCP server, the gateway, the
simulated write tools, the approval queue, the audit log, the admin API, the dashboard, the
injection scanner and the eval harness work. The policy checks themselves
(`gateway/policy.py`) are a TODO: until `check()` is written, the gateway fails closed and
blocks every call with `BLOCK_ERROR`, and the eval reports its gateway results as not run.

## Setup

Needs Python 3.12+ and the triage project checked out next to this one.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ../alert-triage-agent -e '.[dev]'
pytest
```

`tests/test_policy.py` describes what `policy.check()` must do and fails until it is
written. To run everything else: `pytest --ignore=tests/test_policy.py`.

## Run it

```bash
python -m gateway.server --transport stdio --client-id claude-desktop    # what an MCP client launches
python -m gateway.server --transport http --port 8765 --admin-port 8766  # MCP at http://127.0.0.1:8765/mcp, admin API on 8766
python -m gateway.admin_api --port 8766                                   # the admin API on its own
cd dashboard && npm install && npm run dev                                # the dashboard, at http://localhost:3000
```

Gateway processes and the admin API share state through `data/guard.db` (SQLite) and
`policy.yaml`, so the admin API can run on its own next to any number of gateways. That is
the setup to use with Claude Desktop, which starts its own stdio gateway.

At startup the server indexes the 300 change records in an in-memory Qdrant. With the
default fastembed model this took about 12 s here; `EMBEDDING_PROVIDER=hash` makes it
near-instant at the cost of search quality.

| Env var | Default | Effect |
| --- | --- | --- |
| `EMBEDDING_PROVIDER` | `fastembed` | `hash` uses triage's deterministic bag-of-words embedder (no model download) |
| `TRIAGE_DATA_DIR` | `../alert-triage-agent/data` | Where the synthetic `*.jsonl` files are read from |
| `MCP_GUARD_CLIENT_ID` | `anonymous` | Default for `--client-id` |
| `MCP_GUARD_POLICY` | `policy.yaml` | Default for `--policy` |
| `MCP_GUARD_DB` | `data/guard.db` | Default for `--db` |
| `MCP_GUARD_DASHBOARD_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Origins the admin API allows (CORS) |

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

To approve or deny high-risk calls, run `python -m gateway.admin_api` and the dashboard, and
use its Pending page. A held call waits up to `approval_timeout_s` (120 s); the gateway sends
MCP progress notifications while it waits, for clients that ask for them.

Claude Desktop writes the server's stderr to `~/Library/Logs/Claude/mcp-server-mcp-guard.log`,
with one line per tool call.

## Use it from Claude Code

```bash
claude mcp add mcp-guard -- /Users/stephen/Reaper/mcp-guard/.venv/bin/python -m gateway.server --transport stdio --client-id claude-code
```

## Tools

The read tools' schemas are generated from triage's Pydantic argument models and use the
descriptions the triage agent uses. All argument models forbid extra fields.

| Tool | Arguments | Risk | Does |
| --- | --- | --- | --- |
| `search_change_records` | `query`, `host?`, `account?`, `around?` (ISO 8601), `window_hours` (0–168, default 24) | read | Up to 5 change tickets with scores |
| `get_asset` | `hostname` | read | Owner, criticality, environment, role, IP |
| `get_identity` | `name` | read | Account type, team, owner, credential-change history |
| `check_indicator` | `value` (IP or domain) | read | Whether it is on the threat-intel list |
| `close_alert` | `alert_id`, `verdict` (benign or threat), `reason` | medium | Simulated |
| `disable_account` | `account`, `reason` | high | Simulated |
| `quarantine_host` | `hostname`, `reason` | high | Simulated |

The write tools are simulated: they check that the alert, account or host exists, record the
action in the `actions` table and return a confirmation. Nothing real changes.

Results come back as JSON text plus `structuredContent`, with `_meta.mcp_guard` holding the
call's audit ID and decision. A blocked call comes back with `isError: true` and the reason.

## How a call is checked

`Gateway.guarded_call()` in [gateway/server.py](gateway/server.py) runs every call:

1. `policy.check()` decides from the client ID, the tool, the raw arguments, `policy.yaml`,
   the identities and the client's call count over the last minute: allowlist
   (`BLOCK_NOT_ALLOWED`), schema (`BLOCK_SCHEMA`), argument rules (`BLOCK_RULE`), rate
   (`BLOCK_RATE`), or `ALLOW`, possibly needing approval. If it raises, or returns ALLOW
   without validated arguments, the gateway blocks the call with `BLOCK_ERROR`.
2. A call that needs approval is queued and waits for a decision: `BLOCK_DENIED`, or
   `BLOCK_TIMEOUT` after `approval_timeout_s` or if the client cancels.
3. Allowed calls run.
4. A read tool's output is scanned for injected instructions (see below). If anything is
   found, the flagged fields are redacted or wrapped, and the decision becomes
   `ALLOW_REDACTED`.
5. One row goes into the audit log, whatever happened, with the scanner's findings.

## policy.yaml

| Field | Meaning |
| --- | --- |
| `clients.<id>.tools` | Tools that client may call |
| `approval_required` | Tools held for a human decision |
| `approval_timeout_s` | How long a held call waits |
| `protected_account_tags` | `disable_account` may not target accounts with these tags |
| `account_tags` | Extra tags per account. Every account is also tagged with its type (human, service or scanner). `identities.jsonl` has no admin flag, so the it-ops team's people are tagged `admin` here |
| `rate_limit_per_minute` | Calls per client per minute, blocked ones included |
| `max_window_hours` | Cap on `search_change_records` `window_hours` |
| `max_arg_chars` | Cap on a call's arguments, as JSON |
| `scanner.mode` | What to do with flagged fields in read-tool outputs: `redact`, `envelope` or `off` |
| `scanner.llm` | Also ask an LLM classifier (needs an LLM, see below) |

Gateways re-read the file when it changes. `PUT /policy` rewrites it, dropping comments.

## Injection scanner

[gateway/scanner.py](gateway/scanner.py) checks every string field in a read tool's output.
Change-record text is where an attacker could plant instructions, but every field is checked.

- **Rules**, always on: phrases like "ignore previous instructions" and "you are now",
  notes addressed to an AI agent or assistant, role markup (`</system>`, `[INST]`), `system:`
  prefixes, requests to call a tool or mentions of the write tools, verdict steering
  (`escalate=false`, "close this as benign", "do not page"), base64 that decodes to text,
  and zero-width or bidirectional-control characters.
- **An LLM classifier**, off by default (`scanner.llm`): one call per tool output, asking
  which fields address an AI agent. It uses triage's model adapter, so it needs
  `GEMINI_API_KEY` (or `TRIAGE_PROVIDER=ollama`). If the call fails, the rules still apply.

In `redact` mode a flagged field becomes `[REDACTED: <rules>]`. In `envelope` mode it
becomes `{"untrusted_content": ..., "warning": ...}`. Either way, the findings (field path,
rule and matched text) go into the audit log and the dashboard.

The rules are regular expressions, so they miss what they don't anticipate: an injection in
another language, letters spaced out with hyphens, an appeal to authority with no
instruction-like wording, or a polite request in plain prose. The eval includes one of each.

## Dashboard

A Next.js app (App Router, TypeScript, Tailwind) in [dashboard/](dashboard). It needs Node
20.9+ and reads everything from the admin API at `http://127.0.0.1:8766`;
`NEXT_PUBLIC_ADMIN_API` points it elsewhere.

| Page | Shows |
| --- | --- |
| `/` | The call feed: time, client, tool, decision and latency, filterable by decision and client |
| `/calls/[id]` | One call: arguments, output (redacted spans highlighted), scanner findings, the policy's reason, and the approval if it had one |
| `/pending` | Calls waiting for a human, with Approve and Deny, an optional note, and the time left before they time out |
| `/policy` | The policy, read-only, with toggles for the scanner mode and for which tools need approval |

Pages render on the server for each request; the feed, the queue and the pending count in
the header then poll the admin API from the browser every 2 s. A held call's latency
includes the time it waited for a human.

## Evaluation

```bash
python eval/run_eval.py                               # attack cases, benign replay, scanner metrics
python eval/run_eval.py --scanner-llm                 # also score the scanner with its LLM layer
python eval/run_eval.py --llm --setup guard --runs 3  # also triage alerts with an LLM through the gateway
python eval/run_eval.py --readme                      # and write the table below
```

[eval/run_eval.py](eval/run_eval.py) writes `eval/results/summary.json` and
`eval/results/cases.jsonl`. It runs:

- **Attack cases** from [eval/attacks.jsonl](eval/attacks.jsonl), 42 calls with an expected
  decision each:
  - out-of-scope calls (`untrusted-agent` calling `disable_account`, an unknown client, an
    unknown tool);
  - rule violations (disabling service and admin accounts, an over-wide search window);
  - schema abuse (extra fields, wrong types, 5,000- and 10,000-character strings);
  - approvals the harness denies or approves;
  - a 31-call flood;
  - 12 poisoned change records and 4 harmless lookalikes.

  Each poisoned record is pinned to a threat alert's host, account and time. No real record
  matches a threat alert's window, so searching for that alert returns the poisoned record
  alone. A malicious call counts as stopped if it is blocked, or if its output comes back
  `ALLOW_REDACTED`.
- **A benign replay**: for each of the 120 alerts, the lookups an analyst would make (search,
  asset, identity, and indicators for external addresses), about 400 calls as `eval-agent`.
  Each call is timed against the toolbox directly and through the gateway, and the
  difference is the added latency. Each alert gets a fresh audit log, because the replay runs
  far faster than the 30-calls-a-minute limit; the flood case tests that limit.
- **Scanner precision and recall** on labelled fields. The injected fields are the 10 alerts
  in triage's data that carry an injection string, plus the 12 poisoned records. The benign
  fields are everything else: the other alerts, every change record's title and description,
  every identity and asset field, and the lookalikes. The rules were written with triage's 10
  injection strings in view, so recall on those is in-sample. The poisoned records were
  written before the rules were first run against them, and were not tuned against afterwards.
- **With `--llm`**: triage's agent loop (`--setup agent` or `guard`) triages the alerts with
  every lookup going through the gateway. It records false blocks (calls the gateway refused
  that the toolbox would have answered) and added latency. It then triages the poisoned
  records' alerts with the scanner off and on, and counts how often the verdict came out the
  attacker's way. triage's agent has no write tools, so this measures steering, not write
  attempts.

The gateway parts need `policy.check()`; until it exists they report "not run". Without an
LLM, the LLM parts report "not run" too.

### Results

<!-- results:start -->
Generated 2026-10-06 04:12 UTC · 42 attack cases · embedder fastembed:BAAI/bge-small-en-v1.5 · scanner mode redact

| Metric | Result |
| --- | --- |
| Gateway: attack cases, benign replay | not run: gateway/policy.py check() is not implemented yet |
| Scanner precision, rules only | 100% (0 of 1537 benign fields flagged) |
| Scanner recall, rules only: triage injections / poisoned records | 10/10 / 8/12 |
| Scanner, rules + LLM | not run: needs an LLM (set GEMINI_API_KEY) and --scanner-llm or --llm |
| LLM triage through the gateway | not run: gateway/policy.py check() is not implemented yet |
<!-- results:end -->

Synthetic data, small numbers, one machine. The attack cases and the scanner rules were
written by the same person, so treat the scanner's numbers as a sanity check, not a
benchmark.

## Admin API

| Endpoint | Does |
| --- | --- |
| `GET /calls?limit=&decision=&client_id=` | Audit log, newest first |
| `GET /calls/{id}` | One call, with its approval if it had one |
| `GET /pending` | Approvals waiting for a decision, oldest first |
| `POST /pending/{id}/approve`, `POST /pending/{id}/deny` | Body (optional): `{"by": "...", "note": "..."}`. 404 if unknown, 409 if already resolved |
| `GET /tools` | The tools, with risk and whether they write |
| `GET /policy`, `PUT /policy` | Read or replace the policy; an invalid policy is rejected with 422 |

Interactive docs are at `http://127.0.0.1:8766/docs`.

## Audit log

SQLite tables as in SPEC.md section 7, with two additions. `approvals` also stores the
call's client, tool and arguments, because the `calls` row is written only once the call
finishes, and the approver needs to see what they are approving. `BLOCK_ERROR` is an extra
decision, for calls blocked because the policy check failed. Triggers make `calls`
append-only: SQLite rejects any UPDATE or DELETE on it.

## Design notes

- `mcp` 2.x renamed `FastMCP` to `MCPServer`; this uses `MCPServer`.
- `GuardServer` overrides `MCPServer.list_tools` and `call_tool` instead of registering
  decorated functions. A decorated function's arguments are validated by the SDK before any
  of our code runs, so a schema violation could never be blocked and audited by the gateway.
  Here every call, valid or not, reaches `guarded_call()`.
- Approvals are rows in SQLite that the waiting gateway polls every 0.5 s, so a gateway
  started by Claude Desktop can be approved from an admin API in another process. A
  resolution only applies to a row that is still pending, so a late approve cannot race a
  timeout.

## Limitations

Everything is local and synthetic: no real SIEM, directory or threat feed. There is no
authentication on the MCP server, the admin API or the dashboard: anyone who can reach them
can approve calls and change the policy. The servers listen on 127.0.0.1 only. The client
ID is whatever the process was started with, and in HTTP mode all connections share it.
