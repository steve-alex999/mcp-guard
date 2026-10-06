# MCP Guard: cloud run instructions (Claude Code on the web)

Read SPEC.md for the full design. This file only changes what is different when the build runs in a Claude Code cloud session instead of on Stephen's Mac. Where the two disagree, this file wins.

## What is different in the cloud

| Topic | Local SPEC.md | Cloud (use this) |
|---|---|---|
| Triage dependency | `pip install -e ../alert-triage-agent` | `pip install "git+https://github.com/steve-alex999/alert-triage-agent.git"`. If the repo is private or the install fails, clone it into `vendor/alert-triage-agent` (gitignored) and `pip install -e vendor/alert-triage-agent`. Never modify it. |
| Data files | read from the sibling repo | locate `data/*.jsonl` inside the installed package or the vendor clone via a single `TRIAGE_DATA_DIR` env var (default: auto-detect); document it in README |
| Qdrant | whatever triage uses | use Qdrant in-memory / local mode (`QdrantClient(":memory:")` or a path under `.cache/`); no Docker in the session |
| Embeddings | fastembed | fastembed downloads a model on first run; if the download is blocked by the network, fall back to a deterministic hash embedder behind a flag and say so in README |
| MCP client for testing | Claude Desktop | no desktop app in the cloud: test with an in-process MCP client (Python `mcp` SDK `ClientSession` over stdio) in `tests/test_server.py`; keep the Claude Desktop config snippet in README for Stephen to use later |
| LLM for the eval | Gemini / Ollama | no Ollama in the cloud. Use the triage project's OpenAI-compatible adapter with an API key from an env var (`GEMINI_API_KEY` or `OPENAI_API_KEY`). If no key is set, run only the scripted (non-LLM) eval cases and mark LLM results as "not run" |
| Dashboard check | browser at localhost:3000 | run `npm run build` and `npm run lint`; add a Playwright smoke test (start gateway + `next start`, load `/`, `/pending`, approve one pending call) and save screenshots to `eval/results/screenshots/` |
| Docker Compose | optional | write `docker-compose.yml` for Stephen, but do not rely on running it in the session |

## Session setup (run first)

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"            # pyproject must list: mcp, fastapi, uvicorn, pydantic, pyyaml, qdrant-client, fastembed, pytest, httpx
pip install "git+https://github.com/steve-alex999/alert-triage-agent.git" || (git clone https://github.com/steve-alex999/alert-triage-agent vendor/alert-triage-agent && pip install -e vendor/alert-triage-agent)
cd dashboard && npm ci || npm install && cd ..
pytest -q
```

## Order of work (one PR per milestone)

1. **M1 MCP server:** `gateway/server.py` exposes the four read tools by wrapping `triage.tools.Toolbox`. Tests call every tool through an in-process MCP client. Check current MCP Python SDK docs before writing code; don't guess APIs.
2. **M2 Gateway:** `audit.py`, `approvals.py`, `actions.py` (simulated write tools), `admin_api.py`, `policy.yaml`, `config.py`. `policy.py` gets function signatures, docstrings and FAILING tests only, with `# TODO(Stephen)` bodies. Stephen writes the policy logic himself.
3. **M3 Dashboard:** Next.js App Router + TypeScript; pages from SPEC.md section 9; typed client in `lib/api.ts`; Playwright smoke test.
4. **M4 Scanner + eval:** `scanner.py` (rules first, optional LLM layer behind a flag), `eval/attacks.jsonl`, `eval/run_eval.py`, results table in README. Report real numbers only; mark anything not run.

## Rules for the cloud session

- Work on a branch per milestone (`m1-mcp-server`, ...) and open a PR; do not push to main.
- Never commit API keys, `.env`, model caches, `vendor/`, `node_modules/`, `.cache/` or `*.db` (add them to .gitignore in the first commit).
- Do not implement `gateway/policy.py` bodies; leave TODOs and failing tests.
- Keep every claim in README measured and reproducible; note limitations (synthetic data, local only, no auth on the dashboard).
- At the end of each milestone, post a short summary: what was built, test results, anything blocked by the sandbox (network, downloads), and next steps.
