// Paths shared by playwright.config.ts and the smoke test.
import os from "node:os";
import path from "node:path";

export const ROOT = path.resolve(__dirname, "..", "..");
/** The Python with mcp-guard and alert-triage-agent installed. */
export const PYTHON = process.env.PYTHON ?? path.join(ROOT, ".venv", "bin", "python");
/** A fresh audit database for each run, shared by the admin API and scripts/demo.py. */
export const DB_DIR = path.join(os.tmpdir(), "mcp-guard-e2e");
export const DB = path.join(DB_DIR, "guard.db");
export const SCREENSHOTS = path.join(ROOT, "eval", "results", "screenshots");
