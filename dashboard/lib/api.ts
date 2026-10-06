// Typed client for the gateway's admin API (gateway/admin_api.py). Server components call it at
// request time; client components call it from the browser when they poll.

export const ADMIN_API = process.env.NEXT_PUBLIC_ADMIN_API ?? "http://127.0.0.1:8766";

export const DECISIONS = [
  "ALLOW",
  "ALLOW_REDACTED",
  "BLOCK_NOT_ALLOWED",
  "BLOCK_SCHEMA",
  "BLOCK_RULE",
  "BLOCK_RATE",
  "BLOCK_DENIED",
  "BLOCK_TIMEOUT",
  "BLOCK_ERROR",
] as const;
export type Decision = (typeof DECISIONS)[number];

/** One output-scanner hit: which field, which rule, and the text that matched. */
export interface Finding {
  path: string;
  rule: string;
  snippet: string;
}

export interface CallRecord {
  id: string;
  ts: string;
  client_id: string;
  tool: string;
  args: unknown;
  decision: Decision;
  reason: string;
  output: unknown;
  findings: Finding[];
  latency_ms: number;
  approval_id: string | null;
}

export interface Approval {
  id: string;
  call_id: string;
  created_ts: string;
  status: "pending" | "approved" | "denied" | "timeout";
  resolved_ts: string | null;
  resolved_by: string | null;
  note: string | null;
  client_id: string;
  tool: string;
  args: unknown;
}

export interface CallDetail extends CallRecord {
  approval: Approval | null;
}

export interface ToolInfo {
  name: string;
  title: string;
  risk: "low" | "medium" | "high";
  writes: boolean;
}

export type ScannerMode = "redact" | "envelope" | "off";

export interface PolicyConfig {
  clients: Record<string, { tools: string[] }>;
  approval_required: string[];
  approval_timeout_s: number;
  protected_account_tags: string[];
  account_tags: Record<string, string[]>;
  rate_limit_per_minute: number;
  max_window_hours: number;
  max_arg_chars: number;
  scanner: { mode: ScannerMode };
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** FastAPI puts the reason in `detail`: a string, or a list of validation errors. */
function detail(body: unknown): string | null {
  if (!body || typeof body !== "object" || !("detail" in body)) return null;
  const value = (body as { detail: unknown }).detail;
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((e) => `${(e.loc ?? []).join(".")}: ${e.msg}`).join("; ");
  return null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${ADMIN_API}${path}`, {
    ...init,
    cache: "no-store",
    headers: init?.body ? { "content-type": "application/json" } : undefined,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(response.status, detail(body) ?? `${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export function listCalls(filters: { decision?: string; clientId?: string; limit?: number } = {}) {
  const params = new URLSearchParams({ limit: String(filters.limit ?? 200) });
  if (filters.decision) params.set("decision", filters.decision);
  if (filters.clientId) params.set("client_id", filters.clientId);
  return request<CallRecord[]>(`/calls?${params}`);
}

export const getCall = (id: string) => request<CallDetail>(`/calls/${encodeURIComponent(id)}`);

export const listPending = () => request<Approval[]>("/pending");

export function resolveApproval(id: string, action: "approve" | "deny", body: { by: string; note?: string }) {
  return request<Approval>(`/pending/${encodeURIComponent(id)}/${action}`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export const listTools = () => request<ToolInfo[]>("/tools");

export const getPolicy = () => request<PolicyConfig>("/policy");

export const putPolicy = (config: PolicyConfig) =>
  request<PolicyConfig>("/policy", { method: "PUT", body: JSON.stringify(config) });
