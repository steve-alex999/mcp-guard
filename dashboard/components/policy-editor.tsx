"use client";

import { useState } from "react";

import { RiskBadge } from "@/components/badges";
import { BUTTON, CARD, SUBHEADING } from "@/components/styles";
import { getPolicy, putPolicy, type PolicyConfig, type ScannerMode, type ToolInfo } from "@/lib/api";

const SCANNER_MODES: { mode: ScannerMode; help: string }[] = [
  { mode: "redact", help: "Remove injected instructions from tool outputs" },
  { mode: "envelope", help: "Keep them, wrapped in an untrusted_content envelope with a warning" },
  { mode: "off", help: "Pass tool outputs through unscanned" },
];

export function PolicyEditor({ initial, tools }: { initial: PolicyConfig; tools: ToolInfo[] }) {
  const [saved, setSaved] = useState(initial);
  const [mode, setMode] = useState(initial.scanner.mode);
  const [approval, setApproval] = useState(() => new Set(initial.approval_required));
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);

  const dirty =
    mode !== saved.scanner.mode ||
    approval.size !== saved.approval_required.length ||
    saved.approval_required.some((t) => !approval.has(t));

  function toggleApproval(tool: string) {
    const next = new Set(approval);
    if (!next.delete(tool)) next.add(tool);
    setApproval(next);
  }

  function revert() {
    setMode(saved.scanner.mode);
    setApproval(new Set(saved.approval_required));
    setStatus(null);
  }

  async function save() {
    setSaving(true);
    setStatus(null);
    try {
      // Start from the file as it is now, so changes made elsewhere since this page loaded survive.
      const latest = await getPolicy();
      const next = await putPolicy({
        ...latest,
        scanner: { ...latest.scanner, mode },
        approval_required: tools.map((t) => t.name).filter((name) => approval.has(name)),
      });
      setSaved(next);
      setStatus({ ok: true, text: "Saved to policy.yaml. Gateways apply it from their next call." });
    } catch (e) {
      setStatus({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setSaving(false);
    }
  }

  const clients = Object.keys(saved.clients);

  return (
    <div className="space-y-6">
      <section className={`${CARD} space-y-5`}>
        <fieldset>
          <legend className={SUBHEADING}>Output scanner</legend>
          <div className="space-y-1.5">
            {SCANNER_MODES.map(({ mode: value, help }) => (
              <label key={value} className="flex items-baseline gap-2 text-sm">
                <input type="radio" name="scanner-mode" checked={mode === value} onChange={() => setMode(value)} />
                <span className="font-mono">{value}</span>
                <span className="text-zinc-500">{help}</span>
              </label>
            ))}
          </div>
          <p className="mt-2 text-xs text-zinc-500">
            LLM classifier: {saved.scanner.llm ? "on" : "off"} (scanner.llm in policy.yaml).
          </p>
        </fieldset>

        <fieldset>
          <legend className={SUBHEADING}>Human approval</legend>
          <div className="space-y-1.5">
            {tools.map((tool) => (
              <label key={tool.name} className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={approval.has(tool.name)} onChange={() => toggleApproval(tool.name)} />
                <span className="font-mono">{tool.name}</span>
                <RiskBadge risk={tool.risk} />
              </label>
            ))}
          </div>
          <p className="mt-2 text-xs text-zinc-500">Held calls wait up to {saved.approval_timeout_s} s for a decision.</p>
        </fieldset>

        <div className="flex items-center gap-2">
          <button type="button" onClick={save} disabled={!dirty || saving} className={`${BUTTON} bg-zinc-800 dark:bg-zinc-700`}>
            {saving ? "Saving…" : "Save"}
          </button>
          <button
            type="button"
            onClick={revert}
            disabled={!dirty || saving}
            className="rounded px-3 py-1.5 text-sm disabled:opacity-50"
          >
            Revert
          </button>
          {status && (
            <span role="status" className={`text-sm ${status.ok ? "text-emerald-700 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"}`}>
              {status.text}
            </span>
          )}
        </div>
      </section>

      <section>
        <h2 className={SUBHEADING}>Client allowlist</h2>
        <div className="overflow-x-auto">
          <table className="text-sm">
            <thead>
              <tr className="border-b border-zinc-200 dark:border-zinc-800">
                <th className="py-2 pr-6 text-left font-medium">Tool</th>
                {clients.map((c) => (
                  <th key={c} className="px-3 py-2 font-mono text-xs font-medium">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tools.map((tool) => (
                <tr key={tool.name} className="border-b border-zinc-100 dark:border-zinc-900">
                  <td className="py-1.5 pr-6 font-mono">{tool.name}</td>
                  {clients.map((c) => (
                    <td key={c} className="px-3 py-1.5 text-center">
                      {saved.clients[c].tools.includes(tool.name) ? (
                        <span aria-label="allowed">✓</span>
                      ) : (
                        <span aria-label="not allowed" className="text-zinc-300 dark:text-zinc-700">
                          –
                        </span>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="grid gap-6 sm:grid-cols-2">
        <div>
          <h2 className={SUBHEADING}>Limits</h2>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-zinc-500">Rate limit</dt>
            <dd>{saved.rate_limit_per_minute} calls per client per minute</dd>
            <dt className="text-zinc-500">Search window</dt>
            <dd>at most {saved.max_window_hours} h</dd>
            <dt className="text-zinc-500">Arguments</dt>
            <dd>at most {saved.max_arg_chars} characters of JSON</dd>
            <dt className="text-zinc-500">Approval timeout</dt>
            <dd>{saved.approval_timeout_s} s</dd>
          </dl>
        </div>
        <div>
          <h2 className={SUBHEADING}>Protected accounts</h2>
          <p className="text-sm">
            <span className="font-mono">disable_account</span> refuses accounts tagged{" "}
            {saved.protected_account_tags.map((t, i) => (
              <span key={t}>
                {i > 0 && " or "}
                <span className="font-mono">{t}</span>
              </span>
            ))}
            . Every account is tagged with its type (human, service or scanner), plus:
          </p>
          <ul className="mt-1 text-sm">
            {Object.entries(saved.account_tags).map(([account, tags]) => (
              <li key={account}>
                <span className="font-mono">{account}</span>: {tags.join(", ")}
              </li>
            ))}
          </ul>
        </div>
      </section>

      <p className="text-xs text-zinc-500">
        The rest of the policy is read-only here; edit policy.yaml to change it.
      </p>
    </div>
  );
}
