"use client";

import { useState } from "react";

import { RiskBadge } from "@/components/badges";
import { JsonView } from "@/components/json-view";
import { LiveStatus } from "@/components/live-status";
import { BUTTON, CARD, FIELD } from "@/components/styles";
import { ApiError, listPending, resolveApproval, type Approval, type ToolInfo } from "@/lib/api";
import { formatTime } from "@/lib/format";
import { usePolling } from "@/lib/use-polling";

export function PendingQueue({ initial, timeoutS, tools }: { initial: Approval[]; timeoutS: number; tools: ToolInfo[] }) {
  const { data: pending, error, updatedAt, refresh } = usePolling(listPending, initial, { immediate: true });
  const [approver, setApprover] = useState("dashboard");
  const [message, setMessage] = useState<string | null>(null);
  const risk = Object.fromEntries(tools.map((t) => [t.name, t.risk]));

  function resolved(text: string) {
    setMessage(text);
    void refresh();
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-sm">
          Approving as
          <input value={approver} onChange={(e) => setApprover(e.target.value)} maxLength={64} className={FIELD} />
        </label>
        <span className="ml-auto">
          <LiveStatus error={error} />
        </span>
      </div>

      {message && (
        <p role="status" className="rounded border border-zinc-200 px-3 py-2 text-sm dark:border-zinc-800">
          {message}
        </p>
      )}

      {pending.length === 0 ? (
        <p className="py-10 text-center text-zinc-500">Nothing is waiting for approval.</p>
      ) : (
        pending.map((approval) => (
          <PendingCard
            key={approval.id}
            approval={approval}
            risk={risk[approval.tool]}
            approver={approver.trim() || "dashboard"}
            secondsLeft={
              updatedAt === null
                ? null
                : Math.max(0, Math.round((Date.parse(approval.created_ts) + timeoutS * 1000 - updatedAt) / 1000))
            }
            onResolved={resolved}
          />
        ))
      )}
    </div>
  );
}

function PendingCard({
  approval,
  risk,
  approver,
  secondsLeft,
  onResolved,
}: {
  approval: Approval;
  risk: ToolInfo["risk"] | undefined;
  approver: string;
  secondsLeft: number | null;
  onResolved: (message: string) => void;
}) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function resolve(action: "approve" | "deny") {
    setBusy(true);
    setError(null);
    try {
      await resolveApproval(approval.id, action, { by: approver, note: note.trim() || undefined });
      onResolved(`${action === "approve" ? "Approved" : "Denied"} ${approval.tool} for ${approval.client_id}.`);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        onResolved(`Too late for ${approval.tool}: ${e.message}.`);
      } else {
        setError(e instanceof Error ? e.message : String(e));
        setBusy(false);
      }
    }
  }

  return (
    <article className={`${CARD} space-y-3`}>
      <header className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="font-mono font-semibold">{approval.tool}</h2>
        {risk && <RiskBadge risk={risk} />}
        <span className="text-sm text-zinc-500">
          from {approval.client_id} at{" "}
          <time dateTime={approval.created_ts} suppressHydrationWarning>
            {formatTime(approval.created_ts)}
          </time>
        </span>
        {secondsLeft !== null && (
          <span className="ml-auto text-sm text-zinc-500">
            {secondsLeft > 0 ? `times out in ${secondsLeft} s` : "timing out"}
          </span>
        )}
      </header>
      <JsonView value={approval.args} />
      <textarea
        aria-label="Note"
        placeholder="Note (optional), saved with the decision"
        value={note}
        onChange={(e) => setNote(e.target.value)}
        maxLength={500}
        rows={2}
        className={`${FIELD} w-full`}
      />
      <div className="flex items-center gap-2">
        <button type="button" disabled={busy} onClick={() => resolve("approve")} className={`${BUTTON} bg-emerald-600 hover:bg-emerald-700`}>
          Approve
        </button>
        <button type="button" disabled={busy} onClick={() => resolve("deny")} className={`${BUTTON} bg-rose-600 hover:bg-rose-700`}>
          Deny
        </button>
        {error && <span className="text-sm text-rose-600 dark:text-rose-400">{error}</span>}
      </div>
    </article>
  );
}
