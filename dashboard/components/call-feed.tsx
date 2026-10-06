"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

import { DecisionBadge } from "@/components/badges";
import { LiveStatus } from "@/components/live-status";
import { FIELD } from "@/components/styles";
import { DECISIONS, listCalls, type CallRecord } from "@/lib/api";
import { formatLatency, formatTime } from "@/lib/format";
import { usePolling } from "@/lib/use-polling";

export function CallFeed({
  initial,
  decision,
  client,
  knownClients,
}: {
  initial: CallRecord[];
  decision: string;
  client: string;
  knownClients: string[];
}) {
  const router = useRouter();
  const { data: calls, error } = usePolling(() => listCalls({ decision, clientId: client }), initial);
  const clients = [...new Set([...knownClients, ...calls.map((c) => c.client_id), client].filter(Boolean))].sort();

  function filter(change: { decision?: string; client?: string }) {
    const params = new URLSearchParams(Object.entries({ decision, client, ...change }).filter(([, v]) => v));
    router.replace(params.size ? `/?${params}` : "/");
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <select
          aria-label="Decision"
          value={decision}
          onChange={(e) => filter({ decision: e.target.value })}
          className={FIELD}
        >
          <option value="">All decisions</option>
          {DECISIONS.map((d) => (
            <option key={d}>{d}</option>
          ))}
        </select>
        <select aria-label="Client" value={client} onChange={(e) => filter({ client: e.target.value })} className={FIELD}>
          <option value="">All clients</option>
          {clients.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
        <span className="ml-auto">
          <LiveStatus error={error} />
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-xs tracking-wide text-zinc-500 uppercase">
            <tr className="border-b border-zinc-200 dark:border-zinc-800">
              <th className="py-2 pr-4 font-medium">Time</th>
              <th className="py-2 pr-4 font-medium">Client</th>
              <th className="py-2 pr-4 font-medium">Tool</th>
              <th className="py-2 pr-4 font-medium">Decision</th>
              <th className="py-2 text-right font-medium">Latency</th>
            </tr>
          </thead>
          <tbody>
            {calls.map((call) => (
              <tr
                key={call.id}
                className="border-b border-zinc-100 hover:bg-zinc-50 dark:border-zinc-900 dark:hover:bg-zinc-900/60"
              >
                <td className="py-1.5 pr-4 font-mono text-xs text-zinc-500">
                  <time dateTime={call.ts} suppressHydrationWarning>
                    {formatTime(call.ts)}
                  </time>
                </td>
                <td className="py-1.5 pr-4">{call.client_id}</td>
                <td className="py-1.5 pr-4">
                  <Link href={`/calls/${call.id}`} className="font-mono underline-offset-2 hover:underline">
                    {call.tool}
                  </Link>
                </td>
                <td className="py-1.5 pr-4">
                  <DecisionBadge decision={call.decision} />
                </td>
                <td className="py-1.5 text-right font-mono text-xs">{formatLatency(call.latency_ms)}</td>
              </tr>
            ))}
            {calls.length === 0 && (
              <tr>
                <td colSpan={5} className="py-10 text-center text-zinc-500">
                  {decision || client ? "No calls match these filters." : "No calls yet."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
