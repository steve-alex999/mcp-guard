import Link from "next/link";
import type { ReactNode } from "react";
import { notFound } from "next/navigation";

import { DecisionBadge } from "@/components/badges";
import { JsonView } from "@/components/json-view";
import { CARD, SUBHEADING } from "@/components/styles";
import { ApiError, getCall, type CallDetail } from "@/lib/api";
import { formatDateTime, formatLatency } from "@/lib/format";

const APPROVAL = { pending: "still waiting", approved: "approved", denied: "denied", timeout: "timed out" };

async function load(id: string): Promise<CallDetail> {
  try {
    return await getCall(id);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
}

export default async function CallPage(props: PageProps<"/calls/[id]">) {
  const { id } = await props.params;
  const call = await load(id);
  const { approval } = call;

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Link href="/" className="text-sm text-zinc-500 hover:underline">
          ← All calls
        </Link>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-mono text-xl font-semibold">{call.tool}</h1>
          <DecisionBadge decision={call.decision} />
        </div>
        <dl className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-zinc-600 dark:text-zinc-400">
          <Meta label="Client">{call.client_id}</Meta>
          <Meta label="Time">
            <time dateTime={call.ts} suppressHydrationWarning>
              {formatDateTime(call.ts)}
            </time>
          </Meta>
          <Meta label="Latency">{formatLatency(call.latency_ms)}</Meta>
          <Meta label="Call ID">
            <span className="font-mono text-xs">{call.id}</span>
          </Meta>
        </dl>
      </div>

      <section className={CARD}>
        <h2 className={SUBHEADING}>Policy decision</h2>
        <p className="text-sm">{call.reason}</p>
        {approval && (
          <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
            Held for human approval: {APPROVAL[approval.status]}
            {approval.resolved_ts && (
              <>
                {" at "}
                <time dateTime={approval.resolved_ts} suppressHydrationWarning>
                  {formatDateTime(approval.resolved_ts)}
                </time>
              </>
            )}
            .
          </p>
        )}
      </section>

      <section>
        <h2 className={SUBHEADING}>Arguments</h2>
        <JsonView value={call.args} />
      </section>

      <section>
        <h2 className={SUBHEADING}>Output</h2>
        {call.output === null ? (
          <p className="text-sm text-zinc-500">None: the call was blocked before the tool ran.</p>
        ) : (
          <JsonView value={call.output} />
        )}
      </section>

      <section>
        <h2 className={SUBHEADING}>Scanner findings</h2>
        {call.findings.length === 0 ? (
          <p className="text-sm text-zinc-500">None.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-zinc-500">
              <tr>
                <th className="py-1 pr-4 font-medium">Field</th>
                <th className="py-1 pr-4 font-medium">Rule</th>
                <th className="py-1 font-medium">Matched text</th>
              </tr>
            </thead>
            <tbody>
              {call.findings.map((f, i) => (
                <tr key={i} className="border-t border-zinc-100 align-top dark:border-zinc-900">
                  <td className="py-1.5 pr-4 font-mono text-xs">{f.path}</td>
                  <td className="py-1.5 pr-4 font-mono text-xs">{f.rule}</td>
                  <td className="py-1.5">
                    <mark className="rounded bg-amber-200 px-0.5 text-amber-950 dark:bg-amber-600 dark:text-white">
                      {f.snippet}
                    </mark>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-1.5">
      <dt className="text-zinc-500">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}
