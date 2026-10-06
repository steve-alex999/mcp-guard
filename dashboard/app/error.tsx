"use client";

import { BUTTON, HEADING } from "@/components/styles";
import { ADMIN_API } from "@/lib/api";

export default function ErrorPage({ error, retry }: { error: Error & { digest?: string }; retry: () => void }) {
  return (
    <div className="max-w-xl space-y-3">
      <h1 className={HEADING}>Couldn&apos;t load this page</h1>
      <p className="text-sm">
        The dashboard reads everything from the gateway&apos;s admin API at <code className="font-mono">{ADMIN_API}</code>.
        If it isn&apos;t running, start it from the repo root:
      </p>
      <pre className="rounded bg-zinc-100 p-3 font-mono text-xs dark:bg-zinc-900">python -m gateway.admin_api</pre>
      <p className="font-mono text-xs text-zinc-500">{error.message}</p>
      <button type="button" onClick={retry} className={`${BUTTON} bg-zinc-800 dark:bg-zinc-700`}>
        Try again
      </button>
    </div>
  );
}
