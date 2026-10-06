import type { ReactNode } from "react";

import type { Decision, ToolInfo } from "@/lib/api";

const TONES = {
  green: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  amber: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  red: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
  grey: "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

function Badge({ tone, children }: { tone: keyof typeof TONES; children: ReactNode }) {
  return <span className={`rounded px-1.5 py-0.5 font-mono text-xs whitespace-nowrap ${TONES[tone]}`}>{children}</span>;
}

export function DecisionBadge({ decision }: { decision: Decision }) {
  const tone =
    decision === "ALLOW" ? "green" : decision === "ALLOW_REDACTED" ? "amber" : decision === "BLOCK_ERROR" ? "grey" : "red";
  return <Badge tone={tone}>{decision}</Badge>;
}

export function RiskBadge({ risk }: { risk: ToolInfo["risk"] }) {
  return <Badge tone={risk === "high" ? "red" : risk === "medium" ? "amber" : "grey"}>{risk} risk</Badge>;
}
