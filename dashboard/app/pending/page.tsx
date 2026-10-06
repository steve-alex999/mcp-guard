import { connection } from "next/server";

import { PendingQueue } from "@/components/pending-queue";
import { HEADING } from "@/components/styles";
import { getPolicy, listPending, listTools } from "@/lib/api";

export default async function PendingPage() {
  await connection(); // render per request, never at build time
  const [pending, policy, tools] = await Promise.all([listPending(), getPolicy(), listTools()]);

  return (
    <div className="space-y-4">
      <h1 className={HEADING}>Pending approvals</h1>
      <PendingQueue initial={pending} timeoutS={policy.approval_timeout_s} tools={tools} />
    </div>
  );
}
