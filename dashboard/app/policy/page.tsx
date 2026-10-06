import { connection } from "next/server";

import { PolicyEditor } from "@/components/policy-editor";
import { HEADING } from "@/components/styles";
import { getPolicy, listTools } from "@/lib/api";

export default async function PolicyPage() {
  await connection(); // render per request, never at build time
  const [policy, tools] = await Promise.all([getPolicy(), listTools()]);

  return (
    <div className="space-y-4">
      <h1 className={HEADING}>Policy</h1>
      <PolicyEditor initial={policy} tools={tools} />
    </div>
  );
}
