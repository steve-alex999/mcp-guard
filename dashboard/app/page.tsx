import { CallFeed } from "@/components/call-feed";
import { HEADING } from "@/components/styles";
import { DECISIONS, getPolicy, listCalls } from "@/lib/api";

export default async function CallsPage(props: PageProps<"/">) {
  const params = await props.searchParams;
  const decision = DECISIONS.find((d) => d === params.decision) ?? "";
  const client = typeof params.client === "string" ? params.client : "";
  const [calls, policy] = await Promise.all([listCalls({ decision, clientId: client }), getPolicy()]);

  return (
    <div className="space-y-4">
      <h1 className={HEADING}>Calls</h1>
      <CallFeed
        key={`${decision}|${client}`}
        initial={calls}
        decision={decision}
        client={client}
        knownClients={Object.keys(policy.clients)}
      />
    </div>
  );
}
