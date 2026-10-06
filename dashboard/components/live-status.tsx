import { ADMIN_API } from "@/lib/api";
import { POLL_INTERVAL_MS } from "@/lib/use-polling";

export function LiveStatus({ error }: { error: string | null }) {
  if (error) {
    return (
      <span className="text-xs text-rose-600 dark:text-rose-400" role="status">
        Can&apos;t reach the admin API at {ADMIN_API} ({error})
      </span>
    );
  }
  return <span className="text-xs text-zinc-500">Live, refreshing every {POLL_INTERVAL_MS / 1000} s</span>;
}
