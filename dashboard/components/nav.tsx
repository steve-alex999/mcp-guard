"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { listPending, type Approval } from "@/lib/api";
import { usePolling } from "@/lib/use-polling";

const LINKS = [
  { href: "/", label: "Calls" },
  { href: "/pending", label: "Pending" },
  { href: "/policy", label: "Policy" },
];

export function Nav() {
  const pathname = usePathname();
  const { data: pending } = usePolling(listPending, [] as Approval[], { immediate: true });

  return (
    <nav className="flex gap-1 text-sm">
      {LINKS.map(({ href, label }) => {
        const active = href === "/" ? pathname === "/" || pathname.startsWith("/calls") : pathname.startsWith(href);
        return (
          <Link
            key={href}
            href={href}
            aria-current={active ? "page" : undefined}
            className={`rounded px-2.5 py-1 ${active ? "bg-zinc-200 dark:bg-zinc-800" : "hover:bg-zinc-100 dark:hover:bg-zinc-900"}`}
          >
            {label}
            {href === "/pending" && pending.length > 0 && (
              <span className="ml-1.5 rounded-full bg-rose-600 px-1.5 py-px text-xs font-medium text-white">
                {pending.length}
              </span>
            )}
          </Link>
        );
      })}
    </nav>
  );
}
