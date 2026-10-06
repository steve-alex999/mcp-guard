"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export const POLL_INTERVAL_MS = 2000;

/**
 * Re-runs `load` every 2 s and keeps the latest result. `error` is set while the admin API is
 * unreachable, and `updatedAt` is when data last arrived (null until the first poll, so render
 * output that depends on the clock can wait for the client). `immediate` also loads on mount,
 * for components that have no server-rendered data.
 */
export function usePolling<T>(load: () => Promise<T>, initial: T, { immediate = false } = {}) {
  const [data, setData] = useState(initial);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const loadRef = useRef(load);

  useEffect(() => {
    loadRef.current = load;
  });

  const refresh = useCallback(async () => {
    try {
      const next = await loadRef.current();
      setData(next);
      setError(null);
      setUpdatedAt(Date.now());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    if (immediate) void refresh();
    const timer = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [refresh, immediate]);

  return { data, error, updatedAt, refresh };
}
