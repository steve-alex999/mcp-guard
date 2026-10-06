// Fixed locale so the server and the browser format the same way; both run on this machine, so
// they share a time zone.
const TIME = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const DATE_TIME = new Intl.DateTimeFormat("en-GB", {
  day: "numeric",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

export const formatTime = (ts: string) => TIME.format(new Date(ts));

export const formatDateTime = (ts: string) => DATE_TIME.format(new Date(ts));

export const formatLatency = (ms: number) => (ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`);
