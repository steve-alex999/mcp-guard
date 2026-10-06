// The output scanner (milestone 4) replaces injected text with "[REDACTED: <rule>]"; those spans
// are highlighted.
const REDACTED = /(\[REDACTED[^\]]*\])/;

export function JsonView({ value }: { value: unknown }) {
  const parts = (JSON.stringify(value, null, 2) ?? "null").split(REDACTED);
  return (
    <pre className="overflow-x-auto rounded border border-zinc-200 bg-zinc-50 p-3 font-mono text-xs break-words whitespace-pre-wrap dark:border-zinc-800 dark:bg-zinc-900">
      {parts.map((part, i) =>
        i % 2 === 1 ? (
          <mark key={i} className="rounded bg-amber-200 px-0.5 text-amber-950 dark:bg-amber-600 dark:text-white">
            {part}
          </mark>
        ) : (
          part
        ),
      )}
    </pre>
  );
}
