import type { WorkLogEntry } from '../hooks/useDemoSimulation'

function formatReport(entries: WorkLogEntry[]): string {
  const now = new Date().toLocaleString('en-GB')
  const lines = [
    '='.repeat(56),
    '  DVIELLE — WORK LOG REPORT',
    '  Deep Vigilance',
    `  Generated: ${now}`,
    '='.repeat(56),
    '',
  ]
  if (!entries.length) {
    lines.push('  (No work log entries yet)')
  } else {
    lines.push(`  OPEN — Session log begins (${entries[0].ts})`)
    lines.push('  ' + '-'.repeat(52))
    entries.forEach((e, i) => {
      lines.push(`  ${String(i + 1).padStart(4)}. [${e.ts}] ${e.action.padEnd(12)} — ${e.message}`)
    })
    lines.push('  ' + '-'.repeat(52))
    lines.push(`  CLOSE — Report end (${entries[entries.length - 1].ts})`)
    lines.push(`  Total actions logged: ${entries.length}`)
  }
  lines.push('')
  return lines.join('\n')
}

export function WorkLogModal({
  entries,
  onClose,
}: {
  entries: WorkLogEntry[]
  onClose: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="w-full max-w-2xl rounded-lg border border-[#1a3a5c] bg-[#0a1220] shadow-2xl">
        <div className="border-b border-[#1a3a5c] px-5 py-4">
          <h2 className="font-display text-sm font-bold tracking-[0.2em] text-[#00e5ff]">WORK LOG REPORT</h2>
          <p className="mt-1 text-[10px] text-[#6b8fa3]">Chronological list of all actions (open → close)</p>
        </div>
        <pre className="max-h-[420px] overflow-auto p-5 font-mono text-xs leading-relaxed text-[#00fff7]/90 whitespace-pre-wrap">
          {formatReport(entries)}
        </pre>
        <div className="border-t border-[#1a3a5c] px-5 py-3 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 rounded border border-[#1a3a5c] text-xs text-[#6b8fa3] hover:border-[#00e5ff] hover:text-[#00e5ff]"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
