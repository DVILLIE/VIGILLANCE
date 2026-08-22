import type { CloseableApp } from '../hooks/useDemoSimulation'

export function QuickClose({
  apps,
  onClose,
}: {
  apps: CloseableApp[]
  onClose: (id: string, name: string) => void
}) {
  if (apps.length === 0) {
    return (
      <p className="text-xs text-[#6b8fa3] italic py-2">
        No background hogs detected. System optimal.
      </p>
    )
  }

  return (
    <div className="space-y-2">
      <p className="text-[10px] text-[#ffb020] tracking-wider uppercase">Background apps — click to close</p>
      {apps.map((app) => (
        <button
          key={app.id}
          type="button"
          onClick={() => onClose(app.id, app.name)}
          className="w-full text-left px-3 py-2 rounded-md bg-[#050810] border border-[#1a3a5c] hover:border-[#ff3366] hover:bg-[#ff3366]/10 transition-all group"
        >
          <span className="text-[#ff3366] font-mono text-xs group-hover:text-[#ff6688]">✕ </span>
          <span className="font-mono text-xs text-[#e0f7ff]">{app.name}</span>
          <span className="float-right font-mono text-[10px] text-[#6b8fa3]">
            {app.memoryMb}MB · {app.cpuPercent}% CPU
          </span>
        </button>
      ))}
    </div>
  )
}
