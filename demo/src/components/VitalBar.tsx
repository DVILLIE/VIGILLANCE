function barColor(pct: number) {
  if (pct >= 85) return 'bg-[#ff3366]'
  if (pct >= 70) return 'bg-[#ffb020]'
  return 'bg-[#00e5ff]'
}

export function VitalBar({ label, value }: { label: string; value: number }) {
  return (
    <div className="mb-4">
      <div className="flex justify-between text-xs mb-1">
        <span className="text-[#6b8fa3] tracking-wider">{label}</span>
        <span className="font-mono text-[#e0f7ff]">{Math.round(value)}%</span>
      </div>
      <div className="h-2 rounded-full bg-[#0d1a2d] border border-[#1a3a5c] overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ease-out ${barColor(value)}`}
          style={{ width: `${value}%`, boxShadow: value > 70 ? '0 0 12px rgba(0,229,255,0.4)' : 'none' }}
        />
      </div>
    </div>
  )
}
