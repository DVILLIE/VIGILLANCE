const shields = [
  'Network Scan',
  'Attack Shield',
  'Privacy Guard',
  'Microsoft Block',
  'Resource AI',
]

export function ProtectionMatrix({
  onReplayGreeting,
  speaking,
}: {
  onReplayGreeting: () => void
  speaking: boolean
}) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 space-y-2">
        {shields.map((name) => (
          <div
            key={name}
            className="flex justify-between items-center px-3 py-2 rounded-md bg-[#0d1a2d] border border-[#1a3a5c]/50"
          >
            <span className="text-sm text-[#e0f7ff]">{name}</span>
            <span className="font-mono text-xs text-[#00ff9d] tracking-wider">ACTIVE</span>
          </div>
        ))}
      </div>

      <p className="text-xs italic text-[#0099b3] mt-4 leading-relaxed border-t border-[#1a3a5c] pt-4">
        {speaking ? (
          <span className="text-[#00fff7] animate-pulse">"Speaking..."</span>
        ) : (
          '"At your service. All systems under deep vigilance."'
        )}
      </p>

      <button
        type="button"
        onClick={onReplayGreeting}
        className="mt-3 w-full py-2 rounded-md border border-[#1a3a5c] bg-[#0d1a2d] text-xs text-[#00e5ff] hover:border-[#00e5ff] hover:bg-[#00e5ff]/10 transition-all tracking-wide"
      >
        Replay greeting
      </button>
    </div>
  )
}
