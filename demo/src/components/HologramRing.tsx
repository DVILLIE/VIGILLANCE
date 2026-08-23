export type RingMode = 'idle' | 'listening' | 'speaking' | 'thinking'

/** Listening = blue · Speaking = yellow · animated like talk/listen. */
export function HologramRing({
  active = true,
  mode = 'idle',
  size = 80,
  label = 'DV',
}: {
  active?: boolean
  mode?: RingMode
  size?: number
  label?: string
}) {
  const listening = mode === 'listening'
  const speaking = mode === 'speaking'
  const thinking = mode === 'thinking'

  const color = speaking ? '#ffd60a' : listening || thinking ? '#3b9eff' : '#5a7a9a'
  const colorDim = speaking ? '#c9a000' : '#1e6fd4'
  const modeClass = speaking ? 'ring-mode-speak' : listening ? 'ring-mode-listen' : thinking ? 'ring-mode-think' : 'ring-mode-idle'

  return (
    <div
      className={`relative flex items-center justify-center ${modeClass}`}
      style={{ width: size, height: size, ['--ring-color' as string]: color, ['--ring-dim' as string]: colorDim }}
      aria-label={listening ? 'Listening' : speaking ? 'Speaking' : thinking ? 'Thinking' : 'Ready'}
    >
      {/* Outer breath / talk pulses */}
      <div className="ring-pulse-a absolute inset-0 rounded-full" />
      <div className="ring-pulse-b absolute inset-[-6%] rounded-full" />
      <div className="ring-pulse-c absolute inset-[-12%] rounded-full" />

      <svg className="absolute inset-0 w-full h-full ring-spin" viewBox="0 0 80 80">
        <circle
          cx="40"
          cy="40"
          r="34"
          fill="none"
          stroke={color}
          strokeWidth="2.2"
          strokeDasharray={speaking ? '18 12' : '50 140'}
          strokeLinecap="round"
          opacity="0.95"
          className="ring-arc-main"
        />
        <circle
          cx="40"
          cy="40"
          r="34"
          fill="none"
          stroke={colorDim}
          strokeWidth="1.2"
          strokeDasharray="28 180"
          opacity="0.55"
          transform="rotate(90 40 40)"
          className="ring-arc-alt"
        />
        <circle cx="40" cy="40" r="26" fill="none" stroke={color} strokeWidth="0.6" opacity="0.35" />
      </svg>

      {/* Voice bars — animate harder when speaking, soft when listening */}
      <div className="ring-voice absolute inset-0 flex items-center justify-center gap-[3px] z-[1] pointer-events-none">
        {[0, 1, 2, 3, 4].map((i) => (
          <span key={i} className="ring-bar" style={{ animationDelay: `${i * 0.12}s` }} />
        ))}
      </div>

      <span
        className="font-display text-[10px] font-bold z-[2] tracking-widest"
        style={{ color, textShadow: `0 0 10px ${color}` }}
      >
        {active || listening || speaking || thinking ? label : label}
      </span>
    </div>
  )
}
