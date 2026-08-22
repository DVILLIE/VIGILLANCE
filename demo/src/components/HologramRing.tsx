export function HologramRing({ active }: { active: boolean }) {
  return (
    <div className="relative w-20 h-20 flex items-center justify-center">
      <div
        className={`absolute inset-0 rounded-full border border-[#1a3a5c] ${active ? 'pulse-glow' : 'opacity-40'}`}
      />
      <svg
        className={`absolute inset-0 w-full h-full hologram-spin ${active ? '' : 'opacity-30'}`}
        viewBox="0 0 80 80"
      >
        <circle cx="40" cy="40" r="36" fill="none" stroke="#00fff7" strokeWidth="1.5" strokeDasharray="60 170" opacity="0.9" />
        <circle cx="40" cy="40" r="36" fill="none" stroke="#00e5ff" strokeWidth="1" strokeDasharray="40 200" opacity="0.5" transform="rotate(120 40 40)" />
        <circle cx="40" cy="40" r="28" fill="none" stroke="#0099b3" strokeWidth="0.5" opacity="0.4" />
        <line x1="40" y1="40" x2="40" y2="8" stroke="#00fff7" strokeWidth="1" opacity="0.8" />
      </svg>
      <span className="font-display text-[11px] font-bold text-[#00fff7] z-10 tracking-widest">DV</span>
    </div>
  )
}
