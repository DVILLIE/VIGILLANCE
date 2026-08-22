import type { ReactNode } from 'react'
import { HologramRing } from './components/HologramRing'
import { IntelligenceFeed } from './components/IntelligenceFeed'
import { ProtectionMatrix } from './components/ProtectionMatrix'
import { QuickClose } from './components/QuickClose'
import { VitalBar } from './components/VitalBar'
import { useDemoSimulation } from './hooks/useDemoSimulation'

function Panel({ title, children, className = '' }: { title: string; children: ReactNode; className?: string }) {
  return (
    <div className={`flex flex-col rounded-lg border border-[#1a3a5c] bg-[#0a1220]/90 backdrop-blur-sm overflow-hidden min-h-0 ${className}`}>
      <div className="px-4 py-3 border-b border-[#1a3a5c]/60">
        <h2 className="font-display text-xs font-bold tracking-[0.2em] text-[#00e5ff]">{title}</h2>
      </div>
      <div className="flex-1 p-4 min-h-0 overflow-hidden">{children}</div>
    </div>
  )
}

export default function App() {
  const demo = useDemoSimulation()

  return (
    <div className="scanlines grid-bg h-full flex flex-col">
      {/* Demo banner */}
      <div className="bg-[#00e5ff]/10 border-b border-[#00e5ff]/30 px-4 py-1.5 text-center">
        <span className="font-mono text-[10px] tracking-widest text-[#00e5ff] uppercase">
          Demo UX — simulated data · no agent required
        </span>
      </div>

      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-[#1a3a5c] bg-[#0a1220]/95">
        <div className="flex items-center gap-4">
          <HologramRing active={demo.vigilance} />
          <div>
            <h1 className="font-display text-2xl font-black tracking-[0.15em] text-[#00fff7] drop-shadow-[0_0_20px_rgba(0,255,247,0.3)]">
              DVIELLE
            </h1>
            <p className="text-[10px] tracking-[0.35em] text-[#6b8fa3] uppercase">Deep Vigilance</p>
            <p className="text-xs italic text-[#0099b3] mt-1 max-w-md truncate">{demo.greeting}</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span
            className={`text-2xl ${demo.vigilance ? 'text-[#00ff9d] pulse-glow' : 'text-[#ffb020]'}`}
          >
            ●
          </span>
          <span className={`font-display text-sm tracking-wider ${demo.vigilance ? 'text-[#00ff9d]' : 'text-[#ffb020]'}`}>
            {demo.vigilance ? 'VIGILANCE ACTIVE' : 'STANDBY'}
          </span>
        </div>
      </header>

      {/* Main grid */}
      <main className="flex-1 grid grid-cols-1 lg:grid-cols-[1fr_1.6fr_1fr] gap-4 p-4 min-h-0">
        <Panel title="SYSTEM VITALS">
          <VitalBar label="CPU" value={demo.cpu} />
          <VitalBar label="RAM" value={demo.ram} />
          <VitalBar label="DISK" value={demo.disk} />
          <p className="font-mono text-[10px] text-[#6b8fa3] mb-4">Cycles: {demo.cycles}</p>
          <div className="border-t border-[#1a3a5c] pt-3">
            <h3 className="font-display text-[10px] tracking-wider text-[#ffb020] mb-2">QUICK CLOSE</h3>
            <QuickClose apps={demo.closeable} onClose={demo.closeApp} />
          </div>
        </Panel>

        <Panel title="INTELLIGENCE FEED" className="lg:col-span-1">
          <IntelligenceFeed events={demo.feed} />
        </Panel>

        <Panel title="PROTECTION MATRIX">
          <ProtectionMatrix onReplayGreeting={demo.replayGreeting} speaking={demo.speaking} />
        </Panel>
      </main>

      {/* Footer */}
      <footer className="flex items-center justify-between px-6 py-3 border-t border-[#1a3a5c] bg-[#0a1220]/95">
        <span className="font-mono text-[10px] text-[#6b8fa3]">
          v1.2 DEMO · C:\DVILLIE · Deep vigilance
        </span>
        <div className="flex gap-3">
          <button
            type="button"
            onClick={demo.toggleVigilance}
            className="px-5 py-2 rounded border border-[#00e5ff]/50 bg-[#1a3a5c]/40 text-xs text-[#00e5ff] hover:bg-[#00e5ff]/15 tracking-wider transition-all font-display"
          >
            {demo.vigilance ? 'Pause Vigilance' : 'Resume Vigilance'}
          </button>
          <button
            type="button"
            className="px-5 py-2 rounded border border-[#1a3a5c] bg-[#0d1a2d] text-xs text-[#6b8fa3] hover:border-[#6b8fa3] tracking-wider transition-all"
            title="In full app: minimizes to system tray"
          >
            Minimize to Tray
          </button>
        </div>
      </footer>
    </div>
  )
}
