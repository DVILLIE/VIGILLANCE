import type { ReactNode } from 'react'
import { HologramRing } from './components/HologramRing'
import { IntelligenceFeed } from './components/IntelligenceFeed'
import { NetworkPanel } from './components/NetworkPanel'
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
      <div className="flex-1 p-4 min-h-0 overflow-hidden overflow-y-auto">{children}</div>
    </div>
  )
}

export default function App() {
  const demo = useDemoSimulation()
  const dimmed = !demo.started

  return (
    <div className="scanlines grid-bg h-full flex flex-col relative">
      <div className="bg-[#00e5ff]/10 border-b border-[#00e5ff]/30 px-4 py-1.5 text-center">
        <span className="font-mono text-[10px] tracking-widest text-[#00e5ff] uppercase">
          Demo UX — press START for live network + VPN scan
        </span>
      </div>

      {/* Top bar with START */}
      <div className="flex items-center justify-center gap-4 px-6 py-3 border-b border-[#1a3a5c] bg-[#0a1220]">
        {!demo.started ? (
          <button
            type="button"
            onClick={() => demo.start()}
            className="font-display text-sm font-bold tracking-[0.25em] px-12 py-3 rounded-md border-2 border-[#00fff7] bg-[#00e5ff]/20 text-[#00fff7] hover:bg-[#00e5ff]/35 hover:shadow-[0_0_30px_rgba(0,255,247,0.4)] transition-all pulse-glow uppercase"
          >
            ▶ START
          </button>
        ) : (
          <div className="flex items-center gap-4">
            <span className="font-display text-xs tracking-[0.2em] text-[#00ff9d]">● LIVE MONITORING</span>
            <button
              type="button"
              onClick={demo.toggleVigilance}
              className="font-mono text-xs px-4 py-1.5 rounded border border-[#1a3a5c] text-[#6b8fa3] hover:border-[#00e5ff] hover:text-[#00e5ff]"
            >
              {demo.vigilance ? 'Pause' : 'Resume'}
            </button>
          </div>
        )}
      </div>

      <header className={`flex items-center justify-between px-6 py-4 border-b border-[#1a3a5c] bg-[#0a1220]/95 transition-opacity ${dimmed ? 'opacity-40' : ''}`}>
        <div className="flex items-center gap-4">
          <HologramRing active={demo.vigilance && demo.started} />
          <div>
            <h1 className="font-display text-2xl font-black tracking-[0.15em] text-[#00fff7]">DVIELLE</h1>
            <p className="text-[10px] tracking-[0.35em] text-[#6b8fa3] uppercase">Deep Vigilance</p>
            <p className="text-xs italic text-[#0099b3] mt-1 max-w-md truncate">{demo.greeting}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`text-2xl ${demo.vigilance && demo.started ? 'text-[#00ff9d] pulse-glow' : 'text-[#6b8fa3]'}`}>●</span>
          <span className={`font-display text-sm tracking-wider ${demo.vigilance && demo.started ? 'text-[#00ff9d]' : 'text-[#6b8fa3]'}`}>
            {!demo.started ? 'AWAITING START' : demo.vigilance ? 'VIGILANCE ACTIVE' : 'PAUSED'}
          </span>
        </div>
      </header>

      <main className={`flex-1 grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 gap-4 p-4 min-h-0 transition-opacity ${dimmed ? 'opacity-30 pointer-events-none' : ''}`}>
        <Panel title="NETWORK & VPN">
          <NetworkPanel network={demo.network} loading={demo.networkLoading} />
        </Panel>

        <Panel title="SYSTEM VITALS">
          <VitalBar label="CPU" value={demo.cpu} />
          <VitalBar label="RAM" value={demo.ram} />
          <VitalBar label="DISK" value={demo.disk || 58} />
          <p className="font-mono text-[10px] text-[#6b8fa3] mb-3">Cycles: {demo.cycles}</p>
          <div className="border-t border-[#1a3a5c] pt-3">
            <h3 className="font-display text-[10px] tracking-wider text-[#ffb020] mb-2">QUICK CLOSE</h3>
            <QuickClose apps={demo.closeable} onClose={demo.closeApp} />
          </div>
        </Panel>

        <Panel title="INTELLIGENCE FEED" className="xl:col-span-1">
          <IntelligenceFeed events={demo.feed} />
        </Panel>

        <Panel title="PROTECTION MATRIX">
          <ProtectionMatrix onReplayGreeting={demo.replayGreeting} speaking={demo.speaking} />
        </Panel>
      </main>

      <footer className="flex items-center justify-between px-6 py-3 border-t border-[#1a3a5c] bg-[#0a1220]/95">
        <span className="font-mono text-[10px] text-[#6b8fa3]">v1.3 DEMO · C:\DVILLIE</span>
        <button
          type="button"
          className="px-5 py-2 rounded border border-[#1a3a5c] bg-[#0d1a2d] text-xs text-[#6b8fa3] hover:border-[#6b8fa3] tracking-wider"
        >
          Minimize to Tray
        </button>
      </footer>

      {dimmed && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <p className="font-display text-lg tracking-[0.3em] text-[#00fff7]/60 mt-32">PRESS START ABOVE</p>
        </div>
      )}
    </div>
  )
}
