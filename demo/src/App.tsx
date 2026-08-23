import type { ReactNode } from 'react'
import { HologramRing } from './components/HologramRing'
import { IntelligenceFeed } from './components/IntelligenceFeed'
import { NetworkPanel } from './components/NetworkPanel'
import { ProtectionMatrix } from './components/ProtectionMatrix'
import { QuickClose } from './components/QuickClose'
import { VitalBar } from './components/VitalBar'
import { WorkLogModal } from './components/WorkLogModal'
import { ChatPanel } from './components/ChatPanel'
import { flushBootVoice } from './lib/villVoice'
import { useDemoSimulation } from './hooks/useDemoSimulation'
import type { ChatStats } from './lib/chatAssistant'

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

  const chatStats: ChatStats = {
    agentStarted: demo.agentStarted,
    agentCycles: demo.cycles,
    cpu: demo.cpu,
    ram: demo.ram,
    disk: demo.disk || 58,
    network: demo.network,
  }

  if (demo.minimized) {
    return (
      <div className="scanlines grid-bg h-full flex flex-col items-center justify-center gap-6 p-8">
        <div className="text-center">
          <p className="font-display text-lg tracking-[0.25em] text-[#00fff7]">DVIELLE — RUNNING IN TRAY</p>
          <p className="mt-2 font-mono text-xs text-[#6b8fa3]">Quiet mode: critical alerts only</p>
          {demo.trayAlert && (
            <div className="mt-6 rounded border border-[#ff4466] bg-[#ff4466]/10 px-4 py-3 font-mono text-xs text-[#ff8899]">
              CRITICAL: {demo.trayAlert}
            </div>
          )}
        </div>
        <button
          type="button"
          onClick={demo.restoreFromTray}
          className="font-mono text-xs px-6 py-2 rounded border border-[#00e5ff] text-[#00e5ff] hover:bg-[#00e5ff]/10"
        >
          Restore Window
        </button>
      </div>
    )
  }

  return (
    <div
      className="scanlines grid-bg h-full flex flex-col relative"
      onClick={() => void flushBootVoice()}
      onKeyDown={() => void flushBootVoice()}
      role="presentation"
    >
      <div className="bg-[#00e5ff]/10 border-b border-[#00e5ff]/30 px-4 py-1.5 text-center">
        <span className="font-mono text-[10px] tracking-widest text-[#00e5ff] uppercase">
          Demo · chat always open · mic on · VILL · UK English
        </span>
      </div>

      <div className="flex items-center justify-center gap-4 px-6 py-3 border-b border-[#1a3a5c] bg-[#0a1220]">
        {!demo.agentStarted ? (
          <button
            type="button"
            onClick={demo.startAgent}
            className="font-display text-sm font-bold tracking-[0.25em] px-12 py-3 rounded-md border-2 border-[#00fff7] bg-[#00e5ff]/20 text-[#00fff7] hover:bg-[#00e5ff]/35 hover:shadow-[0_0_30px_rgba(0,255,247,0.4)] transition-all pulse-glow uppercase"
          >
            ▶ START AGENT
          </button>
        ) : (
          <div className="flex items-center gap-4">
            <span className="font-display text-xs tracking-[0.2em] text-[#00ff9d]">● AGENT ACTIVE</span>
            <button
              type="button"
              onClick={demo.toggleVigilance}
              className="font-mono text-xs px-4 py-1.5 rounded border border-[#1a3a5c] text-[#6b8fa3] hover:border-[#00e5ff] hover:text-[#00e5ff]"
            >
              {demo.vigilance ? 'Pause Agent' : 'Resume Agent'}
            </button>
          </div>
        )}
        <span className="font-mono text-[10px] text-[#6b8fa3]">
          Agent: {demo.agentStarted ? (demo.vigilance ? 'ACTIVE' : 'PAUSED') : 'STANDBY'} | Stats: LIVE
        </span>
      </div>

      <header className="flex items-center justify-between px-6 py-4 border-b border-[#1a3a5c] bg-[#0a1220]/95">
        <div className="flex items-center gap-4">
          <HologramRing active={demo.vigilance && demo.agentStarted} mode={demo.agentStarted && demo.vigilance ? 'listening' : 'idle'} />
          <div>
            <h1 className="font-display text-2xl font-black tracking-[0.15em] text-[#00fff7]">DVIELLE</h1>
            <p className="text-[10px] tracking-[0.35em] text-[#6b8fa3] uppercase">Deep Vigilance</p>
            <p className="text-xs italic text-[#0099b3] mt-1 max-w-md truncate">{demo.greeting}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`text-2xl ${demo.agentStarted && demo.vigilance ? 'text-[#00ff9d] pulse-glow' : 'text-[#00e5ff]'}`}>●</span>
          <span
            className={`font-display text-sm tracking-wider ${
              demo.agentStarted && demo.vigilance ? 'text-[#00ff9d]' : 'text-[#00e5ff]'
            }`}
          >
            {demo.agentStarted ? (demo.vigilance ? 'VIGILANCE ACTIVE' : 'AGENT PAUSED') : 'STATS LIVE'}
          </span>
        </div>
      </header>

      <div className="flex-1 flex min-h-0 gap-4 p-4">
        <main className="flex-1 grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4 min-h-0 min-w-0">
          <Panel title="NETWORK & VPN">
            <NetworkPanel network={demo.network} loading={demo.networkLoading} />
          </Panel>

          <Panel title="SYSTEM VITALS">
            <VitalBar label="CPU" value={demo.cpu} />
            <VitalBar label="RAM" value={demo.ram} />
            <VitalBar label="DISK" value={demo.disk} />
            <p className="font-mono text-[10px] text-[#6b8fa3] mb-3">
              Agent cycles: {demo.agentStarted ? demo.cycles : '—'}
            </p>
            <div className="border-t border-[#1a3a5c] pt-3">
              <h3 className="font-display text-[10px] tracking-wider text-[#ffb020] mb-2">QUICK CLOSE</h3>
              <QuickClose apps={demo.closeable} onClose={demo.closeApp} />
            </div>
          </Panel>

          <Panel title="INTELLIGENCE FEED" className="xl:col-span-1">
            <IntelligenceFeed events={demo.feed} />
          </Panel>

          <Panel title="PROTECTION MATRIX" className="lg:col-span-2 xl:col-span-3">
            <ProtectionMatrix onReplayGreeting={demo.replayGreeting} speaking={demo.speaking} />
          </Panel>
        </main>

        <div className="w-full max-w-md shrink-0 min-h-0">
          <ChatPanel stats={chatStats} />
        </div>
      </div>

      <footer className="flex flex-wrap items-center justify-between gap-2 px-6 py-3 border-t border-[#1a3a5c] bg-[#0a1220]/95">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[10px] text-[#6b8fa3]">v1.4 DEMO · C:\DVILLIE · chat always open</span>
          <button
            type="button"
            onClick={demo.viewWorkLog}
            className="px-3 py-1.5 rounded border border-[#1a3a5c] bg-[#0d1a2d] text-[10px] text-[#6b8fa3] hover:border-[#00e5ff] hover:text-[#00e5ff] tracking-wider"
          >
            View Work Log Report
          </button>
          <button
            type="button"
            onClick={demo.clearWorkLog}
            className="px-3 py-1.5 rounded border border-[#1a3a5c] bg-[#0d1a2d] text-[10px] text-[#6b8fa3] hover:border-[#ff4466] hover:text-[#ff8899] tracking-wider"
          >
            Clear Work Log Report
          </button>
        </div>
        <button
          type="button"
          onClick={demo.minimizeToTray}
          className="px-5 py-2 rounded border border-[#1a3a5c] bg-[#0d1a2d] text-xs text-[#6b8fa3] hover:border-[#6b8fa3] tracking-wider"
        >
          Minimize to Tray
        </button>
      </footer>

      {demo.showWorkLog && <WorkLogModal entries={demo.workLog} onClose={demo.closeWorkLog} />}
    </div>
  )
}
