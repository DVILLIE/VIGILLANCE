import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { parseSnapshot, finiteNumber, ageSeconds, displayValue, type Snapshot } from './lib/snapshot'

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return <section className="rounded-xl border border-[#1a3a5c] bg-[#0a1220] p-5 min-w-0">
    <h2 className="text-xs tracking-[0.2em] text-[#00e5ff] mb-4 uppercase">{title}</h2>
    {children}
  </section>
}

function Metric({ label, value, unit, sampled, now }: { label: string; value: unknown; unit: string; sampled: unknown; now: number }) {
  const number = finiteNumber(value)
  const age = ageSeconds(sampled, now)
  return <div className="mb-5">
    <div className="text-xs text-[#93abba]">{label}</div>
    <div className="text-3xl mt-1 tabular-nums">{number === null ? 'Unavailable' : number.toFixed(1) + unit}</div>
    <div className="text-xs text-[#93abba] mt-1">{age === null ? 'No valid sample time' : 'Sampled ' + Math.floor(age) + 's ago'}</div>
  </div>
}

export default function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [error, setError] = useState('')
  const [now, setNow] = useState(() => Date.now())
  const input = useRef<HTMLInputElement>(null)
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer) }, [])

  async function load(file: File | undefined) {
    if (!file) return
    try {
      if (file.size > 2_000_000) throw new Error('Snapshot exceeds the 2 MB limit.')
      setSnapshot(parseSnapshot(await file.text()))
      setError('')
    } catch (cause) {
      setSnapshot(null)
      setError(cause instanceof Error ? cause.message : 'Cannot read this snapshot.')
    }
  }

  const data = snapshot
  const heartbeatAge = ageSeconds(data?.runtime.heartbeat_at, now)
  const heartbeatInterval = finiteNumber(data?.collectors.heartbeat?.interval_seconds) ?? 5
  const recent = heartbeatAge !== null && heartbeatAge < Math.max(30, heartbeatInterval * 3)
  const status = !data ? 'No snapshot loaded' : data.runtime.state !== 'running'
    ? 'Recorded owner state: ' + displayValue(data.runtime.state) : recent ? 'Recent heartbeat in snapshot' : 'Stale heartbeat in snapshot'
  const posture = (value: unknown) => value === true ? 'Enabled at sample time' : value === false ? 'Disabled at sample time' : 'Unavailable'

  return <div className="h-full overflow-y-auto bg-[#050810] text-[#e0f7ff]">
    <header className="border-b border-[#1a3a5c] px-6 py-7 md:px-10 flex flex-wrap items-center justify-between gap-5">
      <div>
        <p className="text-xs tracking-[0.35em] text-[#00e5ff]">DVIELLE / DEEP VIGILANCE</p>
        <h1 className="text-3xl mt-2 font-semibold">Your machine, from evidence.</h1>
        <p className="text-sm text-[#93abba] mt-2">Local snapshot viewer · {status}</p>
      </div>
      <button type="button" onClick={() => input.current?.click()} className="rounded-lg border border-[#00e5ff] px-5 py-3 text-[#00e5ff] hover:bg-[#00e5ff]/10 focus-visible:outline-2 focus-visible:outline-offset-4">Load agent snapshot</button>
      <input ref={input} className="hidden" type="file" accept=".json,application/json" aria-label="Load agent snapshot JSON" onChange={event => { void load(event.target.files?.[0]); event.target.value = '' }} />
    </header>
    <main className="max-w-7xl mx-auto p-6 md:p-10">
      <div className="mb-6 border-l-2 border-[#00e5ff] pl-4 text-sm text-[#b7cbd5] leading-6">
        Open <code>C:\DVILLIE\data\twin.json</code> from your running Windows agent. This page reads the selected file locally.
        Reload the file to refresh observations; the browser cannot start monitoring or change Windows settings.
      </div>
      {error && <p role="alert" className="mb-6 rounded-lg bg-[#ff3366]/10 border border-[#ff3366] p-4">{error}</p>}
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        <Panel title="Workload">
          <p className="text-2xl">{displayValue(data?.workload.profile)}</p>
          <p className="text-sm text-[#b7cbd5] mt-3 leading-6">{displayValue(data?.workload.reason, 'Load a snapshot to see the agent’s measured workload assessment.')}</p>
          <p className="text-xs mt-4 text-[#93abba]">Foreground: {displayValue(data?.workload.foreground_name)}</p>
        </Panel>
        <Panel title="Resources">
          <Metric label="CPU demand" value={data?.system.cpu_percent} unit="%" sampled={data?.system.cpu_sampled_at} now={now} />
          <Metric label="Memory load" value={data?.memory.memory_load_percent} unit="%" sampled={data?.memory.sampled_at} now={now} />
          <Metric label="Disk space available" value={data?.system.disk_free_gb} unit=" GB" sampled={data?.system.disk_sampled_at} now={now} />
          <p className="text-xs text-[#93abba]">Memory load alone does not establish memory pressure.</p>
        </Panel>
        <Panel title="Windows security">
          <dl className="text-sm space-y-4">
            <div><dt className="text-[#93abba]">Defender antivirus</dt><dd>{posture(data?.security.defender_enabled)}</dd></div>
            <div><dt className="text-[#93abba]">Real-time protection</dt><dd>{posture(data?.security.realtime_protection)}</dd></div>
            <div><dt className="text-[#93abba]">Firewall profiles</dt><dd>{posture(data?.security.firewall_enabled)}</dd></div>
          </dl>
          <p className="text-xs text-[#93abba] mt-5">Recorded: {displayValue(data?.security.sampled_at)}. These settings do not prove the machine is threat-free.</p>
        </Panel>
        <Panel title="Agent footprint">
          <Metric label="CPU / total logical capacity" value={data?.self_budget.cpu_percent} unit="%" sampled={data?.runtime.heartbeat_at} now={now} />
          <p className="text-sm leading-6 text-[#b7cbd5]">{displayValue(data?.self_budget.reason)}</p>
          <p className="text-xs text-[#93abba] mt-4">The budget controls optional collection cadence; it is not an operating-system resource quota.</p>
        </Panel>
        <Panel title="Network context">
          <dl className="text-sm space-y-3">
            <div><dt className="text-[#93abba]">Hostname</dt><dd>{displayValue(data?.network.hostname)}</dd></div>
            <div><dt className="text-[#93abba]">Gateway</dt><dd>{displayValue(data?.network.gateway)}</dd></div>
            <div><dt className="text-[#93abba]">VPN-like adapter</dt><dd>{displayValue(data?.network.vpn_adapter, 'No adapter reported in this snapshot')}</dd></div>
          </dl>
          <p className="text-xs text-[#93abba] mt-5">An adapter name does not verify VPN routing or encryption.</p>
        </Panel>
        <Panel title="Collection evidence">
          {!data && <p className="text-sm text-[#93abba]">Collector results appear after loading a snapshot.</p>}
          <ul className="space-y-4">
            {Object.entries(data?.collectors ?? {}).map(([name, collector]) => <li key={name} className="text-sm">
              <div className="flex gap-3 justify-between"><span className="break-all">{name}</span><span className={collector.status === 'error' ? 'text-[#ff8899]' : 'text-[#b7cbd5]'}>{displayValue(collector.status)}</span></div>
              <div className="text-xs text-[#93abba] mt-1">Last success: {displayValue(collector.last_success_at, 'No successful sample recorded')}</div>
              {typeof collector.error === 'string' && <div className="text-xs text-[#ff8899] mt-1">{collector.error}</div>}
            </li>)}
          </ul>
        </Panel>
      </div>
    </main>
  </div>
}
