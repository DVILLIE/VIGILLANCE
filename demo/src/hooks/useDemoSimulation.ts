import { useCallback, useEffect, useState } from 'react'

export interface NetworkInfo {
  localIp: string
  publicIp: string
  vpnActive: boolean
  vpnName: string | null
  vpnIp: string | null
  dnsServers: string[]
  gateway: string
  hostname: string
}

export interface CloseableApp {
  id: string
  name: string
  memoryMb: number
  cpuPercent: number
}

export interface FeedEvent {
  id: string
  time: string
  level: 'info' | 'warn' | 'critical'
  module: string
  message: string
}

const GREETINGS = [
  'Good to see you. Press START to begin deep vigilance.',
  'All systems ready. Awaiting your command.',
  'At your service. I will map your network, VPN, and DNS in real time.',
]

const FEED_POOL: Omit<FeedEvent, 'id' | 'time'>[] = [
  { level: 'info', module: 'network', message: 'Network scan complete. Baseline updated.' },
  { level: 'info', module: 'scan', message: 'Cycle complete — GUARD mode active.' },
  { level: 'warn', module: 'ram', message: 'RAM 87% — chrome.exe using 2.1 GB in background.' },
  { level: 'info', module: 'network', message: 'VPN tunnel verified. DNS routed through VPN.' },
  { level: 'info', module: 'privacy', message: 'Microsoft telemetry upload blocked.' },
]

const INITIAL_APPS: CloseableApp[] = [
  { id: '1', name: 'Discord.exe', memoryMb: 780, cpuPercent: 4 },
  { id: '2', name: 'steam.exe', memoryMb: 420, cpuPercent: 1 },
]

function rand(min: number, max: number) {
  return min + Math.random() * (max - min)
}

function nowTime() {
  return new Date().toLocaleTimeString('en-GB', { hour12: false })
}

async function fetchPublicIp(): Promise<string> {
  try {
    const r = await fetch('https://api.ipify.org?format=json')
    const j = await r.json()
    return j.ip || '—'
  } catch {
    return '—'
  }
}

async function fetchLocalIp(): Promise<string> {
  return new Promise((resolve) => {
    try {
      const pc = new RTCPeerConnection({ iceServers: [] })
      pc.createDataChannel('')
      pc.createOffer().then((o) => pc.setLocalDescription(o))
      pc.onicecandidate = (e) => {
        if (!e.candidate) return
        const m = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(e.candidate.candidate)
        if (m) {
          resolve(m[1])
          pc.close()
        }
      }
      setTimeout(() => {
        resolve('192.168.1.42')
        pc.close()
      }, 2000)
    } catch {
      resolve('192.168.1.42')
    }
  })
}

/** Demo VPN profile — full Windows agent uses real adapter detection */
const DEMO_VPN: NetworkInfo = {
  localIp: '192.168.1.42',
  publicIp: '203.0.113.88',
  vpnActive: true,
  vpnName: 'NordLynx',
  vpnIp: '10.5.0.2',
  dnsServers: ['10.5.0.1', '1.1.1.1'],
  gateway: '10.5.0.1',
  hostname: 'DVIELLE-PC',
}

export function useDemoSimulation() {
  const [started, setStarted] = useState(false)
  const [cpu, setCpu] = useState(0)
  const [ram, setRam] = useState(0)
  const [disk] = useState(0)
  const [cycles, setCycles] = useState(0)
  const [vigilance, setVigilance] = useState(false)
  const [greeting, setGreeting] = useState(GREETINGS[0])
  const [feed, setFeed] = useState<FeedEvent[]>([])
  const [closeable, setCloseable] = useState<CloseableApp[]>([])
  const [speaking, setSpeaking] = useState(false)
  const [network, setNetwork] = useState<NetworkInfo | null>(null)
  const [networkLoading, setNetworkLoading] = useState(false)

  const refreshNetwork = useCallback(async () => {
    if (!started) return
    setNetworkLoading(true)
    const [localIp, publicIp] = await Promise.all([fetchLocalIp(), fetchPublicIp()])
    // Demo: show VPN detection UX (real agent detects on Windows)
    const info: NetworkInfo = {
      ...DEMO_VPN,
      localIp,
      publicIp: publicIp !== '—' ? publicIp : DEMO_VPN.publicIp,
      hostname: typeof window !== 'undefined' ? window.location.hostname || 'DVIELLE-PC' : 'DVIELLE-PC',
    }
    setNetwork(info)
    setNetworkLoading(false)
    return info
  }, [started])

  const start = useCallback(async () => {
    setStarted(true)
    setVigilance(true)
    setCpu(28)
    setRam(65)
    setCloseable(INITIAL_APPS)
    const g = 'DVielle online. Deep vigilance initiated. Mapping network channels.'
    setGreeting(g)
    setFeed([{ id: '0', time: nowTime(), level: 'info', module: 'dvielle', message: g }])
    setSpeaking(true)
    setTimeout(() => setSpeaking(false), 2500)

    const info = await refreshNetwork()
    if (info) {
      setFeed((prev) => [
        {
          id: String(Date.now()),
          time: nowTime(),
          level: 'info',
          module: 'network',
          message: `Local IP: ${info.localIp} | Public: ${info.publicIp}`,
        },
        {
          id: String(Date.now() + 1),
          time: nowTime(),
          level: 'info',
          module: 'network',
          message: info.vpnActive
            ? `VPN ACTIVE — ${info.vpnName} | Tunnel IP: ${info.vpnIp} | DNS: ${info.dnsServers.join(', ')}`
            : 'No VPN detected. Traffic on direct connection.',
        },
        ...prev,
      ])
    }
  }, [refreshNetwork])

  useEffect(() => {
    if (!started || !vigilance) return
    const t = setInterval(() => {
      setCpu((c) => Math.min(98, Math.max(8, c + rand(-6, 8))))
      setRam((r) => Math.min(96, Math.max(40, r + rand(-4, 5))))
      setCycles((c) => c + 1)
    }, 2500)
    return () => clearInterval(t)
  }, [started, vigilance])

  useEffect(() => {
    if (!started || !vigilance) return
    const t = setInterval(() => {
      const item = FEED_POOL[Math.floor(Math.random() * FEED_POOL.length)]
      setFeed((prev) => [{ ...item, id: String(Date.now()), time: nowTime() }, ...prev.slice(0, 49)])
    }, 5000)
    return () => clearInterval(t)
  }, [started, vigilance])

  useEffect(() => {
    if (!started) return
    const t = setInterval(() => refreshNetwork(), 15000)
    return () => clearInterval(t)
  }, [started, refreshNetwork])

  const toggleVigilance = useCallback(() => {
    if (!started) return
    setVigilance((v) => !v)
  }, [started])

  const closeApp = useCallback((id: string, name: string) => {
    setCloseable((apps) => apps.filter((a) => a.id !== id))
    setRam((r) => Math.max(45, r - rand(8, 15)))
    setFeed((prev) => [
      { id: String(Date.now()), time: nowTime(), level: 'info', module: 'action', message: `Closed ${name}.` },
      ...prev,
    ])
  }, [])

  const replayGreeting = useCallback(() => {
    setSpeaking(true)
    setTimeout(() => setSpeaking(false), 2500)
  }, [])

  return {
    started, start, cpu, ram, disk, cycles, vigilance, greeting, speaking,
    feed, closeable, toggleVigilance, closeApp, replayGreeting,
    network, networkLoading,
  }
}
