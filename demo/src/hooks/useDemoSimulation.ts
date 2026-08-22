import { useCallback, useEffect, useRef, useState } from 'react'
import { primeJarvisVoice, queueBootVoice, randomJarvisGreeting, speakJarvis, flushBootVoice } from '../lib/jarvisVoice'

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

export interface WorkLogEntry {
  id: string
  ts: string
  action: string
  message: string
}

const WORK_LOG_KEY = 'dvielle-work-log'

const GREETINGS = [
  'Stats live. Press START to activate deep vigilance agent.',
  'All systems ready. Awaiting your command.',
  'At your service. Network, VPN, and DNS updating in real time.',
]

const FEED_POOL: Omit<FeedEvent, 'id' | 'time'>[] = [
  { level: 'info', module: 'network', message: 'Network scan complete. Baseline updated.' },
  { level: 'info', module: 'scan', message: 'Cycle complete — GUARD mode active.' },
  { level: 'warn', module: 'ram', message: 'RAM 87% — chrome.exe using 2.1 GB in background.' },
  { level: 'info', module: 'network', message: 'VPN tunnel verified. DNS routed through VPN.' },
  { level: 'info', module: 'privacy', message: 'Microsoft telemetry upload blocked.' },
  { level: 'critical', module: 'attacks', message: 'CRITICAL: Brute-force attempt blocked from 203.0.113.55' },
]

const INITIAL_APPS: CloseableApp[] = [
  { id: '1', name: 'Discord.exe', memoryMb: 780, cpuPercent: 4 },
  { id: '2', name: 'steam.exe', memoryMb: 420, cpuPercent: 1 },
]

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

function rand(min: number, max: number) {
  return min + Math.random() * (max - min)
}

function nowTime() {
  return new Date().toLocaleTimeString('en-GB', { hour12: false })
}

function nowTs() {
  return new Date().toISOString().slice(0, 19).replace('T', ' ')
}

function loadWorkLog(): WorkLogEntry[] {
  try {
    const raw = localStorage.getItem(WORK_LOG_KEY)
    return raw ? (JSON.parse(raw) as WorkLogEntry[]) : []
  } catch {
    return []
  }
}

function saveWorkLog(entries: WorkLogEntry[]) {
  localStorage.setItem(WORK_LOG_KEY, JSON.stringify(entries))
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

export function useDemoSimulation() {
  const [agentStarted, setAgentStarted] = useState(false)
  const [cpu, setCpu] = useState(28)
  const [ram, setRam] = useState(62)
  const [disk] = useState(58)
  const [cycles, setCycles] = useState(0)
  const [vigilance, setVigilance] = useState(false)
  const [greeting, setGreeting] = useState(GREETINGS[0])
  const [feed, setFeed] = useState<FeedEvent[]>([])
  const [closeable, setCloseable] = useState<CloseableApp[]>(INITIAL_APPS)
  const [speaking, setSpeaking] = useState(false)
  const speakTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const playVoice = useCallback(async (text: string, ms = 3500): Promise<boolean> => {
    primeJarvisVoice()
    await flushBootVoice()
    setSpeaking(true)
    if (speakTimer.current) clearTimeout(speakTimer.current)
    const ok = await speakJarvis(text)
    speakTimer.current = setTimeout(() => setSpeaking(false), ok ? ms : 1200)
    return ok
  }, [])
  const [network, setNetwork] = useState<NetworkInfo | null>(null)
  const [networkLoading, setNetworkLoading] = useState(true)
  const [workLog, setWorkLog] = useState<WorkLogEntry[]>(() => loadWorkLog())
  const [showWorkLog, setShowWorkLog] = useState(false)
  const [minimized, setMinimized] = useState(false)
  const [trayAlert, setTrayAlert] = useState<string | null>(null)
  const bootLogged = useRef(false)

  const appendWorkLog = useCallback((action: string, message: string) => {
    const entry: WorkLogEntry = {
      id: String(Date.now()) + Math.random(),
      ts: nowTs(),
      action,
      message,
    }
    setWorkLog((prev) => {
      const next = [...prev, entry]
      saveWorkLog(next)
      return next
    })
    return entry
  }, [])

  const refreshNetwork = useCallback(async () => {
    setNetworkLoading(true)
    const [localIp, publicIp] = await Promise.all([fetchLocalIp(), fetchPublicIp()])
    const info: NetworkInfo = {
      ...DEMO_VPN,
      localIp,
      publicIp: publicIp !== '—' ? publicIp : DEMO_VPN.publicIp,
      hostname: typeof window !== 'undefined' ? window.location.hostname || 'DVIELLE-PC' : 'DVIELLE-PC',
    }
    setNetwork(info)
    setNetworkLoading(false)
    return info
  }, [])

  // Stats always live on launch + Jarvis speaks on open
  useEffect(() => {
    if (bootLogged.current) return
    bootLogged.current = true
    primeJarvisVoice()
    const openLine = 'Good to see you. DVielle online. Stats monitoring active.'
    appendWorkLog('OPEN', 'DVielle interface launched — stats monitoring active')
    setGreeting(openLine)
    queueBootVoice(openLine)
    void playVoice(openLine, 4500).then((ok) => {
      if (!ok) queueBootVoice(openLine)
    })
    setFeed([
      {
        id: 'boot',
        time: nowTime(),
        level: 'info',
        module: 'dvielle',
        message: 'Stats live. Press START to activate deep vigilance agent.',
      },
    ])
    refreshNetwork().then((info) => {
      if (!info) return
      appendWorkLog(
        'NETWORK',
        info.vpnActive
          ? `VPN ${info.vpnName} IP ${info.vpnIp}`
          : `Direct connection public IP ${info.publicIp}`,
      )
    })
    const t = setInterval(() => {
      setCpu((c) => Math.min(98, Math.max(8, c + rand(-4, 6))))
      setRam((r) => Math.min(96, Math.max(40, r + rand(-3, 4))))
    }, 2500)
    const netT = setInterval(() => refreshNetwork(), 15000)
    return () => {
      clearInterval(t)
      clearInterval(netT)
      if (speakTimer.current) clearTimeout(speakTimer.current)
    }
  }, [appendWorkLog, refreshNetwork, playVoice])

  // Agent cycles only after START
  useEffect(() => {
    if (!agentStarted || !vigilance) return
    const t = setInterval(() => setCycles((c) => c + 1), 2500)
    return () => clearInterval(t)
  }, [agentStarted, vigilance])

  useEffect(() => {
    if (!agentStarted || !vigilance) return
    const t = setInterval(() => {
      const item = FEED_POOL[Math.floor(Math.random() * FEED_POOL.length)]
      setFeed((prev) => [{ ...item, id: String(Date.now()), time: nowTime() }, ...prev.slice(0, 49)])
      if (item.level === 'critical' && minimized) {
        setTrayAlert(item.message)
        setTimeout(() => setTrayAlert(null), 6000)
      }
    }, 5000)
    return () => clearInterval(t)
  }, [agentStarted, vigilance, minimized])

  const startAgent = useCallback(() => {
    if (agentStarted) return
    setAgentStarted(true)
    setVigilance(true)
    const g = 'DVielle online. Deep vigilance agent initiated.'
    setGreeting(g)
    appendWorkLog('START', 'Deep vigilance agent started')
    void playVoice(g, 4000)
    setFeed((prev) => [
      { id: String(Date.now()), time: nowTime(), level: 'info', module: 'dvielle', message: g },
      ...prev,
    ])
  }, [agentStarted, appendWorkLog, playVoice])

  const toggleVigilance = useCallback(() => {
    if (!agentStarted) return
    setVigilance((v) => {
      appendWorkLog(v ? 'PAUSE' : 'RESUME', v ? 'Agent paused by operator' : 'Agent resumed')
      return !v
    })
  }, [agentStarted, appendWorkLog])

  const closeApp = useCallback(
    (id: string, name: string) => {
      setCloseable((apps) => apps.filter((a) => a.id !== id))
      setRam((r) => Math.max(45, r - rand(8, 15)))
      const msg = `Closed ${name}.`
      appendWorkLog('CLOSE_APP', msg)
      setFeed((prev) => [
        { id: String(Date.now()), time: nowTime(), level: 'info', module: 'action', message: msg },
        ...prev,
      ])
    },
    [appendWorkLog],
  )

  const replayGreeting = useCallback(() => {
    const text = randomJarvisGreeting()
    setGreeting(text)
    void playVoice(text, 4000)
  }, [playVoice])

  const viewWorkLog = useCallback(() => setShowWorkLog(true), [])
  const closeWorkLog = useCallback(() => setShowWorkLog(false), [])

  const clearWorkLog = useCallback(() => {
    const n = workLog.length
    const fresh: WorkLogEntry[] = []
    saveWorkLog(fresh)
    setWorkLog(fresh)
    appendWorkLog('CLEAR', `Work log cleared (${n} entries removed)`)
  }, [workLog.length, appendWorkLog])

  const minimizeToTray = useCallback(() => {
    setMinimized(true)
    appendWorkLog('MINIMIZE', 'Minimized to tray — critical alerts only')
  }, [appendWorkLog])

  const restoreFromTray = useCallback(() => {
    setMinimized(false)
    setTrayAlert(null)
  }, [])

  return {
    agentStarted,
    startAgent,
    cpu,
    ram,
    disk,
    cycles,
    vigilance,
    greeting,
    speaking,
    feed,
    closeable,
    toggleVigilance,
    closeApp,
    replayGreeting,
    network,
    networkLoading,
    workLog,
    showWorkLog,
    viewWorkLog,
    closeWorkLog,
    clearWorkLog,
    minimized,
    minimizeToTray,
    restoreFromTray,
    trayAlert,
  }
}
