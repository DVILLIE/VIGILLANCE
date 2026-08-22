import { useCallback, useEffect, useState } from 'react'

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
  'Good to see you. DVielle online. Deep vigilance active.',
  'All systems nominal. Your machine is under deep vigilance.',
  'At your service. Monitoring network, memory, and privacy channels.',
  'Vigilance protocols engaged. I will alert you to any threat.',
  'Your internet belongs to you alone. Telemetry channels blocked.',
]

const FEED_POOL: Omit<FeedEvent, 'id' | 'time'>[] = [
  { level: 'info', module: 'scan', message: 'Cycle complete — LEARN mode active.' },
  { level: 'info', module: 'network', message: '847 connections scanned. Baseline updated.' },
  { level: 'warn', module: 'ram', message: 'RAM 87% — chrome.exe using 2.1 GB in background.' },
  { level: 'warn', module: 'resource', message: 'Suggestion: Close Discord (780 MB) if not in use.' },
  { level: 'info', module: 'privacy', message: 'Microsoft telemetry upload blocked — CompatTelRunner.' },
  { level: 'critical', module: 'attacks', message: 'Failed logon attempt from 203.0.113.42 — monitoring.' },
  { level: 'info', module: 'microsoft', message: 'Registry drift corrected: AllowTelemetry=0.' },
  { level: 'info', module: 'security', message: 'Defender active. Firewall profiles enabled.' },
]

const INITIAL_APPS: CloseableApp[] = [
  { id: '1', name: 'Discord.exe', memoryMb: 780, cpuPercent: 4 },
  { id: '2', name: 'steam.exe', memoryMb: 420, cpuPercent: 1 },
  { id: '3', name: 'OneDrive.exe', memoryMb: 310, cpuPercent: 2 },
]

function rand(min: number, max: number) {
  return min + Math.random() * (max - min)
}

function nowTime() {
  return new Date().toLocaleTimeString('en-GB', { hour12: false })
}

export function useDemoSimulation() {
  const [cpu, setCpu] = useState(34)
  const [ram, setRam] = useState(72)
  const [disk] = useState(58)
  const [cycles, setCycles] = useState(12)
  const [vigilance, setVigilance] = useState(true)
  const [greeting, setGreeting] = useState(GREETINGS[0])
  const [greetingIdx, setGreetingIdx] = useState(0)
  const [feed, setFeed] = useState<FeedEvent[]>([
    { id: '0', time: nowTime(), level: 'info', module: 'dvielle', message: GREETINGS[0] },
  ])
  const [closeable, setCloseable] = useState<CloseableApp[]>(INITIAL_APPS)
  const [speaking, setSpeaking] = useState(false)

  // Simulate vitals
  useEffect(() => {
    const t = setInterval(() => {
      setCpu((c) => Math.min(98, Math.max(8, c + rand(-6, 8))))
      setRam((r) => Math.min(96, Math.max(40, r + rand(-4, 5))))
      if (vigilance) setCycles((c) => c + 1)
    }, 2500)
    return () => clearInterval(t)
  }, [vigilance])

  // Rotate greetings
  useEffect(() => {
    const t = setInterval(() => {
      setGreetingIdx((i) => {
        const next = (i + 1) % GREETINGS.length
        setGreeting(GREETINGS[next])
        return next
      })
    }, 12000)
    return () => clearInterval(t)
  }, [])

  // Add feed events
  useEffect(() => {
    if (!vigilance) return
    const t = setInterval(() => {
      const item = FEED_POOL[Math.floor(Math.random() * FEED_POOL.length)]
      setFeed((prev) => [
        { ...item, id: String(Date.now()), time: nowTime() },
        ...prev.slice(0, 49),
      ])
    }, 4000)
    return () => clearInterval(t)
  }, [vigilance])

  const toggleVigilance = useCallback(() => {
    setVigilance((v) => !v)
    setFeed((prev) => [
      {
        id: String(Date.now()),
        time: nowTime(),
        level: 'info',
        module: 'dvielle',
        message: vigilance ? 'Vigilance paused by operator.' : 'Deep vigilance resumed.',
      },
      ...prev,
    ])
  }, [vigilance])

  const closeApp = useCallback((id: string, name: string) => {
    setCloseable((apps) => apps.filter((a) => a.id !== id))
    setRam((r) => Math.max(45, r - rand(8, 15)))
    setFeed((prev) => [
      {
        id: String(Date.now()),
        time: nowTime(),
        level: 'info',
        module: 'action',
        message: `Closed ${name}. Resources released.`,
      },
      ...prev,
    ])
  }, [])

  const replayGreeting = useCallback(() => {
    setSpeaking(true)
    const g = GREETINGS[greetingIdx]
    setGreeting(g)
    setFeed((prev) => [
      { id: String(Date.now()), time: nowTime(), level: 'info', module: 'voice', message: g },
      ...prev,
    ])
    setTimeout(() => setSpeaking(false), 3000)
  }, [greetingIdx])

  return {
    cpu, ram, disk, cycles, vigilance, greeting, speaking,
    feed, closeable, toggleVigilance, closeApp, replayGreeting,
  }
}
