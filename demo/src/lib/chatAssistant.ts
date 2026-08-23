/** Open chat — VILL (UK English). Free talk + screen stats + voice web. */

export interface ChatStats {
  agentStarted: boolean
  agentCycles: number
  cpu: number
  ram: number
  disk: number
  network: {
    localIp: string
    publicIp: string
    vpnActive: boolean
    vpnName: string | null
    vpnIp: string | null
    dnsServers: string[]
    gateway: string
    hostname: string
  } | null
}

export interface ChatReply {
  text: string
  usedWeb: boolean
  usedLlm: boolean
  usedLocal: boolean
}

const AGENT = 'VILL'

const WEB_HINT =
  /\b(what is|who is|when is|where is|how to|latest|news|weather|today|define|meaning of|tell me about|look up|search)\b/i

const STATS_ONLY =
  /^(how('?s| is)? (my )?(cpu|ram|memory|disk|vpn|ip|status)|what('?s| is) (my )?(cpu|ram|memory|disk|vpn|ip|status)|stats|summary)\b/i

function formatStatsBlock(stats: ChatStats): string {
  const n = stats.network
  const vpn = n?.vpnActive
    ? `VPN ON (${n.vpnName}) tunnel IP ${n.vpnIp}`
    : `VPN OFF — public IP ${n?.publicIp ?? 'unknown'}`
  const agent = stats.agentStarted ? `running (${stats.agentCycles} cycles)` : 'standby (stats only)'
  return [
    'OPTIONAL LIVE SCREEN STATS (use when user asks about the PC/screen):',
    `- Vigilance agent: ${agent}`,
    `- CPU: ${stats.cpu.toFixed(0)}%`,
    `- RAM: ${stats.ram.toFixed(0)}%`,
    `- Disk: ${stats.disk.toFixed(0)}% used`,
    `- Host: ${n?.hostname ?? 'unknown'}`,
    `- Local IP: ${n?.localIp ?? 'unknown'}`,
    `- Public IP: ${n?.publicIp ?? 'unknown'}`,
    `- ${vpn}`,
    `- DNS: ${(n?.dnsServers ?? []).join(', ') || 'unknown'}`,
    `- Gateway: ${n?.gateway ?? 'unknown'}`,
  ].join('\n')
}

function statsAnswer(q: string, stats: ChatStats): string | null {
  if (!STATS_ONLY.test(q.trim()) && !/\b(cpu|ram|memory|disk|vpn)\b/i.test(q)) return null
  const s = q.toLowerCase()

  if (/\b(ram|memory)\b/.test(s)) {
    const pct = stats.ram
    if (pct >= 85) return `Memory is quite full at ${pct.toFixed(0)}% — the PC may feel slow. Close apps you're not using.`
    return `Memory is at ${pct.toFixed(0)}% — ${pct < 70 ? 'healthy' : 'a bit busy'} for everyday use.`
  }
  if (/\b(cpu|processor)\b/.test(s)) {
    return `Processor is ${stats.cpu.toFixed(0)}% busy — ${stats.cpu > 80 ? 'something may be working hard in the background' : 'normal for light use'}.`
  }
  if (/\b(disk|storage|drive)\b/.test(s)) {
    return `Disk is ${stats.disk.toFixed(0)}% full — ${stats.disk > 85 ? 'getting tight, worth clearing files' : 'plenty of room'}.`
  }
  if (/\b(vpn)\b/.test(s)) {
    const n = stats.network
    if (n?.vpnActive) return `Yes — VPN is on (${n.vpnName}), tunnel IP ${n.vpnIp}.`
    return 'No VPN detected — direct connection.'
  }
  if (/\b(status|stats|summary)\b/.test(s)) {
    return `Quick look: CPU ${stats.cpu.toFixed(0)}%, memory ${stats.ram.toFixed(0)}%, disk ${stats.disk.toFixed(0)}%. ${stats.network?.vpnActive ? 'VPN on.' : 'No VPN.'}`
  }
  return null
}

function greeting(): string {
  return "Hello — I'm VILL. Chat about anything you like. I can also read what's on your screen, and if you speak, I can look things up on the web."
}

async function searchWeb(query: string): Promise<string> {
  try {
    const url = `/api/search?q=${encodeURIComponent(query)}`
    const r = await fetch(url)
    if (!r.ok) return ''
    const j = await r.json()
    return (j.abstract || j.snippet || '') as string
  } catch {
    return ''
  }
}

async function ollamaChat(messages: { role: string; content: string }[]): Promise<string | null> {
  try {
    const r = await fetch('http://127.0.0.1:11434/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'llama3.2', messages, stream: false }),
    })
    if (!r.ok) return null
    const j = await r.json()
    return (j.message?.content as string)?.trim() || null
  } catch {
    return null
  }
}

const SYSTEM = [
  `You are ${AGENT}, the voice of DVielle (Deep Vigilance).`,
  'Speak in natural British English (UK spelling and phrasing). Warm, clear, never robotic or stiff.',
  'The user may talk about ANYTHING — life, ideas, jokes, tech help, the PC, or random questions.',
  'Do NOT refuse ordinary conversation or force them back to system monitoring.',
  'When they ask about the PC/screen, use LIVE STATS and explain in plain English.',
  'Keep replies concise (2–5 sentences) unless they ask for detail.',
  'Never mention Jarvis, KT, or other assistant names — you are only VILL.',
].join(' ')

function openFallback(q: string, webNote: string): string {
  if (/\b(hello|hi|hey|good (morning|afternoon|evening))\b/i.test(q)) return greeting()
  if (webNote) {
    return `Here's what I found: ${webNote.slice(0, 420)}${webNote.length > 420 ? '…' : ''}`
  }
  return "I'm listening — ask me anything. I can chat, read your screen stats, and look things up when you speak."
}

export async function askChat(
  question: string,
  stats: ChatStats,
  fromVoice: boolean,
): Promise<ChatReply> {
  const q = question.trim()
  if (!q) {
    return { text: "I didn't catch that — try again.", usedWeb: false, usedLlm: false, usedLocal: false }
  }

  if (/\b(hello|hi|hey)\b/i.test(q) && q.split(/\s+/).length <= 4) {
    return { text: greeting(), usedWeb: false, usedLlm: false, usedLocal: true }
  }

  let webNote = ''
  let usedWeb = false
  if (fromVoice && (WEB_HINT.test(q) || q.endsWith('?'))) {
    webNote = await searchWeb(q)
    usedWeb = Boolean(webNote)
  }

  const statsHit = statsAnswer(q, stats)
  if (statsHit && !usedWeb && STATS_ONLY.test(q)) {
    return { text: statsHit, usedWeb, usedLlm: false, usedLocal: true }
  }

  const statsBlock = formatStatsBlock(stats)
  const extra = webNote ? `\n\nWEB RESULTS (from voice lookup):\n${webNote}` : ''
  const llm = await ollamaChat([
    { role: 'system', content: `${SYSTEM}\n\n${statsBlock}${extra}` },
    { role: 'user', content: q },
  ])
  if (llm) {
    return { text: llm, usedWeb, usedLlm: true, usedLocal: false }
  }

  if (statsHit) {
    return { text: statsHit, usedWeb, usedLlm: false, usedLocal: true }
  }

  return {
    text: openFallback(q, webNote),
    usedWeb,
    usedLlm: false,
    usedLocal: false,
  }
}

type Recog = {
  lang: string
  continuous: boolean
  interimResults: boolean
  maxAlternatives: number
  onresult: ((e: SpeechRecognitionEventLike) => void) | null
  onerror: ((e: { error?: string }) => void) | null
  onend: (() => void) | null
  start: () => void
  stop: () => void
  abort: () => void
}

type SpeechRecognitionEventLike = {
  results: ArrayLike<ArrayLike<{ transcript: string; confidence: number }> & { isFinal?: boolean }>
}

function getSR(): (new () => Recog) | null {
  const w = window as unknown as {
    SpeechRecognition?: new () => Recog
    webkitSpeechRecognition?: new () => Recog
  }
  return w.SpeechRecognition || w.webkitSpeechRecognition || null
}

export function listenOnce(): Promise<string> {
  return new Promise((resolve, reject) => {
    const SR = getSR()
    if (!SR) {
      reject(new Error('Speech recognition not supported in this browser'))
      return
    }
    const rec = new SR()
    rec.lang = 'en-GB'
    rec.continuous = false
    rec.interimResults = false
    rec.maxAlternatives = 1
    rec.onresult = (e) => resolve(e.results[0][0].transcript)
    rec.onerror = () => reject(new Error('Could not hear you'))
    rec.onend = null
    rec.start()
  })
}

/** Continuous listen — UK English. Mic always on. */
export function startContinuousListen(
  onUtterance: (text: string) => void,
  onState?: (state: 'listening' | 'idle' | 'error', detail?: string) => void,
): { stop: () => void } {
  const SR = getSR()
  let stopped = false
  let rec: Recog | null = null

  const start = () => {
    if (stopped) return
    const Ctor = getSR()
    if (!Ctor) {
      onState?.('error', 'Speech recognition not supported')
      return
    }
    rec = new Ctor()
    rec.lang = 'en-GB'
    rec.continuous = true
    rec.interimResults = true
    rec.maxAlternatives = 1
    let handled = 0
    rec.onresult = (e) => {
      for (let i = handled; i < e.results.length; i++) {
        const row = e.results[i] as ArrayLike<{ transcript: string }> & { isFinal?: boolean }
        if (!row.isFinal) continue
        const t = row[0]?.transcript?.trim()
        if (t) onUtterance(t)
        handled = i + 1
      }
    }
    rec.onerror = (ev) => {
      if (stopped) return
      const err = ev.error || 'error'
      if (err === 'aborted' || err === 'no-speech' || err === 'network' || err === 'audio-capture') {
        setTimeout(() => {
          if (!stopped) {
            try {
              start()
            } catch {
              /* retry via onend */
            }
          }
        }, 250)
        return
      }
      onState?.('error', err)
      setTimeout(() => {
        if (!stopped) start()
      }, 800)
    }
    rec.onend = () => {
      if (stopped) {
        onState?.('idle')
        return
      }
      setTimeout(() => {
        if (stopped) return
        try {
          start()
        } catch {
          setTimeout(start, 400)
        }
      }, 120)
    }
    try {
      rec.start()
      onState?.('listening')
    } catch {
      setTimeout(start, 500)
    }
  }

  if (!SR) {
    onState?.('error', 'Speech recognition not supported')
    return { stop: () => undefined }
  }

  start()

  return {
    stop: () => {
      stopped = true
      try {
        rec?.abort()
      } catch {
        try {
          rec?.stop()
        } catch {
          /* ignore */
        }
      }
      onState?.('idle')
    },
  }
}

export function speechSupported(): boolean {
  return Boolean(getSR())
}

export { AGENT }
