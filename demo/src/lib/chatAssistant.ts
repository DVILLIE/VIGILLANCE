/** Browser chat — mirrors Python assistant (stats + optional Ollama + voice web). */

export type PersonaId = 'jarvis' | 'kt'

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
  persona: PersonaId
  usedWeb: boolean
  usedLlm: boolean
  usedLocal: boolean
}

const WEB_HINT =
  /\b(what is|who is|when is|where is|how to|latest|news|weather|today|define|meaning of)\b/i

const STATS_HINT =
  /\b(cpu|ram|memory|disk|vpn|ip|dns|gateway|stats|screen|computer|agent|vigilance|status|summary)\b/i

function formatStatsBlock(stats: ChatStats): string {
  const n = stats.network
  const vpn = n?.vpnActive
    ? `VPN ON (${n.vpnName}) tunnel IP ${n.vpnIp}`
    : `VPN OFF — public IP ${n?.publicIp ?? 'unknown'}`
  const agent = stats.agentStarted ? `running (${stats.agentCycles} cycles)` : 'standby (stats only)'
  return [
    'LIVE STATS:',
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

function localAnswer(q: string, stats: ChatStats, persona: PersonaId): string | null {
  const s = q.toLowerCase()
  const brit = persona === 'kt'

  if (/\b(hello|hi|hey)\b/.test(s)) {
    return brit
      ? "Hello. I'm KT — ask about your screen stats, or tap the mic for a web question."
      : 'Hello. Jarvis online — ask about your stats or use the mic for web questions.'
  }
  if (/\b(ram|memory)\b/.test(s)) {
    const pct = stats.ram
    if (brit) {
      if (pct >= 85) return `Memory is quite full at ${pct.toFixed(0)}% — the PC may feel slow. Close apps you're not using.`
      return `Memory is at ${pct.toFixed(0)}% — ${pct < 70 ? 'healthy' : 'a bit busy'} for everyday use.`
    }
    return pct >= 85
      ? `RAM is high at ${pct.toFixed(0)}%. Close background apps.`
      : `RAM is ${pct.toFixed(0)}% — looks fine.`
  }
  if (/\b(cpu|processor)\b/.test(s)) {
    return brit
      ? `Processor is ${stats.cpu.toFixed(0)}% busy — ${stats.cpu > 80 ? 'something may be working hard in the background' : 'normal for light use'}.`
      : `CPU at ${stats.cpu.toFixed(0)}%.`
  }
  if (/\b(disk|storage|drive)\b/.test(s)) {
    return brit
      ? `Disk is ${stats.disk.toFixed(0)}% full — ${stats.disk > 85 ? 'getting tight, worth clearing files' : 'plenty of room'}.`
      : `Disk ${stats.disk.toFixed(0)}% used.`
  }
  if (/\b(vpn)\b/.test(s)) {
    const n = stats.network
    if (n?.vpnActive) {
      return brit
        ? `Yes — VPN is on (${n.vpnName}), tunnel IP ${n.vpnIp}.`
        : `VPN active: ${n.vpnName}, IP ${n.vpnIp}.`
    }
    return brit ? 'No VPN detected — direct connection.' : `No VPN. Public IP ${n?.publicIp ?? 'unknown'}.`
  }
  if (/\b(status|stats|summary|screen|everything)\b/.test(s)) {
    return brit
      ? `Quick look: CPU ${stats.cpu.toFixed(0)}%, memory ${stats.ram.toFixed(0)}%, disk ${stats.disk.toFixed(0)}%. ${stats.network?.vpnActive ? 'VPN on.' : 'No VPN.'}`
      : `Status: CPU ${stats.cpu.toFixed(0)}%, RAM ${stats.ram.toFixed(0)}%, disk ${stats.disk.toFixed(0)}%. ${stats.network?.vpnActive ? 'VPN on' : 'VPN off'}.`
  }
  return null
}

function needsWeb(q: string): boolean {
  return WEB_HINT.test(q) && !STATS_HINT.test(q)
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

const SYSTEM: Record<PersonaId, string> = {
  jarvis:
    'You are Jarvis, DVielle co-pilot. US English. Plain English for non-technical users. Use LIVE STATS only.',
  kt: 'You are KT, DVielle assistant. British English. Warm, simple explanations. Use LIVE STATS only.',
}

export async function askChat(
  question: string,
  persona: PersonaId,
  stats: ChatStats,
  fromVoice: boolean,
): Promise<ChatReply> {
  const q = question.trim()
  if (!q) {
    return { text: "I didn't catch that.", persona, usedWeb: false, usedLlm: false, usedLocal: false }
  }

  let webNote = ''
  let usedWeb = false
  if (fromVoice && needsWeb(q)) {
    webNote = await searchWeb(q)
    usedWeb = Boolean(webNote)
  }

  const local = localAnswer(q, stats, persona)
  if (local && !usedWeb) {
    return { text: local, persona, usedWeb, usedLlm: false, usedLocal: true }
  }

  const statsBlock = formatStatsBlock(stats)
  const extra = webNote ? `\n\nWEB RESULTS:\n${webNote}` : ''
  const llm = await ollamaChat([
    { role: 'system', content: `${SYSTEM[persona]}\n\n${statsBlock}${extra}` },
    { role: 'user', content: q },
  ])
  if (llm) {
    return { text: llm, persona, usedWeb, usedLlm: true, usedLocal: false }
  }

  const fallback =
    local ||
    (persona === 'kt'
      ? "I'm not sure. Try asking about CPU, memory, VPN, or disk — or use the mic for web questions."
      : 'Unclear on that. Ask about CPU, RAM, VPN, or disk — mic enables web lookup.')

  return { text: fallback, persona, usedWeb, usedLlm: false, usedLocal: Boolean(local) }
}

export function listenOnce(): Promise<string> {
  return new Promise((resolve, reject) => {
    type SpeechRecognitionCtor = new () => {
      lang: string
      interimResults: boolean
      maxAlternatives: number
      onresult: ((e: { results: { [i: number]: { [j: number]: { transcript: string } } } }) => void) | null
      onerror: (() => void) | null
      start: () => void
    }
    const w = window as unknown as {
      SpeechRecognition?: SpeechRecognitionCtor
      webkitSpeechRecognition?: SpeechRecognitionCtor
    }
    const SR = w.SpeechRecognition || w.webkitSpeechRecognition
    if (!SR) {
      reject(new Error('Speech recognition not supported in this browser'))
      return
    }
    const rec = new SR()
    rec.lang = 'en-US'
    rec.interimResults = false
    rec.maxAlternatives = 1
    rec.onresult = (e) => resolve(e.results[0][0].transcript)
    rec.onerror = () => reject(new Error('Could not hear you'))
    rec.start()
  })
}
