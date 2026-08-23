import { useCallback, useEffect, useRef, useState } from 'react'
import { HologramRing, type RingMode } from './HologramRing'
import {
  AGENT,
  askChat,
  speechSupported,
  startContinuousListen,
  type ChatStats,
} from '../lib/chatAssistant'
import { speakVill } from '../lib/villVoice'

interface Message {
  id: string
  who: string
  text: string
}

/** Mic always on · single UK voice: VILL */
export function ChatPanel({ stats }: { stats: ChatStats }) {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '0',
      who: '—',
      text: "Mic is always on. I'm VILL — British English. Just talk.",
    },
  ])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('MIC ON · VILL ready…')
  const [ringMode, setRingMode] = useState<RingMode>('listening')
  const [micArmed, setMicArmed] = useState(false)

  const busyRef = useRef(false)
  const ignoreUntilRef = useRef(0)
  const statsRef = useRef(stats)
  const lastHeardRef = useRef(0)
  const scrollRef = useRef<HTMLDivElement>(null)
  const listenCtlRef = useRef<{ stop: () => void } | null>(null)
  const sendRef = useRef<(text: string, fromVoice: boolean) => Promise<void>>(async () => undefined)

  statsRef.current = stats
  busyRef.current = busy

  const push = useCallback((who: string, text: string) => {
    setMessages((m) => [...m, { id: String(Date.now()) + Math.random(), who, text }])
  }, [])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages])

  const startListen = useCallback(() => {
    if (!speechSupported()) {
      setStatus('Mic unsupported in this browser — type instead')
      setRingMode('idle')
      return
    }
    listenCtlRef.current?.stop()
    listenCtlRef.current = startContinuousListen(
      (utterance) => {
        if (Date.now() < ignoreUntilRef.current) return
        if (busyRef.current) return
        void sendRef.current(utterance, true)
      },
      (state, detail) => {
        if (state === 'listening') {
          setRingMode(busyRef.current ? 'thinking' : 'listening')
          if (!busyRef.current) setStatus('MIC ON · VILL listening (UK)')
        } else if (state === 'error') {
          setStatus(`MIC ON · recovering (${detail || 'error'})…`)
        }
      },
    )
    if (!busyRef.current) setRingMode('listening')
  }, [])

  const send = useCallback(
    async (text: string, fromVoice: boolean) => {
      const q = text.trim()
      if (!q || busyRef.current) return
      if (fromVoice) {
        const now = Date.now()
        if (now - lastHeardRef.current < 800) return
        lastHeardRef.current = now
      }

      busyRef.current = true
      setBusy(true)
      setRingMode('thinking')
      ignoreUntilRef.current = Date.now() + 60_000

      push(fromVoice ? 'You (voice)' : 'You', q)
      setInput('')
      setStatus('MIC ON · VILL thinking…')
      const reply = await askChat(q, statsRef.current, fromVoice)
      push(AGENT, reply.text)
      setRingMode('speaking')
      setStatus('MIC ON · VILL speaking…')
      await speakVill(reply.text)

      ignoreUntilRef.current = Date.now() + 600
      busyRef.current = false
      setBusy(false)
      setRingMode('listening')
      setStatus('MIC ON · VILL listening (UK)')
      startListen()
    },
    [push, startListen],
  )
  sendRef.current = send

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      if (!speechSupported()) {
        setStatus('Mic unsupported — type instead')
        return
      }
      try {
        if (navigator.mediaDevices?.getUserMedia) {
          const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
          stream.getTracks().forEach((t) => t.stop())
        }
      } catch {
        setStatus('MIC ON · allow microphone, then click once')
      }
      if (!cancelled) setMicArmed(true)
    })()
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (!micArmed) return
    startListen()
    const watchdog = window.setInterval(() => {
      if (!speechSupported() || busyRef.current) return
      startListen()
    }, 12_000)
    return () => {
      window.clearInterval(watchdog)
      listenCtlRef.current?.stop()
      listenCtlRef.current = null
    }
  }, [micArmed, startListen])

  useEffect(() => {
    const arm = () => {
      setMicArmed(true)
      startListen()
    }
    window.addEventListener('pointerdown', arm, { once: true })
    return () => window.removeEventListener('pointerdown', arm)
  }, [startListen])

  return (
    <aside className="flex flex-col h-full min-h-0 border border-[#1a3a5c] rounded-lg bg-[#0a1220]/95 overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[#1a3a5c] bg-[#0d1a2d]/80">
        <HologramRing active mode={ringMode} size={88} label="VILL" />
        <div className="flex-1 min-w-0">
          <h2 className="font-display text-xs font-bold tracking-[0.2em] text-[#00e5ff]">VILL</h2>
          <p className="text-[10px] text-[#00ff9d] truncate">MIC ALWAYS ON · UK English · Deep Vigilance</p>
        </div>
        <span className="font-mono text-[10px] tracking-wider text-[#00ff9d] pulse-glow">● LIVE</span>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs min-h-0">
        {messages.map((m) => (
          <div key={m.id} className="text-[#00fff7]/90 animate-[fade-in-up_0.25s_ease]">
            <span className="text-[#6b8fa3]">{m.who}:</span> {m.text}
          </div>
        ))}
      </div>

      <p className="px-4 py-1 text-[10px] text-[#00ff9d] border-t border-[#1a3a5c]/40">{status}</p>

      <div className="flex gap-2 p-4 border-t border-[#1a3a5c]">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void send(input, false)}
          placeholder="Talk to VILL…"
          className="flex-1 rounded border border-[#1a3a5c] bg-[#0d1a2d] px-3 py-2 text-xs text-[#e0f7ff] outline-none focus:border-[#00e5ff]"
        />
        <button
          type="button"
          onClick={() => void send(input, false)}
          disabled={busy}
          className="px-4 py-2 rounded border border-[#00e5ff] bg-[#00e5ff]/20 text-xs text-[#00fff7] disabled:opacity-40"
        >
          Send
        </button>
      </div>
    </aside>
  )
}
