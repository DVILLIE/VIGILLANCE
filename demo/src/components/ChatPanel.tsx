import { useCallback, useState } from 'react'
import type { PersonaId } from '../lib/chatAssistant'
import { askChat, listenOnce, type ChatStats } from '../lib/chatAssistant'
import { speakJarvis } from '../lib/jarvisVoice'

interface Message {
  id: string
  who: string
  text: string
}

export function ChatPanel({
  stats,
  onClose,
}: {
  stats: ChatStats
  onClose: () => void
}) {
  const [persona, setPersona] = useState<PersonaId>('jarvis')
  const [messages, setMessages] = useState<Message[]>([
    { id: '0', who: '—', text: 'Jarvis & KT online. Ask about stats or use 🎤 for web (voice only).' },
  ])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('Type for stats · 🎤 for web questions')

  const push = useCallback((who: string, text: string) => {
    setMessages((m) => [...m, { id: String(Date.now()) + Math.random(), who, text }])
  }, [])

  const send = useCallback(
    async (text: string, fromVoice: boolean) => {
      if (!text.trim() || busy) return
      setBusy(true)
      push(fromVoice ? 'You (voice)' : 'You', text)
      setInput('')
      setStatus('Thinking…')
      const reply = await askChat(text, persona, stats, fromVoice)
      const label = reply.persona === 'kt' ? 'KT' : 'Jarvis'
      push(label, reply.text)
      await speakJarvis(reply.text, reply.persona)
      setStatus(
        `${label} replied${reply.usedWeb ? ' (web)' : ''}${reply.usedLlm ? ' · Ollama' : reply.usedLocal ? ' · stats' : ''}`,
      )
      setBusy(false)
    },
    [busy, persona, push, stats],
  )

  const onMic = useCallback(async () => {
    if (busy) return
    setStatus('Listening…')
    try {
      const text = await listenOnce()
      setInput(text)
      await send(text, true)
    } catch {
      setStatus("Couldn't hear you — try again or type.")
      setBusy(false)
    }
  }, [busy, send])

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-full max-w-md flex flex-col border-l border-[#1a3a5c] bg-[#0a1220]/98 shadow-2xl">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1a3a5c]">
        <div>
          <h2 className="font-display text-xs font-bold tracking-[0.2em] text-[#00e5ff]">CHAT</h2>
          <p className="text-[10px] text-[#6b8fa3]">Jarvis US · KT British · stats + voice web</p>
        </div>
        <button type="button" onClick={onClose} className="text-[#6b8fa3] hover:text-[#00e5ff] text-sm">
          ✕
        </button>
      </div>

      <div className="flex gap-3 px-4 py-2 border-b border-[#1a3a5c]/60">
        <label className="flex items-center gap-1.5 text-xs text-[#e0f7ff] cursor-pointer">
          <input type="radio" checked={persona === 'jarvis'} onChange={() => setPersona('jarvis')} />
          Jarvis (US)
        </label>
        <label className="flex items-center gap-1.5 text-xs text-[#e0f7ff] cursor-pointer">
          <input type="radio" checked={persona === 'kt'} onChange={() => setPersona('kt')} />
          KT (British)
        </label>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
        {messages.map((m) => (
          <div key={m.id} className="text-[#00fff7]/90">
            <span className="text-[#6b8fa3]">{m.who}:</span> {m.text}
          </div>
        ))}
      </div>

      <p className="px-4 text-[10px] text-[#6b8fa3]">{status}</p>

      <div className="flex gap-2 p-4 border-t border-[#1a3a5c]">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void send(input, false)}
          placeholder="How is my RAM?"
          className="flex-1 rounded border border-[#1a3a5c] bg-[#0d1a2d] px-3 py-2 text-xs text-[#e0f7ff] outline-none focus:border-[#00e5ff]"
        />
        <button
          type="button"
          onClick={() => void onMic()}
          disabled={busy}
          className="px-3 py-2 rounded border border-[#1a3a5c] text-sm hover:border-[#00e5ff]"
          title="Voice — enables web lookup"
        >
          🎤
        </button>
        <button
          type="button"
          onClick={() => void send(input, false)}
          disabled={busy}
          className="px-4 py-2 rounded border border-[#00e5ff] bg-[#00e5ff]/20 text-xs text-[#00fff7]"
        >
          Send
        </button>
      </div>
    </div>
  )
}
