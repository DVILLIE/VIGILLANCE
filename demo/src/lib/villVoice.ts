/** VILL — single UK-accent voice for DVielle. */

const GREETINGS = [
  "Hello. I'm VILL — Deep Vigilance is online.",
  'All quiet on the wire. Your machine is under my watch.',
  "I'm VILL. Ask me anything, or just talk — I'm listening.",
  'Deep Vigilance engaged. Network, memory, and privacy channels ready.',
  "Welcome back. I'm VILL — at your service.",
]

/** Prefer natural / neural UK English voices over robotic defaults. */
const UK_VOICE_PREFS = [
  'sonia',
  'libby',
  'maisie',
  'ryan',
  'hazel',
  'susan',
  'serena',
  'google uk english female',
  'google uk english male',
  'microsoft hazel',
  'microsoft george',
  'en-gb-sonia',
  'en-gb-ryan',
  'en-gb-libby',
  'natural',
  'neural',
  'uk english',
]

function canSpeak(): boolean {
  return typeof window !== 'undefined' && 'speechSynthesis' in window
}

function loadVoices(): Promise<SpeechSynthesisVoice[]> {
  return new Promise((resolve) => {
    const existing = speechSynthesis.getVoices()
    if (existing.length) {
      resolve(existing)
      return
    }
    const onChange = () => {
      speechSynthesis.removeEventListener('voiceschanged', onChange)
      resolve(speechSynthesis.getVoices())
    }
    speechSynthesis.addEventListener('voiceschanged', onChange)
    setTimeout(() => resolve(speechSynthesis.getVoices()), 500)
  })
}

function scoreUkVoice(v: SpeechSynthesisVoice): number {
  const name = v.name.toLowerCase()
  const lang = v.lang.toLowerCase()
  let score = 0
  if (lang.startsWith('en-gb') || lang === 'en_gb') score += 50
  else if (lang.startsWith('en')) score += 5
  else return -100
  for (let i = 0; i < UK_VOICE_PREFS.length; i++) {
    if (name.includes(UK_VOICE_PREFS[i])) score += 40 - i
  }
  if (name.includes('natural') || name.includes('neural')) score += 25
  if (name.includes('online') || name.includes('desktop')) score += 5
  // Penalise clearly robotic / compact voices
  if (name.includes('compact') || name.includes('mobile')) score -= 15
  return score
}

function pickUkVoice(voices: SpeechSynthesisVoice[]): SpeechSynthesisVoice | null {
  if (!voices.length) return null
  const ranked = [...voices].map((v) => ({ v, s: scoreUkVoice(v) })).sort((a, b) => b.s - a.s)
  return ranked[0]?.s > -50 ? ranked[0].v : voices.find((v) => v.lang.toLowerCase().startsWith('en')) ?? voices[0]
}

/** Soften text slightly for TTS (less robotic cadence). */
function prepareForSpeech(text: string): string {
  return text
    .replace(/\s+/g, ' ')
    .replace(/([.!?])\s+/g, '$1 ')
    .replace(/\bDVielle\b/gi, 'Dee Ville')
    .replace(/\bVILL\b/g, 'Vill')
    .trim()
}

function splitSentences(text: string): string[] {
  const parts = text.match(/[^.!?]+[.!?]+|[^.!?]+$/g) ?? [text]
  return parts.map((p) => p.trim()).filter(Boolean)
}

export function randomVillGreeting(): string {
  return GREETINGS[Math.floor(Math.random() * GREETINGS.length)]
}

let bootVoicePending: string | null = null

export function queueBootVoice(text: string): void {
  bootVoicePending = text
}

export async function speakVill(text: string): Promise<boolean> {
  if (!canSpeak()) {
    console.warn('[VILL] Web Speech API not available in this browser')
    return false
  }
  const voices = await loadVoices()
  const voice = pickUkVoice(voices)
  const prepared = prepareForSpeech(text)
  const chunks = splitSentences(prepared)

  speechSynthesis.cancel()

  return new Promise((resolve) => {
    let i = 0
    let settled = false
    const finish = (ok: boolean) => {
      if (settled) return
      settled = true
      resolve(ok)
    }

    const speakNext = () => {
      if (i >= chunks.length) {
        finish(true)
        return
      }
      const utter = new SpeechSynthesisUtterance(chunks[i])
      i += 1
      if (voice) utter.voice = voice
      utter.lang = 'en-GB'
      // Slightly slower + neutral pitch = less robotic
      utter.rate = 0.92
      utter.pitch = 1.0
      utter.volume = 1
      utter.onend = () => {
        // Tiny pause between sentences
        setTimeout(speakNext, 120)
      }
      utter.onerror = () => finish(false)
      speechSynthesis.speak(utter)
    }

    speakNext()
    // Safety: if browser blocks speech silently
    setTimeout(() => {
      if (!speechSynthesis.speaking && i === 1) finish(speechSynthesis.pending)
    }, 400)
  })
}

/** @deprecated use speakVill */
export const speakJarvis = (_text: string, _persona?: unknown) => speakVill(String(_text))

export async function flushBootVoice(): Promise<void> {
  if (!bootVoicePending) return
  const text = bootVoicePending
  bootVoicePending = null
  await speakVill(text)
}

export function primeVillVoice(): void {
  if (!canSpeak()) return
  void loadVoices()
}

/** @deprecated use primeVillVoice */
export const primeJarvisVoice = primeVillVoice

/** @deprecated use randomVillGreeting */
export const randomJarvisGreeting = randomVillGreeting
