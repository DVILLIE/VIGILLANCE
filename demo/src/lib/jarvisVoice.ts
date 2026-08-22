const GREETINGS = [
  'Good to see you. DVielle online. Deep Vigilance active.',
  'All systems nominal. Your machine is under deep vigilance.',
  'At your service. Monitoring network, memory, and privacy channels.',
  'Vigilance protocols engaged. I will alert you to any threat.',
  'Welcome back. I have been watching over your system.',
  'I am DVielle. Every connection, every process — under my watch.',
]

const VOICE_PREFS = [
  'microsoft david',
  'microsoft mark',
  'google uk english male',
  'daniel',
  'alex',
  'microsoft george',
  'male',
  'english',
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
    setTimeout(() => resolve(speechSynthesis.getVoices()), 400)
  })
}

function pickVoice(voices: SpeechSynthesisVoice[]): SpeechSynthesisVoice | null {
  const lowered = voices.map((v) => ({ v, name: v.name.toLowerCase() }))
  for (const pref of VOICE_PREFS) {
    const hit = lowered.find((x) => x.name.includes(pref))
    if (hit) return hit.v
  }
  return voices.find((v) => v.lang.toLowerCase().startsWith('en')) ?? voices[0] ?? null
}

export function randomJarvisGreeting(): string {
  return GREETINGS[Math.floor(Math.random() * GREETINGS.length)]
}

let bootVoicePending: string | null = null

export function queueBootVoice(text: string): void {
  bootVoicePending = text
}

export async function speakJarvis(text: string): Promise<boolean> {
  if (!canSpeak()) {
    console.warn('[DVielle] Web Speech API not available in this browser')
    return false
  }
  const voices = await loadVoices()
  const utter = new SpeechSynthesisUtterance(text)
  utter.voice = pickVoice(voices)
  utter.rate = 0.92
  utter.pitch = 0.88
  utter.volume = 1
  speechSynthesis.cancel()
  return new Promise((resolve) => {
    utter.onend = () => resolve(true)
    utter.onerror = () => resolve(false)
    speechSynthesis.speak(utter)
    // Some browsers never fire onend for blocked speech
    setTimeout(() => resolve(speechSynthesis.speaking), 300)
  })
}

/** Call once after a user click if autoplay blocked the launch greeting. */
export async function flushBootVoice(): Promise<void> {
  if (!bootVoicePending) return
  const text = bootVoicePending
  bootVoicePending = null
  await speakJarvis(text)
}

/** Prime the voice list on first user interaction (browser autoplay policy). */
export function primeJarvisVoice(): void {
  if (!canSpeak()) return
  void loadVoices()
}
