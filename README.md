# DVielle — DEEP VIGILLANCE

Futuristic Jarvis-style Windows security agent.

## Demo UX (try this first)

Interactive browser preview with **simulated data** — no install required:

```bash
cd demo
npm install
npm run dev
```

Open **http://localhost:43123** — hologram ring, vitals, intelligence feed, quick-close buttons.

See [demo/README.md](demo/README.md) for details.

---

## Full agent install (Windows)

- **Rotating hologram ring** — Jarvis-style animated core in the header
- **Voice greetings** — speaks on startup (Windows TTS via pyttsx3)
- **Quick Close panel** — one-click buttons to close background resource hogs
- **Replay greeting** button in the protection panel
- **Install to C:\DVILLIE** — everything in one folder

## Install on your laptop (Administrator UAC)

1. Install **Python 3.12+** from [python.org](https://python.org) — check **Add to PATH**
2. Copy this repo to your laptop (or clone)
3. Double-click:

```
installer\Install-DVielle.bat
```

Click **Yes** on the UAC prompt. The installer will:
- Create **`C:\DVILLIE`** and copy all files
- Install Python packages (CustomTkinter, psutil, pyttsx3, etc.)
- Run **smoke test** automatically
- Create Desktop + Start Menu shortcuts
- Start DVielle at Windows login
- Launch the GUI

## Folder layout after install

```
C:\DVILLIE\
  agent\          # monitoring engine
  dvielle\        # GUI (Jarvis interface)
  config\         # settings
  data\           # logs + SQLite database
  scripts\        # hardening + smoke test
  installer\      # install/uninstall
```

## Uninstall

Double-click `installer\Uninstall-DVielle.bat` → UAC → removes shortcuts, startup task, and optionally deletes `C:\DVILLIE`.

## GUI features

| Feature | Description |
|---------|-------------|
| Hologram ring | Rotating cyan arc animation in header |
| Voice | Jarvis-style spoken greeting on launch |
| **Chat** | **Jarvis (US male) & KT (British female)** — reads live stats, plain-English help |
| System vitals | Live CPU / RAM / disk gauges |
| Quick Close | Buttons to close background hogs instantly |
| Intelligence feed | Real-time security event stream |
| System tray | Minimize to tray; restore from taskbar icon |

## Manual commands

```powershell
cd C:\DVILLIE
pip install -r requirements.txt
python scripts\smoke_test.py     # verify install
python -m dvielle                 # launch GUI
python -m dvielle --headless      # background only
```

## Chat — Jarvis & KT (free)

| Feature | Detail |
|---------|--------|
| **Jarvis** | US English, male voice — security co-pilot |
| **KT** | British English, female voice — patient plain-English explanations |
| **Screen stats** | Ask "how is my RAM?" / "am I on VPN?" — reads live gauges |
| **Web lookup** | **Microphone only** — DuckDuckGo search for general questions |
| **Free AI** | [Ollama](https://ollama.com) locally (`ollama pull llama3.2`) — no API key |
| **Cloud fallback** | Optional `GROQ_API_KEY` env (free tier at groq.com) |

Open **💬 Chat (Jarvis / KT)** in the footer. Type for stats; use **🎤** for voice + web.

```powershell
ollama pull llama3.2   # optional — smarter answers, still free
```

Without Ollama, built-in plain-English stat explanations work offline.

## Privacy hardening (once, as Admin)

```powershell
cd C:\DVILLIE
powershell -ExecutionPolicy Bypass -File scripts\harden-once.ps1
```

## License

MIT
