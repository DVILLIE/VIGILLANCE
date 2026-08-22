# DVielle — DEEP VIGILLANCE

**Laptop-only Windows agent.** Everything runs on your PC under `C:\DVILLIE`.  
No cloud server is required to use DVielle after install.

> Cloud Agent chats only *write* the code in git. They do **not** install files onto your C: drive.  
> You must pull the repo and run the installer **on the laptop**.

---

## Install on your laptop (creates `C:\DVILLIE`)

### 0. Prerequisites on the laptop

- Windows 10/11
- [Python 3.12+](https://www.python.org/downloads/) — tick **Add python.exe to PATH**
- [Git](https://git-scm.com/download/win) (or download the ZIP from Cursor / GitHub)
- Optional for chat AI: [Ollama](https://ollama.com) → then `ollama pull llama3.2`
- Optional for web demo only: [Node.js LTS](https://nodejs.org)

### 1. Put the project on the laptop

**In Cursor Desktop (recommended):**

1. Open this repository on your machine (not a Cloud Agent chat)
2. Checkout branch: `cursor/dvielle-demo-ux-1fb4`
3. Note the folder path shown in Explorer (e.g. `C:\Users\You\...\tmp-fc09ac10e8480d90`)

**Or clone with Git (CMD / PowerShell — not the Node.js window):**

```bat
cd %USERPROFILE%\Documents
git clone https://github.com/DVILLIE/VIGILLANCE.git
cd VIGILLANCE
git checkout cursor/dvielle-demo-ux-1fb4
```

### 2. Install → creates `C:\DVILLIE`

In File Explorer open the project folder → `installer` → right‑click:

```
Install-DVielle.bat
```

→ **Run as administrator** → Yes on UAC.

That copies everything to:

```
C:\DVILLIE\
```

Desktop shortcut **DVielle** will appear. Launch from there.

### 3. Daily use (all local)

| Action | Where |
|--------|--------|
| Open GUI | Desktop shortcut or `python -m dvielle` from `C:\DVILLIE` |
| Chat Jarvis / KT | Footer **💬 Chat** — voices via Windows TTS |
| Free AI brain | Local Ollama (`llama3.2`) — offline capable for stats |
| Web lookup | Mic questions only — uses DuckDuckGo from **your** PC |
| Uninstall | `C:\DVILLIE\installer\Uninstall-DVielle.bat` |

---

## Web demo (also local — optional)

Only if you want the browser UI without the full agent:

```bat
cd <project>\demo
Start-Demo.bat
```

Then open **http://127.0.0.1:43123** on **that same laptop**.  
Do **not** open that URL hoping a cloud machine is serving it — it will refuse.

---

## What will never appear until you install

| Path | When it appears |
|------|-----------------|
| `C:\DVILLIE` | After `Install-DVielle.bat` on the laptop |
| Desktop shortcut | Same install |
| Agent database / logs | Under `C:\DVILLIE\data` after first run |

---

## Features (once installed)

| Feature | Description |
|---------|-------------|
| Stats on launch | Network, CPU, RAM, disk live immediately |
| START AGENT | Begins background vigilance |
| Quiet tray | Popups only on CRITICAL when minimized |
| Work log | View / Clear chronological OPEN→CLOSE report |
| Chat | Jarvis (US male) · KT (British female) |
| Voices | Windows SAPI — no cloud TTS |

## Privacy hardening (optional, Admin)

```powershell
cd C:\DVILLIE
powershell -ExecutionPolicy Bypass -File scripts\harden-once.ps1
```

## License

MIT
