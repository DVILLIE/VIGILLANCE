# DVielle Demo UX — VILL

Interactive **VILL** preview of the DVielle interface. Uses **simulated data** — no Windows agent or Python required.

> **Important:** `http://127.0.0.1:43123` only works on the machine where you start the demo.

## Run

```
demo\Start-Demo.bat
```

Then open **http://127.0.0.1:43123** (same PC). Requires [Node.js 20+](https://nodejs.org).

## What's in the demo

- Stats live on launch · **START AGENT** for vigilance only
- Always-open chat with hologram ring (blue = listening, yellow = speaking)
- **VILL** — single UK-accent voice (Jarvis/KT removed)
- Mic always on · talk about anything
- Voice queries can use free DuckDuckGo lookup

## Build

```bash
npm run build
npm run preview
```
