# DVielle Demo UX

Interactive **Jarvis-style** preview of the DVielle interface. Uses **simulated data** — no Windows agent or Python required.

## Run locally

```bash
cd demo
npm install
npm run dev
```

Open **http://localhost:43123**

## What's in the demo

- Rotating hologram ring + pulsing status indicator
- Live-animated CPU / RAM / disk bars (simulated)
- Intelligence feed with streaming security events
- Quick Close buttons (click to "close" background apps)
- Protection matrix with active shields
- Pause / Resume vigilance toggle
- Replay greeting (visual feedback)

## Build for production

```bash
npm run build
npm run preview
```

This demo is the UX reference for the full `C:\DVILLIE` desktop agent.
