# DVielle Demo UX

Interactive **Jarvis-style** preview of the DVielle interface. Uses **simulated data** — no Windows agent or Python required.

> **Important:** `http://127.0.0.1:43123` only works on the machine where you start the demo.
> Opening that URL on your laptop while the agent runs in the cloud will show **ERR_CONNECTION_REFUSED**.

## Run on your Windows laptop

1. Pull / copy this repo onto the laptop
2. Double-click:

```
demo\Start-Demo.bat
```

Or in PowerShell / CMD:

```bat
cd demo
npm install
npm run dev
```

3. Then open **http://127.0.0.1:43123** in Chrome (same PC)

Requires [Node.js 20+](https://nodejs.org) (LTS).

## What's in the demo

- Stats live on launch · **START AGENT** for vigilance only
- Network / VPN panel · vitals · intelligence feed · quick close
- **Chat (Jarvis US / KT British)** · work log report · tray quiet mode
- Replay greeting with browser voice

## Build for production

```bash
npm run build
npm run preview
```

This demo is the UX reference for the full `C:\DVILLIE` desktop agent.
