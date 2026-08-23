# Chat / VILL / web demo — deferred

**Status:** frozen until the core guardian is solid.

## Why

Product aim is a **local Windows nurse**: connections, attacks (4625), RAM/CPU/disk, Defender/firewall, Microsoft privacy drift. Chat, TTS (“VILL”), and the Vite web demo are polish — they must not define the product or block core work.

## Current config

In `config/config.yaml`:

```yaml
chat:
  enabled: false
```

Do not turn this on for “v1 done.” Demo under `demo\` stays optional and secondary.

## When to resume

After:

1. Headless scheduled agent is the default runtime  
2. Audit policy + Update allowlists are trusted  
3. Smoke + core tests stay green on Python 3.12  
4. Harden-once / privacy drift behavior matches Home honesty docs  

Then: tray/toasts polish → optional chat/VILL as a thin layer on top of the same SQLite/logs.
