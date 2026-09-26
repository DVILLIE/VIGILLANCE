# Chat / VILL / web demo — deferred

**Status:** frozen until the core guardian is solid.

Version 1.6 retains optional chat behind `chat.enabled: false`. The enabled flag is enforced by the assistant and console; core scheduling has no model dependency. Speech recognition, cloud LLM and web search each require their own opt-in. The browser entry point is now a local snapshot viewer and does not activate legacy demo chat or microphone code.

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
