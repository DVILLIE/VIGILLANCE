# PUT DVIELLE ON YOUR LAPTOP (not cloud)

The Cloud Agent **cannot** create `C:\DVILLIE` for you.  
Do these steps **on the Windows laptop** in Cursor Desktop or File Explorer.

## A. Open the project locally in Cursor

1. Close / ignore Cloud Agent browser previews (`127.0.0.1` from cloud = useless on your PC).
2. In **Cursor Desktop** → open this git repo from your disk (e.g. `C:\DVILLIE`).
3. In the left file tree you should see `installer\`, `agent\`, `config\`.

## B. Create / refresh `C:\DVILLIE`

1. File Explorer → project root → `installer`
2. Right‑click `Install-DVielle.bat` → **Run as administrator**
3. Wait until it finishes
4. Confirm tasks **DVielle** (headless) and **DVielleGUI** (optional) in Task Scheduler

## C. Run

- **Core:** headless agent starts at logon (`pythonw -m agent.main`)
- **GUI (optional):** Desktop **DVielle**, or `cd C:\DVILLIE` then `py -3.12 -m dvielle`
- **Harden (optional, Admin):** `scripts\harden-once.ps1`

## Chat / web demo

Deferred — see [CHAT_DEFERRED.md](CHAT_DEFERRED.md). Do not treat `demo\` as the product.

## Telemetry honesty

See [TELEMETRY_AND_HOME.md](TELEMETRY_AND_HOME.md).
