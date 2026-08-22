# PUT DVIELLE ON YOUR LAPTOP (not cloud)

The Cloud Agent **cannot** create `C:\DVILLIE` for you.  
Do these steps **on the Windows laptop** in Cursor Desktop or File Explorer.

## A. Open the project locally in Cursor

1. Close / ignore Cloud Agent browser previews (`127.0.0.1` from cloud = useless on your PC).
2. In **Cursor Desktop** → open this git repo from your disk.
3. Branch: `cursor/dvielle-demo-ux-1fb4`
4. In the left file tree you should see `installer\`, `demo\`, `dvielle\`.

If you do not see those folders, the project is not on the laptop yet — clone or download the repo first.

## B. Create `C:\DVILLIE`

1. File Explorer → project root → `installer`
2. Right‑click `Install-DVielle.bat` → **Run as administrator**
3. Wait until it finishes
4. Open `C:\` — you should now see **`DVILLIE`**

## C. Run

- Double‑click Desktop **DVielle**, or  
- `cd C:\DVILLIE` then `python -m dvielle`

## Demo only (no install)

```bat
cd <project>\demo
Start-Demo.bat
```

Open http://127.0.0.1:43123 **after** that window says the server is ready.

## Wrong windows

| Window | Use? |
|--------|------|
| Node.js (`>` prompt) | **No** — type `.exit` |
| CMD / PowerShell | **Yes** |
| Cloud Agent “Open preview” | **No** for your laptop |

Everything after install (agent, voices, chat, Ollama) stays on the laptop.
