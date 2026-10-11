# D'Vielle user guide

**Repair branch status (2026-10-09):** the setup wrapper and Highest installation
are held. The normal Limited script requires protected source staging and a
protected system Python executable on PATH, separates protected code from
private data/config, and refuses shared-writable old trees. Published 2.4.2
archives were not rebuilt. The historical installation guide below is not a
field acceptance result for the repairs. See [the current constraints](REPAIR_INSTALL_PRIVILEGE_BOUNDARY.md).

![D'Vielle logo](images/dvielle-logo.png)

Version 2.5.0. D'Vielle (Intelligent Vigilance) is a free local guardian for a Windows PC. It watches that PC, explains what it noticed, and waits for you before it changes anything important.

This guide is the install and day-to-day page. Promises and limits are in [CLAIMS.md](CLAIMS.md). Pass and fail checks are in [TRUST_GATES.md](TRUST_GATES.md).

## Theme and logo

- **Nexus Fold Prime** is the console theme. It has a pearl folded overview, a cobalt spatial network stage and a bottom dock on all six pages. Pick **Dark** or **Light** in the header. **Motion** follows the Windows animation setting until you change it, and turning it off freezes every animation. Animation is decoration only and never stands in for a reading. See [NEXUS_FOLD_PRIME.md](NEXUS_FOLD_PRIME.md).
- **Quantum Key** is the logo. The header shows it with silent blue electrical surges; the window, taskbar, tray and shortcuts use the matching static icon.

![Nexus Fold Prime, Dark](images/nexus-fold-prime-dark.png)

Both choices are saved in local `console_ui.json` and are not uploaded.

The install steps below describe the last packaged installer (2.4.x, Python 3.12). For the 2.5.0 Program Files install with Python 3.14, follow [installer/INSTALL.txt](../installer/INSTALL.txt).

## What you need

- A laptop or desktop PC running Windows 10 or Windows 11, 64-bit.
- Python 3.12 from [python.org](https://www.python.org/downloads/windows/), with Tcl/Tk and the `py` launcher.
- A normal user account you can log on with. The background task starts at your logon. It does not watch the PC while you are logged off.
- No special graphics card. The console is a window, not a GPU workload.

Linux and macOS can run shared logic in limited mode. They do not get the Windows installer, Defender, firewall helper, or scheduled task. They are not a full D'Vielle install. See [Supported systems](../README.md#supported-systems).

D'Vielle is not a cloud service and not a server product. Install it on the PC you want watched. Details: [LAPTOP_ONLY.md](LAPTOP_ONLY.md).

## Install

1. Download the latest release from [github.com/DVILLIE/VIGILLANCE/releases/latest](https://github.com/DVILLIE/VIGILLANCE/releases/latest).
   - `DVielle-2.4.2-windows-installer.zip` is the bundle to unzip and install.
   - `DVielle-2.4.2-windows-source.zip` is the same tree under a source name, plus the GitHub source archive that a tag creates automatically.
   - `DVielle-Setup-2.4.2.exe` is not on the Release. The project can build that setup wrapper. It bootstraps official Python 3.12.10 and then runs the same Limited installer. It is not a PyInstaller binary. Use the zip until a Release lists the exe by name. See [WINDOWS_INSTALLER.md](WINDOWS_INSTALLER.md).
2. Install Python 3.12 if it is not already on the PC.
3. Unzip the archive. You should see `installer`, `agent`, `dvielle`, `config`, and `pyproject.toml` in one folder.
4. Right-click `installer\Install-DVielle.bat` and choose **Run as administrator**.
5. Wait until the window says the install finished. It creates `C:\DVILLIE`, a private Python environment at `C:\DVILLIE\.venv`, a desktop shortcut, and one logon task named `D'Vielle`.
The desktop and Start Menu shortcuts open `.venv\Scripts\DVielle.exe -m dvielle` (branded console host). Task Manager lists that process as **DVielle.exe**. The background logon task remains `pythonw.exe` and still looks like Python there.


The unzip folder is the **source**. GitHub may name it `VIGILLANCE-2.4.2` or `VIGILLANCE-main`. That name is not the install location. The installer default destination is **`C:\DVILLIE`**. There is no second default such as `C:\DVILLIE-main`.

For a different folder, open Administrator PowerShell in the unzipped tree and run:

```powershell
installer\install-dvielle.ps1 -InstallDir 'C:\Apps\DVielle'
```

Use a dedicated local folder. The installer rejects a drive root, a shared Windows directory, and a reparse-point path. After that, start, stop, config, and data all use the folder you chose. D'Vielle does not silently fall back to another copy.

Copying new files over an existing install does not refresh `.venv`. Run `Install-DVielle.bat` again.

The resident task stays **Limited** (least privilege). A Highest task is an explicit installer switch only, and only after the install folder is locked down. Elevated unattended use is not recommended. The installer does not add a Microsoft Defender `ExclusionPath` for D'Vielle.

## First open

Open the desktop shortcut **D'Vielle - Intelligent Vigilance**, or run `installer\Launch-DVielle.bat` from the install folder.

The console attaches to the background agent. It does not start a second set of collectors. The header should move from “Connecting” to a monitoring line when the agent is alive.

The left rail has six pages:

| Page | What it is for |
|------|----------------|
| Now | How busy the PC is, and the latest notes |
| This PC | Processor, memory, and disk in more detail |
| Network | This PC, local address, gateway, and DNS |
| Findings | What was noticed, in plain language |
| Protection | Defender and related posture the edition actually supports |
| Apps | Programs D'Vielle can talk about closing, only after you choose |

The rings are measurements. If a check is missing, partial, or stale, the console says so. A number on the screen is not a promise that the PC is safe.

The sample line “Layout preview. This is not a live Windows reading.” means the window was opened with labeled sample data. On your PC, notes come from the local agent.

## Theme

The console opens in **Dark**. **Light** is the button in the header. The choice is saved as `console_ui.json` in the local data directory (`C:\DVILLIE\data` by default). It is not uploaded.

The date picks one of five accent pairs (Violet, Coral, Gold, Sky, Rose) and a still orbit angle. Only the logo animates. Cards, rings, and the rest of the window stay still.

## What the notes mean

Latest notes use short words:

| Word | Meaning |
|------|---------|
| Noted | Something was recorded. It is not by itself a problem. |
| Caution | A warning or a partial check. Read it before you treat the PC as fine. |
| Needs a look | A stronger signal (critical, error, or a hold). Open the note. |
| Settled | A check completed or a finding was marked resolved. |

A partial collector is incomplete. It is not a clean bill of health.

Buttons along the bottom:

- **Work log** — local record of what the console and agent did.
- **Why** — the evidence behind a note. It does not change the PC.
- **Attacks** — failed sign-ins and suspicious connection notes. It does not show a live “blocked right now” count, and it does not read your passwords or keystrokes.
- **Clear log** — clears the on-screen work log. It does not wipe Windows or your files.
- **Pause Agent** — asks the background owner to stop. If you only have the console attached to an agent that is already running, pause stays with that owner.
- **Hide to tray** — the window hides. Monitoring can continue. Critical notices can still appear. Show it again from the tray icon.

## What a popup means

D'Vielle’s loop is: **observe → explain → options → act only after you choose.**

A finding is a ticket: **Found → Fix → Resolved** (or still monitoring). Seeing a note is not the same as a fix.

When a change would touch the PC (close an app, change a Defender setting that the edition allows, add one firewall block, open an unfamiliar folder in Windows Sandbox), you get an options card. Nothing is written until both of these agree:

1. You picked that option for this finding.
2. The decision check accepts that same action.

If either side refuses, D'Vielle does not change the PC. Closing an app also needs the current process identity. A stale window is refused. Automatic file cleanup and automatic RAM trimming stay off.

**Keep on** means “this is expected; stay quiet while it still matches.” A mismatch can open a note again. It still does not act by itself.

Everyday, Sensitive, and Open unfamiliar change how soon a note appears and what is *offered*. They do not skip your choice for closing an app or opening an unfamiliar file.

## Protection, in plain language

D'Vielle works **with** Windows security. It does not replace Microsoft Defender, and it does not turn real-time protection off.

- It can report Defender health, MAPS reachability, and what your Windows edition supports.
- Attack surface reduction and Controlled Folder Access can move one step only after you approve, and only if a second read of the live setting matches. Controlled Folder Access is a modification shield. It is not a claim that files cannot be read or copied out.
- A firewall block is one app rule you confirm. It is not a leakproof firewall, and D'Vielle does not stop the firewall service.
- Windows Sandbox is offered on Pro, Enterprise, or Education when that feature is present. Windows Home is shown a checklist instead. A normal window is not a sandbox.
- Windows Home and Pro have a floor of Required diagnostic data. A registry value is not proof that traffic stopped.

Offline backups and a restore test you have actually tried stay your job. D'Vielle does not become your backup product.

## Privacy

Local-first:

- Observations, the work log, keep-on choices, and the theme file stay on this PC.
- There is no chat assistant and no cloud model in the product. Chat was removed in 2.3.3. See [CHAT_REMOVED.md](CHAT_REMOVED.md).
- Short spoken lines for close and confirm, on Windows, use the local voice library. They are not a conversation and they are not sent to a chat service.
- Looking up this PC’s public IP address is off unless you opt in. Core monitoring does not need it.
- D'Vielle does not upload its snapshot, your files, or screenshots as part of normal monitoring.

Optional hardening scripts are separate. They do not run during install. Read [TELEMETRY_AND_HOME.md](TELEMETRY_AND_HOME.md) before you use them. They do not make Microsoft traffic zero.

## Uninstall

1. Run `installer\Uninstall-DVielle.bat` as administrator from the install folder (or use the Start menu shortcut **Uninstall D'Vielle**).
2. It asks the agent to stop, then removes the startup task and the shortcuts it created.
3. Your files stay unless you type `DELETE` for that exact install folder.
4. To remove the task and shortcuts and keep the files without that prompt, run `installer\uninstall-dvielle.ps1 -KeepData` as administrator.

If you applied optional hardening, restore it from the backup path that script printed before you delete the folder. A custom data directory outside the install folder is kept.

## If install fails

- “Python 3.12 is required” — install that version from python.org and run the installer again. Python 3.13 and 3.14 are not the supported runtime.
- “Run as Administrator” — use the `.bat` file so Windows can show the approval prompt.
- “Invalid source tree” — you unzipped only the `installer` folder. Use the full installer zip so `agent` and `pyproject.toml` sit beside `installer`.
- An older D'Vielle window is still open — exit it from the tray and run the installer again. The installer does not kill unrelated Python programs.

A failed update can leave startup disabled. Keep your config and retry from a complete unzip after you fix the error on screen. The installer does not roll the folder back by itself.

## What this guide does not promise

D'Vielle cannot prove the PC is free of threats. It cannot prove a firewall rule blocks every leak. It cannot prove a site offers a passkey, and it does not change your accounts. Those limits are written down in [CLAIMS.md](CLAIMS.md).

## Support and contact

**Ravikant R. T. · kt.tradingsystem@gmail.com**

Use that address for questions about this guide, the installer, or the software. D'Vielle has no in-app chat assistant.
# Advanced Ethical Hacking workspace — implementation update

The repair checkout includes an **Ethical Hacking** navigation button. Select
**Assess this computer** to review actual local Windows protection posture,
Defender signature health, ASR/CFA settings, TCP listeners, selected
application-runtime versions and cryptographic provider
information. Results are review items with evidence and coverage notes. A
listener or missing response is not a confirmed intrusion. This workspace
does not silently change Windows settings.

The runtime-version sharing checkbox is off by default. Selecting it authorizes
one run to send the displayed package names and versions to the free OSV API;
it does not upload application files, browsing content or credentials. The
checkbox resets after starting. Advisory matches need applicability review and
a trusted update; this feature does not install a downloaded package.

To review a website, use **Authorized website**, enter one HTTP(S) origin,
record your ownership or authorization reference, and confirm your authority.
The assessment makes one HEAD request to `/`. Redirect destinations, other
paths and other domains are not included. HTTPS certificate/TLS observations
and response-header presence are recorded. Quantum readiness distinguishes
the observed certificate key from unmeasured negotiated post-quantum properties.

Use **Evidence** for the underlying report and **Resolution plan** for the
recommended next actions. These recommendations have not been executed.
**History** opens existing records without authorizing a new scan. **Stop
assessment** prevents subsequent checks after the current bounded operation
returns; a failed/stopped run keeps its partial evidence.

**Export redacted report** removes origin/authority, network addresses, process
IDs, certificate fingerprint and security-header values. Selected runtime
versions, ports and algorithm observations remain visible. Review the exported
file before sharing it. Local assessment records are ordinary user-owned
evidence, not privileged approval or tamper-proof forensic records.

Source/deployment status and current verification are recorded in
[Implementation Progress and Acceptance Evidence](implementation/IMPLEMENTATION_PROGRESS_AND_ACCEPTANCE_EVIDENCE_2026-10-10.md).
The source additions are in `C:\DVILLIE-main-repairs`; previously published or
installed application binaries were not replaced by this implementation.


## Assessment history privacy and service readiness

In Ethical Hacking, Privacy & costs provides explicit history retention, preview
and confirmed deletion, plus observed process-tree costs. Automatic cleanup
starts off; exported reports and backups are separate. Saved assessment views
show snapshot freshness and evidence-linked recommendations without action
authorization. Check protection service reads actual installed prerequisites
and does not install, elevate or change Windows policy.
