# I think I was hit — plain-English checklist

Use this when something feels wrong on **this PC**. D'Vielle is a co-pilot, not antivirus proof. Checkboxes are for you; none of this uploads your data.

## Immediate (do now)

1. **Stop pasting.** Close any browser tab that told you to press Win+R or paste into PowerShell / Terminal to “verify you are human.” Real Cloudflare / Google checks never ask for that ([Microsoft TerminalFix, 2026-08-28](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)).
2. **Disconnect if actively encrypting or ransoming.** Unplug Ethernet / turn off Wi‑Fi only if files are being renamed/locked right now.
3. **Open Windows Security** → Virus & threat protection → Quick scan. Note whether real-time protection is **On**.

## What D'Vielle can show you

| Check | Where | Honest limit |
|-------|--------|--------------|
| Defender / firewall / ASR posture | Console security / prevention | MAPS cloud check may need elevation (Limited task) |
| New Defender **exclusions** after baseline | Safety ticket `defender_exclusion_*` | Needs readable `Get-MpPreference`; access denied ≠ “clean” |
| Paste-and-run / ClickFix-like commands | Safety ticket `paste_run_suspicion` | **Never reads clipboard**; needs process cmdline and/or PowerShell 4104 logging |
| Failed sign-ins | Attacks feed | Needs Security log rights + audit policy |
| Unknown internet talk | Connections / privacy options | Unknown ≠ malware |

## What D'Vielle does **not** cover yet

- Clipboard crypto-address swap (clipper)
- Malicious browser extensions inventory
- Full scheduled-task + Windows service persistence map (startup items only partially)
- Stopping exchange / DeFi / bridge billion-dollar heists (out of home-PC scope)

## Aftercare

1. Change passwords for email and banking **from a different clean device** if you already pasted a command or saw a new exclusion you did not approve.
2. Turn on **Tamper Protection** in Windows Security if it is off.
3. Enable **PowerShell Script Block Logging** (Group Policy / admin) so paste-and-run tickets can use event 4104.
4. Keep offline / versioned backups (CISA #StopRansomware). Cloud sync alone is not a backup.

## Truth rule

If a collector says **partial** or **unavailable**, treat that as “we could not see,” not “you are safe.”
