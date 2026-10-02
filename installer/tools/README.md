# Installer tools

| File | Role |
|------|------|
| `rcedit-x64.exe` | MIT-licensed [electron/rcedit](https://github.com/electron/rcedit) v2.0.0. Used only at install / refresh time by `scripts/New-DvielleGuiExe.ps1` to embed `assets/brand/dvielle.ico` and version strings into `.venv\Scripts\DVielle.exe`. |

Pin: `installer/rcedit-x64.pin.json` (SHA-256 + size). Do not run rcedit against the resident `pythonw.exe` used by the logon task; only against the GUI shim copy.
