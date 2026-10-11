# D'Vielle brand assets

## Current approved mark: Quantum Key (2026-10-10)

Primary assets are `quantum-key.png`, `quantum-key.ico` and the preserved
`quantum-key-master.png`. Canonical PNG/ICO/GIF filenames now contain the
approved artwork. Desktop and Start Menu shortcut icons reference quantum-key.ico.
Historical samples below describe earlier designs.

Native electrical animation lives in `dvielle/gui/quantum.py`: a 45-second cube
circuit, five-second blue lightning surges, V corner impulses and proximity
communication glow. Effects are silent decoration. Motion off freezes the logo;
hidden widgets stop scheduling; Tk dynamic-image caching remains bounded.
Windows tray/taskbar/shortcut icons use a matching static frame.

Validation: 24 targeted logo, theme and real Tk widget tests passed. Native
surge artwork was visually inspected. No installer or resident service was
replaced. Rendering reference: https://pillow.readthedocs.io/en/stable/reference/ImageFilter.html

Canonical Windows / console mark for **D'Vielle** (product spelling; UI text never says "diville").

| File | Use |
|------|-----|
| `dvielle-logo-animated.gif` | Console header animation (Pillow frame loop) |
| `dvielle-logo-still.png` | Full-resolution still (512×512) |
| `dvielle.ico` | Window title bar, taskbar, tray, desktop / Start Menu shortcuts |
| `dvielle_logo.png` / `dvielle_64.png` / `dvielle_88.png` / `dvielle_128.png` | UI sizes derived from the still |

Wired by `dvielle.brand` (`apply_tk_window_icon`, `load_brand_pil_image`, `load_brand_gif_frames`) and `dvielle.gui.logo_mark.LogoMark`. Docs preview copies live under `docs/images/`.

Install also stamps this ICO into `.venv\Scripts\DVielle.exe` (console host) so Task Manager shows the same mark. The resident agent stays `pythonw.exe`.

# Approved Nexus identity — 2026-10-10

`nexus-orbital-d.png` is the isolated chrome orbital D selected from the top-left
of Nexus Spatial. The UI uses it for Nexus Fold Prime. `nexus-orbital-d.ico`
contains native Windows icon sizes exported from that same artwork. The older
files above remain fallback/historical assets. The application prefers Nexus
branding when it is present. Animated perspective/lighting frames are generated
and cached by the native UI; they do not represent agent activity or protection.
