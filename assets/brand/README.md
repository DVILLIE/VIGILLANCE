# DVielle brand assets

- `dvielle_logo.png` — source brand / radar DV mark (in-window header)
- `dvielle_64.png` / `dvielle_88.png` / `dvielle_128.png` — UI sizes
- `dvielle.ico` — **canonical** Windows icon (window title bar, taskbar, tray, shortcuts)

Used by: GUI header (PNG), and one standard icon path via `dvielle.brand.apply_tk_window_icon` + tray (`load_brand_pil_image` from the `.ico`). Windows AppUserModelID is set before UI create so the taskbar does not show the Python interpreter icon.
