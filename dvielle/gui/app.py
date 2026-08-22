"""DVielle — Jarvis-style futuristic GUI."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import psutil

from agent.controller import AgentController
from agent.utils import PROJECT_ROOT
from dvielle import APP_NAME, TAGLINE, VERSION
from dvielle.gui import theme as T
from dvielle.gui.tray import notify_tray, setup_tray

try:
    import customtkinter as ctk

    HAS_CTK = True
except ImportError:
    HAS_CTK = False


class DVielleApp:
  """Main holographic command interface."""

  def __init__(self, config_dir: Path | None = None) -> None:
    if not HAS_CTK:
      raise RuntimeError("customtkinter required: pip install customtkinter pillow pystray")

    self.config_dir = config_dir or (PROJECT_ROOT / "config")
    self.controller = AgentController(
      config_dir=self.config_dir if (self.config_dir / "config.yaml").exists() else None,
      on_cycle=self._on_cycle,
    )
    self._pulse_on = True
    self._tray_ok = False

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    self.root = ctk.CTk()
    self.root.title(f"{APP_NAME} — {TAGLINE}")
    self.root.geometry("1020x680")
    self.root.minsize(900, 600)
    self.root.configure(fg_color=T.BG_DARK)
    self.root.protocol("WM_DELETE_WINDOW", self._minimize_to_tray)

    self._build_ui()
    self._tray_ok = setup_tray(
      on_show=self._show_window,
      on_hide=self._minimize_to_tray,
      on_quit=self._quit_app,
      on_toggle_vigilance=self._toggle_vigilance,
    )
    self._tick_stats()
    self._tick_logs()
    self._pulse_status()
    self.controller.start()

  def _build_ui(self) -> None:
    # ── Header ──
    header = ctk.CTkFrame(self.root, fg_color=T.BG_PANEL, corner_radius=0, height=90)
    header.pack(fill="x", padx=0, pady=0)
    header.pack_propagate(False)

    left_h = ctk.CTkFrame(header, fg_color="transparent")
    left_h.pack(side="left", padx=24, pady=12)

    ctk.CTkLabel(left_h, text=APP_NAME.upper(), font=T.FONT_DISPLAY, text_color=T.ACCENT_GLOW).pack(anchor="w")
    ctk.CTkLabel(left_h, text=TAGLINE, font=T.FONT_TAGLINE, text_color=T.TEXT_DIM).pack(anchor="w")

    right_h = ctk.CTkFrame(header, fg_color="transparent")
    right_h.pack(side="right", padx=24, pady=16)

    self.status_dot = ctk.CTkLabel(right_h, text="●", font=("Segoe UI", 22), text_color=T.SUCCESS)
    self.status_dot.pack(side="left", padx=(0, 8))
    self.status_label = ctk.CTkLabel(right_h, text="VIGILANCE ACTIVE", font=T.FONT_TITLE, text_color=T.SUCCESS)
    self.status_label.pack(side="left")

    # ── Body ──
    body = ctk.CTkFrame(self.root, fg_color="transparent")
    body.pack(fill="both", expand=True, padx=16, pady=12)
    body.columnconfigure(0, weight=1)
    body.columnconfigure(1, weight=2)
    body.columnconfigure(2, weight=1)
    body.rowconfigure(0, weight=1)

    self._build_vitals_panel(body)
    self._build_log_panel(body)
    self._build_shield_panel(body)

    # ── Footer controls ──
    footer = ctk.CTkFrame(self.root, fg_color=T.BG_PANEL, corner_radius=0, height=56)
    footer.pack(fill="x", side="bottom")
    footer.pack_propagate(False)

    btn_frame = ctk.CTkFrame(footer, fg_color="transparent")
    btn_frame.pack(side="right", padx=16, pady=10)

    self.vigilance_btn = ctk.CTkButton(
      btn_frame, text="Pause Vigilance", width=140, command=self._toggle_vigilance,
      fg_color=T.BORDER, hover_color=T.ACCENT_DIM, border_color=T.ACCENT, border_width=1,
    )
    self.vigilance_btn.pack(side="left", padx=6)
    ctk.CTkButton(
      btn_frame, text="Minimize to Tray", width=140, command=self._minimize_to_tray,
      fg_color=T.BG_PANEL_ALT, hover_color=T.BORDER,
    ).pack(side="left", padx=6)

    ctk.CTkLabel(
      footer, text=f"v{VERSION}  |  Your system. Your internet. Deep vigilance.",
      font=T.FONT_TAGLINE, text_color=T.TEXT_DIM,
    ).pack(side="left", padx=20, pady=16)

  def _panel(self, parent, title: str) -> ctk.CTkFrame:
    frame = ctk.CTkFrame(parent, fg_color=T.BG_PANEL, border_color=T.BORDER, border_width=1, corner_radius=8)
    ctk.CTkLabel(frame, text=title, font=T.FONT_TITLE, text_color=T.ACCENT).pack(anchor="w", padx=14, pady=(12, 6))
    return frame

  def _build_vitals_panel(self, parent) -> None:
    panel = self._panel(parent, "SYSTEM VITALS")
    panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

    inner = ctk.CTkFrame(panel, fg_color="transparent")
    inner.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    self.cpu_bar, self.cpu_lbl = self._metric_row(inner, "CPU", 0)
    self.ram_bar, self.ram_lbl = self._metric_row(inner, "RAM", 1)
    self.disk_bar, self.disk_lbl = self._metric_row(inner, "DISK", 2)

    self.cycle_lbl = ctk.CTkLabel(inner, text="Cycles: 0", font=T.FONT_MONO, text_color=T.TEXT_DIM)
    self.cycle_lbl.pack(anchor="w", pady=(12, 0))

  def _metric_row(self, parent, name: str, row: int):
    ctk.CTkLabel(parent, text=name, font=T.FONT_BODY, text_color=T.TEXT_DIM).grid(row=row * 2, column=0, sticky="w", pady=(8, 0))
    bar = ctk.CTkProgressBar(parent, width=200, height=10, progress_color=T.ACCENT, fg_color=T.BG_PANEL_ALT)
    bar.grid(row=row * 2 + 1, column=0, sticky="ew", pady=(2, 0))
    bar.set(0)
    lbl = ctk.CTkLabel(parent, text="—", font=T.FONT_MONO, text_color=T.TEXT)
    lbl.grid(row=row * 2 + 1, column=1, padx=(10, 0))
    parent.columnconfigure(0, weight=1)
    return bar, lbl

  def _build_log_panel(self, parent) -> None:
    panel = self._panel(parent, "INTELLIGENCE FEED")
    panel.grid(row=0, column=1, sticky="nsew", padx=4)

    self.log_box = ctk.CTkTextbox(
      panel, font=T.FONT_MONO, fg_color=T.BG_DARK, text_color=T.ACCENT_GLOW,
      border_color=T.BORDER, border_width=1, wrap="word",
    )
    self.log_box.pack(fill="both", expand=True, padx=14, pady=(0, 14))
    self.log_box.insert("1.0", f"[DVIELLE] {TAGLINE} online. Monitoring all channels.\n")
    self.log_box.configure(state="disabled")

  def _build_shield_panel(self, parent) -> None:
    panel = self._panel(parent, "PROTECTION MATRIX")
    panel.grid(row=0, column=2, sticky="nsew", padx=(8, 0))

    inner = ctk.CTkFrame(panel, fg_color="transparent")
    inner.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    shields = [
      ("Network Scan", "ACTIVE"),
      ("Attack Shield", "ACTIVE"),
      ("Privacy Guard", "ACTIVE"),
      ("Microsoft Block", "ACTIVE"),
      ("Resource AI", "ACTIVE"),
    ]
    self.shield_labels: list[ctk.CTkLabel] = []
    for name, state in shields:
      row = ctk.CTkFrame(inner, fg_color=T.BG_PANEL_ALT, corner_radius=6)
      row.pack(fill="x", pady=4)
      ctk.CTkLabel(row, text=name, font=T.FONT_BODY, text_color=T.TEXT).pack(side="left", padx=10, pady=8)
      lbl = ctk.CTkLabel(row, text=state, font=T.FONT_MONO, text_color=T.SUCCESS)
      lbl.pack(side="right", padx=10, pady=8)
      self.shield_labels.append(lbl)

    self.jarvis_line = ctk.CTkLabel(
      inner,
      text='"At your service. All systems under deep vigilance."',
      font=("Segoe UI", 10, "italic"),
      text_color=T.ACCENT_DIM,
      wraplength=220,
    )
    self.jarvis_line.pack(side="bottom", pady=(16, 0))

  def _append_log(self, line: str) -> None:
    self.log_box.configure(state="normal")
    self.log_box.insert("end", line + "\n")
    self.log_box.see("end")
    lines = int(self.log_box.index("end-1c").split(".")[0])
    if lines > 200:
      self.log_box.delete("1.0", "20.0")
    self.log_box.configure(state="disabled")

  def _on_cycle(self, status) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    mode = "LEARN" if status.monitor_only else "GUARD"
    self.root.after(0, lambda: self._append_log(f"[{ts}] Cycle {status.cycle_count} — {mode} mode scan complete."))

  def _tick_stats(self) -> None:
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    try:
      disk = psutil.disk_usage("/" if sys.platform != "win32" else "C:\\")
    except Exception:
      disk = psutil.disk_usage("/")

    self.cpu_bar.set(cpu / 100)
    self.cpu_lbl.configure(text=f"{cpu:.0f}%")
    self.ram_bar.set(mem.percent / 100)
    self.ram_lbl.configure(text=f"{mem.percent:.0f}%")
    self.disk_bar.set(disk.percent / 100)
    self.disk_lbl.configure(text=f"{disk.percent:.0f}%")

    if self.controller.status.running:
      self.cycle_lbl.configure(text=f"Cycles: {self.controller.status.cycle_count}")

    color = T.DANGER if cpu > 85 or mem.percent > 90 else T.WARNING if cpu > 70 or mem.percent > 80 else T.ACCENT
    self.cpu_bar.configure(progress_color=color if cpu > 70 else T.ACCENT)
    self.ram_bar.configure(progress_color=color if mem.percent > 80 else T.ACCENT)

    self.root.after(2000, self._tick_stats)

  def _tick_logs(self) -> None:
    try:
      events = self.controller.recent_events(8)
      for ev in reversed(events):
        ts = ev.get("ts", "")[:19].replace("T", " ")
        sev = ev.get("severity", "INFO")
        msg = ev.get("message", "")
        mod = ev.get("module", "")
        prefix = "⚠" if sev in ("WARNING", "CRITICAL") else "›"
        line = f"[{ts}] {prefix} [{mod}] {msg}"
        # Only append if not duplicate of last line — simple check
        content = self.log_box.get("end-2l", "end-1l")
        if msg and msg not in content:
          self._append_log(line)
    except Exception:
      pass
    self.root.after(8000, self._tick_logs)

  def _pulse_status(self) -> None:
    if self.controller.status.running:
      self._pulse_on = not self._pulse_on
      color = T.SUCCESS if self._pulse_on else T.ACCENT_DIM
      self.status_dot.configure(text_color=color)
    self.root.after(900, self._pulse_status)

  def _toggle_vigilance(self) -> None:
    if self.controller.status.running:
      self.controller.stop()
      self.status_label.configure(text="STANDBY", text_color=T.WARNING)
      self.vigilance_btn.configure(text="Resume Vigilance")
      self._append_log("[DVIELLE] Vigilance paused by operator.")
      notify_tray(APP_NAME, "Vigilance paused")
    else:
      self.controller.start()
      self.status_label.configure(text="VIGILANCE ACTIVE", text_color=T.SUCCESS)
      self.vigilance_btn.configure(text="Pause Vigilance")
      self._append_log("[DVIELLE] Vigilance resumed. All channels active.")
      notify_tray(APP_NAME, "Vigilance active")

  def _minimize_to_tray(self) -> None:
    self.root.withdraw()
    if self._tray_ok:
      notify_tray(APP_NAME, "Running in system tray — double-click icon to restore")

  def _show_window(self) -> None:
    self.root.deiconify()
    self.root.lift()
    self.root.focus_force()

  def _quit_app(self) -> None:
    self.controller.stop()
    self.root.quit()
    self.root.destroy()

  def run(self) -> None:
    self.root.mainloop()


def main(config_dir: Path | None = None) -> int:
  try:
    app = DVielleApp(config_dir=config_dir)
    app.run()
    return 0
  except RuntimeError as exc:
    print(exc, file=sys.stderr)
    return 1


if __name__ == "__main__":
  sys.exit(main())
