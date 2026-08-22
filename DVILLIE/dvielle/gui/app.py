"""DVielle — Jarvis-style futuristic GUI with hologram, voice, and close-app actions."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import psutil

from agent.controller import AgentController
from agent.modules.resource_advisor import close_process, get_closeable_processes
from agent.utils import PROJECT_ROOT
from dvielle import APP_NAME, TAGLINE, VERSION
from dvielle.gui import theme as T
from dvielle.gui.hologram import HologramRing
from dvielle.gui.tray import notify_tray, setup_tray
from dvielle.gui.voice import greet_on_startup, speak_async

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
        self._close_buttons: list[ctk.CTkButton] = []
        self._greeting_idx = 0

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.root = ctk.CTk()
        self.root.title(f"{APP_NAME} — {TAGLINE}")
        self.root.geometry("1060x720")
        self.root.minsize(920, 640)
        self.root.configure(fg_color=T.BG_DARK)
        self.root.protocol("WM_DELETE_WINDOW", self._minimize_to_tray)

        self._build_ui()
        self._tray_ok = setup_tray(
            on_show=self._show_window,
            on_hide=self._minimize_to_tray,
            on_quit=self._quit_app,
            on_toggle_vigilance=self._toggle_vigilance,
        )

        greeting = greet_on_startup()
        self.jarvis_line.configure(text=f'"{greeting}"')
        self._append_log(f"[DVIELLE] {greeting}")

        self._tick_stats()
        self._tick_logs()
        self._tick_close_panel()
        self._tick_greeting()
        self._pulse_status()
        self.controller.start()

    def _build_ui(self) -> None:
        header = ctk.CTkFrame(self.root, fg_color=T.BG_PANEL, corner_radius=0, height=100)
        header.pack(fill="x")
        header.pack_propagate(False)

        ring_frame = ctk.CTkFrame(header, fg_color="transparent")
        ring_frame.pack(side="left", padx=(16, 8), pady=6)
        HologramRing(ring_frame, size=80).pack()

        left_h = ctk.CTkFrame(header, fg_color="transparent")
        left_h.pack(side="left", padx=8, pady=12)
        ctk.CTkLabel(left_h, text=APP_NAME.upper(), font=T.FONT_DISPLAY, text_color=T.ACCENT_GLOW).pack(anchor="w")
        ctk.CTkLabel(left_h, text=TAGLINE, font=T.FONT_TAGLINE, text_color=T.TEXT_DIM).pack(anchor="w")
        self.greeting_lbl = ctk.CTkLabel(
            left_h, text="Initializing deep vigilance...", font=("Segoe UI", 9, "italic"),
            text_color=T.ACCENT_DIM,
        )
        self.greeting_lbl.pack(anchor="w", pady=(4, 0))

        right_h = ctk.CTkFrame(header, fg_color="transparent")
        right_h.pack(side="right", padx=24, pady=16)
        self.status_dot = ctk.CTkLabel(right_h, text="●", font=("Segoe UI", 22), text_color=T.SUCCESS)
        self.status_dot.pack(side="left", padx=(0, 8))
        self.status_label = ctk.CTkLabel(right_h, text="VIGILANCE ACTIVE", font=T.FONT_TITLE, text_color=T.SUCCESS)
        self.status_label.pack(side="left")

        body = ctk.CTkFrame(self.root, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)
        body.columnconfigure(2, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_vitals_panel(body)
        self._build_log_panel(body)
        self._build_shield_panel(body)

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
            footer, text=f"v{VERSION}  |  C:\\DVILLIE  |  Deep vigilance.",
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
        inner.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        self.cpu_bar, self.cpu_lbl = self._metric_row(inner, "CPU", 0)
        self.ram_bar, self.ram_lbl = self._metric_row(inner, "RAM", 1)
        self.disk_bar, self.disk_lbl = self._metric_row(inner, "DISK", 2)
        self.cycle_lbl = ctk.CTkLabel(inner, text="Cycles: 0", font=T.FONT_MONO, text_color=T.TEXT_DIM)
        self.cycle_lbl.pack(anchor="w", pady=(8, 0))

        ctk.CTkLabel(inner, text="QUICK CLOSE", font=T.FONT_TITLE, text_color=T.WARNING).pack(anchor="w", pady=(14, 4))
        self.close_panel = ctk.CTkFrame(inner, fg_color=T.BG_PANEL_ALT, corner_radius=6)
        self.close_panel.pack(fill="x", pady=(0, 8))
        self.close_hint = ctk.CTkLabel(
            self.close_panel, text="No background hogs detected.",
            font=T.FONT_TAGLINE, text_color=T.TEXT_DIM, wraplength=220,
        )
        self.close_hint.pack(padx=8, pady=8)

    def _metric_row(self, parent, name: str, row: int):
        ctk.CTkLabel(parent, text=name, font=T.FONT_BODY, text_color=T.TEXT_DIM).grid(row=row * 2, column=0, sticky="w", pady=(6, 0))
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
        self.log_box.insert("1.0", f"[DVIELLE] {TAGLINE} online.\n")
        self.log_box.configure(state="disabled")

    def _build_shield_panel(self, parent) -> None:
        panel = self._panel(parent, "PROTECTION MATRIX")
        panel.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        for name, state in [
            ("Network Scan", "ACTIVE"), ("Attack Shield", "ACTIVE"),
            ("Privacy Guard", "ACTIVE"), ("Microsoft Block", "ACTIVE"), ("Resource AI", "ACTIVE"),
        ]:
            row = ctk.CTkFrame(inner, fg_color=T.BG_PANEL_ALT, corner_radius=6)
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(row, text=name, font=T.FONT_BODY, text_color=T.TEXT).pack(side="left", padx=10, pady=8)
            ctk.CTkLabel(row, text=state, font=T.FONT_MONO, text_color=T.SUCCESS).pack(side="right", padx=10, pady=8)

        self.jarvis_line = ctk.CTkLabel(
            inner, text='"At your service."',
            font=("Segoe UI", 10, "italic"), text_color=T.ACCENT_DIM, wraplength=220,
        )
        self.jarvis_line.pack(side="bottom", pady=(16, 0))

        ctk.CTkButton(
            inner, text="🔊 Replay greeting", width=180,
            command=lambda: self._replay_greeting(),
            fg_color=T.BG_PANEL_ALT, hover_color=T.BORDER,
        ).pack(side="bottom", pady=(8, 0))

    def _replay_greeting(self) -> None:
        text = greet_on_startup()
        self.jarvis_line.configure(text=f'"{text}"')
        self._append_log(f"[DVIELLE] {text}")

    def _append_log(self, line: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n")
        self.log_box.see("end")
        if int(self.log_box.index("end-1c").split(".")[0]) > 200:
            self.log_box.delete("1.0", "20.0")
        self.log_box.configure(state="disabled")

    def _on_cycle(self, status) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        mode = "LEARN" if status.monitor_only else "GUARD"
        self.root.after(0, lambda: self._append_log(f"[{ts}] Cycle {status.cycle_count} — {mode} scan complete."))

    def _tick_stats(self) -> None:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        try:
            disk = psutil.disk_usage("C:\\" if sys.platform == "win32" else "/")
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

        if cpu > 70 or mem.percent > 80:
            self.cpu_bar.configure(progress_color=T.WARNING if cpu < 85 else T.DANGER)
            self.ram_bar.configure(progress_color=T.WARNING if mem.percent < 90 else T.DANGER)
        else:
            self.cpu_bar.configure(progress_color=T.ACCENT)
            self.ram_bar.configure(progress_color=T.ACCENT)

        self.root.after(2000, self._tick_stats)

    def _tick_close_panel(self) -> None:
        for btn in self._close_buttons:
            btn.destroy()
        self._close_buttons.clear()

        closable = get_closeable_processes(4)
        if not closable:
            self.close_hint.configure(text="No background hogs detected. System optimal.")
        else:
            self.close_hint.configure(text="Background apps using resources — click to close:")
            for proc in closable:
                label = f"✕ {proc.name}  ({proc.memory_mb:.0f}MB / {proc.cpu_percent:.0f}% CPU)"
                btn = ctk.CTkButton(
                    self.close_panel, text=label, height=28, anchor="w",
                    fg_color=T.BG_DARK, hover_color=T.DANGER,
                    text_color=T.TEXT, font=T.FONT_TAGLINE,
                    command=lambda p=proc: self._close_app(p.pid, p.name),
                )
                btn.pack(fill="x", padx=6, pady=2)
                self._close_buttons.append(btn)

        self.root.after(5000, self._tick_close_panel)

    def _close_app(self, pid: int, name: str) -> None:
        ok, msg = close_process(pid, name)
        self._append_log(f"[ACTION] {msg}")
        speak_async(f"Closed {name}." if ok else f"Could not close {name}.")
        notify_tray(APP_NAME, msg)
        if ok:
            self.jarvis_line.configure(text=f'"Released resources from {name}."')

    def _tick_logs(self) -> None:
        try:
            seen = self.log_box.get("1.0", "end")
            for ev in reversed(self.controller.recent_events(6)):
                msg = ev.get("message", "")
                if msg and msg not in seen:
                    ts = ev.get("ts", "")[:19].replace("T", " ")
                    sev = ev.get("severity", "INFO")
                    mod = ev.get("module", "")
                    prefix = "⚠" if sev in ("WARNING", "CRITICAL") else "›"
                    self._append_log(f"[{ts}] {prefix} [{mod}] {msg}")
        except Exception:
            pass
        self.root.after(8000, self._tick_logs)

    def _tick_greeting(self) -> None:
        """Rotate Jarvis subtitle line every 30s."""
        from dvielle.gui.voice import GREETINGS
        self._greeting_idx = (self._greeting_idx + 1) % len(GREETINGS)
        self.greeting_lbl.configure(text=GREETINGS[self._greeting_idx][:60] + "...")
        self.root.after(30000, self._tick_greeting)

    def _pulse_status(self) -> None:
        if self.controller.status.running:
            self._pulse_on = not self._pulse_on
            self.status_dot.configure(text_color=T.SUCCESS if self._pulse_on else T.ACCENT_DIM)
        self.root.after(900, self._pulse_status)

    def _toggle_vigilance(self) -> None:
        if self.controller.status.running:
            self.controller.stop()
            self.status_label.configure(text="STANDBY", text_color=T.WARNING)
            self.vigilance_btn.configure(text="Resume Vigilance")
            self._append_log("[DVIELLE] Vigilance paused.")
            speak_async("Vigilance paused.")
        else:
            self.controller.start()
            self.status_label.configure(text="VIGILANCE ACTIVE", text_color=T.SUCCESS)
            self.vigilance_btn.configure(text="Pause Vigilance")
            self._append_log("[DVIELLE] Vigilance resumed.")
            speak_async("Deep vigilance resumed.")

    def _minimize_to_tray(self) -> None:
        self.root.withdraw()
        notify_tray(APP_NAME, "Minimized — click tray icon to restore")

    def _show_window(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _quit_app(self) -> None:
        speak_async("DVielle signing off. Stay safe.")
        self.controller.stop()
        self.root.quit()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def main(config_dir: Path | None = None) -> int:
    try:
        DVielleApp(config_dir=config_dir).run()
        return 0
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
