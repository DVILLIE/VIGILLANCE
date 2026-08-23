"""DVielle — Jarvis-style GUI: stats on launch, START for agent, quiet tray, work log."""

from __future__ import annotations

import sys
import threading
from datetime import datetime
from pathlib import Path

import psutil

from agent.chat.assistant import ChatAssistant
from agent.controller import AgentController
from agent.modules.network_info import collect_network_snapshot
from agent.modules.resource_advisor import (
    AppGroup,
    close_app_group,
    get_app_groups,
)
from agent.store.db import AgentStore
from agent.utils import DEFAULT_DATA_DIR, PROJECT_ROOT
from dvielle import APP_NAME, TAGLINE, VERSION
from dvielle.brand import ICON_ICO, brand_png
from dvielle.gui import theme as T
from dvielle.gui.attacks_window import AttacksWindow
from dvielle.gui.network_panel import NetworkPanel
from dvielle.gui.notify_policy import set_minimized_to_tray
from dvielle.gui.tray import notify_tray, setup_tray
from dvielle.gui.voice import greet_on_startup, speak_async
from dvielle.gui.chat_window import ChatWindow
from dvielle.gui.work_log_window import WorkLogWindow

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False


class DVielleApp:
    def __init__(self, config_dir: Path | None = None) -> None:
        if not HAS_CTK:
            raise RuntimeError("customtkinter required")

        self.config_dir = config_dir or (PROJECT_ROOT / "config")
        self._store = self._open_store()
        self._store.log_work("OPEN", "DVielle interface launched — stats monitoring active")

        self.controller = AgentController(
            config_dir=self.config_dir if (self.config_dir / "config.yaml").exists() else None,
            on_cycle=self._on_cycle,
        )
        self._agent_started = False
        self._minimized = False
        self._pulse_on = True
        self._close_buttons: list[ctk.CTkButton] = []
        self._greeting_idx = 0
        self._seen_events: set[str] = set()
        self._last_network_key: str | None = None
        self._chat: ChatAssistant | None = None
        self._chat_win: ChatWindow | None = None
        self._attacks_win: AttacksWindow | None = None

        ctk.set_appearance_mode("dark")
        self.root = ctk.CTk()
        self.root.title(f"{APP_NAME} — {TAGLINE}")
        self.root.geometry("1280x860")
        self.root.minsize(1100, 760)
        self.root.configure(fg_color=T.BG_DARK)
        self.root.protocol("WM_DELETE_WINDOW", self._minimize_to_tray)
        self._apply_window_icon(self.root)

        self._build_ui()
        setup_tray(
            on_show=self._show_window,
            on_hide=self._minimize_to_tray,
            on_quit=self._quit_app,
            on_toggle_vigilance=self._toggle_vigilance,
        )

        launch_greeting = greet_on_startup()
        self.jarvis_line.configure(text=f'"{launch_greeting}"')
        self.greeting_lbl.configure(text="Stats live. Press START to activate deep vigilance agent.")
        self._append_log("[DVIELLE] Installed. All stats updating in real time.")
        self._append_log("[DVIELLE] Press START to begin background vigilance agent.")

        # Stats always on — agent only after START
        self._refresh_network_async()
        self._tick_stats()
        self._tick_close_panel()
        self._tick_logs()
        self._pulse_status()

    def _open_store(self) -> AgentStore:
        data_dir = DEFAULT_DATA_DIR
        data_dir.mkdir(parents=True, exist_ok=True)
        return AgentStore(data_dir / "agent.db")

    def _build_ui(self) -> None:
        start_bar = ctk.CTkFrame(self.root, fg_color=T.BG_DARK, height=60)
        start_bar.pack(fill="x")
        start_bar.pack_propagate(False)

        self.start_btn = ctk.CTkButton(
            start_bar, text="▶  START AGENT", font=T.FONT_TITLE, width=260, height=44,
            fg_color=T.ACCENT_DIM, hover_color=T.ACCENT, text_color=T.BG_DARK,
            border_color=T.ACCENT_GLOW, border_width=2, command=self._on_start_agent,
        )
        self.start_btn.pack(side="left", padx=16, pady=8)

        self.agent_status_lbl = ctk.CTkLabel(
            start_bar, text="Agent: STANDBY  |  Stats: LIVE",
            font=T.FONT_BODY, text_color=T.TEXT_DIM,
        )
        self.agent_status_lbl.pack(side="left", padx=8)

        header = ctk.CTkFrame(self.root, fg_color=T.BG_PANEL, height=110)
        header.pack(fill="x")
        header.pack_propagate(False)

        brand_frame = ctk.CTkFrame(header, fg_color="transparent", width=88, height=88)
        brand_frame.pack(side="left", padx=(16, 8), pady=6)
        brand_frame.pack_propagate(False)
        logo_path = brand_png(88)
        if logo_path.exists():
            try:
                from PIL import Image

                self._brand_photo = ctk.CTkImage(
                    light_image=Image.open(logo_path),
                    dark_image=Image.open(logo_path),
                    size=(80, 80),
                )
                ctk.CTkLabel(brand_frame, text="", image=self._brand_photo).pack(expand=True)
            except Exception:
                ctk.CTkLabel(brand_frame, text="DV", font=T.FONT_DISPLAY, text_color=T.ACCENT_GLOW).pack(expand=True)
        else:
            ctk.CTkLabel(brand_frame, text="DV", font=T.FONT_DISPLAY, text_color=T.ACCENT_GLOW).pack(expand=True)

        left_h = ctk.CTkFrame(header, fg_color="transparent")
        left_h.pack(side="left", padx=8, pady=12)
        ctk.CTkLabel(left_h, text=APP_NAME.upper(), font=T.FONT_DISPLAY, text_color=T.ACCENT_GLOW).pack(anchor="w")
        ctk.CTkLabel(left_h, text=TAGLINE, font=T.FONT_TAGLINE, text_color=T.TEXT_DIM).pack(anchor="w")
        self.greeting_lbl = ctk.CTkLabel(left_h, text="", font=T.FONT_ITALIC, text_color=T.ACCENT_DIM)
        self.greeting_lbl.pack(anchor="w", pady=(4, 0))

        right_h = ctk.CTkFrame(header, fg_color="transparent")
        right_h.pack(side="right", padx=24, pady=16)
        self.status_dot = ctk.CTkLabel(right_h, text="●", font=T.FONT_STATUS_DOT, text_color=T.ACCENT)
        self.status_dot.pack(side="left", padx=(0, 8))
        self.status_label = ctk.CTkLabel(right_h, text="STATS LIVE", font=T.FONT_TITLE, text_color=T.ACCENT)
        self.status_label.pack(side="left")

        body = ctk.CTkFrame(self.root, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        for i, w in enumerate((1, 1, 2, 1)):
            body.columnconfigure(i, weight=w)
        body.rowconfigure(0, weight=1)

        self._build_network_panel(body)
        self._build_vitals_panel(body)
        self._build_log_panel(body)
        self._build_shield_panel(body)

        footer = ctk.CTkFrame(self.root, fg_color=T.BG_PANEL, height=68)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        left_footer = ctk.CTkFrame(footer, fg_color="transparent")
        left_footer.pack(side="left", padx=12, pady=10)
        ctk.CTkLabel(left_footer, text=f"v{VERSION} | C:\\DVILLIE", font=T.FONT_TAGLINE, text_color=T.TEXT_DIM).pack(side="left", padx=4)
        ctk.CTkButton(
            left_footer, text="View Work Log Report", width=180, height=38,
            command=self._view_work_log, fg_color=T.BG_PANEL_ALT, hover_color=T.BORDER,
            font=T.FONT_BODY,
        ).pack(side="left", padx=6)
        ctk.CTkButton(
            left_footer, text="Attacks Console", width=160, height=38,
            command=self._open_attacks, fg_color=T.DANGER, hover_color=T.WARNING,
            font=T.FONT_BODY,
        ).pack(side="left", padx=6)
        ctk.CTkButton(
            left_footer, text="Clear Work Log Report", width=180, height=38,
            command=self._clear_work_log, fg_color=T.BG_PANEL_ALT, hover_color=T.DANGER,
            font=T.FONT_BODY,
        ).pack(side="left", padx=6)
        ctk.CTkButton(
            left_footer, text="Chat (deferred)", width=150, height=38,
            command=self._open_chat, fg_color=T.ACCENT_DIM, hover_color=T.ACCENT,
            text_color=T.BG_DARK, font=T.FONT_BODY,
        ).pack(side="left", padx=6)

        btn_frame = ctk.CTkFrame(footer, fg_color="transparent")
        btn_frame.pack(side="right", padx=16, pady=10)
        self.vigilance_btn = ctk.CTkButton(
            btn_frame, text="Pause Agent", width=140, height=38, command=self._toggle_vigilance,
            fg_color=T.BORDER, state="disabled", font=T.FONT_BODY,
        )
        self.vigilance_btn.pack(side="left", padx=4)
        ctk.CTkButton(
            btn_frame, text="Minimize to Tray", width=150, height=38, command=self._minimize_to_tray,
            fg_color=T.BG_PANEL_ALT, hover_color=T.BORDER, font=T.FONT_BODY,
        ).pack(side="left", padx=4)

    def _apply_window_icon(self, window) -> None:
        """Set taskbar / title-bar icon from brand ICO."""
        try:
            if ICON_ICO.exists():
                window.iconbitmap(default=str(ICON_ICO))
                window.iconbitmap(str(ICON_ICO))
        except Exception:
            pass

    def _panel(self, parent, title: str) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=T.BG_PANEL, border_color=T.BORDER, border_width=1, corner_radius=8)
        ctk.CTkLabel(frame, text=title, font=T.FONT_TITLE, text_color=T.ACCENT).pack(anchor="w", padx=14, pady=(12, 6))
        return frame

    def _build_network_panel(self, parent) -> None:
        panel = self._panel(parent, "NETWORK & VPN")
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.network_panel = NetworkPanel(inner)
        self.network_panel.pack(fill="both", expand=True)

    def _build_vitals_panel(self, parent) -> None:
        panel = self._panel(parent, "SYSTEM VITALS")
        panel.grid(row=0, column=1, sticky="nsew", padx=4)
        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        metrics = ctk.CTkFrame(inner, fg_color="transparent")
        metrics.pack(fill="x")
        self.cpu_bar, self.cpu_lbl = self._metric_row(metrics, "CPU", 0)
        self.ram_bar, self.ram_lbl = self._metric_row(metrics, "RAM", 1)
        self.disk_bar, self.disk_lbl = self._metric_row(metrics, "DISK", 2)
        self.cycle_lbl = ctk.CTkLabel(inner, text="Agent cycles: 0", font=T.FONT_MONO, text_color=T.TEXT_DIM)
        self.cycle_lbl.pack(anchor="w", pady=(8, 0))
        ctk.CTkLabel(inner, text="SMART CLOSE", font=T.FONT_TITLE, text_color=T.WARNING).pack(anchor="w", pady=(14, 4))
        self.close_panel = ctk.CTkFrame(inner, fg_color=T.BG_PANEL_ALT, corner_radius=6)
        self.close_panel.pack(fill="x", pady=(0, 8))
        self.close_hint = ctk.CTkLabel(
            self.close_panel,
            text="Scanning apps like a smart Task Manager…",
            font=T.FONT_TAGLINE, text_color=T.TEXT_DIM, wraplength=280,
        )
        self.close_hint.pack(padx=8, pady=8)

    def _metric_row(self, parent, name: str, row: int):
        ctk.CTkLabel(parent, text=name, font=T.FONT_BODY, text_color=T.TEXT_DIM).grid(row=row * 2, column=0, sticky="w", pady=(6, 0))
        bar = ctk.CTkProgressBar(parent, width=200, height=14, progress_color=T.ACCENT, fg_color=T.BG_PANEL_ALT)
        bar.grid(row=row * 2 + 1, column=0, sticky="ew", pady=(2, 0))
        bar.set(0)
        lbl = ctk.CTkLabel(parent, text="—", font=T.FONT_MONO, text_color=T.TEXT)
        lbl.grid(row=row * 2 + 1, column=1, padx=(10, 0))
        parent.columnconfigure(0, weight=1)
        return bar, lbl

    def _build_log_panel(self, parent) -> None:
        panel = self._panel(parent, "INTELLIGENCE FEED")
        panel.grid(row=0, column=2, sticky="nsew", padx=4)
        self.log_box = ctk.CTkTextbox(panel, font=T.FONT_MONO, fg_color=T.BG_DARK, text_color=T.ACCENT_GLOW, border_color=T.BORDER, border_width=1)
        self.log_box.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.log_box.configure(state="disabled")

    def _build_shield_panel(self, parent) -> None:
        panel = self._panel(parent, "PROTECTION MATRIX")
        panel.grid(row=0, column=3, sticky="nsew", padx=(6, 0))
        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        for name in ("Network Scan", "Attack Shield", "Privacy Guard", "Microsoft Block", "Resource AI"):
            row = ctk.CTkFrame(inner, fg_color=T.BG_PANEL_ALT, corner_radius=6)
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(row, text=name, font=T.FONT_BODY).pack(side="left", padx=10, pady=8)
            ctk.CTkLabel(row, text="READY", font=T.FONT_MONO, text_color=T.ACCENT_DIM).pack(side="right", padx=10, pady=8)
        self.jarvis_line = ctk.CTkLabel(inner, text='"At your service."', font=T.FONT_ITALIC, text_color=T.ACCENT_DIM, wraplength=280)
        self.jarvis_line.pack(side="bottom", pady=(16, 0))
        ctk.CTkButton(inner, text="🔊 Replay greeting", width=180, command=self._replay_greeting, fg_color=T.BG_PANEL_ALT).pack(side="bottom", pady=(8, 0))

    def _on_start_agent(self) -> None:
        if self._agent_started:
            return
        self._agent_started = True
        self.start_btn.configure(state="disabled", text="● AGENT RUNNING")
        self.agent_status_lbl.configure(text="Agent: ACTIVE  |  Stats: LIVE", text_color=T.SUCCESS)
        self.status_label.configure(text="VIGILANCE ACTIVE", text_color=T.SUCCESS)
        self.vigilance_btn.configure(state="normal")

        greeting = greet_on_startup()
        self.jarvis_line.configure(text=f'"{greeting}"')
        self._store.log_work("START", "Deep vigilance agent started")
        self._append_log(f"[DVIELLE] Agent STARTED. {greeting}")

        self.controller.start()
        self._tick_greeting()

    def _open_chat(self) -> None:
        if self._chat is None:
            self._chat = ChatAssistant()
        if self._chat_win is not None and self._chat_win.winfo_exists():
            self._chat_win.lift()
            return

        from agent.chat.context import gather_stats_context

        def stats() -> dict:
            return gather_stats_context(
                self._agent_started,
                self.controller.status.cycle_count if self._agent_started else 0,
            )

        self._chat_win = ChatWindow(
            self.root,
            self._chat,
            agent_started=lambda: self._agent_started,
            cycle_count=lambda: self.controller.status.cycle_count if self._agent_started else 0,
            stats_provider=stats,
        )

    def _view_work_log(self) -> None:
        WorkLogWindow(self.root, self._store)

    def _open_attacks(self) -> None:
        if self._attacks_win is not None:
            try:
                if self._attacks_win.winfo_exists():
                    self._attacks_win.lift()
                    self._attacks_win.focus()
                    self._attacks_win.refresh()
                    return
            except Exception:
                pass
        self._attacks_win = AttacksWindow(self.root, self._store)
        self._apply_window_icon(self._attacks_win)
        self._store.log_work("ATTACKS", "Opened Attacks Console")

    def _clear_work_log(self) -> None:
        n = self._store.clear_work_log()
        self._store.log_work("CLEAR", f"Work log cleared ({n} entries removed)")
        self._append_log(f"[DVIELLE] Work log cleared ({n} entries).")

    def _refresh_network_async(self) -> None:
        def _work() -> None:
            try:
                snap = collect_network_snapshot()
                self.root.after(0, lambda: self.network_panel.update_snapshot(snap))
                key = f"{snap.public_ip}|{snap.vpn_active}|{snap.vpn_ip}"
                if key != self._last_network_key:
                    self._last_network_key = key
                    msg = (
                        f"VPN {snap.vpn_adapter} IP {snap.vpn_ip}" if snap.vpn_active
                        else f"Direct connection public IP {snap.public_ip}"
                    )
                    self.root.after(0, lambda m=msg, d=snap.to_dict(): self._store.log_work("NETWORK", m, d))
            except Exception as exc:
                self.root.after(0, lambda: self._append_log(f"[NETWORK] {exc}"))
        threading.Thread(target=_work, daemon=True).start()
        self.root.after(15000, self._refresh_network_async)

    def _replay_greeting(self) -> None:
        text = greet_on_startup()
        self.jarvis_line.configure(text=f'"{text}"')

    def _append_log(self, line: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _on_cycle(self, status) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.root.after(0, lambda: self._append_log(f"[{ts}] Agent cycle {status.cycle_count} complete."))

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
        if self._agent_started:
            self.cycle_lbl.configure(text=f"Agent cycles: {self.controller.status.cycle_count}")
        self.root.after(2000, self._tick_stats)

    def _tick_close_panel(self) -> None:
        self._rebuild_close_panel()
        self.root.after(5000, self._tick_close_panel)

    def _rebuild_close_panel(self) -> None:
        for btn in self._close_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._close_buttons.clear()
        groups = get_app_groups(5, include_active=True)
        if not groups:
            self.close_hint.configure(text="No notable apps to manage.")
            return

        self.close_hint.configure(text="Smart groups — tap for advice + confirm:")
        for g in groups:
            if g.risk == "danger_active":
                color, prefix = T.DANGER, "USING"
            elif g.risk == "caution":
                color, prefix = T.WARNING, "LINKED"
            else:
                color, prefix = T.SUCCESS, "SAFE"
            n = len(g.pids)
            label = f"[{prefix}] {g.display_name} ×{n} ({g.memory_mb:.0f}MB)"
            btn = ctk.CTkButton(
                self.close_panel, text=label, height=36,
                command=lambda grp=g: self._smart_close(grp),
                fg_color=T.BG_DARK, hover_color=color, font=T.FONT_BODY,
                anchor="w",
            )
            btn.pack(fill="x", padx=6, pady=2)
            self._close_buttons.append(btn)

    def _smart_close(self, group: AppGroup) -> None:
        """Advise (voice + dialog), then close only if user confirms."""
        speak_async(group.voice_line, persona="jarvis")
        self._append_log(f"[SMART CLOSE] {group.close_advice}")

        title = "Close active app?" if group.risk == "danger_active" else "Confirm close"
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.geometry("560x380")
        dlg.configure(fg_color=T.BG_DARK)
        dlg.transient(self.root)
        dlg.grab_set()
        try:
            self._apply_window_icon(dlg)
        except Exception:
            pass

        ctk.CTkLabel(
            dlg, text=group.display_name, font=T.FONT_TITLE, text_color=T.ACCENT_GLOW,
        ).pack(pady=(16, 4), padx=16, anchor="w")
        ctk.CTkLabel(
            dlg, text=group.close_advice, font=T.FONT_BODY, text_color=T.TEXT,
            wraplength=520, justify="left",
        ).pack(padx=16, pady=8, anchor="w")
        if group.process_names:
            ctk.CTkLabel(
                dlg,
                text="Processes: " + ", ".join(group.process_names[:8]),
                font=T.FONT_MONO, text_color=T.TEXT_DIM, wraplength=520, justify="left",
            ).pack(padx=16, pady=4, anchor="w")

        if group.risk == "danger_active":
            prompt = "You are using this app right now. Close it anyway?"
        elif group.risk == "caution":
            prompt = "This may affect another app. Close anyway?"
        else:
            prompt = "Safe to close. Proceed?"
        ctk.CTkLabel(dlg, text=prompt, font=T.FONT_TAGLINE, text_color=T.WARNING).pack(
            padx=16, pady=(12, 8), anchor="w"
        )

        row = ctk.CTkFrame(dlg, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=16)

        def _cancel() -> None:
            speak_async("Okay. Leaving it running.", persona="jarvis")
            self._append_log(f"[SMART CLOSE] Cancelled — left {group.display_name} running")
            dlg.destroy()

        def _confirm() -> None:
            dlg.destroy()
            speak_async(f"Closing {group.display_name} now.", persona="jarvis")
            ok, msg = close_app_group(group)
            tag = "OK" if ok else "FAILED"
            self._store.log_work("CLOSE_APP", msg)
            self._append_log(f"[ACTION/{tag}] {msg}")
            if ok:
                speak_async("Done. Application closed.", persona="jarvis")
            else:
                speak_async("I could not fully close it. You may need administrator rights.", persona="jarvis")
            self.root.after(400, self._rebuild_close_panel)

        ctk.CTkButton(
            row, text="Keep open", width=140, command=_cancel,
            fg_color=T.BORDER, hover_color=T.ACCENT_DIM,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            row, text="Yes, close it", width=140, command=_confirm,
            fg_color=T.DANGER, hover_color=T.WARNING,
        ).pack(side="right", padx=4)

    def _refresh_close_panel_once(self) -> None:
        self._rebuild_close_panel()

    def _tick_logs(self) -> None:
        if self._agent_started and self.controller.store:
            for ev in self.controller.recent_events(10):
                key = f"{ev.get('ts')}{ev.get('message')}"
                if key in self._seen_events:
                    continue
                self._seen_events.add(key)
                sev = ev.get("severity", "INFO")
                msg = ev.get("message", "")
                ts = ev.get("ts", "")[:19].replace("T", " ")
                self._append_log(f"[{ts}] [{sev}] {msg}")
                if sev == "CRITICAL" and self._minimized:
                    notify_tray(APP_NAME, msg)
                    from agent.utils import show_toast
                    show_toast(APP_NAME, msg, severity="CRITICAL")
        self.root.after(5000, self._tick_logs)

    def _tick_greeting(self) -> None:
        if not self._agent_started:
            return
        from dvielle.gui.voice import GREETINGS
        self._greeting_idx = (self._greeting_idx + 1) % len(GREETINGS)
        self.greeting_lbl.configure(text=GREETINGS[self._greeting_idx][:60])
        self.root.after(30000, self._tick_greeting)

    def _pulse_status(self) -> None:
        if self._agent_started and self.controller.status.running:
            self._pulse_on = not self._pulse_on
            self.status_dot.configure(text_color=T.SUCCESS if self._pulse_on else T.ACCENT_DIM)
        self.root.after(900, self._pulse_status)

    def _toggle_vigilance(self) -> None:
        if not self._agent_started:
            return
        if self.controller.status.running:
            self.controller.stop()
            self._store.log_work("PAUSE", "Agent paused by operator")
            self.status_label.configure(text="AGENT PAUSED", text_color=T.WARNING)
            self.vigilance_btn.configure(text="Resume Agent")
        else:
            self.controller.start()
            self._store.log_work("RESUME", "Agent resumed")
            self.status_label.configure(text="VIGILANCE ACTIVE", text_color=T.SUCCESS)
            self.vigilance_btn.configure(text="Pause Agent")

    def _minimize_to_tray(self) -> None:
        self._minimized = True
        set_minimized_to_tray(True)
        self._store.log_work("MINIMIZE", "Minimized to tray — critical alerts only")
        self.root.withdraw()

    def _show_window(self) -> None:
        self._minimized = False
        set_minimized_to_tray(False)
        self.root.deiconify()
        self.root.lift()

    def _quit_app(self) -> None:
        self._store.log_work("CLOSE", "DVielle signing off")
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
