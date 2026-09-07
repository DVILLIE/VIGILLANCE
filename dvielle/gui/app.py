"""DVielle Mission Console — living Phosphor Void presence."""

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
    get_app_groups,
)
from agent.policy import ActionKind, Authorization, PolicyGate
from agent.policy.levels import LEVEL_REVERSIBLE
from agent.store.db import AgentStore
from agent.utils import DEFAULT_DATA_DIR, PROJECT_ROOT
from dvielle import APP_NAME, TAGLINE, VERSION
from dvielle.brand import ICON_ICO, brand_png
from dvielle.gui import theme as T
from dvielle.gui.attacks_window import AttacksWindow
from dvielle.gui.network_panel import NetworkPanel
from dvielle.gui.notify_policy import set_minimized_to_tray
from dvielle.gui.presence import (
    ActivityTicker,
    ClockMono,
    LivingRadar,
    MatrixRow,
    NerveRail,
    PressureGauge,
    ScanFeed,
)
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
        self._store.log_work("OPEN", "Mission Console launched — presence online")

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
        self._mission_verbs = 0
        # User-initiated action gate (Smart Close). Registers the single
        # CLOSE_PROCESS handler; the Cortex still requires USER_APPROVED, so it
        # only runs after an explicit human confirm.
        self._user_gate: PolicyGate | None = None

        ctk.set_appearance_mode("dark")
        self.root = ctk.CTk()
        self.root.title(f"{APP_NAME} — {TAGLINE}")
        self.root.geometry("1360x900")
        self.root.minsize(1180, 780)
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
        self.mission_lbl.configure(text="Observing this PC — press START to arm the guardian.")
        self._append_log("[DVIELLE] Mission Console online. Presence active.")
        self._append_log("[DVIELLE] Stats live. START arms Adaptive Nerve agent.")

        self._refresh_network_async()
        self._tick_stats()
        self._tick_close_panel()
        self._tick_logs()
        self._pulse_status()
        self._tick_mission_presence()

    def _open_store(self) -> AgentStore:
        data_dir = DEFAULT_DATA_DIR
        data_dir.mkdir(parents=True, exist_ok=True)
        return AgentStore(data_dir / "agent.db")

    def _build_ui(self) -> None:
        # —— NOW strip (full bleed) ——
        now = ctk.CTkFrame(self.root, fg_color=T.BG_PANEL, height=148, corner_radius=0)
        now.pack(fill="x")
        now.pack_propagate(False)

        left = ctk.CTkFrame(now, fg_color="transparent")
        left.pack(side="left", fill="y", padx=(16, 8), pady=10)

        brand_row = ctk.CTkFrame(left, fg_color="transparent")
        brand_row.pack(anchor="w")
        brand_frame = ctk.CTkFrame(brand_row, fg_color="transparent", width=72, height=72)
        brand_frame.pack(side="left")
        brand_frame.pack_propagate(False)
        logo_path = brand_png(72)
        if logo_path.exists():
            try:
                from PIL import Image

                self._brand_photo = ctk.CTkImage(
                    light_image=Image.open(logo_path),
                    dark_image=Image.open(logo_path),
                    size=(68, 68),
                )
                ctk.CTkLabel(brand_frame, text="", image=self._brand_photo).pack(expand=True)
            except Exception:
                ctk.CTkLabel(
                    brand_frame, text="DV", font=T.FONT_DISPLAY, text_color=T.ACCENT_GLOW
                ).pack(expand=True)
        else:
            ctk.CTkLabel(
                brand_frame, text="DV", font=T.FONT_DISPLAY, text_color=T.ACCENT_GLOW
            ).pack(expand=True)

        titles = ctk.CTkFrame(brand_row, fg_color="transparent")
        titles.pack(side="left", padx=12)
        ctk.CTkLabel(
            titles, text=APP_NAME.upper(), font=T.FONT_DISPLAY, text_color=T.ACCENT_GLOW
        ).pack(anchor="w")
        ctk.CTkLabel(
            titles, text=TAGLINE, font=T.FONT_TAGLINE, text_color=T.TEXT_DIM
        ).pack(anchor="w")

        self.mission_lbl = ctk.CTkLabel(
            left,
            text="",
            font=("Segoe UI", 18, "bold"),
            text_color=T.TEXT,
            wraplength=620,
            anchor="w",
            justify="left",
        )
        self.mission_lbl.pack(anchor="w", pady=(10, 0))

        self.ticker = ActivityTicker(left)
        self.ticker.pack(fill="x", pady=(8, 0))

        # Center: living radar
        mid = ctk.CTkFrame(now, fg_color="transparent")
        mid.pack(side="left", expand=True)
        self.radar = LivingRadar(mid, size=124)
        self.radar.pack()

        # Right: arm + status
        right = ctk.CTkFrame(now, fg_color="transparent")
        right.pack(side="right", padx=20, pady=12)
        self.start_btn = ctk.CTkButton(
            right,
            text="▶  START AGENT",
            font=T.FONT_TITLE,
            width=240,
            height=44,
            fg_color=T.ACCENT,
            hover_color=T.ACCENT_GLOW,
            text_color=T.BG_DARK,
            border_width=0,
            command=self._on_start_agent,
        )
        self.start_btn.pack(anchor="e")
        status_row = ctk.CTkFrame(right, fg_color="transparent")
        status_row.pack(anchor="e", pady=(10, 0))
        self.status_dot = ctk.CTkLabel(
            status_row, text="●", font=T.FONT_STATUS_DOT, text_color=T.ACCENT
        )
        self.status_dot.pack(side="left", padx=(0, 6))
        self.status_label = ctk.CTkLabel(
            status_row, text="PRESENCE LIVE", font=T.FONT_TITLE, text_color=T.ACCENT
        )
        self.status_label.pack(side="left")
        self.agent_status_lbl = ctk.CTkLabel(
            right,
            text="Agent STANDBY  ·  Console LIVE",
            font=T.FONT_MONO,
            text_color=T.TEXT_DIM,
        )
        self.agent_status_lbl.pack(anchor="e", pady=(6, 0))
        ClockMono(right).pack(anchor="e", pady=(4, 0))

        # Nerve chase rail
        rail_wrap = ctk.CTkFrame(self.root, fg_color=T.BG_DARK, height=40)
        rail_wrap.pack(fill="x", padx=16, pady=(8, 0))
        rail_wrap.pack_propagate(False)
        ctk.CTkLabel(
            rail_wrap, text="NERVE", font=("Consolas", 11, "bold"), text_color=T.ACCENT_DIM
        ).pack(side="left", padx=(4, 8))
        self.nerve_rail = NerveRail(rail_wrap)
        self.nerve_rail.pack(side="left", fill="x", expand=True)

        # Body
        body = ctk.CTkFrame(self.root, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=10)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.columnconfigure(2, weight=2)
        body.columnconfigure(3, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_network_panel(body)
        self._build_vitals_panel(body)
        self._build_log_panel(body)
        self._build_shield_panel(body)

        # Footer
        footer = ctk.CTkFrame(self.root, fg_color=T.BG_PANEL, height=64, corner_radius=0)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        left_footer = ctk.CTkFrame(footer, fg_color="transparent")
        left_footer.pack(side="left", padx=12, pady=10)
        ctk.CTkLabel(
            left_footer,
            text=f"v{VERSION}  ·  C:\\DVILLIE",
            font=T.FONT_TAGLINE,
            text_color=T.TEXT_DIM,
        ).pack(side="left", padx=4)
        for text, cmd, fg in (
            ("Work Log", self._view_work_log, T.BG_PANEL_ALT),
            ("Attacks Console", self._open_attacks, T.DANGER),
            ("Clear Log", self._clear_work_log, T.BG_PANEL_ALT),
            ("Chat (deferred)", self._open_chat, T.ACCENT_DIM),
        ):
            ctk.CTkButton(
                left_footer,
                text=text,
                width=130,
                height=36,
                command=cmd,
                fg_color=fg,
                hover_color=T.BORDER,
                text_color=T.BG_DARK if fg == T.ACCENT_DIM else T.TEXT,
                font=T.FONT_BODY,
            ).pack(side="left", padx=4)

        btn_frame = ctk.CTkFrame(footer, fg_color="transparent")
        btn_frame.pack(side="right", padx=16, pady=10)
        self.vigilance_btn = ctk.CTkButton(
            btn_frame,
            text="Pause Agent",
            width=140,
            height=36,
            command=self._toggle_vigilance,
            fg_color=T.BORDER,
            state="disabled",
            font=T.FONT_BODY,
        )
        self.vigilance_btn.pack(side="left", padx=4)
        ctk.CTkButton(
            btn_frame,
            text="Minimize to Tray",
            width=150,
            height=36,
            command=self._minimize_to_tray,
            fg_color=T.BG_PANEL_ALT,
            hover_color=T.BORDER,
            font=T.FONT_BODY,
        ).pack(side="left", padx=4)

    def _apply_window_icon(self, window) -> None:
        try:
            if ICON_ICO.exists():
                window.iconbitmap(default=str(ICON_ICO))
                window.iconbitmap(str(ICON_ICO))
        except Exception:
            pass

    def _panel(self, parent, title: str, subtitle: str = "") -> ctk.CTkFrame:
        frame = ctk.CTkFrame(
            parent, fg_color=T.BG_PANEL, border_color=T.BORDER, border_width=1, corner_radius=4
        )
        head = ctk.CTkFrame(frame, fg_color="transparent")
        head.pack(fill="x", padx=14, pady=(10, 4))
        ctk.CTkLabel(head, text=title, font=T.FONT_TITLE, text_color=T.ACCENT).pack(side="left")
        if subtitle:
            ctk.CTkLabel(head, text=subtitle, font=T.FONT_MONO, text_color=T.TEXT_DIM).pack(
                side="right"
            )
        return frame

    def _build_network_panel(self, parent) -> None:
        panel = self._panel(parent, "TRAFFIC", "LIVE")
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.network_panel = NetworkPanel(inner)
        self.network_panel.pack(fill="both", expand=True)

    def _build_vitals_panel(self, parent) -> None:
        panel = self._panel(parent, "PRESSURE", "VECTOR")
        panel.grid(row=0, column=1, sticky="nsew", padx=4)
        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        gauges = ctk.CTkFrame(inner, fg_color="transparent")
        gauges.pack(fill="x")
        self.cpu_gauge = PressureGauge(gauges, "CPU")
        self.cpu_gauge.pack(side="left", expand=True, padx=2)
        self.ram_gauge = PressureGauge(gauges, "RAM")
        self.ram_gauge.pack(side="left", expand=True, padx=2)
        self.disk_gauge = PressureGauge(gauges, "DISK")
        self.disk_gauge.pack(side="left", expand=True, padx=2)

        self.cycle_lbl = ctk.CTkLabel(
            inner, text="Agent cycles: 0", font=T.FONT_MONO, text_color=T.TEXT_DIM
        )
        self.cycle_lbl.pack(anchor="w", pady=(8, 0), padx=4)

        ctk.CTkLabel(
            inner, text="SMART CLOSE", font=T.FONT_TITLE, text_color=T.WARNING
        ).pack(anchor="w", pady=(12, 4), padx=4)
        self.close_panel = ctk.CTkFrame(inner, fg_color=T.BG_PANEL_ALT, corner_radius=4)
        self.close_panel.pack(fill="x", pady=(0, 8))
        self.close_hint = ctk.CTkLabel(
            self.close_panel,
            text="Scanning app groups…",
            font=T.FONT_TAGLINE,
            text_color=T.TEXT_DIM,
            wraplength=300,
        )
        self.close_hint.pack(padx=8, pady=8)

    def _build_log_panel(self, parent) -> None:
        panel = self._panel(parent, "INTELLIGENCE", "FEED")
        panel.grid(row=0, column=2, sticky="nsew", padx=4)
        self.scan_feed = ScanFeed(panel)
        self.scan_feed.pack(fill="both", expand=True, padx=10, pady=(0, 12))

    def _build_shield_panel(self, parent) -> None:
        panel = self._panel(parent, "SURFACE", "MATRIX")
        panel.grid(row=0, column=3, sticky="nsew", padx=(6, 0))
        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        modules = (
            "Network Scan",
            "Attack Shield",
            "Privacy Guard",
            "Workload Watch",
            "Resource AI",
        )
        for i, name in enumerate(modules):
            MatrixRow(inner, name, delay_ms=i * 280).pack(fill="x", pady=3)
        self.jarvis_line = ctk.CTkLabel(
            inner,
            text='"At your service."',
            font=T.FONT_ITALIC,
            text_color=T.ACCENT_DIM,
            wraplength=260,
        )
        self.jarvis_line.pack(side="bottom", pady=(12, 0))
        ctk.CTkButton(
            inner,
            text="🔊 Replay greeting",
            width=180,
            command=self._replay_greeting,
            fg_color=T.BG_PANEL_ALT,
        ).pack(side="bottom", pady=(8, 0))

    def _on_start_agent(self) -> None:
        if self._agent_started:
            return
        self._agent_started = True
        self.start_btn.configure(state="disabled", text="●  AGENT ARMED", fg_color=T.SUCCESS)
        self.agent_status_lbl.configure(
            text="Agent ACTIVE  ·  Console LIVE", text_color=T.SUCCESS
        )
        self.status_label.configure(text="VIGILANCE ACTIVE", text_color=T.SUCCESS)
        self.mission_lbl.configure(text="Guardian armed — protecting responsiveness under your workload.")
        self.vigilance_btn.configure(state="normal")

        greeting = greet_on_startup()
        self.jarvis_line.configure(text=f'"{greeting}"')
        self._store.log_work("START", "Deep vigilance agent started")
        self._append_log(f"[DVIELLE] Agent STARTED. {greeting}")
        self.ticker.push("NERVE · agent armed · pulse online")

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
                        f"VPN {snap.vpn_adapter} IP {snap.vpn_ip}"
                        if snap.vpn_active
                        else f"Direct connection public IP {snap.public_ip}"
                    )
                    self.root.after(
                        0, lambda m=msg, d=snap.to_dict(): self._store.log_work("NETWORK", m, d)
                    )
                    self.root.after(
                        0, lambda: self.ticker.push("TRAFFIC · topology refresh")
                    )
            except Exception as exc:
                self.root.after(0, lambda: self._append_log(f"[NETWORK] {exc}"))

        threading.Thread(target=_work, daemon=True).start()
        self.root.after(15000, self._refresh_network_async)

    def _replay_greeting(self) -> None:
        text = greet_on_startup()
        self.jarvis_line.configure(text=f'"{text}"')

    def _append_log(self, line: str) -> None:
        self.scan_feed.append(line)

    def _on_cycle(self, status) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.root.after(
            0, lambda: self._append_log(f"[{ts}] Agent cycle {status.cycle_count} complete.")
        )
        self.root.after(
            0, lambda: self.ticker.push(f"PULSE · cycle {status.cycle_count} · twin sync")
        )

    def _tick_stats(self) -> None:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        try:
            disk = psutil.disk_usage("C:\\" if sys.platform == "win32" else "/")
        except Exception:
            disk = psutil.disk_usage("/")
        self.cpu_gauge.set_value(cpu)
        self.ram_gauge.set_value(mem.percent)
        self.disk_gauge.set_value(disk.percent)
        if self._agent_started:
            self.cycle_lbl.configure(text=f"Agent cycles: {self.controller.status.cycle_count}")
        self.root.after(1500, self._tick_stats)

    def _tick_mission_presence(self) -> None:
        """Rotate NOW sentence so the console feels continuously engaged."""
        standby = (
            "Watching pressure · traffic · surface — presence is live.",
            "Your PC is under observation. Arm the agent when ready.",
            "Mission Console idle-armed — Nerve rail scanning.",
        )
        active = (
            "Guardian protecting responsiveness under your workload.",
            "Adaptive Nerve online — heartbeat and pulse running.",
            "Observing contention · classifying purpose · ready to explain.",
        )
        pool = active if self._agent_started else standby
        self._mission_verbs = (self._mission_verbs + 1) % len(pool)
        # Don't overwrite right after START for a few seconds — mission_lbl set there
        if not (self._agent_started and self._mission_verbs == 0):
            self.mission_lbl.configure(text=pool[self._mission_verbs])
        self.root.after(7000, self._tick_mission_presence)

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
                self.close_panel,
                text=label,
                height=34,
                command=lambda grp=g: self._smart_close(grp),
                fg_color=T.BG_DARK,
                hover_color=color,
                font=T.FONT_BODY,
                anchor="w",
            )
            btn.pack(fill="x", padx=6, pady=2)
            self._close_buttons.append(btn)

    def _smart_close(self, group: AppGroup) -> None:
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
            dlg, text=group.display_name, font=T.FONT_TITLE, text_color=T.ACCENT_GLOW
        ).pack(pady=(16, 4), padx=16, anchor="w")
        ctk.CTkLabel(
            dlg,
            text=group.close_advice,
            font=T.FONT_BODY,
            text_color=T.TEXT,
            wraplength=520,
            justify="left",
        ).pack(padx=16, pady=8, anchor="w")
        if group.process_names:
            ctk.CTkLabel(
                dlg,
                text="Processes: " + ", ".join(group.process_names[:8]),
                font=T.FONT_MONO,
                text_color=T.TEXT_DIM,
                wraplength=520,
                justify="left",
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
            # Graceful pass first (WM_CLOSE), gated through PolicyGate.
            ok, msg = self._issue_and_close(group, force=False)
            self._store.log_work("CLOSE_APP", msg)
            if ok:
                self._append_log(f"[ACTION/OK] {msg}")
                speak_async("Done. Application closed.", persona="jarvis")
                self.root.after(400, self._rebuild_close_panel)
            else:
                # Did not exit on its own — require a separate, explicit force confirm.
                self._append_log(f"[ACTION/HOLD] {msg}")
                self._prompt_force_close(group, msg)

        ctk.CTkButton(
            row, text="Keep open", width=140, command=_cancel, fg_color=T.BORDER, hover_color=T.ACCENT_DIM
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            row,
            text="Yes, close it",
            width=140,
            command=_confirm,
            fg_color=T.DANGER,
            hover_color=T.WARNING,
        ).pack(side="right", padx=4)

    def _get_user_gate(self) -> PolicyGate:
        """Lazily build the user-action gate (registers CLOSE_PROCESS handler)."""
        if self._user_gate is None:
            self._user_gate = PolicyGate.create(self._store, user_actions=True)
        return self._user_gate

    def _issue_and_close(self, group: AppGroup, *, force: bool) -> tuple[bool, str]:
        """Route a human-confirmed Smart Close through PolicyGate.

        Issues a USER_APPROVED CLOSE_PROCESS Decision (persisted to the evidence
        ledger by the executor) targeting the group's recorded PID set, then runs
        the registered handler. reversible=False: closing an app cannot be undone.
        """
        gate = self._get_user_gate()
        pids = list(group.pids)
        evidence = [
            f"User confirmed Smart Close in Mission Console (force={force})",
            f"{group.display_name}: {len(pids)} process(es), ~{group.memory_mb:.0f} MB",
            "Irreversible: unsaved work may be lost (no rollback)",
        ]
        if group.risk == "danger_active":
            evidence.append("WARNING: this app is currently in the foreground")
        decision = gate.cortex.issue(
            action=ActionKind.CLOSE_PROCESS,
            action_level=LEVEL_REVERSIBLE,
            confidence=1.0,
            evidence_summary=evidence,
            authorization=Authorization.USER_APPROVED,
            target=f"{group.display_name} pids={pids}",
            initiator="mission_console_user",
            reversible=False,
            rollback_plan=None,
            policy_ref="gui_smart_close",
            details={
                "pids": pids,
                "names": list(group.process_names),
                "force": force,
            },
        )
        if decision is None:
            return False, "Refused by policy — Decision not issued"
        return gate.executor.execute(decision, before_state=f"running:{len(pids)}")

    def _prompt_force_close(self, group: AppGroup, reason: str) -> None:
        """Second, explicit confirm before terminating (no silent kill escalation)."""
        speak_async(
            "It did not close on its own. Force close will end it and may lose unsaved work.",
            persona="jarvis",
        )
        dlg = ctk.CTkToplevel(self.root)
        dlg.title("Force close?")
        dlg.geometry("560x300")
        dlg.configure(fg_color=T.BG_DARK)
        dlg.transient(self.root)
        dlg.grab_set()
        try:
            self._apply_window_icon(dlg)
        except Exception:
            pass

        ctk.CTkLabel(
            dlg, text=group.display_name, font=T.FONT_TITLE, text_color=T.ACCENT_GLOW
        ).pack(pady=(16, 4), padx=16, anchor="w")
        ctk.CTkLabel(
            dlg, text=reason, font=T.FONT_BODY, text_color=T.TEXT,
            wraplength=520, justify="left",
        ).pack(padx=16, pady=8, anchor="w")
        ctk.CTkLabel(
            dlg,
            text="Force close terminates the process(es) immediately. Unsaved work may be lost.",
            font=T.FONT_TAGLINE, text_color=T.WARNING, wraplength=520, justify="left",
        ).pack(padx=16, pady=(4, 8), anchor="w")

        row = ctk.CTkFrame(dlg, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=16)

        def _cancel() -> None:
            dlg.destroy()
            speak_async("Okay. Leaving it running.", persona="jarvis")
            self._append_log(f"[SMART CLOSE] Force declined — left {group.display_name} running")
            self.root.after(400, self._rebuild_close_panel)

        def _force() -> None:
            dlg.destroy()
            speak_async(f"Force closing {group.display_name}.", persona="jarvis")
            ok, msg = self._issue_and_close(group, force=True)
            self._store.log_work("CLOSE_APP", msg)
            self._append_log(f"[ACTION/{'OK' if ok else 'FAILED'}] {msg}")
            speak_async(
                "Done. Application closed."
                if ok
                else "I could not fully close it even with force. You may need administrator rights.",
                persona="jarvis",
            )
            self.root.after(400, self._rebuild_close_panel)

        ctk.CTkButton(
            row, text="Keep open", width=140, command=_cancel,
            fg_color=T.BORDER, hover_color=T.ACCENT_DIM,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            row, text="Force close", width=140, command=_force,
            fg_color=T.DANGER, hover_color=T.WARNING,
        ).pack(side="right", padx=4)

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
        self.root.after(30000, self._tick_greeting)

    def _pulse_status(self) -> None:
        self._pulse_on = not self._pulse_on
        if self._agent_started and self.controller.status.running:
            self.status_dot.configure(
                text_color=T.SUCCESS if self._pulse_on else T.ACCENT_DIM
            )
        else:
            self.status_dot.configure(
                text_color=T.ACCENT_GLOW if self._pulse_on else T.ACCENT_DIM
            )
        self.root.after(700, self._pulse_status)

    def _toggle_vigilance(self) -> None:
        if not self._agent_started:
            return
        if self.controller.status.running:
            self.controller.stop()
            self._store.log_work("PAUSE", "Agent paused by operator")
            self.status_label.configure(text="AGENT PAUSED", text_color=T.WARNING)
            self.mission_lbl.configure(text="Agent paused — console presence still live.")
            self.vigilance_btn.configure(text="Resume Agent")
            self.ticker.push("NERVE · paused by operator")
        else:
            self.controller.start()
            self._store.log_work("RESUME", "Agent resumed")
            self.status_label.configure(text="VIGILANCE ACTIVE", text_color=T.SUCCESS)
            self.mission_lbl.configure(text="Guardian re-armed — Nerve pulse resumed.")
            self.vigilance_btn.configure(text="Pause Agent")
            self.ticker.push("NERVE · resumed · pulse online")

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
