"""DVielle Mission Console — living Phosphor Void presence."""

from __future__ import annotations

import sys
import threading
import queue
from datetime import datetime
from pathlib import Path

import psutil

from agent.chat.assistant import ChatAssistant
from agent.controller import AgentController
from agent.modules.network_info import NetworkSnapshot
from agent.runtime import runtime_paths
from agent.modules.resource_advisor import (
    AppGroup,
    get_app_groups,
    never_close_from_config,
)
from agent.store.db import AgentStore
from agent.utils import PROJECT_ROOT, load_yaml
from dvielle import APP_NAME, TAGLINE, VERSION
from dvielle.brand import apply_tk_window_icon, brand_png, configure_windows_app_identity
from dvielle.gui import theme as T
from dvielle.gui.attacks_window import AttacksWindow
from dvielle.gui.network_panel import NetworkPanel
from dvielle.gui.notify_policy import set_minimized_to_tray
from dvielle.gui.observations import activity_summary, chat_stats, collector_state, section_current, snapshot_fresh
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
from dvielle.gui.why_window import WhyWindow
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
        self._config, _, _, _, self.data_dir = runtime_paths(self.config_dir)
        self._ui_events = queue.SimpleQueue()
        self._process_scan_running = False
        set_minimized_to_tray(False)
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
        self._why_win: WhyWindow | None = None
        self._mission_verbs = 0

        # Identity before first window (also set in __main__; safe to call twice).
        configure_windows_app_identity()

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
            on_show=lambda: self._ui_events.put(self._show_window),
            on_hide=lambda: self._ui_events.put(self._minimize_to_tray),
            on_quit=lambda: self._ui_events.put(self._quit_app),
            on_toggle_vigilance=lambda: self._ui_events.put(self._toggle_vigilance),
        )

        launch_greeting = greet_on_startup()
        self.jarvis_line.configure(text=f'"{launch_greeting}"')
        self.mission_lbl.configure(text="Connecting to the monitoring agent…")
        self._append_log("[DVIELLE] Console opened. Waiting for current observations.")

        self._refresh_network_async()
        self._tick_stats()
        self._tick_close_panel()
        self._tick_logs()
        self._pulse_status()
        self._tick_mission_presence()
        self._drain_ui()
        self.root.after(0, self._on_start_agent)

    def _open_store(self) -> AgentStore:
        data_dir = self.data_dir
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
            status_row, text="CONNECTING", font=T.FONT_TITLE, text_color=T.TEXT_DIM
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
            ("Why", self._open_why, T.ACCENT_DIM),
            ("Attacks Console", self._open_attacks, T.DANGER),
            ("Clear Log", self._clear_work_log, T.BG_PANEL_ALT),
            ("Chat" if self._config.get("chat", {}).get("enabled") is True else "Chat disabled", self._open_chat, T.ACCENT_DIM),
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
        """Standard DVielle .ico for title bar, taskbar, and child dialogs."""
        apply_tk_window_icon(window)

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
        # MEM (not RAM%): the gauge shows commit pressure, not raw used% (law #2).
        self.ram_gauge = PressureGauge(gauges, "MEM")
        self.ram_gauge.pack(side="left", expand=True, padx=2)
        self.disk_gauge = PressureGauge(gauges, "DISK")
        self.disk_gauge.pack(side="left", expand=True, padx=2)

        # Honest pressure breakdown + VILL self-budget (are we the slowdown?).
        self.mem_detail_lbl = ctk.CTkLabel(
            inner, text="memory: —", font=T.FONT_TAGLINE, text_color=T.TEXT_DIM,
            wraplength=300, anchor="w", justify="left",
        )
        self.mem_detail_lbl.pack(anchor="w", pady=(6, 0), padx=4)
        self.budget_lbl = ctk.CTkLabel(
            inner, text="VILL footprint: —", font=T.FONT_TAGLINE, text_color=T.TEXT_DIM,
        )
        self.budget_lbl.pack(anchor="w", padx=4)

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
        # Rows bound to real signals (twin/capability/nerve), not animation.
        self._matrix_rows: dict[str, MatrixRow] = {}
        for name in ("Defender", "Firewall", "Nerve", "Vision", "Pulse"):
            row = MatrixRow(inner, name)
            row.pack(fill="x", pady=3)
            self._matrix_rows[name] = row
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
        if self.controller.status.ownership in {"starting", "owner", "attached"}:
            return
        self._agent_started = True
        self.start_btn.configure(state="disabled", text="CONNECTING…")
        self.mission_lbl.configure(text="Connecting to the monitoring owner…")
        self._store.log_work("START_REQUEST", "Requested monitoring start or attachment")
        self.controller.start()

    def _open_chat(self) -> None:
        try:
            cfg = load_yaml(self.config_dir / "config.yaml")
            configured_chat = ChatAssistant.from_config(cfg)
        except (OSError, TypeError, ValueError) as exc:
            self._append_log(f"[CHAT] Configuration unavailable: {exc}")
            return
        if cfg.get("chat", {}).get("enabled") is not True:
            self._append_log("[CHAT] Chat is disabled in configuration.")
            return
        if self._chat_win is not None and self._chat_win.winfo_exists():
            self._chat_win.lift()
            return
        # Reopening applies current privacy options instead of retaining old opt-ins.
        self._chat = configured_chat

        def stats() -> dict:
            twin = self.controller.twin
            return chat_stats(twin.as_dict() if twin else None,
                              self.controller.status.running, self.controller.status.cycle_count)

        self._chat_win = ChatWindow(
            self.root,
            self._chat,
            agent_started=lambda: self.controller.status.running,
            cycle_count=lambda: self.controller.status.cycle_count if self._agent_started else 0,
            stats_provider=stats,
            on_cloud_use=self._on_chat_cloud_use,
        )

    def _on_chat_cloud_use(self) -> None:
        """Record to the work log whenever a chat answer left the machine."""
        raw = getattr(self._chat, "allow_cloud_raw", False)
        detail = "RAW context sent" if raw else "network identity redacted"
        self._store.log_work("CHAT_CLOUD", f"Chat answered via Groq cloud LLM ({detail})")

    def _view_work_log(self) -> None:
        WorkLogWindow(self.root, self._store)

    def _open_why(self) -> None:
        if self._why_win is not None:
            try:
                if self._why_win.winfo_exists():
                    self._why_win.lift()
                    self._why_win.focus()
                    self._why_win.refresh()
                    return
            except Exception:
                pass
        twin = self.controller.twin if self._agent_started else None
        self._why_win = WhyWindow(self.root, self._store, twin)
        self._apply_window_icon(self._why_win)
        self._store.log_work("WHY", "Opened Why / evidence viewer")

    def _observation_snapshot(self) -> dict | None:
        twin = self.controller.twin if self._agent_started else None
        if twin is None:
            return None
        try:
            return twin.as_dict()
        except Exception:
            return None

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
        cfg = {}
        try:
            cfg = load_yaml(self.config_dir / "config.yaml") if (self.config_dir / "config.yaml").exists() else {}
        except Exception:
            cfg = {}
        attacks_cfg = cfg.get("attacks") or {}
        self._attacks_win = AttacksWindow(
            self.root,
            self._store,
            review_window_hours=float(attacks_cfg.get("review_window_hours", 24)),
            summary_window_days=float(attacks_cfg.get("summary_window_days", 14)),
            coverage=lambda: collector_state(self._observation_snapshot(), "attacks"),
        )
        self._apply_window_icon(self._attacks_win)
        self._store.log_work("ATTACKS", "Opened Attacks Console")

    def _clear_work_log(self) -> None:
        n = self._store.clear_work_log()
        self._store.log_work("CLEAR", f"Work log cleared ({n} entries removed)")
        self._append_log(f"[DVIELLE] Work log cleared ({n} entries).")

    def _refresh_network_async(self) -> None:
        # The console reads the owner's observations; opening it never adds network probes.
        if not self._minimized:
            twin = self.controller.twin
            data = twin.as_dict() if twin else None
            net = (data or {}).get("network") or {}
            if section_current(data, "network_info") and net.get("hostname"):
                fields = NetworkSnapshot.__dataclass_fields__
                self.network_panel.update_snapshot(NetworkSnapshot(**{k: v for k, v in net.items() if k in fields}))
            else:
                self.network_panel.update_snapshot(None)
            self.network_panel.set_observation_state(collector_state(data, "network_info"), net.get("sampled_at"))
        self.root.after(5000, self._refresh_network_async)

    def _replay_greeting(self) -> None:
        text = greet_on_startup()
        self.jarvis_line.configure(text=f'"{text}"')

    def _append_log(self, line: str) -> None:
        self.scan_feed.append(line)

    def _on_cycle(self, status) -> None:
        count = status.cycle_count
        self._ui_events.put(lambda: self._append_log(f"[MONITOR] Observation summary {count} published."))

    def _drain_ui(self) -> None:
        for _ in range(50):
            try:
                callback = self._ui_events.get_nowait()
            except queue.Empty:
                break
            try:
                callback()
            except Exception as exc:
                self._append_log(f"[CONSOLE] {exc}")
        self.root.after(100, self._drain_ui)

    def _tick_stats(self) -> None:
        if self._minimized:
            self.root.after(4000, self._tick_stats)  # hidden: don't sample/paint
            return
        v = self._read_vitals()
        self.cpu_gauge.set_value(v["cpu"])
        self.ram_gauge.set_value(v["mem"])
        self.disk_gauge.set_value(v["disk"])
        self.mem_detail_lbl.configure(text=v["mem_detail"])
        self.budget_lbl.configure(text=v["budget"])
        if self._agent_started:
            self.cycle_lbl.configure(text=f"Agent cycles: {self.controller.status.cycle_count}")
        self._update_surface(v)
        self.root.after(1500, self._tick_stats)

    def _read_vitals(self) -> dict:
        """Read only current shared observations; missing values remain unavailable."""
        tw = self.controller.twin if self._agent_started else None
        data = tw.as_dict() if tw is not None else None

        def _mem_fields(mem: dict):
            commit = mem.get("commit_percent")
            load = mem.get("memory_load_percent")
            avail = mem.get("avail_phys_mb")
            bits = []
            if commit is not None:
                bits.append(f"commit {commit:.0f}%")
            if avail is not None:
                bits.append(f"{avail:.0f} MB free")
            if load is not None:
                bits.append(f"load {load:.0f}%")
            detail = "memory: " + " · ".join(bits) if bits else "memory: —"
            return (commit if commit is not None else load), detail

        if data and snapshot_fresh(data):
            sysd = data.get("system") or {}
            sb = data.get("self_budget") or {}
            memory = data.get("memory") or {}
            mem_val, mem_detail = _mem_fields(memory) if section_current(data, "heartbeat", memory.get("sampled_at")) else (None, "Memory observation unavailable")
            sb_cpu = sb.get("cpu_percent")
            sb_rss = sb.get("rss_bytes")
            budget = f"VILL footprint: {sb_cpu:.0f}% CPU" if sb_cpu is not None else "VILL footprint: —"
            if sb_rss:
                budget += f" · {sb_rss / (1024 * 1024):.0f} MB"
            budget += " · " + sb.get("reason", "budget status unavailable")
            return {
                "cpu": sysd.get("cpu_percent") if section_current(data, "heartbeat", sysd.get("cpu_sampled_at")) else None,
                "mem": mem_val,
                "disk": sysd.get("disk_percent") if section_current(data, "disk") else None,
                "mem_detail": mem_detail,
                "budget": budget,
                "twin": data,
            }

        return {
            "cpu": None, "mem": None, "disk": None,
            "mem_detail": "Memory observation unavailable or stale",
            "budget": "Agent footprint unavailable or stale",
            "twin": data,
        }

    def _update_surface(self, v: dict) -> None:
        """Bind SURFACE rows to real posture — never a random 'LIVE'."""
        rows = getattr(self, "_matrix_rows", {})
        if not rows:
            return
        data = v.get("twin")
        sec = (data or {}).get("security") or {}
        security_current = section_current(data, "security")

        def _posture(name: str, val) -> None:
            row = rows.get(name)
            if row is None:
                return
            if val is True:
                row.set_state("ON", T.SUCCESS)
            elif val is False:
                row.set_state("OFF", T.DANGER)
            else:
                row.set_state(collector_state(data, "security").upper() + " / UNKNOWN", T.TEXT_DIM)

        _posture("Defender", sec.get("defender_enabled") if security_current else None)
        _posture("Firewall", sec.get("firewall_enabled") if security_current else None)

        running = self.controller.status.running and snapshot_fresh(data)
        rows["Nerve"].set_state("LIVE" if running else "STANDBY", T.SUCCESS if running else T.TEXT_DIM)

        vision = (data or {}).get("vision") if snapshot_fresh(data) else None
        vcolor = {"AVAILABLE": T.SUCCESS, "LIMITED": T.WARNING, "UNAVAILABLE": T.DANGER}.get(
            vision or "", T.TEXT_DIM
        )
        rows["Vision"].set_state(vision or "—", vcolor)

        if self._agent_started:
            n = self.controller.status.cycle_count
            rows["Pulse"].set_state(f"{n} cyc" if n else "arming", T.ACCENT if n else T.WARNING)
        else:
            rows["Pulse"].set_state("—", T.TEXT_DIM)

    def _tick_mission_presence(self) -> None:
        status = self.controller.status
        twin = self.controller.twin
        data = twin.as_dict() if twin else None
        running = status.running and snapshot_fresh(data)
        label = "MONITORING" if running else status.ownership.upper()
        self.status_label.configure(text=label, text_color=T.SUCCESS if running else T.WARNING)
        self.agent_status_lbl.configure(text=f"{status.ownership.upper()} · {status.message}", text_color=T.SUCCESS if running else T.WARNING)
        self.mission_lbl.configure(text=status.message)
        self.ticker.push(activity_summary(data))
        self.nerve_rail.set_states(data)
        self.radar.set_running(running)
        if status.ownership == "attached":
            self.start_btn.configure(text="ATTACHED TO BACKGROUND AGENT", state="disabled")
            self.vigilance_btn.configure(text="Background owner", state="disabled")
            self.mission_lbl.configure(text=status.message + ". Pause is controlled by the background owner.")
        elif status.ownership == "owner":
            self.start_btn.configure(text="MONITORING OWNER", state="disabled")
            self.vigilance_btn.configure(text="Pause Agent", state="normal" if running else "disabled")
        elif status.ownership == "starting":
            self.start_btn.configure(text="CONNECTING…", state="disabled")
            self.vigilance_btn.configure(state="disabled")
        else:
            self.start_btn.configure(text="START / RECONNECT", state="normal")
            self.vigilance_btn.configure(text="Resume Agent", state="normal")
        self.root.after(2000, self._tick_mission_presence)

    def _tick_close_panel(self) -> None:
        if self._minimized:
            self.root.after(30000, self._tick_close_panel)  # hidden: skip process enumeration
            return
        self._rebuild_close_panel()
        self.root.after(8000, self._tick_close_panel)

    def _rebuild_close_panel(self) -> None:
        if self._process_scan_running:
            return
        self._process_scan_running = True
        self.close_hint.configure(text="Reading current app identities…")

        def work():
            try:
                cfg = load_yaml(self.config_dir / "config.yaml")
                groups = get_app_groups(5, include_active=True, never_close=never_close_from_config(cfg))
                self._ui_events.put(lambda: self._render_close_groups(groups))
            except Exception as exc:
                self._ui_events.put(lambda error=str(exc): self._close_scan_failed(error))

        threading.Thread(target=work, name="DVielle-App-Review", daemon=True).start()

    def _close_scan_failed(self, error: str) -> None:
        self._process_scan_running = False
        self._render_close_groups([])
        self.close_hint.configure(text="Process observations unavailable. Retry after the next refresh.")
        self._append_log(f"[APP REVIEW] {error}")

    def _render_close_groups(self, groups: list[AppGroup]) -> None:
        self._process_scan_running = False
        for btn in self._close_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._close_buttons.clear()
        if not groups:
            self.close_hint.configure(text="No notable apps to manage.")
            return

        self.close_hint.configure(text="Smart groups — tap for advice + confirm:")
        for g in groups:
            n = len(g.pids)
            if g.risk == "protected":
                # On the user's never_close list — shown for awareness, never closable.
                label = f"[PROTECTED] {g.display_name} ×{n} ({g.memory_mb:.0f}MB)"
                btn = ctk.CTkButton(
                    self.close_panel,
                    text=label,
                    height=34,
                    command=lambda grp=g: self._explain_protected(grp),
                    fg_color=T.BG_DARK,
                    hover_color=T.BG_DARK,
                    text_color=T.TEXT_DIM,
                    font=T.FONT_BODY,
                    anchor="w",
                )
                btn.pack(fill="x", padx=6, pady=2)
                self._close_buttons.append(btn)
                continue
            if g.risk == "danger_active":
                color, prefix = T.DANGER, "USING"
            elif g.risk == "caution":
                color, prefix = T.WARNING, "LINKED"
            else:
                color, prefix = T.TEXT_DIM, "BACKGROUND"
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

    def _explain_protected(self, group: AppGroup) -> None:
        """Protected rows have no close affordance — tapping just explains why."""
        speak_async(
            f"{group.display_name} is protected. I will keep it running.",
            persona="jarvis",
        )
        self._append_log(f"[PROTECTED] {group.close_advice}")

    def _smart_close(self, group: AppGroup) -> None:
        """Show the options card. Close only after that choice passes both gates."""
        if group.risk == "protected" or group.is_active_work:
            self._explain_protected(group)
            return
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
            prompt = "Background work may still be active. Close this app?"
        ctk.CTkLabel(dlg, text=prompt, font=T.FONT_TAGLINE, text_color=T.WARNING).pack(
            padx=16, pady=(12, 8), anchor="w"
        )

        row = ctk.CTkFrame(dlg, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=16)

        def _choose(option_id: str) -> None:
            dlg.destroy()
            if option_id == "pause_close":
                speak_async(f"Closing {group.display_name} now.", persona="jarvis")
                self._execute_close_async(group, force=False)
                return
            try:
                finding = self._select_keep_on(group, option_id, force=False)
                message = finding.get("last_result") or option_id
            except Exception as exc:
                message = f"Could not apply that choice: {exc}"
                finding = {}
            self._append_log(f"[OPTIONS/{option_id}] {message}")
            if option_id == "keep_on":
                speak_async("Okay. I'll leave it and stay quiet next time it is really this app.", persona="jarvis")
            else:
                speak_async("Okay. Leaving it for now.", persona="jarvis")
            self.root.after(400, self._rebuild_close_panel)

        ctk.CTkButton(
            row, text="Keep on", width=120, command=lambda: _choose("keep_on"),
            fg_color=T.BORDER, hover_color=T.ACCENT_DIM,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            row, text="Not now", width=120, command=lambda: _choose("not_now"),
            fg_color=T.BORDER, hover_color=T.ACCENT_DIM,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            row, text="Yes, close it", width=140, command=lambda: _choose("pause_close"),
            fg_color=T.DANGER, hover_color=T.WARNING,
        ).pack(side="right", padx=4)

    def _select_keep_on(self, group: AppGroup, option_id: str, *, force: bool) -> dict:
        """One path: options-card selection, then Cortex, then the OS closer."""
        from agent.engine.handlers import HandlerContext, default_lookup
        from agent.engine.service import choose_for_app_group
        from agent.modules.resource_advisor import close_pids

        cfg = self._config if isinstance(self._config, dict) else {}
        never = never_close_from_config(cfg)

        def close(pid: int, name: str) -> tuple[bool, str]:
            return close_pids(
                list(group.pids) or [pid],
                list(group.process_names) or [name],
                force=force,
                identities=list(group.identities),
                observed_at=group.observed_at,
                never_close=never,
            )

        return choose_for_app_group(
            self._store,
            group,
            option_id,
            handler_ctx=HandlerContext(lookup=default_lookup, close=close),
        )

    def _issue_and_close(self, group: AppGroup, *, force: bool) -> tuple[bool, str]:
        """Smart Close shares the keep-on engine. There is no second Cortex-only path."""
        if group.is_active_work or group.risk == "protected":
            return False, "Refused: active or protected application; refresh the process list"
        finding = self._select_keep_on(group, "pause_close", force=force)
        message = str(finding.get("last_result") or "")
        return finding.get("resolution_status") == "resolved", message

    def _execute_close_async(self, group: AppGroup, *, force: bool) -> None:
        def work():
            try:
                ok, msg = self._issue_and_close(group, force=force)
                self._store.log_work("CLOSE_APP", msg)
            except Exception as exc:
                ok, msg = False, f"Close unavailable: {exc}"
            self._ui_events.put(lambda: self._close_result(group, force, ok, msg))
        threading.Thread(target=work, name="DVielle-Confirmed-Close", daemon=True).start()

    def _close_result(self, group: AppGroup, force: bool, ok: bool, msg: str) -> None:
        self._append_log(f"[ACTION/{'OK' if ok else 'HOLD'}] {msg}")
        if ok:
            speak_async(msg, persona="jarvis")
        elif not force and msg.startswith("Not closed"):
            self._prompt_force_close(group, msg)
        else:
            speak_async("The close request could not be completed. Review the recorded reason and refresh the app list.", persona="jarvis")
        self.root.after(400, self._rebuild_close_panel)

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
            self._execute_close_async(group, force=True)

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
                if len(self._seen_events) > 1000:
                    self._seen_events = {f"{e.get('ts')}{e.get('message')}" for e in self.controller.recent_events(100)}
                sev = ev.get("severity", "INFO")
                msg = ev.get("message", "")
                ts = ev.get("ts", "")[:19].replace("T", " ")
                self._append_log(f"[{ts}] [{sev}] {msg}")
                # Alerts are delivered once by the monitoring owner, not replayed from history.
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
        if self.controller.status.ownership in {"attached", "starting"}:
            return
        if self.controller.status.running:
            self.controller.stop()
            self._store.log_work("PAUSE_REQUEST", "Operator requested monitoring stop")
            self.status_label.configure(text="STOPPING", text_color=T.WARNING)
            self.vigilance_btn.configure(state="disabled")
        else:
            self.controller.start()
            self._agent_started = True
            self._store.log_work("RESUME_REQUEST", "Requested monitoring start or attachment")
            self.status_label.configure(text="CONNECTING", text_color=T.WARNING)
            self.vigilance_btn.configure(state="disabled")

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
