"""DVielle console — Clear Deck. Sidebar pages, cards, logo motion only."""

from __future__ import annotations

import queue
import sys
import threading
from pathlib import Path

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
from dvielle.brand import apply_tk_window_icon, configure_windows_app_identity
from dvielle.gui import theme as T
from dvielle.gui.attacks_window import AttacksWindow
from dvielle.gui.logo_mark import LogoMark
from dvielle.gui.network_panel import NetworkPanel
from dvielle.gui.notify_policy import set_minimized_to_tray
from dvielle.gui.observations import (
    activity_summary,
    collector_state,
    prevention_evidence_line,
    section_current,
    snapshot_fresh,
)
from dvielle.gui.presence import (
    ActivityTicker,
    ClockMono,
    MatrixRow,
    NerveRail,
    PressureGauge,
    ScanFeed,
)
from dvielle.gui.graphics import rule_pair
from dvielle.gui.shell import PAGES, FindingCards, NetworkMap, RingCard, StatusOrb, nav_icon
from dvielle.gui.theme_store import load_appearance, save_appearance
from dvielle.gui.tray import setup_tray
from dvielle.gui.voice import greet_on_startup, speak_async
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
        self._close_buttons: list[ctk.CTkButton] = []
        self._greeting_idx = 0
        self._seen_events: set[str] = set()
        self._last_network_key: str | None = None
        self._attacks_win: AttacksWindow | None = None
        self._why_win: WhyWindow | None = None
        self._mission_verbs = 0

        # Identity before first window (also set in __main__; safe to call twice).
        configure_windows_app_identity()

        T.install_day()
        T.apply(load_appearance(self.data_dir))
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
        self._tick_mission_presence()
        self._drain_ui()
        self.root.after(0, self._on_start_agent)

    def _open_store(self) -> AgentStore:
        data_dir = self.data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        return AgentStore(data_dir / "agent.db")

    def _build_ui(self) -> None:
        self._build_header()
        rule = ctk.CTkLabel(self.root, text="", height=3)
        light_rule, dark_rule = rule_pair()
        self._rule_photo = ctk.CTkImage(light_image=light_rule, dark_image=dark_rule, size=(1360, 3))
        rule.configure(image=self._rule_photo)
        rule.pack(fill="x")

        shell = ctk.CTkFrame(self.root, fg_color="transparent")
        shell.pack(fill="both", expand=True)

        self.nav = ctk.CTkFrame(shell, fg_color=T.BG_PANEL, width=220, corner_radius=0)
        self.nav.pack(side="left", fill="y")
        self.nav.pack_propagate(False)
        ctk.CTkLabel(
            self.nav, text="PAGES", font=T.FONT_TAGLINE, text_color=T.TEXT_DIM,
        ).pack(anchor="w", padx=18, pady=(16, 8))

        self.stage = ctk.CTkFrame(shell, fg_color="transparent")
        self.stage.pack(side="left", fill="both", expand=True, padx=20, pady=16)
        self.stage.grid_columnconfigure(0, weight=1)
        self.stage.grid_rowconfigure(0, weight=1)

        self._pages: dict[str, ctk.CTkScrollableFrame] = {}
        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        self._nav_marks: dict[str, ctk.CTkFrame] = {}
        for key, label in PAGES:
            self._add_nav(key, label)
            page = ctk.CTkScrollableFrame(self.stage, fg_color="transparent")
            self._pages[key] = page

        self._build_now_page(self._pages["now"])
        self._build_pc_page(self._pages["pc"])
        self._build_network_page(self._pages["network"])
        self._build_findings_page(self._pages["findings"])
        self._build_protection_page(self._pages["protection"])
        self._build_apps_page(self._pages["apps"])
        self._show_page("now")
        self._build_footer()

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self.root, fg_color=T.BG_PANEL, height=92, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.pack(side="left", fill="y", padx=(16, 8), pady=12)
        self.logo = LogoMark(brand, size=56)
        self.logo.pack(side="left")

        titles = ctk.CTkFrame(header, fg_color="transparent")
        titles.pack(side="left", fill="both", expand=True, pady=12)
        ctk.CTkLabel(
            titles, text=APP_NAME, font=T.FONT_DISPLAY, text_color=T.TEXT,
        ).pack(anchor="w")
        self.mission_lbl = ctk.CTkLabel(
            titles,
            text="",
            font=T.FONT_BODY,
            text_color=T.TEXT_DIM,
            wraplength=560,
            anchor="w",
            justify="left",
        )
        self.mission_lbl.pack(anchor="w")

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.pack(side="right", padx=16, pady=14)
        theme_row = ctk.CTkFrame(controls, fg_color="transparent")
        theme_row.pack(anchor="e")
        self.day_chip = ctk.CTkLabel(
            theme_row,
            text=f"Today · {T.current_motif()['name']}",
            font=T.FONT_TAGLINE,
            text_color=T.ACCENT,
        )
        self.day_chip.pack(side="left", padx=(0, 8))
        self.theme_dark = ctk.CTkButton(
            theme_row, text="Dark", width=76, height=32, corner_radius=8,
            font=T.FONT_TAGLINE, command=lambda: self._set_theme("dark"),
        )
        self.theme_dark.pack(side="left", padx=(0, 4))
        self.theme_light = ctk.CTkButton(
            theme_row, text="Light", width=76, height=32, corner_radius=8,
            font=T.FONT_TAGLINE, command=lambda: self._set_theme("light"),
        )
        self.theme_light.pack(side="left")
        self._paint_theme_buttons()

        status_row = ctk.CTkFrame(controls, fg_color="transparent")
        status_row.pack(anchor="e", pady=(8, 0))
        self.status_orb = StatusOrb(status_row)
        self.status_orb.pack(side="left", padx=(0, 8))
        self.status_label = ctk.CTkLabel(
            status_row, text="Connecting", font=T.FONT_BODY, text_color=T.TEXT,
        )
        self.status_label.pack(side="left", padx=(0, 8))
        self.start_btn = ctk.CTkButton(
            status_row,
            text="Start",
            font=T.FONT_BODY,
            width=168,
            height=32,
            corner_radius=8,
            fg_color=T.ACCENT,
            hover_color=T.ACCENT_DIM,
            text_color=T.ON_ACCENT,
            border_width=0,
            command=self._on_start_agent,
        )
        self.start_btn.pack(side="left")
        self.agent_status_lbl = ctk.CTkLabel(
            controls,
            text="Waiting for the monitoring agent",
            font=T.FONT_TAGLINE,
            text_color=T.TEXT_DIM,
        )
        self.agent_status_lbl.pack(anchor="e", pady=(4, 0))

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self.root, fg_color=T.BG_PANEL, height=56, corner_radius=0)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        left_footer = ctk.CTkFrame(footer, fg_color="transparent")
        left_footer.pack(side="left", padx=12, pady=8)
        ctk.CTkLabel(
            left_footer,
            text=f"v{VERSION}",
            font=T.FONT_TAGLINE,
            text_color=T.TEXT_DIM,
        ).pack(side="left", padx=(4, 8))
        ClockMono(left_footer).pack(side="left", padx=(0, 8))
        for text, cmd, role in (
            ("Work log", self._view_work_log, "panel_alt"),
            ("Why", self._open_why, "accent_dim"),
            ("Attacks", self._open_attacks, "crit"),
            ("Clear log", self._clear_work_log, "panel_alt"),
        ):
            if role == "accent_dim":
                text_color = T.ON_ACCENT
            elif role == "crit":
                text_color = T.ON_CRIT
            else:
                text_color = T.TEXT
            ctk.CTkButton(
                left_footer,
                text=text,
                width=110,
                height=34,
                corner_radius=8,
                command=cmd,
                fg_color=T.pair(role),
                hover_color=T.BORDER,
                text_color=text_color,
                font=T.FONT_TAGLINE,
            ).pack(side="left", padx=3)

        btn_frame = ctk.CTkFrame(footer, fg_color="transparent")
        btn_frame.pack(side="right", padx=12, pady=8)
        self.vigilance_btn = ctk.CTkButton(
            btn_frame,
            text="Pause",
            width=100,
            height=34,
            corner_radius=8,
            command=self._toggle_vigilance,
            fg_color=T.BORDER,
            state="disabled",
            font=T.FONT_TAGLINE,
        )
        self.vigilance_btn.pack(side="left", padx=3)
        ctk.CTkButton(
            btn_frame,
            text="Hide to tray",
            width=120,
            height=34,
            corner_radius=8,
            command=self._minimize_to_tray,
            fg_color=T.BG_PANEL_ALT,
            hover_color=T.BORDER,
            text_color=T.TEXT,
            font=T.FONT_TAGLINE,
        ).pack(side="left", padx=3)

    def _add_nav(self, key: str, label: str) -> None:
        row = ctk.CTkFrame(self.nav, fg_color="transparent", height=42)
        row.pack(fill="x", padx=10, pady=2)
        row.pack_propagate(False)
        mark = ctk.CTkFrame(row, width=4, fg_color=T.BG_PANEL, corner_radius=2)
        mark.pack(side="left", fill="y", pady=6)
        mark.pack_propagate(False)
        icon = nav_icon(key)
        button = ctk.CTkButton(
            row,
            text=label,
            image=icon,
            compound="left",
            anchor="w",
            height=42,
            corner_radius=8,
            font=T.FONT_BODY,
            fg_color="transparent",
            hover_color=T.BG_PANEL_ALT,
            text_color=T.TEXT_DIM,
            command=lambda name=key: self._show_page(name),
        )
        button._nav_icon = icon
        button.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self._nav_marks[key] = mark
        self._nav_buttons[key] = button

    def _show_page(self, key: str) -> None:
        for name, page in self._pages.items():
            if name == key:
                page.grid(row=0, column=0, sticky="nsew")
            else:
                page.grid_remove()
        for name, button in self._nav_buttons.items():
            selected = name == key
            button.configure(
                fg_color=T.BG_PANEL_ALT if selected else "transparent",
                text_color=T.TEXT if selected else T.TEXT_DIM,
            )
            self._nav_marks[name].configure(fg_color=T.ACCENT if selected else T.BG_PANEL)

    def _paint_theme_buttons(self) -> None:
        mode = T.current_mode()
        for name, button in (("dark", self.theme_dark), ("light", self.theme_light)):
            selected = name == mode
            button.configure(
                fg_color=T.ACCENT if selected else T.BG_PANEL_ALT,
                hover_color=T.ACCENT_DIM if selected else T.BORDER,
                text_color=T.ON_ACCENT if selected else T.TEXT,
            )

    def _set_theme(self, mode: str) -> None:
        if T.current_mode() != mode:
            T.apply(mode)
            save_appearance(self.data_dir, mode)
            self._store.log_work("THEME", f"Appearance set to {mode}")
        self._paint_theme_buttons()

    def _page_head(self, page, title: str, lede: str) -> None:
        ctk.CTkLabel(page, text=title, font=("Segoe UI", 26, "bold"), text_color=T.TEXT).pack(
            anchor="w", pady=(4, 0)
        )
        ctk.CTkLabel(
            page, text=lede, font=T.FONT_BODY, text_color=T.TEXT_DIM, wraplength=820, justify="left",
        ).pack(anchor="w", pady=(2, 8))

    def _build_now_page(self, page) -> None:
        self._page_head(
            page,
            "Now",
            "Rings show how busy this PC is. Notes are what was noticed.",
        )
        self.ticker = ActivityTicker(page)
        self.ticker.pack(fill="x", pady=(0, 6))

        stats = ctk.CTkFrame(page, fg_color="transparent")
        stats.pack(fill="x", pady=(0, 6))
        self.now_cpu = RingCard(stats, "Processor")
        self.now_cpu.pack(side="left", padx=(0, 8))
        self.now_mem = RingCard(stats, "Memory")
        self.now_mem.pack(side="left", padx=8)
        self.now_disk = RingCard(stats, "Disk")
        self.now_disk.pack(side="left", padx=(8, 0))
        self.link_map = NetworkMap(page)
        self.link_map.pack(fill="x", pady=(0, 6))

        notes = ctk.CTkFrame(page, fg_color="transparent")
        notes.pack(fill="x")
        ctk.CTkLabel(notes, text="Latest notes", font=T.FONT_TITLE, text_color=T.TEXT).pack(anchor="w", pady=(0, 8))
        self.finding_cards = FindingCards(notes, limit=3)
        self.finding_cards.pack(fill="x")

        ctk.CTkLabel(page, text="Checks", font=T.FONT_TITLE, text_color=T.TEXT).pack(anchor="w", pady=(8, 4))
        self.nerve_rail = NerveRail(page)
        self.nerve_rail.pack(fill="x", pady=(0, 8))

    def _build_pc_page(self, page) -> None:
        self._page_head(
            page,
            "This PC",
            "How busy the computer is. Memory is commit pressure, not a simple used-percent.",
        )
        self.cpu_gauge = PressureGauge(page, "Processor")
        self.cpu_gauge.pack(fill="x", pady=(0, 8))
        self.ram_gauge = PressureGauge(page, "Memory")
        self.ram_gauge.pack(fill="x", pady=8)
        self.disk_gauge = PressureGauge(page, "Disk")
        self.disk_gauge.pack(fill="x", pady=(8, 12))
        self.mem_detail_lbl = ctk.CTkLabel(
            page, text="memory: —", font=T.FONT_BODY, text_color=T.TEXT_DIM,
            wraplength=760, anchor="w", justify="left",
        )
        self.mem_detail_lbl.pack(anchor="w")
        self.budget_lbl = ctk.CTkLabel(
            page, text="VILL footprint: —", font=T.FONT_BODY, text_color=T.TEXT_DIM,
            wraplength=760, anchor="w", justify="left",
        )
        self.budget_lbl.pack(anchor="w", pady=(4, 0))
        self.cycle_lbl = ctk.CTkLabel(
            page, text="Agent cycles: 0", font=T.FONT_MONO, text_color=T.TEXT_DIM,
        )
        self.cycle_lbl.pack(anchor="w", pady=(8, 0))

    def _build_network_page(self, page) -> None:
        self._page_head(
            page,
            "Network",
            "Addresses and adapters DVielle can see. A VPN-like name is not proof of a private route.",
        )
        self.route_map = NetworkMap(page)
        self.route_map.pack(fill="x", pady=(0, 10))
        card = ctk.CTkFrame(page, fg_color=T.BG_PANEL, corner_radius=14, border_width=1, border_color=T.BORDER)
        card.pack(fill="both", expand=True)
        self.network_panel = NetworkPanel(card)
        self.network_panel.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_findings_page(self, page) -> None:
        self._page_head(
            page,
            "Findings",
            "The record of what was noticed. Cards on Now are the latest lines. This is the full list.",
        )
        card = ctk.CTkFrame(page, fg_color=T.BG_PANEL, corner_radius=14, border_width=1, border_color=T.BORDER)
        card.pack(fill="both", expand=True)
        self.scan_feed = ScanFeed(card)
        self.scan_feed.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_protection_page(self, page) -> None:
        self._page_head(
            page,
            "Protection",
            "What Windows protection looks like from here. A blank or unknown row is not a clean bill of health.",
        )
        self.evidence_lbl = ctk.CTkLabel(
            page,
            text="Prevention evidence unavailable.",
            font=T.FONT_BODY,
            text_color=T.TEXT_DIM,
            wraplength=820,
            justify="left",
            anchor="w",
        )
        self.evidence_lbl.pack(anchor="w", fill="x", pady=(0, 10))
        self._matrix_rows = {}
        for name in ("Defender", "Firewall", "Nerve", "Vision", "Pulse"):
            row = MatrixRow(page, name)
            row.pack(fill="x", pady=4)
            self._matrix_rows[name] = row
        self.jarvis_line = ctk.CTkLabel(
            page,
            text='"At your service."',
            font=T.FONT_ITALIC,
            text_color=T.ACCENT_DIM,
            wraplength=820,
        )
        self.jarvis_line.pack(anchor="w", pady=(16, 0))
        ctk.CTkButton(
            page,
            text="Replay greeting",
            width=180,
            height=36,
            corner_radius=8,
            command=self._replay_greeting,
            fg_color=T.BG_PANEL_ALT,
            text_color=T.TEXT,
        ).pack(anchor="w", pady=(8, 0))

    def _build_apps_page(self, page) -> None:
        self._page_head(
            page,
            "Apps",
            "Nothing closes by itself. You see the app, you pick an option, and only then can it close.",
        )
        steps = ctk.CTkFrame(page, fg_color="transparent")
        steps.pack(fill="x", pady=(0, 12))
        for index, (title, detail) in enumerate(
            (
                ("1  Noticed", "DVielle lists apps it can see."),
                ("2  You choose", "Keep it, not now, or close it."),
                ("3  Then it acts", "Close runs only after that choice."),
            ),
            start=0,
        ):
            card = ctk.CTkFrame(
                steps, fg_color=T.BG_PANEL, corner_radius=12, border_width=1, border_color=T.BORDER,
            )
            card.pack(side="left", fill="x", expand=True, padx=(0 if index == 0 else 8, 0))
            ctk.CTkLabel(card, text=title, font=T.FONT_BODY, text_color=T.TEXT).pack(anchor="w", padx=12, pady=(10, 0))
            ctk.CTkLabel(
                card, text=detail, font=T.FONT_TAGLINE, text_color=T.TEXT_DIM, wraplength=240, justify="left",
            ).pack(anchor="w", padx=12, pady=(2, 12))
        self.close_panel = ctk.CTkFrame(
            page, fg_color=T.BG_PANEL, corner_radius=14, border_width=1, border_color=T.BORDER,
        )
        self.close_panel.pack(fill="x")
        self.close_hint = ctk.CTkLabel(
            self.close_panel,
            text="Checking which apps are open…",
            font=T.FONT_BODY,
            text_color=T.TEXT_DIM,
            wraplength=760,
            justify="left",
        )
        self.close_hint.pack(anchor="w", padx=12, pady=12)

    def _apply_window_icon(self, window) -> None:
        """Standard DVielle .ico for title bar, taskbar, and child dialogs."""
        apply_tk_window_icon(window)

    def _on_start_agent(self) -> None:
        if self.controller.status.ownership in {"starting", "owner", "attached"}:
            return
        self._agent_started = True
        self.start_btn.configure(state="disabled", text="Connecting…")
        self.mission_lbl.configure(text="Connecting to the monitoring owner…")
        self._store.log_work("START_REQUEST", "Requested monitoring start or attachment")
        self.controller.start()

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

    def _paint_link_maps(self, net: dict | None) -> None:
        if net:
            local_ips = net.get("local_ips") or []
            dns = net.get("dns_servers") or []
            nodes = (
                ("This PC", str(net.get("hostname") or "here")[:22], "accent"),
                ("Local", str(local_ips[0]) if local_ips else "—", "ok" if local_ips else "mute"),
                ("Gateway", str(net.get("gateway") or "—")[:22], "accent" if net.get("gateway") else "mute"),
                ("DNS", str(dns[0]) if dns else "—", "ok" if dns else "mute"),
            )
        else:
            nodes = (
                ("This PC", "here", "accent"),
                ("Local", "—", "mute"),
                ("Gateway", "—", "mute"),
                ("DNS", "—", "mute"),
            )
        for name in ("link_map", "route_map"):
            widget = getattr(self, name, None)
            if widget is not None:
                widget.set_nodes(nodes)

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
            self._paint_link_maps(net if section_current(data, "network_info") else None)
        self.root.after(5000, self._refresh_network_async)

    def _replay_greeting(self) -> None:
        text = greet_on_startup()
        self.jarvis_line.configure(text=f'"{text}"')

    def _append_log(self, line: str) -> None:
        self.scan_feed.append(line)
        cards = getattr(self, "finding_cards", None)
        if cards is not None:
            cards.push(line)

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
        self.now_cpu.set_value(v["cpu"])
        self.now_mem.set_value(v["mem"])
        self.now_disk.set_value(v["disk"])
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
            contract = sb.get("cpu_contract") if isinstance(sb.get("cpu_contract"), dict) else {}
            if contract.get("scheduling_mode") == "measured":
                budget += " · measured scheduling"
            elif contract.get("scheduling_mode") == "job_hard_cap" and contract.get("job_cap_applied") is True:
                budget += " · job hard cap"
            rate = contract.get("analysis_cpu_rate")
            if isinstance(rate, int) and not isinstance(rate, bool):
                budget += f" · analysis CpuRate {rate}"
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
        evidence = prevention_evidence_line(data)
        evidence_lbl = getattr(self, "evidence_lbl", None)
        if evidence_lbl is not None:
            incomplete = (
                "coverage incomplete" in evidence
                or evidence.startswith("Prevention evidence stale")
                or evidence.startswith("Prevention evidence unavailable")
            )
            evidence_lbl.configure(text=evidence, text_color=T.WARNING if incomplete else T.ACCENT)

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

        defender_row = rows.get("Defender")
        if defender_row is not None:
            health = sec.get("defender_health") if isinstance(sec.get("defender_health"), dict) else {}
            if not security_current:
                defender_row.set_state(collector_state(data, "security").upper(), T.WARNING if collector_state(data, "security") == "partial" else T.TEXT_DIM)
            elif health.get("all_clear") is True and sec.get("defender_enabled") is True:
                defender_row.set_state("ACTIVE", T.SUCCESS)
            elif sec.get("defender_enabled") is False or sec.get("realtime_protection") is False:
                defender_row.set_state("OFF", T.DANGER)
            else:
                defender_row.set_state(str(health.get("overall") or "UNKNOWN"), T.WARNING)
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
        self.status_orb.set_tone("ok" if running else "warn")
        self.agent_status_lbl.configure(text=f"{status.ownership.upper()} · {status.message}", text_color=T.SUCCESS if running else T.WARNING)
        self.mission_lbl.configure(text=status.message)
        self.ticker.push(activity_summary(data))
        self.nerve_rail.set_states(data)
        if status.ownership == "attached":
            self.start_btn.configure(text="Attached", state="disabled")
            self.vigilance_btn.configure(text="Background owner", state="disabled")
            self.mission_lbl.configure(text=status.message + ". Pause is controlled by the background owner.")
        elif status.ownership == "owner":
            self.start_btn.configure(text="Monitoring", state="disabled")
            self.vigilance_btn.configure(text="Pause Agent", state="normal" if running else "disabled")
        elif status.ownership == "starting":
            self.start_btn.configure(text="Connecting…", state="disabled")
            self.vigilance_btn.configure(state="disabled")
        else:
            self.start_btn.configure(text="Start", state="normal")
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

        self.close_hint.configure(text="Choose an app. You will see options before anything closes.")
        for g in groups:
            n = len(g.pids)
            if g.risk == "protected":
                label = f"Protected  {g.display_name}  ×{n}  ({g.memory_mb:.0f} MB)"
                btn = self._close_choice(
                    label,
                    lambda grp=g: self._explain_protected(grp),
                    T.BORDER,
                    T.TEXT_DIM,
                )
                btn.pack(fill="x", padx=6, pady=2)
                self._close_buttons.append(btn)
                continue
            if g.risk == "danger_active":
                border, prefix = T.DANGER, "In use"
            elif g.risk == "caution":
                border, prefix = T.WARNING, "Linked"
            else:
                border, prefix = T.BORDER, "Background"
            label = f"{prefix}  {g.display_name}  ×{n}  ({g.memory_mb:.0f} MB)"
            btn = self._close_choice(
                label,
                lambda grp=g: self._smart_close(grp),
                border,
                T.TEXT,
            )
            btn.pack(fill="x", padx=6, pady=2)
            self._close_buttons.append(btn)

    def _close_choice(self, label: str, command, border, text_color) -> ctk.CTkButton:
        return ctk.CTkButton(
            self.close_panel,
            text=label,
            height=34,
            command=command,
            fg_color=T.BG_PANEL,
            hover_color=T.BORDER,
            text_color=text_color,
            border_color=border,
            border_width=2,
            font=T.FONT_BODY,
            anchor="w",
        )

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
            dlg, text=group.display_name, font=T.FONT_TITLE, text_color=T.ACCENT
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
            dlg, text=group.display_name, font=T.FONT_TITLE, text_color=T.ACCENT
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

    def _toggle_theme(self) -> None:
        nxt = "light" if T.current_mode() == "dark" else "dark"
        self._set_theme(nxt)

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
