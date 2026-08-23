"""Network / VPN status panel for DVielle GUI."""

from __future__ import annotations

import customtkinter as ctk

from agent.modules.network_info import NetworkSnapshot
from dvielle.gui import theme as T


class NetworkPanel(ctk.CTkFrame):
    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=6, **kwargs)
        self._labels: dict[str, ctk.CTkLabel] = {}
        fields = [
            ("local", "Local IP"),
            ("public", "Public IP"),
            ("vpn", "VPN Status"),
            ("vpn_ip", "VPN IP"),
            ("dns", "DNS Servers"),
            ("gateway", "Gateway"),
        ]
        for key, title in fields:
            row = ctk.CTkFrame(self, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=2)
            ctk.CTkLabel(row, text=title, font=T.FONT_BODY, text_color=T.TEXT_DIM, width=110, anchor="w").pack(side="left")
            lbl = ctk.CTkLabel(row, text="—", font=T.FONT_MONO, text_color=T.TEXT, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            self._labels[key] = lbl

        self._labels["vpn"].configure(text_color=T.TEXT_DIM)

    def update_snapshot(self, snap: NetworkSnapshot | None) -> None:
        if snap is None:
            for lbl in self._labels.values():
                lbl.configure(text="—")
            return

        local = ", ".join(snap.local_ips[:3]) if snap.local_ips else "—"
        self._labels["local"].configure(text=local)
        self._labels["public"].configure(text=snap.public_ip or "—")

        if snap.vpn_active:
            self._labels["vpn"].configure(
                text=f"ACTIVE ({snap.vpn_adapter or 'detected'})",
                text_color=T.SUCCESS,
            )
            self._labels["vpn_ip"].configure(text=snap.vpn_ip or snap.public_ip or "—")
        else:
            self._labels["vpn"].configure(text="NOT DETECTED", text_color=T.TEXT_DIM)
            self._labels["vpn_ip"].configure(text="—")

        dns = ", ".join(snap.dns_servers[:4]) if snap.dns_servers else "—"
        self._labels["dns"].configure(text=dns)
        self._labels["gateway"].configure(text=snap.gateway or "—")
