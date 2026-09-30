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
        self._observation = ctk.CTkLabel(self, text="Observations pending", font=T.FONT_TAGLINE, text_color=T.TEXT_DIM)
        self._observation.pack(anchor="w", padx=8, pady=(4, 8))

    def set_observation_state(self, state: str, sampled_at: str | None) -> None:
        stamp = f" · sampled {sampled_at[:19]} UTC" if sampled_at else ""
        tone = {
            "ok": T.SUCCESS,
            "partial": T.WARNING,
            "stale": T.WARNING,
            "deferred": T.WARNING,
            "error": T.DANGER,
        }.get(state, T.TEXT_DIM)
        self._observation.configure(text=f"{state.upper()}{stamp}", text_color=tone)

    def update_snapshot(self, snap: NetworkSnapshot | None) -> None:
        if snap is None:
            for lbl in self._labels.values():
                lbl.configure(text="—")
            return

        local = ", ".join(snap.local_ips[:3]) if snap.local_ips else "—"
        self._labels["local"].configure(text=local)
        self._labels["public"].configure(text=snap.public_ip or ("Unavailable" if snap.public_ip_lookup_enabled else "Lookup disabled"))

        if snap.vpn_active:
            self._labels["vpn"].configure(
                text=f"Adapter up ({snap.vpn_adapter or 'VPN-like'}); route unverified",
                text_color=T.WARNING,
            )
            self._labels["vpn_ip"].configure(text=snap.vpn_ip or "—")
        else:
            self._labels["vpn"].configure(text="No VPN-like adapter detected; route unverified", text_color=T.TEXT_DIM)
            self._labels["vpn_ip"].configure(text="—")

        dns_state = getattr(snap, "dns_observation", "ok")
        gateway_state = getattr(snap, "gateway_observation", "ok")
        if dns_state != "ok":
            dns = dns_state
        else:
            dns = ", ".join(snap.dns_servers[:4]) if snap.dns_servers else "none observed"
        if gateway_state != "ok":
            gateway = gateway_state
        else:
            gateway = snap.gateway or "none observed"
        self._labels["dns"].configure(text=dns)
        self._labels["gateway"].configure(text=gateway)
