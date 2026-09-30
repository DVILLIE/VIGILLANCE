"""Clear Deck shell pieces — cards and page chrome, no motion."""

from __future__ import annotations

import customtkinter as ctk

from dvielle.gui import theme as T
from dvielle.gui.presence import bounded_percent

# Pages in the left rail. Keys are stable; labels are plain English.
PAGES = (
    ("now", "Now"),
    ("pc", "This PC"),
    ("network", "Network"),
    ("findings", "Findings"),
    ("protection", "Protection"),
    ("apps", "Apps"),
)


# Short on purpose. A CTkFrame with pack_propagate(False) and no height
# keeps CustomTkinter's 200px default and pushes the checks off screen.
CARD_HEIGHT = 56


def line_status(line: str) -> tuple[str, tuple[str, str]]:
    """Plain severity word and color for a log line."""
    upper = line.upper()
    if any(word in upper for word in ("CRITICAL", "DANGER", "ERROR", "HOLD", " FAIL")):
        return "Needs a look", T.DANGER
    if any(word in upper for word in ("WARN", "PARTIAL", "CAUTION", "STALE")):
        return "Caution", T.WARNING
    if any(word in upper for word in ("RESOLVED", " ACTIVE", "[OK]")):
        return "Settled", T.SUCCESS
    return "Noted", T.ACCENT


def line_tone(line: str):
    """Severity color for a log line. Unknown lines stay on the accent."""
    return line_status(line)[1]


class NumberCard(ctk.CTkFrame):
    """Compact figure for the Now page. The matching bar lives on This PC."""

    def __init__(self, master, title: str, **kwargs) -> None:
        super().__init__(
            master,
            fg_color=T.BG_PANEL,
            corner_radius=14,
            border_width=1,
            border_color=T.BORDER,
            **kwargs,
        )
        self.pip = ctk.CTkFrame(self, fg_color=T.ACCENT, width=8, height=8, corner_radius=4)
        self.pip.place(x=16, y=16)
        ctk.CTkLabel(
            self, text=title, font=T.FONT_TAGLINE, text_color=T.TEXT_DIM,
        ).pack(anchor="w", padx=(32, 16), pady=(12, 0))
        self.value = ctk.CTkLabel(
            self, text="—", font=("Segoe UI", 36, "bold"), text_color=T.TEXT,
        )
        self.value.pack(anchor="w", padx=16, pady=(0, 14))

    def set_value(self, percent: float | None) -> None:
        numeric = bounded_percent(percent)
        if numeric is None:
            self.value.configure(text="—", text_color=T.TEXT_DIM)
            self.pip.configure(fg_color=T.BORDER)
            return
        tone = "crit" if numeric >= 90 else "warn" if numeric >= 75 else "accent"
        self.value.configure(text=f"{numeric:.0f}", text_color=T.pair(tone))
        self.pip.configure(fg_color=T.pair(tone))


class FindingCards(ctk.CTkFrame):
    """Latest notes as cards. Older lines stay in the record, not as widgets."""

    def __init__(self, master, limit: int = 4, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.limit = limit
        self._cards: list[ctk.CTkFrame] = []

    def push(self, line: str) -> None:
        word, tone = line_status(line)
        card = ctk.CTkFrame(
            self,
            fg_color=T.BG_PANEL,
            corner_radius=12,
            border_width=1,
            border_color=T.BORDER,
            height=CARD_HEIGHT,
        )
        card.pack_propagate(False)
        stripe = ctk.CTkFrame(card, fg_color=tone, width=8, height=CARD_HEIGHT, corner_radius=0)
        stripe.pack(side="left", fill="y")
        stripe.pack_propagate(False)
        ctk.CTkLabel(
            card,
            text=word,
            font=("Segoe UI", 13, "bold"),
            text_color=tone,
            width=118,
            anchor="w",
        ).pack(side="left", padx=(14, 8))
        ctk.CTkLabel(
            card,
            text=line.strip()[:180],
            font=T.FONT_BODY,
            text_color=T.TEXT,
            anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=(0, 14))
        if self._cards:
            card.pack(fill="x", pady=(0, 8), before=self._cards[0])
        else:
            card.pack(fill="x", pady=(0, 8))
        self._cards.insert(0, card)
        while len(self._cards) > self.limit:
            self._cards.pop().destroy()
