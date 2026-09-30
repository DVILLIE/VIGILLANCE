"""Clear Deck shell pieces — drawn instruments and page chrome, no motion."""

from __future__ import annotations

import customtkinter as ctk

from dvielle.gui import graphics as G
from dvielle.gui import theme as T
from dvielle.gui.presence import bounded_percent


def _photo(pair) -> ctk.CTkImage:
    light, dark = pair
    return ctk.CTkImage(light_image=light, dark_image=dark, size=light.size)

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
CARD_HEIGHT = 64

GLYPH_KIND = {
    "Noted": "noted",
    "Caution": "caution",
    "Needs a look": "look",
    "Settled": "settled",
}


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


class RingCard(ctk.CTkFrame):
    """Processor, memory, or disk as a still ring. The arc does not sweep."""

    def __init__(self, master, title: str, **kwargs) -> None:
        super().__init__(
            master,
            fg_color="transparent",
            width=G.RING_SIZE[0],
            height=G.RING_SIZE[1],
            **kwargs,
        )
        self.pack_propagate(False)
        self.title = title
        self._percent: float | None = None
        self._photo: ctk.CTkImage | None = None
        self._view = ctk.CTkLabel(self, text="")
        self._view.pack(anchor="w")
        self.set_value(None)

    def set_value(self, percent: float | None) -> None:
        numeric = bounded_percent(percent)
        if numeric == self._percent and self._photo is not None:
            return
        self._percent = numeric
        self._photo = _photo(G.ring_pair(self.title, numeric))
        self._view.configure(image=self._photo)


class StatusOrb(ctk.CTkLabel):
    """Header orb. The core color changes with state. It does not pulse."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, text="", **kwargs)
        self._tone = ""
        self._photo: ctk.CTkImage | None = None
        self.set_tone("warn")

    def set_tone(self, tone: str) -> None:
        if tone == self._tone and self._photo is not None:
            return
        self._tone = tone
        self._photo = _photo(G.orb_pair(tone))
        self.configure(image=self._photo)


class NetworkMap(ctk.CTkFrame):
    """Still link picture: this PC, local address, gateway, DNS."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(
            master,
            fg_color="transparent",
            width=G.MAP_SIZE[0],
            height=G.MAP_SIZE[1],
            **kwargs,
        )
        self.pack_propagate(False)
        self._key: tuple | None = None
        self._photo: ctk.CTkImage | None = None
        self._view = ctk.CTkLabel(self, text="")
        self._view.pack(anchor="w")
        self.set_nodes(
            (
                ("This PC", "here", "accent"),
                ("Local", "—", "mute"),
                ("Gateway", "—", "mute"),
                ("DNS", "—", "mute"),
            )
        )

    def set_nodes(self, nodes) -> None:
        key = tuple(nodes)
        if key == self._key and self._photo is not None:
            return
        self._key = key
        self._photo = _photo(G.map_pair(list(nodes)))
        self._view.configure(image=self._photo)


def nav_icon(name: str) -> ctk.CTkImage:
    return _photo(G.icon_pair(name))


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
        badge = ctk.CTkLabel(card, text="")
        badge._photo = _photo(G.glyph_pair(GLYPH_KIND.get(word, "noted")))
        badge.configure(image=badge._photo)
        badge.pack(side="left", padx=(10, 8))
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
