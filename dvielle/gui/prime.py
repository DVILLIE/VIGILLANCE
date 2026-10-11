"""Nexus Fold Prime surfaces, live readings, and decorative spatial illustration."""
from __future__ import annotations

import tkinter as tk
import math
import time
from pathlib import Path
from functools import lru_cache

import customtkinter as ctk
from PIL import Image, ImageTk

from dvielle.gui import theme as T
from dvielle.gui.presence import bounded_percent

ASSET = Path(__file__).resolve().parents[2] / "assets" / "theme" / "nexus-network.png"
PEARL = ("#EFF3F8", "#DFE7F1")
PEARL_INK = "#0B203B"
PEARL_MUTE = "#405873"


@lru_cache(maxsize=1)
def _network_artwork():
    try:
        with Image.open(ASSET) as source:
            return source.convert("RGB")
    except OSError:
        return None


class FoldPanel(ctk.CTkFrame):
    """Live widgets on a folded pearl surface; the artwork contains no UI text."""
    def __init__(self, master, height=570, **kwargs):
        super().__init__(master, fg_color=PEARL, height=height, corner_radius=18, **kwargs)
        self.pack_propagate(False)
        self.grid_propagate(False)
        self._fold_canvas = tk.Canvas(self, highlightthickness=0, bd=0)
        self._fold_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.body = ctk.CTkFrame(self, fg_color=PEARL, corner_radius=0)
        self.body.pack(fill="both", expand=True, padx=(18, 64), pady=(16, 32))
        self._fold_canvas.bind("<Configure>", self._render_fold)
        T.subscribe(self._on_theme)

    def _render_fold(self, _event=None):
        w, h = self._fold_canvas.winfo_width(), self._fold_canvas.winfo_height()
        bg = PEARL[0 if T.current_mode() == "light" else 1]
        self._fold_canvas.configure(bg=T.hex_color("void"))
        self._fold_canvas.delete("all")
        self._fold_canvas.create_polygon(0, 0, w-5, 0, w-35, h-62, w-65, h-32, 0, h-32,
                                         fill=bg, outline=bg)
        self._fold_canvas.create_polygon(w-5, 0, w, 0, w-22, h-48, w-50, h-16, w-65, h-32, w-35, h-62,
                                    fill="#BACADB", outline="#F5FAFF")
        self._fold_canvas.create_polygon(0, h-32, w-65, h-32, w-50, h-16, w, h, 0, h,
                                    fill="#C4D2E1", outline="#A6BBD1")
        self._fold_canvas.create_line(w-6, 10, w-36, h-64, fill="#D29B52", width=2)
        for offset in range(5, 27, 5):
            self._fold_canvas.create_line(12+offset, h-28, w-34, h-12+offset//3, fill="#AFC2D7")

    def _on_theme(self, _mode):
        self._render_fold()

    def destroy(self):
        T.unsubscribe(self._on_theme)
        super().destroy()


class MetricTile(ctk.CTkFrame):
    def __init__(self, master, title, **kwargs):
        super().__init__(master, width=120, fg_color="#F4F7FB", border_color="#B8CBE0",
                         border_width=1, corner_radius=12, **kwargs)
        ctk.CTkLabel(self, text=title, font=("Segoe UI", 14, "bold"),
                     text_color=PEARL_INK).pack(anchor="w", padx=12, pady=(10, 0))
        self.value = ctk.CTkLabel(self, text="—", font=("Consolas", 25, "bold"),
                                  text_color=PEARL_INK)
        self.value.pack(anchor="w", padx=12)
        self.detail = ctk.CTkLabel(self, text="Waiting for readings", font=("Segoe UI", 11),
                                   text_color=PEARL_MUTE)
        self.detail.pack(anchor="w", padx=12)
        self.bar = ctk.CTkProgressBar(self, width=70, height=4, fg_color="#CFDBE7", progress_color="#225E9D")
        self.bar.pack(fill="x", padx=12, pady=(8, 13))
        self.bar.set(0)

    def set_value(self, percent):
        numeric = bounded_percent(percent)
        self.value.configure(text="—" if numeric is None else f"{numeric:.0f}%")
        self.detail.configure(text="Waiting for readings" if numeric is None else "Current observation")
        self.bar.set(0 if numeric is None else numeric / 100)
        self.bar.configure(progress_color="#A32B43" if numeric is not None and numeric >= 90 else
                           "#8A5600" if numeric is not None and numeric >= 75 else "#225E9D")


class SpatialStage(ctk.CTkFrame):
    """Decorative devices with real observation labels. Hover is selection, not traffic."""
    POSITIONS = ((.50, .47), (.18, .575), (.82, .575), (.50, .80))

    def __init__(self, master, motion, height=410, **kwargs):
        super().__init__(master, fg_color="#06152D", height=height, corner_radius=12, **kwargs)
        self.pack_propagate(False)
        self.motion = motion
        self.nodes = tuple((name, "Unknown", "mute") for name in ("This PC", "Local", "Gateway", "DNS"))
        self._background = _network_artwork()
        self._photo = None
        self._size = None
        self._selected = -1
        self._resize_job = None
        self._vibration_job = None
        self._vibration_started = time.monotonic()
        self.canvas = tk.Canvas(self, bg="#06152D", bd=0, highlightthickness=0, takefocus=0)
        self.canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.canvas.bind("<Configure>", self._queue_resize)
        self.canvas.bind("<Motion>", self._hover)
        self.canvas.bind("<Leave>", lambda _e: self._select(-1))
        self.bind("<Map>", self._start_vibration, add="+")
        self.bind("<Unmap>", self._stop_vibration, add="+")

    def _start_vibration(self, _event=None):
        if self._vibration_job is None and self.winfo_viewable():
            self._vibrate()

    def _stop_vibration(self, _event=None):
        if self._vibration_job is not None:
            self.after_cancel(self._vibration_job)
            self._vibration_job = None

    def _vibrate(self):
        """Decorative energy tremor; does not imply measured network traffic."""
        self._vibration_job = None
        if not self.winfo_exists() or not self.winfo_viewable():
            return
        self.canvas.delete("link_vibration")
        if self.motion.enabled:
            w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
            t = time.monotonic() - self._vibration_started
            # Align with the luminous diamond connections in the selected artwork.
            anchors = ((.5,.34),(.19,.45),(.535,.655),(.88,.45))
            for edge in range(4):
                a, b = anchors[edge], anchors[(edge+1)%4]
                ax, ay, bx, by = a[0]*w, a[1]*h, b[0]*w, b[1]*h
                dx, dy = bx-ax, by-ay
                length = math.hypot(dx,dy) or 1
                points = []
                amplitude = min(7.5, h*.018)
                for step in range(41):
                    u = step/40
                    wave = math.sin(math.pi*u)*amplitude*(
                        .65*math.sin(u*48-t*24+edge)+.35*math.sin(u*83+t*31))
                    points.extend((ax+dx*u-dy/length*wave, ay+dy*u+dx/length*wave))
                for color, width in (("#11468A",7),("#167CFF",3),("#8ADEFF",1)):
                    self.canvas.create_line(*points, fill=color, width=width,
                                            tags="link_vibration")
            if self.canvas.find_withtag("node0"):
                self.canvas.tag_lower("link_vibration", "node0")
        self._vibration_job = self.after(40 if self.motion.enabled else 200, self._vibrate)

    def _queue_resize(self, _event=None):
        if self._resize_job is not None:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(60, self._render_stage)

    def _render_stage(self):
        self._resize_job = None
        w, h = max(1, self.canvas.winfo_width()), max(1, self.canvas.winfo_height())
        self.canvas.delete("all")
        if self._background is not None:
            if self._size != (w, h):
                self._photo = ImageTk.PhotoImage(self._background.resize((w, h), Image.Resampling.LANCZOS), master=self.canvas)
                self._size = (w, h)
            self.canvas.create_image(0, 0, image=self._photo, anchor="nw")
        else:
            # Missing decoration never prevents access to the actual readings.
            self.canvas.create_text(w/2, 24, text="Network relationships", fill="#DAEBFF", font=("Segoe UI", 16))
        scale = self._get_widget_scaling()
        for index, ((name, value, _tone), (x, y)) in enumerate(zip(self.nodes, self.POSITIONS)):
            px, py = w*x, h*y
            width = min(160*scale, w*.28)
            self.canvas.create_rectangle(px-width/2, py-5*scale, px+width/2, py+40*scale,
                                         fill="#081B35", outline="#173F66", tags=f"node{index}")
            self.canvas.create_text(px, py+6*scale, text=name, fill="#F3F8FF",
                                    font=("Segoe UI", round(13*scale), "bold"))
            self.canvas.create_text(px, py+26*scale, text=str(value)[:26], fill="#B5DAFF",
                                    font=("Consolas", round(11*scale)))
        self._paint_focus(1.0)

    def set_nodes(self, nodes):
        nodes = tuple(nodes)
        if nodes != self.nodes:
            self.nodes = nodes
            if self.winfo_exists():
                self._render_stage()

    def _hover(self, event):
        w, h = max(1, self.canvas.winfo_width()), max(1, self.canvas.winfo_height())
        nearest = min(range(4), key=lambda i: (event.x/w-self.POSITIONS[i][0])**2 +
                      (event.y/h-self.POSITIONS[i][1])**2)
        x, y = self.POSITIONS[nearest]
        self._select(nearest if abs(event.x/w-x) < .15 and abs(event.y/h-y) < .13 else -1)

    def _select(self, index):
        if index != self._selected:
            self._selected = index
            self.motion.tween((id(self), "focus"), self._paint_focus, 240)

    def _paint_focus(self, progress):
        for index in range(4):
            self.canvas.itemconfigure(f"node{index}", outline="#8BCBFF" if index == self._selected else "#173F66",
                                      fill="#123C65" if index == self._selected else "#081B35",
                                      width=1+3*progress if index == self._selected else 1)

    def destroy(self):
        self._stop_vibration()
        if self._resize_job is not None:
            self.after_cancel(self._resize_job)
        super().destroy()
