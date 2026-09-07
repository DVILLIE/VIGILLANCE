"""Chat window — Jarvis & KT with voice input and stats-aware replies."""

from __future__ import annotations

import threading
from typing import Callable

import customtkinter as ctk

from agent.chat.assistant import ChatAssistant
from dvielle.brand import apply_tk_window_icon
from dvielle.gui import theme as T
from dvielle.gui.voice import speak_async


class ChatWindow(ctk.CTkToplevel):
    def __init__(
        self,
        master,
        assistant: ChatAssistant,
        *,
        agent_started: Callable[[], bool],
        cycle_count: Callable[[], int],
        stats_provider: Callable[[], dict] | None = None,
    ) -> None:
        super().__init__(master)
        self.assistant = assistant
        self._agent_started = agent_started
        self._cycle_count = cycle_count
        self._stats_provider = stats_provider
        self._persona = ctk.StringVar(value="jarvis")
        self._busy = False

        self.title("DVielle Chat — Jarvis & KT")
        self.geometry("520x640")
        self.configure(fg_color=T.BG_DARK)
        self.minsize(440, 520)
        apply_tk_window_icon(self)

        top = ctk.CTkFrame(self, fg_color=T.BG_PANEL)
        top.pack(fill="x", padx=12, pady=(12, 6))

        ctk.CTkLabel(top, text="CHAT ASSISTANT", font=T.FONT_TITLE, text_color=T.ACCENT).pack(
            anchor="w", padx=12, pady=(10, 4)
        )
        ctk.CTkLabel(
            top,
            text="Jarvis (US) · KT (British) · reads your screen stats · web on voice only",
            font=T.FONT_TAGLINE,
            text_color=T.TEXT_DIM,
            wraplength=460,
        ).pack(anchor="w", padx=12, pady=(0, 8))

        persona_row = ctk.CTkFrame(top, fg_color="transparent")
        persona_row.pack(fill="x", padx=12, pady=(0, 10))
        ctk.CTkRadioButton(
            persona_row, text="Jarvis (US male)", variable=self._persona, value="jarvis",
            font=T.FONT_BODY, text_color=T.TEXT,
        ).pack(side="left", padx=(0, 16))
        ctk.CTkRadioButton(
            persona_row, text="KT (British female)", variable=self._persona, value="kt",
            font=T.FONT_BODY, text_color=T.TEXT,
        ).pack(side="left")

        self.log = ctk.CTkTextbox(
            self, font=T.FONT_MONO, fg_color=T.BG_PANEL, text_color=T.ACCENT_GLOW,
            border_color=T.BORDER, border_width=1,
        )
        self.log.pack(fill="both", expand=True, padx=12, pady=6)
        self.log.configure(state="disabled")

        self.status = ctk.CTkLabel(
            self, text="Tip: use 🎤 for web questions. Type for on-screen stats.",
            font=T.FONT_TAGLINE, text_color=T.TEXT_DIM, wraplength=480,
        )
        self.status.pack(anchor="w", padx=14)

        entry_row = ctk.CTkFrame(self, fg_color="transparent")
        entry_row.pack(fill="x", padx=12, pady=(4, 12))

        self.entry = ctk.CTkEntry(entry_row, placeholder_text="Ask about your stats…", font=T.FONT_BODY)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.entry.bind("<Return>", lambda _e: self._send_text())

        ctk.CTkButton(
            entry_row, text="🎤", width=40, command=self._send_voice,
            fg_color=T.BG_PANEL_ALT, hover_color=T.ACCENT_DIM,
        ).pack(side="left", padx=2)
        ctk.CTkButton(
            entry_row, text="Send", width=70, command=self._send_text,
            fg_color=T.ACCENT_DIM, hover_color=T.ACCENT, text_color=T.BG_DARK,
        ).pack(side="left", padx=2)

        self._append("system", "Jarvis & KT online. Ask 'how is my RAM?' or use 🎤 for web questions.")

    def _append(self, who: str, text: str) -> None:
        self.log.configure(state="normal")
        prefix = {"jarvis": "Jarvis", "kt": "KT", "you": "You", "system": "—"}.get(who, who)
        self.log.insert("end", f"{prefix}: {text}\n\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _send_text(self) -> None:
        if self._busy:
            return
        q = self.entry.get().strip()
        if not q:
            return
        self.entry.delete(0, "end")
        self._run_query(q, from_voice=False)

    def _send_voice(self) -> None:
        if self._busy:
            return
        self.status.configure(text="Listening… speak now")
        threading.Thread(target=self._listen_and_ask, daemon=True).start()

    def _listen_and_ask(self) -> None:
        text = self._recognize_speech()
        if not text:
            self.after(0, lambda: self.status.configure(text="Couldn't hear that — try again or type."))
            return
        self.after(0, lambda: self.entry.insert(0, text))
        self.after(0, lambda: self._run_query(text, from_voice=True))

    def _recognize_speech(self) -> str | None:
        try:
            import speech_recognition as sr

            r = sr.Recognizer()
            with sr.Microphone() as source:
                r.adjust_for_ambient_noise(source, duration=0.4)
                audio = r.listen(source, timeout=6, phrase_time_limit=12)
            return r.recognize_google(audio, language="en-US")
        except Exception as exc:
            logger_msg = str(exc)
            self.after(0, lambda: self._append("system", f"Voice input failed: {logger_msg}"))
            return None

    def _run_query(self, question: str, *, from_voice: bool) -> None:
        self._busy = True
        persona = self._persona.get()
        who = "you" if not from_voice else "you (voice)"
        self._append(who, question)
        self.status.configure(text="Thinking…")

        def work() -> None:
            stats = self._stats_provider() if self._stats_provider else None
            resp = self.assistant.ask(
                question,
                persona_id=persona,
                from_voice=from_voice,
                agent_started=self._agent_started(),
                cycle_count=self._cycle_count(),
                stats_override=stats,
            )
            self.after(0, lambda: self._show_reply(resp.text, resp.persona, resp.used_web))

        threading.Thread(target=work, daemon=True).start()

    def _show_reply(self, text: str, persona: str, used_web: bool) -> None:
        self._append(persona, text)
        speak_async(text, persona=persona)  # type: ignore[arg-type]
        note = " (web lookup used)" if used_web else ""
        self.status.configure(text=f"Reply spoken by {persona.upper()}{note}")
        self._busy = False
