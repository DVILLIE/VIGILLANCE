# Chat assistant — removed

**Status:** removed in 2.3.3. This is not deferred work, and there is no resume plan.

The console has no Chat control. `dvielle/gui/chat_window.py` and the `agent/chat/` package are gone. `config/config.yaml` has no `chat:` block. The `chat` extra (`duckduckgo-search`, `SpeechRecognition`) is gone.

Console voice for close and confirm stays in `dvielle/gui/voice.py` (`speak_async`, `greet_on_startup`). On Windows that path uses `pyttsx3` from the `windows` extra. It is not a chat assistant.

The browser snapshot viewer did not mount a chat panel. The unused demo chat sources were removed with this change.
