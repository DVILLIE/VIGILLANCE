"""Free LLM backends — Ollama (local) with optional Groq via env."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("dvielle.chat.llm")


def ollama_available(model: str = "llama3.2") -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=2) as resp:
            data = json.loads(resp.read().decode())
        names = {m.get("name", "").split(":")[0] for m in data.get("models", [])}
        base = model.split(":")[0]
        return base in names or any(n.startswith(base) for n in names)
    except Exception:
        return False


def chat_completion(
    messages: list[dict[str, str]],
    *,
    model: str = "llama3.2",
    temperature: float = 0.4,
) -> str | None:
    text = _chat_ollama(messages, model=model, temperature=temperature)
    if text:
        return text
    return _chat_groq(messages, temperature=temperature)


def _chat_ollama(
    messages: list[dict[str, str]],
    *,
    model: str,
    temperature: float,
) -> str | None:
    payload = json.dumps(
        {"model": model, "messages": messages, "stream": False, "options": {"temperature": temperature}}
    ).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode())
        msg = data.get("message") or {}
        content = (msg.get("content") or "").strip()
        return content or None
    except Exception as exc:
        logger.debug("Ollama unavailable: %s", exc)
        return None


def _chat_groq(messages: list[dict[str, str]], *, temperature: float) -> str | None:
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return None
    model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
    payload = json.dumps(
        {"model": model, "messages": messages, "temperature": temperature}
    ).encode()
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data: dict[str, Any] = json.loads(resp.read().decode())
        choices = data.get("choices") or []
        if choices:
            return (choices[0].get("message") or {}).get("content", "").strip() or None
    except urllib.error.HTTPError as exc:
        logger.warning("Groq HTTP %s", exc.code)
    except Exception as exc:
        logger.warning("Groq failed: %s", exc)
    return None
