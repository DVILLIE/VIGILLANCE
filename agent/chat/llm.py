"""Free LLM backends — Ollama (local, on-device) with an OPT-IN Groq cloud path.

Privacy contract (audit C2):
- Local Ollama (127.0.0.1) is the only backend used by default.
- The Groq cloud path runs ONLY when the caller passes allow_cloud=True (wired
  from config `chat.allow_cloud_llm`, default false) AND GROQ_API_KEY is set.
- Before any cloud send, the machine's network identity is redacted from the
  payload unless the caller explicitly opts into raw context (cloud_secrets=None).
- chat_completion returns (text, backend) so callers can surface that the answer
  came from the cloud.
"""

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


def redact_messages(
    messages: list[dict[str, str]], secrets: list[str] | None
) -> list[dict[str, str]]:
    """Return a copy of messages with each secret string replaced by [redacted].

    Never mutates the input (the un-redacted messages are still used for the
    on-device Ollama call and for chat history).
    """
    if not secrets:
        return messages
    out: list[dict[str, str]] = []
    for msg in messages:
        content = msg.get("content", "")
        for secret in secrets:
            if secret:
                content = content.replace(secret, "[redacted]")
        out.append({**msg, "content": content})
    return out


def chat_completion(
    messages: list[dict[str, str]],
    *,
    model: str = "llama3.2",
    temperature: float = 0.4,
    allow_cloud: bool = False,
    cloud_secrets: list[str] | None = None,
    ollama_timeout: float = 5.0,
) -> tuple[str | None, str | None]:
    """Return (text, backend). backend is "ollama", "groq", or None.

    Cloud (Groq) is attempted only when local Ollama yields nothing AND
    allow_cloud is True. When cloud is used, cloud_secrets (if provided) are
    scrubbed from the outbound payload first.
    """
    text = _chat_ollama(messages, model=model, temperature=temperature, timeout=ollama_timeout)
    if text:
        return text, "ollama"
    if not allow_cloud:
        return None, None
    payload = redact_messages(messages, cloud_secrets)
    text = _chat_groq(payload, temperature=temperature)
    return (text, "groq") if text else (None, None)


def _chat_ollama(
    messages: list[dict[str, str]],
    *,
    model: str,
    temperature: float,
    timeout: float = 5.0,
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
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
