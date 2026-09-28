"""C2: chat cloud LLM is off by default, opt-in only, and redacts network identity.

Locks the privacy contract:
- local Ollama is the only backend unless allow_cloud is explicitly True;
- with cloud disabled, the Groq path is never reached;
- when cloud is used, the machine's network fingerprint is scrubbed first;
- `used_cloud` propagates to ChatResponse so the UI can flag it.
"""

from __future__ import annotations

from agent.chat import llm
from agent.chat.assistant import ChatAssistant
from agent.chat.context import sensitive_values
from agent.chat.llm import chat_completion, redact_messages


STATS = {
    "agent_started": False,
    "agent_cycles": 0,
    "cpu_percent": 10,
    "ram_percent": 40,
    "ram_available_gb": 8.0,
    "disk_percent_used": 50,
    "disk_free_gb": 100,
    "hostname": "MY-LAPTOP",
    "local_ips": ["192.168.1.42"],
    "public_ip": "203.0.113.7",
    "vpn_active": True,
    "vpn_name": "WireGuard",
    "vpn_ip": "10.9.0.2",
    "dns_servers": ["1.1.1.1"],
    "gateway": "192.168.1.1",
}


# ---- sensitive_values / redaction ----------------------------------------

def test_sensitive_values_collects_fingerprint():
    vals = sensitive_values(STATS)
    for expected in ["MY-LAPTOP", "203.0.113.7", "10.9.0.2", "192.168.1.42", "1.1.1.1", "192.168.1.1"]:
        assert expected in vals
    # longest-first so replacement can't partially clobber
    assert vals == sorted(vals, key=len, reverse=True)


def test_sensitive_values_skips_unknown_and_none():
    vals = sensitive_values({"hostname": "unknown", "public_ip": None, "local_ips": [], "dns_servers": []})
    assert vals == []


def test_redact_messages_scrubs_every_secret():
    msgs = [{"role": "system", "content": "host MY-LAPTOP pub 203.0.113.7 gw 192.168.1.1"}]
    out = redact_messages(msgs, sensitive_values(STATS))
    body = out[0]["content"]
    assert "MY-LAPTOP" not in body
    assert "203.0.113.7" not in body
    assert "192.168.1.1" not in body
    assert "[redacted]" in body
    # original untouched
    assert "MY-LAPTOP" in msgs[0]["content"]


def test_redact_ip_with_port_even_when_absent_from_stats():
    msgs = [{"role": "user", "content": "connect 192.168.10.27:8080 and [2001:db8::1]:443"}]
    out = redact_messages(msgs, [])
    body = out[0]["content"]
    assert "192.168.10.27" not in body
    assert "2001:db8::1" not in body
    assert ":8080" not in body
    assert ":443" not in body
    assert body == "connect [redacted] and [redacted]"
    assert "192.168.10.27:8080" in msgs[0]["content"]


def test_redact_messages_no_secrets_is_noop():
    msgs = [{"role": "user", "content": "hello"}]
    assert redact_messages(msgs, None) is msgs


# ---- chat_completion backend gating --------------------------------------

def test_local_answer_returns_ollama_backend(monkeypatch):
    called = {"groq": False}
    monkeypatch.setattr(llm, "_chat_ollama", lambda *a, **k: "local reply")
    monkeypatch.setattr(llm, "_chat_groq", lambda *a, **k: called.__setitem__("groq", True) or "cloud")
    text, backend = chat_completion([{"role": "user", "content": "hi"}])
    assert (text, backend) == ("local reply", "ollama")
    assert called["groq"] is False  # cloud never touched when local answered


def test_cloud_not_reached_when_disabled(monkeypatch):
    called = {"groq": False}
    monkeypatch.setattr(llm, "_chat_ollama", lambda *a, **k: None)
    monkeypatch.setattr(llm, "_chat_groq", lambda *a, **k: called.__setitem__("groq", True) or "cloud")
    text, backend = chat_completion([{"role": "user", "content": "hi"}], allow_cloud=False)
    assert (text, backend) == (None, None)
    assert called["groq"] is False  # off by default


def test_cloud_used_when_enabled_and_payload_is_redacted(monkeypatch):
    seen = {}
    monkeypatch.setattr(llm, "_chat_ollama", lambda *a, **k: None)

    def fake_groq(messages, *, temperature):
        seen["messages"] = messages
        return "cloud reply"

    monkeypatch.setattr(llm, "_chat_groq", fake_groq)
    msgs = [{"role": "system", "content": "pub 203.0.113.7 host MY-LAPTOP"}]
    text, backend = chat_completion(
        msgs, allow_cloud=True, cloud_secrets=sensitive_values(STATS)
    )
    assert (text, backend) == ("cloud reply", "groq")
    sent = seen["messages"][0]["content"]
    assert "203.0.113.7" not in sent and "MY-LAPTOP" not in sent
    assert "[redacted]" in sent


# ---- assistant wiring ----------------------------------------------------

def test_from_config_defaults_are_offline():
    bot = ChatAssistant.from_config({})
    assert bot.allow_cloud is False
    assert bot.allow_cloud_raw is False
    assert bot.ollama_timeout == 5.0


def test_from_config_reads_flags():
    bot = ChatAssistant.from_config(
        {"chat": {"allow_cloud_llm": True, "allow_cloud_raw_context": True, "ollama_timeout_seconds": 3}}
    )
    assert bot.allow_cloud is True
    assert bot.allow_cloud_raw is True
    assert bot.ollama_timeout == 3.0


def test_assistant_offline_never_calls_cloud(monkeypatch):
    called = {"groq": False}
    monkeypatch.setattr(llm, "_chat_ollama", lambda *a, **k: None)
    monkeypatch.setattr(llm, "_chat_groq", lambda *a, **k: called.__setitem__("groq", True) or "cloud")
    bot = ChatAssistant.from_config({"chat": {"enabled": True}})  # cloud off
    resp = bot.ask("tell me a joke", persona_id="jarvis", stats_override=STATS)
    assert called["groq"] is False
    assert resp.used_cloud is False


def test_assistant_used_cloud_propagates(monkeypatch):
    monkeypatch.setattr(llm, "_chat_ollama", lambda *a, **k: None)
    monkeypatch.setattr(llm, "_chat_groq", lambda messages, *, temperature: "cloud reply")
    bot = ChatAssistant.from_config({"chat": {"enabled": True, "allow_cloud_llm": True}})
    resp = bot.ask("tell me a joke", persona_id="jarvis", stats_override=STATS)
    assert resp.used_cloud is True
    assert resp.used_llm is True
    assert resp.text == "cloud reply"
