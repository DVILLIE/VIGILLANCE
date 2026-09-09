"""Audit #2: network honesty — pending-DNS ≠ suspicious, signed-app downgrade,
cross-pulse dedup. Pure helpers + cached Authenticode check (mocked)."""

from __future__ import annotations

import time

from agent.modules import connections as C


# ---- _refine_suspicion (pure) --------------------------------------------

def test_refine_passthrough_when_not_suspicious():
    assert C._refine_suspicion(base_suspicious=False, hostname=None, within_grace=False, is_signed=False) == (False, "")


def test_refine_pending_dns_within_grace():
    s, note = C._refine_suspicion(base_suspicious=True, hostname=None, within_grace=True, is_signed=False)
    assert s is False and note == "pending_dns"


def test_refine_signed_downgrade_after_grace():
    s, note = C._refine_suspicion(base_suspicious=True, hostname=None, within_grace=False, is_signed=True)
    assert s is False and note == "signed_downgrade"


def test_refine_signed_downgrade_even_when_resolved():
    s, note = C._refine_suspicion(base_suspicious=True, hostname="host.example", within_grace=False, is_signed=True)
    assert s is False and note == "signed_downgrade"


def test_refine_still_review_when_unsigned_and_unresolved():
    s, note = C._refine_suspicion(base_suspicious=True, hostname=None, within_grace=False, is_signed=False)
    assert s is True and note == "review"


# ---- _within_resolve_grace (time-based) ----------------------------------

def test_grace_first_sighting_is_pending():
    C._first_unresolved_at.clear()
    assert C._within_resolve_grace("203.0.113.5", resolved=False) is True  # just started


def test_grace_expires_then_flaggable():
    C._first_unresolved_at.clear()
    C._first_unresolved_at["203.0.113.6"] = time.monotonic() - (C.GRACE_SECONDS + 10)
    assert C._within_resolve_grace("203.0.113.6", resolved=False) is False


def test_grace_cleared_on_resolution():
    C._first_unresolved_at.clear()
    C._within_resolve_grace("203.0.113.7", resolved=False)
    assert "203.0.113.7" in C._first_unresolved_at
    assert C._within_resolve_grace("203.0.113.7", resolved=True) is False
    assert "203.0.113.7" not in C._first_unresolved_at


# ---- _alert_cooldown_ok --------------------------------------------------

def test_cooldown_first_true_then_suppressed():
    C._alerted_at.clear()
    assert C._alert_cooldown_ok("review|1.2.3.4|app.exe") is True
    assert C._alert_cooldown_ok("review|1.2.3.4|app.exe") is False  # within TTL
    assert C._alert_cooldown_ok("review|5.6.7.8|other.exe") is True  # different key


# ---- _is_signed_valid (cached; Authenticode mocked) ----------------------

def test_is_signed_valid_none_path():
    assert C._is_signed_valid(None) is False


def test_is_signed_valid_valid_and_cached(tmp_path, monkeypatch):
    C._sig_cache.clear()
    exe = tmp_path / "signed.exe"
    exe.write_bytes(b"MZ...")
    calls = {"n": 0}

    def fake_ps(script, *, timeout, secondary=3.0):
        calls["n"] += 1
        return "Valid", False

    monkeypatch.setattr(C, "run_powershell", fake_ps)
    assert C._is_signed_valid(str(exe)) is True
    assert C._is_signed_valid(str(exe)) is True   # cached
    assert calls["n"] == 1                          # signature checked once


def test_is_signed_valid_unsigned(tmp_path, monkeypatch):
    C._sig_cache.clear()
    exe = tmp_path / "unsigned.exe"
    exe.write_bytes(b"MZ...")
    monkeypatch.setattr(C, "run_powershell", lambda *a, **k: ("NotSigned", False))
    assert C._is_signed_valid(str(exe)) is False


def test_is_signed_valid_recheck_on_mtime_change(tmp_path, monkeypatch):
    C._sig_cache.clear()
    exe = tmp_path / "app.exe"
    exe.write_bytes(b"one")
    monkeypatch.setattr(C, "run_powershell", lambda *a, **k: ("Valid", False))
    assert C._is_signed_valid(str(exe)) is True
    # Replace the binary (size+mtime change) -> new cache key -> re-check as unsigned.
    import os
    exe.write_bytes(b"different bytes now")
    os.utime(exe, (time.time() + 5, time.time() + 5))
    monkeypatch.setattr(C, "run_powershell", lambda *a, **k: ("NotSigned", False))
    assert C._is_signed_valid(str(exe)) is False
