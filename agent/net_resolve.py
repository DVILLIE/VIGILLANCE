"""Non-blocking reverse-DNS cache for the nerve loop.

socket.gethostbyaddr can block for seconds on IPs with no PTR record. On the
single nerve-loop thread that stalls heartbeat AND pulse together — a direct
self-budget breach (design law 5). This resolver never blocks the caller:
lookup(ip) returns a cached name (or None) immediately and resolves in the
background, so the answer is available on a later pulse. Serve-stale-while-
revalidate keeps values steady across pulses.
"""

from __future__ import annotations

import socket
import threading
import time

_TTL = 3600.0      # keep a resolved name for an hour
_NEG_TTL = 600.0   # remember a miss for 10 min before retrying
_TIMEOUT = 1.5     # per-lookup socket timeout (on the worker thread only)
_MAX_INFLIGHT = 8  # cap concurrent background resolves

_lock = threading.Lock()
_cache: dict[str, tuple[str | None, float]] = {}  # ip -> (host|None, expiry_monotonic)
_inflight: set[str] = set()


def _worker(ip: str) -> None:
    host: str | None = None
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_TIMEOUT)
        host, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        host = None
    finally:
        try:
            socket.setdefaulttimeout(old)
        except Exception:
            pass
    ttl = _TTL if host else _NEG_TTL
    with _lock:
        _cache[ip] = (host, time.monotonic() + ttl)
        _inflight.discard(ip)


def lookup(ip: str) -> str | None:
    """Cached hostname or None, immediately. Resolves in the background on miss/stale."""
    if not ip:
        return None
    now = time.monotonic()
    with _lock:
        entry = _cache.get(ip)
        fresh = entry is not None and entry[1] > now
        if fresh:
            return entry[0]
        if ip not in _inflight and len(_inflight) < _MAX_INFLIGHT:
            _inflight.add(ip)
            spawn = True
        else:
            spawn = False
    if spawn:
        threading.Thread(target=_worker, args=(ip,), name="dv-rdns", daemon=True).start()
    return entry[0] if entry else None  # serve stale while revalidating


def resolve_blocking(ip: str, timeout: float = _TIMEOUT) -> str | None:
    """Synchronous lookup for on-demand callers (e.g. the user clicks Investigate).

    NOT for the nerve loop — use lookup() there.
    """
    if not ip:
        return None
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None
    finally:
        try:
            socket.setdefaulttimeout(old)
        except Exception:
            pass
