"""Non-blocking reverse-DNS cache for the nerve loop.

socket.gethostbyaddr can block for seconds on IPs with no PTR record. On the
single nerve-loop thread that stalls heartbeat AND pulse together — a direct
self-budget breach (design law 5). This resolver never blocks the caller:
lookup(ip) returns a cached name (or None) immediately and resolves in the
background, so the answer is available on a later pulse. Serve-stale-while-
revalidate keeps values steady across pulses.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time

_TTL = 3600.0      # keep a resolved name for an hour
_NEG_TTL = 600.0   # remember a miss for 10 min before retrying
_TIMEOUT = 1.5     # maximum caller wait; OS resolver calls cannot be cancelled
_MAX_INFLIGHT = 8  # cap concurrent background resolves
_MAX_CACHE = 1024

_lock = threading.Lock()
_cache: dict[str, tuple[str | None, float]] = {}  # ip -> (host|None, expiry_monotonic)
_inflight: set[str] = set()
_completed: dict[str, threading.Event] = {}


def _cache_result_locked(ip: str, host: str | None) -> None:
    now = time.monotonic()
    for key, (_, expiry) in list(_cache.items()):
        if expiry <= now:
            _cache.pop(key, None)
    _cache.pop(ip, None)
    while len(_cache) >= _MAX_CACHE:
        _cache.pop(next(iter(_cache)))
    _cache[ip] = (host, now + (_TTL if host else _NEG_TTL))


def _worker(ip: str) -> None:
    host: str | None = None
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        host = None
    with _lock:
        _cache_result_locked(ip, host)
        _inflight.discard(ip)
        done = _completed.pop(ip, None)
        if done:
            done.set()


def lookup(ip: str) -> str | None:
    """Cached hostname or None, immediately. Resolves in the background on miss/stale."""
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    now = time.monotonic()
    with _lock:
        entry = _cache.get(ip)
        fresh = entry is not None and entry[1] > now
        if fresh:
            return entry[0]
        if ip not in _inflight and len(_inflight) < _MAX_INFLIGHT:
            _inflight.add(ip)
            _completed[ip] = threading.Event()
            spawn = True
        else:
            spawn = False
    if spawn:
        try:
            threading.Thread(target=_worker, args=(ip,), name="dv-rdns", daemon=True).start()
        except RuntimeError:
            with _lock:
                _inflight.discard(ip)
                done = _completed.pop(ip, None)
                if done:
                    done.set()
    return entry[0] if entry else None  # serve stale while revalidating


def resolve_blocking(ip: str, timeout: float = _TIMEOUT) -> str | None:
    """Synchronous lookup for on-demand callers (e.g. the user clicks Investigate).

    NOT for the nerve loop — use lookup() there.
    """
    # Share the bounded worker pool. A slow OS resolver can occupy a slot, but
    # cannot alter socket behavior in unrelated collectors or stall this caller.
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    value = lookup(ip)
    if value:
        return value
    with _lock:
        done = _completed.get(ip)
    if done:
        done.wait(max(0.0, min(float(timeout), 5.0)))
    with _lock:
        entry = _cache.get(ip)
        return entry[0] if entry else None
