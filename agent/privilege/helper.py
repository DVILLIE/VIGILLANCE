"""Explicit, non-privileged test harness; no deployable privileged service.

A bearer token over loopback is not an OS-authenticated approval boundary.
Production dispatch is refused, and this harness refuses elevated tokens.
The future service must authenticate callers and check protected, expiring,
single-use authorization server-side before any privileged operation.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import threading
from pathlib import Path
from typing import Any, Callable

from agent.cpu_contract import MEASURED_NOTE, try_assign_current_process
from agent.modules.firewall_apply import apply_scope, apply_verified
from agent.ownership import atomic_json
from agent.privilege.contract import DEFINED_OP, LOOPBACK_HOST, PROTOCOL_VERSION, undefined_op, validate_restrict_params

Runner = Callable[[str], tuple[str | None, bool]]
_MAX_BYTES = 65536
_ENVELOPE_KEYS = frozenset({"v", "op", "token", "params"})


def _is_elevated() -> bool:
    """Check the effective Windows token; unavailable checks fail closed."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError, TypeError, ValueError):
        return True


def _body(ok: bool, code: str, message: str, *, performed: bool = False) -> dict[str, Any]:
    return {"ok": ok, "code": code, "performed": performed, "message": message, "verified": []}


def dispatch(
    envelope: object, *, runner: Runner, expected_token: str, test_harness: bool = False
) -> dict[str, Any]:
    """Refuse undefined work. The one defined operation re-checks every parameter."""
    if not isinstance(envelope, dict) or set(envelope) - _ENVELOPE_KEYS:
        return _body(False, "bad_params", "The helper request was not a versioned object. Nothing was changed.")
    if type(envelope.get("v")) is not int or envelope.get("v") != PROTOCOL_VERSION:
        return _body(False, "bad_params", "The helper request version is not supported. Nothing was changed.")
    op = envelope.get("op")
    if undefined_op(op):
        return _body(
            False,
            "undefined_op",
            "That operation is not defined on the privileged helper. Nothing was changed.",
        )
    token = envelope.get("token")
    try:
        token_ok = isinstance(token, str) and hmac.compare_digest(token, expected_token)
    except (TypeError, ValueError):
        token_ok = False
    if not token_ok:
        return _body(False, "refused", "The helper token did not match. Nothing was changed.")
    if op != DEFINED_OP:
        return _body(False, "undefined_op", "That operation is not defined on the privileged helper. Nothing was changed.")
    checked, error = validate_restrict_params(envelope.get("params"))
    if checked is None:
        return _body(False, "bad_params", error + " Nothing was changed.")
    if not test_harness or _is_elevated():
        return _body(False, "service_unavailable", "The authenticated privileged service is not implemented. Nothing was changed.")
    try:
        with apply_scope():
            return apply_verified(checked, runner)
    except Exception:
        # An adapter may have partially acted before failing. Never claim undo.
        return _body(False, "outcome_unknown", "The test adapter failed. Its outcome is unknown; inspect the adapter state.")


class LoopbackHelper:
    """Opt-in unit adapter transport. Never an elevated mutation service."""

    def __init__(self, runner: Runner, *, test_harness: bool = False, assign_job: bool = False) -> None:
        if not test_harness or _is_elevated():
            raise RuntimeError("LoopbackHelper is an explicit non-privileged test harness, not a privileged service.")
        self.runner = runner
        self.token = secrets.token_hex(32)
        # Tests leave this off so a Windows CI process is not hard-capped.
        # The stub's main() opts in for the helper process only.
        self.job = (
            try_assign_current_process()
            if assign_job
            else {"applied": False, "reason": MEASURED_NOTE}
        )
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((LOOPBACK_HOST, 0))
        self._sock.listen(8)
        self.port = int(self._sock.getsockname()[1])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="dvielle-helper", daemon=True)
        self._thread.start()

    def endpoint(self) -> dict[str, Any]:
        return {"host": LOOPBACK_HOST, "port": self.port, "token": self.token, "job_cap_applied": self.job["applied"], "test_harness": True, "privileged_service": False}

    def write_endpoint(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, self.endpoint())

    def _serve(self) -> None:
        while not self._stop.is_set():
            self._sock.settimeout(0.2)
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                continue
            with conn:
                data = b""
                conn.settimeout(2.0)
                try:
                    while b"\n" not in data and len(data) <= _MAX_BYTES:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except OSError:
                    continue
                if len(data) > _MAX_BYTES:
                    response = _body(False, "bad_params", "The helper request was too large. Nothing was changed.")
                    try:
                        conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                    except OSError:
                        pass
                    continue
                line = data.split(b"\n", 1)[0]
                try:
                    envelope = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError, RecursionError):
                    response = _body(False, "bad_params", "The helper request was not JSON. Nothing was changed.")
                else:
                    response = dispatch(envelope, runner=self.runner, expected_token=self.token, test_harness=True)
                try:
                    conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                except OSError:
                    continue

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def main(argv: list[str] | None = None) -> int:
    """Fail closed: no command-line launcher for a token-only mutation server."""
    print("D\'Vielle's authenticated privileged service is not implemented. No listener was started.")
    return 2
