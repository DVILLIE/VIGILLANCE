"""Privileged helper stub.

This is not a Windows service and it does not change the resident scheduled
task. It binds 127.0.0.1, requires a per-start token, and dispatches only
``restrict_network``. Undefined operations never reach a firewall cmdlet.

A later service should replace this loopback stub with the named pipe in
``contract.PIPE_NAME`` and an ACL limited to the installed user. Do not elevate
the Limited scheduled task to Highest to avoid building that service.
"""

from __future__ import annotations

import hmac
import json
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


def _body(ok: bool, code: str, message: str, *, performed: bool = False) -> dict[str, Any]:
    return {"ok": ok, "code": code, "performed": performed, "message": message, "verified": []}


def dispatch(envelope: object, *, runner: Runner, expected_token: str) -> dict[str, Any]:
    """Refuse undefined work. The one defined operation re-checks every parameter."""
    if not isinstance(envelope, dict) or set(envelope) - _ENVELOPE_KEYS:
        return _body(False, "bad_params", "The helper request was not a versioned object. Nothing was changed.")
    if envelope.get("v") != PROTOCOL_VERSION:
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
    with apply_scope():
        return apply_verified(checked, runner)


class LoopbackHelper:
    """Smallest process split that CI can run: one loopback listener, one op."""

    def __init__(self, runner: Runner, *, assign_job: bool = False) -> None:
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
        return {"host": LOOPBACK_HOST, "port": self.port, "token": self.token, "job_cap_applied": self.job["applied"]}

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
                line = data.split(b"\n", 1)[0]
                try:
                    envelope = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    response = _body(False, "bad_params", "The helper request was not JSON. Nothing was changed.")
                else:
                    response = dispatch(envelope, runner=self.runner, expected_token=self.token)
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
    """Run the stub until interrupted. Writes an endpoint file the Limited agent can read."""
    import argparse

    from agent.utils import IS_WINDOWS, run_powershell

    parser = argparse.ArgumentParser(description="DVielle privileged helper stub")
    parser.add_argument("--endpoint-file", required=True)
    args = parser.parse_args(argv)

    def runner(script: str) -> tuple[str | None, bool]:
        if not IS_WINDOWS:
            return None, False
        return run_powershell(script, timeout=30)

    helper = LoopbackHelper(runner, assign_job=True)
    helper.write_endpoint(Path(args.endpoint_file))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        return 0
    finally:
        helper.close()
    return 0
