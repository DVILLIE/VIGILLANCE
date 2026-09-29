"""Limited-side client for the privileged helper.

Sends one checked ``restrict_network`` request over the loopback IPC stub.
Does not run firewall cmdlets. If the helper is not listening, nothing is changed.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from agent.policy.dual import cortex_mutate_active
from agent.privilege.contract import DEFINED_OP, LOOPBACK_HOST, PROTOCOL_VERSION, validate_restrict_params

_MAX_BYTES = 65536


def _refused(message: str, *, code: str) -> dict[str, Any]:
    return {"ok": False, "code": code, "performed": False, "message": message, "verified": []}


def discover_endpoint(data_dir: Path) -> dict[str, Any] | None:
    """Read a helper endpoint file. Non-loopback hosts are ignored."""
    path = Path(data_dir) / "helper_endpoint.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return _endpoint_ok(payload)


def _endpoint_ok(payload: object) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    host = payload.get("host")
    port = payload.get("port")
    token = payload.get("token")
    if host != LOOPBACK_HOST or isinstance(port, bool) or not isinstance(port, int):
        return None
    if port < 1 or port > 65535:
        return None
    if not isinstance(token, str) or len(token) < 32 or any(ch not in "0123456789abcdef" for ch in token):
        return None
    return {"host": host, "port": port, "token": token}


def _exchange(endpoint: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    blob = json.dumps(envelope, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(blob) > _MAX_BYTES:
        return _refused("The firewall request was too large. Nothing was changed.", code="bad_params")
    try:
        with socket.create_connection((endpoint["host"], endpoint["port"]), timeout=2.0) as sock:
            sock.settimeout(30.0)
            sock.sendall(blob)
            data = b""
            while b"\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > _MAX_BYTES:
                    break
    except OSError:
        return _refused(
            "The privileged helper is not available. DVielle did not add a firewall rule. Traffic was not stopped.",
            code="helper_unavailable",
        )
    line = data.split(b"\n", 1)[0]
    try:
        body = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _refused(
            "The privileged helper returned an unreadable result. DVielle did not add a firewall rule. Traffic was not stopped.",
            code="helper_unavailable",
        )
    if not isinstance(body, dict):
        return _refused(
            "The privileged helper returned an unreadable result. DVielle did not add a firewall rule. Traffic was not stopped.",
            code="helper_unavailable",
        )
    return body


def submit_restrict_network(
    params: dict[str, Any],
    *,
    endpoint: dict[str, Any] | None,
) -> dict[str, Any]:
    """Validate, require the dual-gate mutate context, then ask the helper."""
    checked, error = validate_restrict_params(params)
    if checked is None:
        return _refused(
            error + " DVielle did not add a firewall rule. Traffic was not stopped.",
            code="bad_params",
        )
    if not cortex_mutate_active():
        return _refused(
            "Refusing a firewall change without Cortex authorization. DVielle did not add a firewall rule. Traffic was not stopped.",
            code="refused",
        )
    target = _endpoint_ok(endpoint) if endpoint is not None else None
    if target is None:
        return _refused(
            "The privileged helper is not available. DVielle did not add a firewall rule. Traffic was not stopped.",
            code="helper_unavailable",
        )
    envelope = {
        "v": PROTOCOL_VERSION,
        "op": DEFINED_OP,
        "token": target["token"],
        "params": checked,
    }
    body = _exchange(target, envelope)
    if "performed" not in body:
        body = _refused(
            "The privileged helper did not confirm a rule. DVielle did not add a firewall rule. Traffic was not stopped.",
            code="verify_failed",
        )
    return body
