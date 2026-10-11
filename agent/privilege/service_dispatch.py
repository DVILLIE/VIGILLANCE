"""Closed dispatcher for authenticated pipe requests and protected grants.

No issue/revoke/recover operation is exposed through the resident protocol.
Production runs under SYSTEM against protected state; tests cannot elevate.
"""
from __future__ import annotations

import re
from pathlib import Path

from agent.local_files import file_lock
from agent.modules.firewall_apply import apply_scope, apply_verified
from agent.privilege.contract import DEFINED_OP, PROTOCOL_VERSION, validate_restrict_params
from agent.privilege.grants import GrantStore
from agent.privilege.native_channel import ReceivedRequest
from agent.privilege.target import executable_lease

_ID = re.compile(r"[0-9a-f]{32}")


def system_identity() -> bool:
    import os
    if os.name != "nt":
        return False
    import win32api
    import win32con
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        return win32security.ConvertSidToStringSid(sid) == "S-1-5-18"
    finally:
        token.Close()


def refused(code: str, message: str, *, unknown: bool = False) -> dict:
    return {"ok": False, "code": code, "performed": False, "verified": [],
            "state_unknown": unknown, "message": message}


class ServiceDispatcher:
    def __init__(self, store: GrantStore, *, runner=None):
        if store.test_harness and runner is None:
            raise PermissionError("Contract adapters require an explicit non-production executor.")
        if runner is not None and not store.test_harness:
            raise PermissionError("Production does not accept caller-supplied executors.")
        if not store.test_harness and not system_identity():
            raise PermissionError("The mutation service requires the protected SYSTEM identity.")
        self.store = store
        self.runner = runner

    def dispatch(self, received: ReceivedRequest) -> dict:
        envelope = received.body
        if (not isinstance(envelope, dict) or set(envelope) != {"v", "op", "grant_id", "params"}
                or type(envelope.get("v")) is not int or envelope.get("v") != PROTOCOL_VERSION):
            return refused("bad_params", "The request does not match the closed privileged protocol.")
        if envelope["op"] != DEFINED_OP:
            return refused("undefined_op", "This operation is not defined; no privileged command was issued.")
        grant_id = envelope["grant_id"]
        if not isinstance(grant_id, str) or not _ID.fullmatch(grant_id):
            return refused("unauthorized", "A valid one-use administrative grant is required.")
        params, error = validate_restrict_params(envelope["params"])
        if params is None:
            return refused("bad_params", error)
        if (not isinstance(received.peer, dict)
                or received.peer.get("identity_source") != "Windows pipe client token"):
            return refused("unauthorized", "The request lacks an OS-authenticated pipe peer.")
        operation_id = None
        try:
            with file_lock(self.store.directory / "service.lock"):
                if self.store.pending():
                    return refused("recovery_required", "An unresolved operation requires reconciliation before another mutation.")
                with executable_lease(params["program"], test_harness=self.store.test_harness) as identity:
                    operation_id = self.store.claim(grant_id, received.peer.get("sid"), params, identity)
                    journal = self.store.directory / (operation_id + ".firewall.json")
                    with apply_scope():
                        result = apply_verified(params, self.runner, journal_path=journal)
                    result["operation_id"] = operation_id
                    self.store.finish(operation_id, result)
                    return result
        except PermissionError:
            if operation_id is None:
                return refused("unauthorized", "The scoped grant or executable identity did not authorize this request.")
        except Exception:
            if operation_id is None:
                return refused("service_unavailable", "Protected authorization storage or target observation is unavailable.")
        return refused("outcome_unknown", "The durable operation was claimed but its outcome is unresolved; retain its recovery records.", unknown=True)
