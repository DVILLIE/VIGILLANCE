"""ACL'd named-pipe contract for the privileged helper.

The resident task stays RunLevel Limited. This is not a SYSTEM service.
``\\\\.\\pipe\\DViellePrivilegedHelper`` is the intended Windows transport.
The proposed DACL grants SYSTEM full control and one installed-user SID
specific client rights, excluding FILE_CREATE_PIPE_INSTANCE.
Everyone, Authenticated Users, and the Users group are refused.

The in-process model applies an allow-list for refusal tests; it is not an OS
authentication boundary. native_channel now implements bounded OS request
reception and identity verification, without a mutation dispatcher or deployed
service. This descriptor creates nothing; resident enforcement stays unavailable.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from agent.privilege.contract import DEFINED_OP, PIPE_NAME, PROTOCOL_VERSION
from agent.privilege.helper import Runner, dispatch
from agent.utils import IS_WINDOWS

# S-1-5-21-… is a machine or domain user. SYSTEM is added separately.
_USER_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+")
# FILE_GENERIC_READ | FILE_GENERIC_WRITE, minus FILE_CREATE_PIPE_INSTANCE (0x4).
# https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
PIPE_CLIENT_RIGHTS = 0x0012019B
PIPE_REJECT_REMOTE_CLIENTS = 0x8  # Required future CreateNamedPipe mode; not applied here.
_DENIED_SIDS = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-545",  # Users
        "WD",
        "AU",
        "BU",
        "BA",
    }
)


def build_pipe_sddl(user_sid: str) -> str:
    """Return a protected DACL. Raises ValueError for a shared or empty SID."""
    if not isinstance(user_sid, str) or user_sid in _DENIED_SIDS or not _USER_SID.fullmatch(user_sid):
        raise ValueError("The pipe ACL needs one installed-user SID. Everyone, Users, and Administrators are refused.")
    return f"D:P(A;;GA;;;SY)(A;;0x{PIPE_CLIENT_RIGHTS:08x};;;{user_sid})"


def describe_pipe(user_sid: str | None) -> dict[str, Any]:
    """Describe the contract. Does not create a pipe."""
    support = windows_pipe_support()
    support.update({"server_created": False, "remote_rejection_enforced": False,
                    "required_pipe_mode": PIPE_REJECT_REMOTE_CLIENTS})
    if not user_sid:
        return {
            "transport": "named_pipe",
            "pipe": PIPE_NAME,
            "acl": "UNAVAILABLE",
            "sddl": None,
            "allows_everyone": False,
            "defined_op": DEFINED_OP,
            "privileged_service": False,
            "resident_runlevel": "Limited",
            "windows": support,
            "reason": "No installed-user SID was supplied. The pipe was not created.",
        }
    try:
        sddl = build_pipe_sddl(user_sid)
    except ValueError as exc:
        return {
            "transport": "named_pipe",
            "pipe": PIPE_NAME,
            "acl": "REFUSED",
            "sddl": None,
            "allows_everyone": False,
            "defined_op": DEFINED_OP,
            "privileged_service": False,
            "resident_runlevel": "Limited",
            "windows": support,
            "reason": str(exc),
        }
    return {
        "transport": "named_pipe",
        "pipe": PIPE_NAME,
        "acl": "defined_only",
        "sddl": sddl,
        "allows_everyone": False,
        "defined_op": DEFINED_OP,
        "protocol": PROTOCOL_VERSION,
        "privileged_service": False,
        "resident_runlevel": "Limited",
        "windows": support,
        "reason": "The DACL and remote-rejection requirement are defined only. No OS pipe or SYSTEM service is created.",
    }


def windows_pipe_support() -> dict[str, Any]:
    if not IS_WINDOWS:
        return {
            "available": False,
            "reason": "Named pipes are a Windows transport. This host is not Windows. Nothing was created.",
        }
    try:
        import win32file  # noqa: F401
        import win32pipe  # noqa: F401
        import win32security  # noqa: F401
    except ImportError:
        return {
            "available": False,
            "reason": "pywin32 is not installed. The ACL contract is defined and the pipe was not created.",
        }
    return {
        "available": True,
        "reason": "pywin32 can create the pipe. The Limited scheduled task does not start it.",
    }


class InProcessPipe:
    """Unit refusal model without a kernel object or privileged dispatcher."""

    def __init__(self, allowed: set[str] | frozenset[str], runner: Runner, token: str) -> None:
        self.allowed = frozenset(allowed)
        self.runner = runner
        self.token = token

    def request(self, caller: str, envelope: object) -> dict[str, Any]:
        if caller not in self.allowed:
            return {
                "ok": False,
                "code": "acl_denied",
                "performed": False,
                "message": "The caller is not on the pipe ACL. Nothing was changed.",
                "verified": [],
            }
        return dispatch(envelope, runner=self.runner, expected_token=self.token)
