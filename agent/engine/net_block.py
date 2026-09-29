"""Per-app network block. Only after a selected option. Never an IP attack rule.

The Limited process does not run New-NetFirewallRule. The checked request goes
to the privileged helper, which re-reads Get-NetFirewallRule before success.
"""

from __future__ import annotations

from typing import Any

from agent.modules.resource_advisor import SYSTEM_PROTECTED

HONEST_FAIL = "DVielle did not add a firewall rule. Traffic was not stopped."


def block_app_network(
    name: str,
    path: str,
    *,
    runner=None,
    profile: str = "Any",
    address_families: list[str] | None = None,
    remote_addresses: list[str] | None = None,
    endpoint: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Ask the helper to block outbound traffic for one program file.

    ``runner`` is ignored. A caller-supplied shell is not a privileged helper
    and cannot bypass the IPC contract.
    """
    del runner
    if not name or name.lower() in SYSTEM_PROTECTED:
        return False, f"DVielle will not block the network for {name or 'that process'}. Traffic was not stopped."
    from agent.privilege.broker import submit_restrict_network

    body = submit_restrict_network(
        {
            "program": path,
            "profile": profile,
            "address_families": list(address_families or ["IPv4", "IPv6"]),
            "remote_addresses": list(remote_addresses or []),
        },
        endpoint=endpoint,
    )
    message = str(body.get("message") or HONEST_FAIL)
    if not body.get("performed"):
        if "not stopped" not in message.lower():
            message = message.rstrip(".") + ". Traffic was not stopped."
        return False, message
    if "does not prove" not in message.lower():
        message = message.rstrip(".") + ". This does not prove every connection already stopped."
    if "not a leakproof" not in message.lower() and "not leakproof" not in message.lower():
        message = message.rstrip(".") + ". This is not a leakproof block."
    return True, message
