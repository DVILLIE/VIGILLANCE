"""Checked IPC contract for the privileged helper.

One operation is defined: ``restrict_network``. Every other name is undefined
and is refused before any firewall cmdlet runs. Parameters that are not in the
schema are refused, including anything that would stop MpsSvc, add a Defender
exclusion, or fetch a GitHub update.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 1
DEFINED_OP = "restrict_network"
PIPE_NAME = r"\\.\pipe\DViellePrivilegedHelper"
LOOPBACK_HOST = "127.0.0.1"

# Closed on purpose. Adding an operation requires a new review, not a free-form string.
_UNSAFE_PATH = set("'\"\n\r\t&|;`$(){}<>^!")
_PROFILES = frozenset({"Domain", "Private", "Public", "Any"})
_FAMILIES = ("IPv4", "IPv6")
_PARAM_KEYS = frozenset({"program", "profile", "address_families", "remote_addresses"})


def undefined_op(op: object) -> bool:
    return op != DEFINED_OP


def _path_ok(program: str) -> str | None:
    if not isinstance(program, str) or not program.strip():
        return "A program path is required."
    if any(ch in program for ch in _UNSAFE_PATH) or any(ord(ch) < 32 for ch in program):
        return "The program path was not safe to pass to the firewall."
    candidate = Path(program)
    if not candidate.is_absolute() or ".." in candidate.parts:
        return "The program path must be an absolute file path."
    if not candidate.is_file():
        return "No program file was identified."
    return None


def _remote_ok(value: str, families: set[str]) -> str | None:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None
    if network.prefixlen == 0 or network.num_addresses > 65536:
        return None
    family = "IPv4" if network.version == 4 else "IPv6"
    if family not in families:
        return None
    return str(network)


def validate_restrict_params(params: object) -> tuple[dict[str, Any] | None, str]:
    """Return a normalized parameter dict, or an error string. Does not mutate."""
    if not isinstance(params, dict):
        return None, "Firewall parameters must be an object."
    if set(params) - _PARAM_KEYS:
        return None, "The firewall request contains a parameter that is not allowed."
    program = params.get("program")
    path_error = _path_ok(program) if isinstance(program, str) else "A program path is required."
    if path_error:
        return None, path_error
    profile = params.get("profile", "Any")
    if profile not in _PROFILES:
        return None, "The firewall profile must be Domain, Private, Public, or Any."
    raw_families = params.get("address_families", ["IPv4", "IPv6"])
    if not isinstance(raw_families, list) or not raw_families:
        return None, "At least one address family is required."
    if any(not isinstance(item, str) for item in raw_families):
        return None, "Address families must be IPv4, IPv6, or both."
    families = [family for family in _FAMILIES if family in raw_families]
    if len(families) != len(set(raw_families)) or set(raw_families) - set(_FAMILIES):
        return None, "Address families must be IPv4, IPv6, or both."
    raw_remotes = params.get("remote_addresses", [])
    if raw_remotes is None:
        raw_remotes = []
    if not isinstance(raw_remotes, list) or len(raw_remotes) > 4:
        return None, "Remote addresses must be a list of at most four specific networks."
    remotes: list[str] = []
    family_set = set(families)
    for item in raw_remotes:
        if not isinstance(item, str):
            return None, "A remote address was not a specific network."
        parsed = _remote_ok(item.strip(), family_set)
        if parsed is None:
            return None, "A remote address was not a specific network for the chosen address family."
        if parsed not in remotes:
            remotes.append(parsed)
    assert isinstance(program, str)
    return {
        "program": str(Path(program)),
        "profile": profile,
        "address_families": families,
        "remote_addresses": remotes,
    }, ""
