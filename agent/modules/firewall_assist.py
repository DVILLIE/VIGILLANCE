"""Read-only Windows Firewall assistant.

Observation and proposals live here. Creating or removing a rule lives in
``firewall_apply`` and runs only inside the privileged helper, after the dual
gate has already accepted ``RESTRICT_NETWORK``.

Authority (fetched 2026-09-29):
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/

Windows Firewall is the host firewall, enabled by default on all Windows
editions. DVielle is not a second firewall engine. Stopping the firewall
service (MpsSvc) is unsupported. This module never stops or starts it.

A rule that matches one program is not a leakproof block. IPv4 and IPv6 are
separate filters, and a VPN or other adapter can move traffic onto an
interface the rule does not match. That guarantee is UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from agent.utils import IS_WINDOWS, run_powershell

Coverage = Literal["complete", "partial", "unavailable"]

LEAK_WARNING = (
    "A Windows Firewall app rule is not a leakproof block. "
    "IPv4 and IPv6 are separate filters, and a VPN or other adapter can move traffic "
    "onto an interface the rule does not match. DVielle does not claim the app is isolated "
    "from every network."
)
MPSSVC_WARNING = (
    "DVielle does not stop or start the Windows Firewall service (MpsSvc). "
    "Microsoft documents that stopping MpsSvc is unsupported."
)
FIREWALL_ASSUMPTIONS: tuple[str, ...] = (
    "Windows Firewall is the host firewall on Home and Pro. DVielle adds rules; it is not a second engine.",
    "Profiles are Domain, Private, and Public. A rule on one profile does not cover the others.",
    LEAK_WARNING,
    MPSSVC_WARNING,
    "Success is a second Get-NetFirewallRule read, not the text of New-NetFirewallRule.",
    "An optional remote address narrows a Block to those destinations. It is not an allowlist, and outbound allow remains the Windows default for other destinations.",
    "A full VPN-plus-IPv6 leakproof guarantee is UNKNOWN.",
)

# Read-only. No New/Remove/Set-NetFirewallRule, no Stop-Service, no profile disable.
OBSERVE_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  Write-Output 'OBSERVE:FIREWALL'
  $svc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
  if (-not $svc) {
    Write-Output 'MPSSVC:Unknown'
  } else {
    Write-Output ('MPSSVC:' + [string]$svc.Status)
  }
  $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
  foreach ($p in $profiles) {
    Write-Output ('PROFILE:' + $p.Name + ':' + $p.Enabled)
  }
  $rules = @(Get-NetFirewallRule -DisplayName 'DVielle-restrict-*' -ErrorAction SilentlyContinue)
  Write-Output ('COUNT:' + $rules.Count)
  foreach ($r in $rules) {
    $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
    $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
    $prog = ''
    if ($app) { $prog = [string]$app.Program }
    $fam = ''
    $remote = ''
    if ($addr) {
      $fam = [string]$addr.AddressFamily
      $remote = (@($addr.RemoteAddress) -join ',')
    }
    $clean = {
      Name = ([string]$r.Name) -replace '[|\r\n]', ' '
      Enabled = [string]$r.Enabled
      Direction = [string]$r.Direction
      Action = [string]$r.Action
      Profile = [string]$r.Profile
      Family = $fam -replace '[|\r\n]', ' '
      Program = $prog -replace '[|\r\n]', ' '
      Remote = $remote -replace '[|\r\n]', ' '
    }
    Write-Output ('RULE:' + $clean.Name + '|' + $clean.Enabled + '|' + $clean.Direction + '|' + $clean.Action + '|' + $clean.Profile + '|' + $clean.Family + '|' + $clean.Program + '|' + $clean.Remote)
  }
  $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
  foreach ($a in $adapters) {
    $blob = ([string]$a.InterfaceDescription) + ' ' + ([string]$a.Name)
    if ($blob -match 'VPN|WireGuard|OpenVPN|Tailscale|Wintun|Tunnel|WAN Miniport') {
      $label = (([string]$a.Name) -replace '[\r\n|]', ' ').Trim()
      if ($label) { Write-Output ('VPN:' + $label) }
    }
  }
  Write-Output 'STATUS:OK'
} catch {
  $flat = (([string]$_.Exception.Message) -replace '\s+', ' ')
  if ($flat -match 'denied|0x80070005|80070005|Unauthorized') {
    Write-Output 'STATUS:ACCESS_DENIED'
  } else {
    Write-Output 'STATUS:FAILED'
  }
  Write-Output ('DETAIL:' + $flat)
}
exit 0
"""


@dataclass
class ObservedRule:
    name: str
    enabled: bool
    direction: str
    action: str
    profile: str
    address_family: str
    program: str
    remote: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "direction": self.direction,
            "action": self.action,
            "profile": self.profile,
            "address_family": self.address_family,
            "program": self.program,
            "remote": self.remote,
        }


@dataclass
class FirewallAssist:
    coverage: Coverage
    coverage_detail: str
    mpssvc: str = "Unknown"
    profiles: dict[str, bool] = field(default_factory=dict)
    rules: list[ObservedRule] = field(default_factory=list)
    vpn_adapters: list[str] = field(default_factory=list)
    proposals: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage": self.coverage,
            "coverage_detail": self.coverage_detail,
            "mpssvc": self.mpssvc,
            "profiles": dict(self.profiles),
            "rules": [rule.to_dict() for rule in self.rules],
            "vpn_adapters": list(self.vpn_adapters),
            "proposals": list(self.proposals),
            "warnings": list(self.warnings),
            "leakproof": False,
            "assumptions": list(FIREWALL_ASSUMPTIONS),
        }


def _blank(coverage: Coverage, detail: str) -> FirewallAssist:
    body = FirewallAssist(coverage=coverage, coverage_detail=detail, warnings=[LEAK_WARNING, MPSSVC_WARNING])
    body.proposals = []
    return body


def _enabled(token: str) -> bool | None:
    return {"true": True, "false": False}.get(token.strip().lower())


def _split_rule(line: str) -> ObservedRule | None:
    parts = line.split("|")
    if len(parts) != 8:
        return None
    name, enabled, direction, action, profile, family, program, remote = parts
    flag = _enabled(enabled)
    if flag is None or not name.startswith("DVielle-restrict-"):
        return None
    return ObservedRule(
        name=name,
        enabled=flag,
        direction=direction,
        action=action,
        profile=profile,
        address_family=family,
        program=program,
        remote=remote,
    )


def _proposal_for_program(program: str, profile: str, families: list[str], *, why: str) -> dict[str, Any]:
    name = program.replace("\\", "/").rstrip("/").split("/")[-1] or program
    both = families == ["IPv4", "IPv6"]
    family_note = (
        "Both IPv4 and IPv6 rules are requested."
        if both
        else "This proposal does not cover every address family. That is not a leakproof block."
    )
    return {
        "handler": "safety.restrict_network",
        "title_simple": f"Block {name} on the {profile} profile",
        "what_it_will_do": (
            "Add a Windows Firewall outbound Block for this program on that profile, "
            "then re-read the rule. " + family_note + " " + LEAK_WARNING
        ),
        "signals": {
            "program": program,
            "name": name,
            "profile": profile,
            "address_families": list(families),
            "remote_addresses": [],
        },
        "why": why,
    }


def build_proposals(posture: FirewallAssist) -> list[dict[str, Any]]:
    """Suggestions only. Nothing here creates a rule."""
    if posture.coverage != "complete":
        return []
    if posture.mpssvc != "Running":
        return []
    if False in posture.profiles.values() and not any(posture.profiles.values()):
        return []
    proposals: list[dict[str, Any]] = []
    by_program: dict[str, set[str]] = {}
    for rule in posture.rules:
        if rule.direction.lower() != "outbound" or rule.action.lower() != "block" or not rule.program:
            continue
        by_program.setdefault(rule.program, set()).add(rule.address_family)
    for program, families in sorted(by_program.items()):
        if "IPv4" in families and "IPv6" not in families:
            proposals.append(
                _proposal_for_program(
                    program,
                    "Any",
                    ["IPv6"],
                    why="An existing DVielle block for this program was observed without an IPv6 rule.",
                )
            )
        elif "IPv6" in families and "IPv4" not in families:
            proposals.append(
                _proposal_for_program(
                    program,
                    "Any",
                    ["IPv4"],
                    why="An existing DVielle block for this program was observed without an IPv4 rule.",
                )
            )
    if not proposals and posture.profiles.get("public") is True:
        proposals.append(
            {
                "handler": "safety.restrict_network",
                "title_simple": "Block one chosen app on the Public profile",
                "what_it_will_do": (
                    "After you name a program file, add an outbound Block on the Public profile "
                    "for IPv4 and IPv6, then re-read both rules. " + LEAK_WARNING
                ),
                "signals": {
                    "profile": "Public",
                    "address_families": ["IPv4", "IPv6"],
                    "remote_addresses": [],
                },
                "needs_program": True,
                "why": "Public is the profile Windows uses for unidentified networks. No app is blocked until you confirm a program.",
            }
        )
    return proposals


def parse_firewall_observe(stdout: str | None, *, timed_out: bool = False) -> FirewallAssist:
    warnings = [LEAK_WARNING, MPSSVC_WARNING]
    if timed_out:
        return _blank("partial", "Firewall rule collection timed out. No rule was changed.")
    if not stdout or "OBSERVE:FIREWALL" not in stdout:
        return _blank("partial", "Firewall rule collection returned no transcript. No rule was changed.")
    status = ""
    detail = ""
    mpssvc = "Unknown"
    profiles: dict[str, bool] = {}
    rules: list[ObservedRule] = []
    vpns: list[str] = []
    count: int | None = None
    for raw in stdout.splitlines():
        line = raw.strip()
        if line.startswith("STATUS:"):
            status = line.split(":", 1)[1].strip()
        elif line.startswith("DETAIL:"):
            detail = line.split(":", 1)[1].strip()
        elif line.startswith("MPSSVC:"):
            mpssvc = line.split(":", 1)[1].strip() or "Unknown"
        elif line.startswith("PROFILE:"):
            body = line.split(":", 1)[1]
            if ":" not in body:
                continue
            name, enabled = body.split(":", 1)
            flag = _enabled(enabled)
            key = name.strip().lower()
            if flag is not None and key in {"domain", "private", "public"}:
                profiles[key] = flag
        elif line.startswith("COUNT:"):
            try:
                count = int(line.split(":", 1)[1].strip())
            except ValueError:
                count = None
        elif line.startswith("RULE:"):
            parsed = _split_rule(line.split(":", 1)[1])
            if parsed is not None:
                rules.append(parsed)
        elif line.startswith("VPN:"):
            label = line.split(":", 1)[1].strip()
            if label and label not in vpns:
                vpns.append(label)
    if status == "ACCESS_DENIED":
        return _blank("partial", "Firewall rule collection was access denied. No rule was changed.")
    if status != "OK":
        text = detail or "Firewall rule collection failed. No rule was changed."
        return _blank("partial", text)
    if count is None or count != len(rules) or len(profiles) != 3:
        return _blank("partial", "Firewall rule collection was incomplete. No rule was changed.")
    if vpns:
        warnings.append(
            "A VPN-like adapter is up (" + ", ".join(vpns) + "). "
            "DVielle cannot claim a block covers that tunnel."
        )
    if mpssvc != "Running":
        warnings.append(
            "MpsSvc is not Running (" + mpssvc + "). DVielle will not start it and will not stop it. No rule is proposed."
        )
    posture = FirewallAssist(
        coverage="complete",
        coverage_detail="Firewall profiles and DVielle app rules were read. Nothing was changed.",
        mpssvc=mpssvc,
        profiles=profiles,
        rules=rules,
        vpn_adapters=vpns,
        warnings=warnings,
    )
    posture.proposals = build_proposals(posture)
    return posture


def query_firewall_assist() -> FirewallAssist:
    if not IS_WINDOWS:
        return _blank("unavailable", "Firewall rule collection is unavailable: not Windows")
    stdout, timed_out = run_powershell(OBSERVE_PS, timeout=25)
    return parse_firewall_observe(stdout, timed_out=timed_out)
