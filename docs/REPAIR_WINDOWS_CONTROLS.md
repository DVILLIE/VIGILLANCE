# Windows control repair evidence — 2026-10-09

Changes are in the isolated repair checkout. No Defender preference, firewall
rule, Sandbox session, or installed task was changed during this work.

## Implemented contracts

- ASR changes preserve every configured GUID/action, including GUIDs outside
  the D'Vielle catalog. New IDs use `Add-MpPreference`; changing an existing ID
  supplies the full preserved arrays to `Set-MpPreference`. Removal uses
  `Remove-MpPreference`. The writer rechecks the full baseline before mutation;
  the result verifies the full map and unchanged CFA mode.
- One cross-process journal lock covers the entire ASR/CFA lifecycle, across
  different findings and GUIDs. Nested operations are refused. A durable
  journal is mandatory, written before mutation; unreadable, corrupt, or
  unresolved recovery records block further changes. A failed attempt is
  cleared only when the complete original state is observed again.
- CFA changes also compare the prior mode and full ASR map before writing,
  journal before the command, and verify unrelated ASR state afterward.
- Firewall families use per-family `RemoteAddress` arrays, not nonexistent
  `AddressFamily` cmdlet parameters or address-filter properties. Specific
  IPv4 destinations never accidentally become an all-IPv6 block. Verification
  reads ActiveStore, normalizes exact CIDR/host/range sets, and checks program,
  profile, action, direction, enablement, and ownership. Failed attempts remove
  only rules bearing that invocation's ownership tag. Cleanup read failures
  remain unknown; pre-existing rules are preserved.
- Sandbox launches accept only the system path returned by the Windows API.
  The production launcher also rejects redirected executable paths. Session
  `.wsb` files have unique, exclusively created names. Networking, clipboard,
  audio/video input, printer redirection, and vGPU are explicitly disabled;
  mapping remains read-only. Finding fields cannot provide guest probe results.
  Without independent session evidence, networking remains UNKNOWN and the
  overall isolation result remains LIMITED.

## Verification actually performed

`tests/test_repair_controls.py` adds 26 fixture cases for full-map preservation
and undo, absent-rule additions, collateral-loss refusal, corrupt/unreadable
journals, shared lifecycle serialization, reentrancy refusal, exact firewall
filters, rollback uncertainty, system-path refusal, unique profiles, and forged
network claims. These are unit fixtures, not host security measurements.

The controls suite plus existing P1/P2/P3 suites passed 88 tests. Seven generated
PowerShell scripts were parsed using the installed PowerShell parser without
syntax errors. Read-only cmdlet metadata confirmed `Description`,
`RemoteAddress`, and `PolicyStore` exist, and `AddressFamily` does not. No
generated mutation script was executed.

## Primary material checked

- [ASR configuration and Set replacement semantics](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)
- [New-NetFirewallRule supported parameters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps)
- [MSFT_NetAddressFilter properties](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netaddressfilter)
- [Effective firewall policy](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps)
- [Windows Sandbox configuration settings](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)

## Remaining acceptance work

Disposable Windows validation must exercise actual Defender array updates and
recovery, tamper protection and managed-policy overrides, all IPv4/IPv6 filter
representations, name collisions and partial firewall failures, and independent
guest networking evidence. The journal lock coordinates D'Vielle instances;
Windows exposes no atomic preference compare-and-swap against external policy
writers. A system path is not a fresh binary-signature attestation. A successful
rule read is not a packet-level isolation guarantee. The production guest probe
and a user recovery workflow for unresolved prevention journals remain absent.
