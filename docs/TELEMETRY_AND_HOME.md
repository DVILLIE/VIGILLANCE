# Telemetry honesty (Home vs Pro) and Update allowlist

**Last updated:** 2026-08-23

## What DVielle promises

- **Reduce** diagnostic/advertising/privacy drift and **detect** when settings flip back.
- **Never** claim “zero Microsoft traffic” or “100% anti-spy.”

## Windows Home vs Pro

| Edition | AllowTelemetry “Security (0)” | Realistic floor |
|---------|-------------------------------|-----------------|
| **Home** | Not truly available via policy the way Enterprise docs describe | **Required** diagnostic data still flows |
| **Pro / Enterprise** | Policy can target lower levels; still not “no Microsoft endpoints” | Required + Update/Defender/CRL traffic remains |

Harden-once sets `AllowTelemetry = 0` where the OS accepts it. On Home, Windows may still behave as **Required**. Privacy/microsoft guards may report drift — that is expected until the setting sticks; treat Home as “as low as the SKU allows.”

Microsoft references:

- [Configure Windows diagnostic data](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization)
- [Manage connections to Microsoft services](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)

## Domains we must not block

Firewall/hosts/microsoft_guard keep these (and related substrings) open:

- `*.windowsupdate.com` / `update.microsoft.com`
- `*.delivery.mp.microsoft.com` / `delivery.mp.microsoft.com`
- `ctldl.windowsupdate.com` (CRL / certificate trust)
- Login endpoints used by Update/account flows (`login.live.com`, `login.microsoftonline.com`) when listed in allowlists

Config: `config/whitelists.yaml` → `never_block_domains`  
Script: `scripts/block-telemetry-firewall.ps1` → `$UpdateSafe`  
Code: `agent/modules/microsoft_guard.py` → `UPDATE_SAFE_SUBSTRINGS`

Aggressive “Restricted Traffic Baseline” is **expert-only**, not v1 default.

## Logon audit

Failed logon detection needs audit policy. Installer and harden-once run:

```text
auditpol /set /subcategory:"Logon" /failure:enable
```

Without this (common on Home until enabled), the attacks module sees **no** Event 4625.
