# Telemetry limits and optional Windows hardening

Updated 2026-09-13 for DVielle 1.6.0.

DVielle observes privacy settings and reports unavailable readings explicitly. The resident monitor does not rewrite registry values, edit hosts, add firewall rules, or remove applications. Those changes require a separately invoked script with `-Apply`.

| Windows edition | Hardening policy target | Interpretation |
| --- | --- | --- |
| Home and Pro | `AllowTelemetry = 1` | Required diagnostic data; writing zero does not establish that diagnostics are off. |
| Enterprise, Education and Server | `AllowTelemetry = 0` | Windows supports the diagnostic-data-off policy. Other Microsoft services can still communicate. |

A registry value is policy configuration, not a measurement of effective network traffic. Organization policies can override local settings. Microsoft documents these edition limits and recommends Required diagnostics for organizations using Windows Update: [Windows diagnostic data configuration](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization).

## Endpoints kept reachable

The domain filter uses exact names and subdomain boundaries. It excludes Update, download/delivery, certificate-update, notification, and account endpoints, including `windowsupdate.com`, `update.microsoft.com`, `download.microsoft.com`, `mp.microsoft.com`, `wns.windows.com`, `login.live.com` and `login.microsoftonline.com`.

`settings-win.data.microsoft.com` is also excluded. Microsoft identifies it as a diagnostics settings endpoint that can control which events are sent; blocking it is not equivalent to reducing diagnostics. See the endpoint table in [Microsoft's configuration guidance](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization#endpoints).

The exclusions live in `scripts/hardening-common.ps1` and `config/whitelists.yaml`. No finite list guarantees that all Windows features will work with a customized hosts block.

## Preview, apply and restore

From an Administrator PowerShell window in the project root:

```powershell
# Preview only; no changes.
.\scripts\harden-once.ps1
# Apply the displayed registry and hosts changes.
.\scripts\harden-once.ps1 -Apply
# Optional program blocks require a separate explicit switch.
.\scripts\harden-once.ps1 -Apply -BlockTelemetryPrograms
# Restore using the exact backup path printed by the apply run.
.\scripts\harden-once.ps1 -RestoreFrom 'C:\DVILLIE\data\hardening\<run>\backup.clixml' -Apply
```

The script requires a successful restore-point request unless `-SkipRestorePoint` is explicitly supplied. It journals original registry value kinds and absence, exact hosts bytes, and the names of its new firewall rules before each change. Writes and restores are read back. Restoration refuses unexpected targets, a different Windows user or machine, and conflicting later edits. Preserve the printed backup even after an interrupted run; conflicting edits require a manual merge.

No AppX package removal is performed. Cortana policy changes require `-DisableCortana`. Program blocks cover only CompatTelRunner and DeviceCensus where those binaries exist; they do not block Search or Windows Error Reporting. These scripts do not establish zero Microsoft traffic.

## Authentication event coverage

The installer requests failure auditing for Logon (4625) and Credential Validation (4776) using their language-independent subcategory GUIDs, and checks each native command's exit status. Credential-validation events occur on the authority for those credentials; domain-account events may be on a domain controller rather than this laptop. Successful 4776 events are not failed authentications. A query returning no matching events does not establish that nobody attempted access.

References: [auditing constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants) and [Credential Validation audit policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-credential-validation).
