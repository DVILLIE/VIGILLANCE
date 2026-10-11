# Changelog

All notable changes to D'Vielle (Intelligent Vigilance) are recorded here.
Versions follow `pyproject.toml` `[project].version`. Dates are in IST.

## [2.5.0] - 2026-10-11

D'Vielle 2.5.0 is a large hardening and capability release, published as source.
The resident monitor stays Limited, and changes still need your choice and a
second check.

### Highlights

- **D'Vielle rebrand.** The product name is now **D'Vielle**, with the tagline
  **Intelligent Vigilance**, across the console, installer display text,
  shortcuts and documentation.
- **Nexus Fold Prime theme.** A pearl folded overview, cobalt spatial network
  stage and bottom dock across all six pages, in Dark and Light. Motion follows
  the Windows animation setting, can be turned off, and stops when hidden.
- **Quantum Key logo.** A cube-circuit mark with silent, decorative blue
  electrical surges in the header, and a matching static icon for the window,
  taskbar, tray and shortcuts.
- **Assessment engine and Quantum readiness tab.** A consent-based local
  assessment of this PC: process identity, code signatures, dependencies,
  certificate inventory, TLS key-exchange observation, attack paths and
  resource costs, with evidence lifecycle and history. The Quantum readiness tab
  reports post-quantum provider support and migration readiness.

### Scoped protection helper (new Windows service)

- Adds the optional **D'Vielle Scoped Protection Helper** service
  (`DViellePrivilegedHelper`). It runs as **LocalSystem** so that one approved
  change can be applied without elevating the whole agent.
- It is limited to scoped actions: the protocol defines a single operation,
  `restrict_network` (a per-application firewall restriction owned by D'Vielle),
  received over an authenticated local named pipe with a restricted DACL. Each
  request needs a protected, one-time grant tied to the exact target executable.
  Unknown operations, malformed requests and requests without a valid grant are
  refused without running a privileged command.
- Production dispatch refuses caller-supplied executors and requires the SYSTEM
  identity; test adapters cannot run elevated. Grant recovery, release identity
  and runtime approval records are kept in protected state.
- The resident scheduled task remains Limited. The installer refuses an
  always-elevated (Highest) task.

### Protection and repairs

- **Firewall rollback journal.** Firewall changes made by D'Vielle are journalled
  with ownership checks so they can be verified and rolled back; colliding rules
  that D'Vielle does not own are refused.
- **ASR and Controlled Folder Access journalling.** Attack Surface Reduction and
  CFA preference changes are recorded before they are applied, with recovery
  states.
- **Sandbox hardening.** Windows Sandbox is started only from the Windows system
  directory with a networking-disabled, read-only profile; other executables are
  refused.
- **Threat-intel fixes.** Corrected KEV/OSV fetching, matching, inventory and
  reporting, plus a shared safe I/O layer for intel files.
- **Offline-update recovery.** The TUF update path recovers from interrupted
  offline updates instead of leaving a half-applied state.
- **Database claims and path handling.** Safer local database claims, protected
  path resolution and local file locking.
- Privacy, camera, egress, Defender health, passkey and resource-advisor modules
  received honesty and reliability fixes.

### Install and runtime

- Protected **Python 3.14** runtime (pinned 3.14.8 installer with hash checks).
- Default install location is now **`C:\Program Files\DVielle`**, with protected
  code and private per-user data and configuration.
- Verified, protected source staging, offline dependency bundles, runtime SBOM
  export and release-readiness checks.
- The setup wrapper (`DVielle-Setup-*.exe`) stays held until protected bootstrap
  staging is complete.

### Documentation

- Full project documentation set under `docs/project/`, security design and
  research notes, formal model (`docs/formal/`), third-party notice review
  (`docs/legal/`) and implementation evidence (`docs/implementation/`).

### Compatibility notes

- Internal identifiers keep the `DVielle` / `dvielle` spelling so existing
  installs keep working: the `dvielle` package, `DVielle.exe`, install and data
  paths, scheduled task, service, firewall group and registry names.

## [2.4.2] - 2026-10-02

- Branded `DVielle.exe` console host (pythonw copy with the brand icon) so Task
  Manager shows the console by name. The resident task stays `pythonw.exe`.
- Brand logo made permanent across the app and GitHub.

## [2.4.0] - 2026-09-30

- Console page shell with Dark and Light themes.
- Documented as free MIT software; public author and contact.
- Windows setup executable (Inno Setup wrapper, Limited install).
- Product-only branding in shipped files.

## [2.3.3] - 2026-09-30

- Removed the deferred chat assistant.

## [2.3.2] - 2026-09-30

- Fail closed on Sensitive severity; collector deadline fixes.

## [2.3.1] - 2026-09-29

- `verify_runtime` support for the pythoncore venv shim.

## [2.3.0] - 2026-09-29

- P5 activity experiences, passkey guidance and claims.

## [2.2.0] - 2026-09-29

- P4 local KEV/OSV threat intel and Defender-safe privacy changes.

## [2.1.0] - 2026-09-29

- P3 Windows Sandbox "unfamiliar" profile and offline TUF updates.

## [2.0.0] - 2026-09-29

- P2 firewall assist, privileged helper contract and CPU contracts.

## [1.9.0] - 2026-09-29

- P1 ASR/CFA audit-before-block and recovery states.

## [1.8.0] - 2026-09-29

- Free roadmap lock and read-only P0 health.

## [1.7.1] - 2026-09-29

- Security and honesty hardening.

## [1.7.0] - 2026-09-26

- Honesty rules unified with the keep-on dual gate.

[2.5.0]: https://github.com/DVILLIE/VIGILLANCE/releases/tag/v2.5.0
[2.4.0]: https://github.com/DVILLIE/VIGILLANCE/releases/tag/v2.4.0