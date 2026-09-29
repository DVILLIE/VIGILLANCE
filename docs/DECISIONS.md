# Project Decisions

Canonical product thesis and engine map: **[VIGILLANCE_MASTER_ARCHITECTURE.md](VIGILLANCE_MASTER_ARCHITECTURE.md)**.

Futuristic cadence / Twin: **[VIGILLANCE_FUTURE_ARCHITECTURE.md](VIGILLANCE_FUTURE_ARCHITECTURE.md)** (Adaptive Nerve is cadence authority).

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Product identity | System intelligence + resource governance + privacy + defensive security — **not** AV-first | User workload (esp. AI) must stay responsive |
| Version source | `pyproject.toml` → runtime `agent.version` → installer DisplayVersion | One authoritative semver (2.0.0) |
| Dual mutate gate | Options-card token (or published auto-protect for that subject) **and** Cortex ActionKind + registered handler | Firewall, temp delete, startup disable, smart close, and BLOCK_IP fail closed if either half refuses. CLOSE_PROCESS is USER_APPROVED_ONLY. A Level≥3 decision must be durably saved before any handler runs. No second OS path. |
| Scheduled task RunLevel | **Limited** | `TASK_RUNLEVEL_LUA`. `-RunLevel Highest` (`TASK_RUNLEVEL_HIGHEST`) is explicit only, and only after the install tree is locked to Administrators and SYSTEM write. Elevated unattended use is not recommended until that lockdown is proven on the target PC. `elevate.ps1` elevates the installer process, not the resident task. |
| Install identity | Selected `InstallDir` | Start, verify, stop, config, and data use that tree. No silent fallback to another install such as `C:\DVILLIE`. |
| Defender exclusion | **No** `Add-MpPreference ExclusionPath` | Installer must not carve DVielle out of Defender. |
| Platform honesty | Windows-primary; Linux/macOS limited-mode | Camera in-use on Windows is not available yet. Footprint collector returns no hits; remote rows are drill tickets. |
| F1 runtime | CapabilityReport + shared Twin + independent Nerve collectors + evidence schema | Single owner, workload-aware deferral and retry recovery; see `AUTONOMY.md` |
| P0 safety contract | Collectors observe; Cortex decides; Action Executor mutates with Decision ID | Fail-closed; no module Level ≥2 bypass |
| Automatic RAM trim | **DISABLED** (EmptyWorkingSet / EmptyStandbyList) | Microsoft: testing/tuning; use pressure analysis |
| 4776 handling | Source Workstation = hostname only; never IP block | Microsoft Learn Event 4776 |
| Intelligence shape | Collection → correlate → score → confidence → recommend → act | Module toasts alone are insufficient |
| Windows edition | 10/11 Home & Pro | Same agent; Home registry/`auditpol`; Pro may use GPO |
| Stack | **Python 3.12** + PowerShell | 3.14 unsupported until deps proven |
| Install path | Default **`C:\DVILLIE`** | A selected `-InstallDir` is that installation's only config and data root |
| Runtime | Headless `agent.main` + attached optional GUI | One OS lock per data directory; shared atomic snapshot |
| Cadence authority | **Future Architecture § Adaptive Nerve only** | No duplicate cadence docs; per-collector, not global “2–5s full scan” |
| Review discipline | Master § Architecture Review Rules | CURRENT / REGRESSION / HISTORICAL labels; audit named refs |
| Module renames | Semantics before filenames | Keep `microsoft_guard.py` until Privacy Control Plane exists |
| Default posture | Autonomous Observe–Explain–Recommend | Baseline and legacy flags never authorize destructive collectors; user actions require fresh identity and confirmation |
| Memory | **Pressure**, not “RAM % used” | Windows cache/standby is often healthy |
| Network | Purpose classification + user policy | Not “block Microsoft” |
| Privacy | Control plane: observe → recommend → authorize → verify | Home and Pro Required floor; a registry policy is not proof of effective traffic blocking |
| Security | Local attack-surface / defensive assessment | Not offensive ethical hacking toolkit |
| Defender | Work **with** Defender; **no** install-time path exclusion | Verified resolved on current main (no ExclusionPath) |
| World-class FREE (2026-09-29) | Core prevention stays free and is not paywalled. Orchestrate Microsoft Defender; do not replace it or disable real-time protection to take over. Windows Home has no Windows Sandbox and no App Control PowerShell authoring. CFA is a modification control, not a read or exfiltration claim. TUF comes before any privileged auto-update. CISA KEV (CC0, no CISA/DHS logo) and OSV (Apache-2.0) are acceptable intel. abuse.ch only with a user-supplied Auth-Key at fetch time; do not bundle their dumps | Locked from the 2026-09-29 primary-source brief. 1.8.0 shipped P0 observe (Defender health, MAPS, edition matrix). 1.9.0 shipped P1: ASR/CFA observation, Audit-before-Block for two standard rules, Audit-only for WMI and other rules, CFA Audit then Enabled, and three separate recovery states. 2.0.0 ships P2: firewall app-rule assistant on the existing RESTRICT_NETWORK dual gate, a loopback privileged-helper contract that refuses undefined operations, and published CPU contracts (measured scheduling on the resident task; Job Object hard cap only on the helper when assignment succeeds). No leakproof firewall claim. MpsSvc is not stopped. The resident task stays Limited. Sandbox `.wsb` and TUF stay P3. Attestation checksum stays unchecked. See `FUNCTION_SPEC.md` §1.1 and `TRUST_GATES.md` |
| Alerts | Evidence-backed logs + optional toasts | Explainability required |
| Chat / VILL | Deferred | See `CHAT_DEFERRED.md` |
| Scope v1→v2 | Laptop guardian; expand engines per architecture phases | Avoid feature spray |
