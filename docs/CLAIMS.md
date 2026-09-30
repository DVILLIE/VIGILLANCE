# Claims, assumptions, and evidence

Version 2.3.2. This page is the public list of what DVielle promises, what it assumes, and how a check shows the promise is wired. It follows the seL4 practice of writing the assumptions down: https://www.sel4.systems/Verification/assumptions.html (reviewed via the 2026-09-29 primary-source brief). 2.3.2 does not add a protection promise. A finished collector, including a partial collection, is due again at last-run plus its interval. That is scheduling, not a new control.

An empty box in [TRUST_GATES.md](TRUST_GATES.md) is UNCHECKED. A green box is a check that was actually run. An AMTSO Security Features Check, if one is ever run, proves wiring. It is not a malware-efficacy percentage. https://www.amtso.org/security-features-check/

Claim language follows `docs/FUNCTION_SPEC.md` and the primary-source brief dated 2026-09-29 (Microsoft Learn, CISA, W3C WebAuthn, TUF, seL4, AMTSO). A claim without that basis stays UNKNOWN.

## How to read a row

| Column | Meaning |
|--------|---------|
| Promise | The sentence DVielle is willing to say. |
| Assumptions | What must be true or the promise does not apply. Silence here would be an over-claim. |
| Evidence | The check that shows the wiring. Fixture tests are not a live Windows resident. |
| UNCHECKED | What this version does not prove. |

## Pillars

### 1. Defender orchestration

- **Promise.** Observe Defender and configure only features the edition supports. Do not disable real-time protection to replace it. Do not add an install-time `ExclusionPath`.
- **Assumptions.** Defender is present. The user consents before a preference change. ASR and CFA changes go through the dual gate, then a second read of the live preference.
- **Evidence.** `Get-MpComputerStatus` fields on the health report. Access denial stays partial. `tests/test_worldclass_p0.py` and `tests/test_install_acl_contract.py` reject `ExclusionPath`.
- **UNCHECKED.** Engine freshness stays UNKNOWN. This version does not compare the engine with a catalog. Live binary attestation of the running process is UNCHECKED.

### 2. Edition-honest matrix

- **Promise.** Show Home versus Pro+ support before enablement. Windows Sandbox and App Control PowerShell authoring are unavailable on Home.
- **Assumptions.** Edition comes from the edition id / caption classification. Smart App Control is a probe, not a guess that a clean install is eligible. Whether SAC On/Off became freely reversible after an April 2026 update is UNKNOWN.
- **Evidence.** `feature_matrix` on the capability report and the console evidence strip. `tests/test_worldclass_p0.py`.
- **UNCHECKED.** A screenshot of a physical Home PC is not part of CI.

### 3. ASR and CFA

- **Promise.** ASR and CFA are Defender features on Home and Pro. CFA helps block untrusted apps from changing protected folders. DVielle does not claim CFA prevents reading or exfiltration. Standard rules other than WMI may move to Block only after live Audit. Other rules stay Audit-only.
- **Assumptions.** Defender Active, real-time on, and MAPS pass. The user approves the one change. Group Policy or tamper protection may win; the re-read is the result. Offline encrypted backups and a restore drill are still required (CISA #StopRansomware). Microsoft Learn does not publish the sentence “CFA never blocks reads”; read protection is simply not claimed.
- **Evidence.** 1.9.0 reads `Get-MpPreference`, plans one next mode, and applies it only inside the dual gate. `tests/test_worldclass_p1.py`.
- **UNCHECKED.** A live Windows preference write is not what the Linux unit run proves. The unit test checks the gate and the re-read contract.

### 4. Firewall assist

- **Promise.** Propose Windows Firewall app rules per profile. DVielle is not a second firewall engine. A blocked app is not a claim that nothing leaks on every interface. Do not stop MpsSvc.
- **Assumptions.** Domain, Private, and Public profiles exist. VPN and IPv6 are first-class. A full VPN leakproof guarantee is UNKNOWN. The helper is local. The resident task stays Limited.
- **Evidence.** 2.0.0 reads rules and applies a block only inside the dual gate. Success is the second `Get-NetFirewallRule` read. `tests/test_worldclass_p2.py`.
- **UNCHECKED.** Behavior under every third-party VPN client is UNKNOWN.

### 5. Isolation honesty

- **Promise.** Windows Sandbox is a Pro, Enterprise, or Education action. Home is told there is no first-party disposable GUI sandbox. WDAG is deprecated and removed starting Windows 11 24H2. Client Hyper-V is not a Home substitute. Open unfamiliar is that Sandbox path, user-approved, with networking disabled and one read-only folder.
- **Assumptions.** The SKU matches Microsoft’s Sandbox edition list. Default Sandbox networking is on until a `.wsb` disables it. Group Policy can override a `.wsb` file. Guest networking is UNKNOWN unless a probe reports it. Home has no Sandbox in the current Learn page; a future Home SKU is UNKNOWN.
- **Evidence.** 2.1.0 starts only `WindowsSandbox.exe` after the dual gate. 2.3.0 names that path as the Open unfamiliar experience. Home resolves to the checklist and does not start a process. `tests/test_worldclass_p3.py` and `tests/test_worldclass_p5.py`.
- **UNCHECKED.** Guest escape, and a probe that Group Policy did not override the `.wsb`, stay unclaimed. A verified network probe is not a malware-escape claim.

### 6. Privacy, sign-in, and recovery

- **Promise.** Prefer Required diagnostic data. Do not block MAPS, Windows Update, or CRL endpoints by default. Passkeys are a phishing-resistant sign-in ceremony where the relying party supports them. WebAuthn is scoped to that relying party, so a lookalike origin cannot reuse the credential. Session theft and weak recovery are separate. Backup configured, backup fresh, and restore verified are different states.
- **Assumptions.** Home has no consumer “diagnostic data off” switch. WebAuthn Level 3 binds the credential to the RP ID (https://www.w3.org/TR/webauthn-3/). Device Bound Session Credentials exist because cookies after login are a different layer (https://www.w3.org/TR/dbsc/). FIDO recovery guidance prefers more than one authenticator. The recovery marker is a declaration, not proof a backup file exists.
- **Evidence.** 2.2.0 reads AllowTelemetry, refuses Security=Off on Home and Pro, and counts a change only when the second read matches. 2.3.0 ships local passkey guidance with `phishing_impossible: false`, no badge, and no browser automation. `tests/test_worldclass_p4.py` and `tests/test_worldclass_p5.py`.
- **UNCHECKED.** DVielle does not prove a site offers a passkey, does not register one, and does not sign the user out of other sessions.

### 7. Supply chain and intel

- **Promise.** No privileged auto-update until TUF verifies root, timestamp, snapshot, and targets. On failure, keep the last good file. Ship CISA KEV (CC0, no CISA or DHS logo) and OSV (Apache-2.0). abuse.ch only with a user-supplied Auth-Key at fetch time, or do not bundle it.
- **Assumptions.** Online update keys are not the root of trust. Redistributing abuse.ch dumps is not assumed to be fair use. The client does not download unless fetch is explicitly enabled.
- **Evidence.** 2.1.0 verifies a local TUF repository and keeps the previous file when rollback, freeze, or a bad hash is injected. 2.2.0 loads local KEV and OSV. A missing file is `intel: unavailable`. `tests/test_worldclass_p3.py` and `tests/test_worldclass_p4.py`.
- **UNCHECKED.** Privileged auto-update stays off. Live measurement of the running process stays UNCHECKED. The exact abuse.ch fair-use boundary for a redistributed dump stays UNKNOWN; this product does not ship one.

### 8. Verification discipline and activity experiences

- **Promise.** Public claims map to wiring checks plus this assumptions list. Efficacy language is omitted. CPU limits are published with the measurement method. Everyday, Sensitive, and Open unfamiliar differ in thresholds and proposals, not in a label alone.
- **Assumptions.** The host matches the assumption list for that claim. Feature checks are not lab efficacy. Job Object hard caps do not apply under RDS Dynamic Fair Share Scheduling. The dual gate is unchanged. Everyday cannot enable denylist actions. Sensitive cannot auto-mutate CLOSE_PROCESS. Open unfamiliar on Home is the checklist only.
- **Evidence.** This page, TRUST_GATES, `tests/test_worldclass_p5.py`, and the twin `cpu_contract`. The resident mode is measured scheduling unless a helper assignment reports `job_cap_applied`.
- **UNCHECKED.** The items in the leftover list below.

## Activity experiences (2.3.0)

| Experience | What actually changes | What does not change |
|------------|------------------------|----------------------|
| Everyday | ASR, CFA, and Firewall stay observation. Alerts start at high severity. Medium findings stay quiet. | Denylist actions stay off even if config says true. CLOSE_PROCESS is not automatic. The dual gate is unchanged. |
| Sensitive | Alerts can start at low severity when confidence is medium or high. Auto-protect for the published set requires critical severity. CFA Audit and firewall restrict are proposed sooner, with `applied: false`. | CLOSE_PROCESS and Open unfamiliar stay user-approved. Config cannot turn `close_process_auto` on. Nothing is written without the dual gate. |
| Open unfamiliar | Names the existing `safety.open_unfamiliar` / Windows Sandbox path on Pro+. | Home shows the SAC, ASR, CFA, and Firewall checklist only. Resolving the experience does not start a process. `launch: true` in config is refused. |

## Passkeys (2.3.0)

Local guidance tells the user to adopt a passkey where the relying party supports one. It says the credential is RP-scoped. It warns that session theft and weak recovery are separate. Checklist marks mean the user said they looked. They do not change an account. There is no phishing-impossible badge.

## Leftover list (still UNCHECKED or out of this version)

These are named so a later change cannot treat them as already done:

1. **Live Windows resident `verify_runtime`.** `python scripts/verify_runtime.py` after a real resident start on Windows. A Linux or CI unit run does not check this box. See TRUST_GATES. **Assumption (2.3.1).** The living owner may be the base interpreter image. On Windows a venv `Scripts\python.exe` / `pythonw.exe` is a redirector (CPython bpo-34977). `owner_pid` is the process whose image `psutil` reports, which can be `pythonw.exe` in the `sys.base_prefix` directory (the base install, including a pythoncore layout) while `sys.executable` stays in `Scripts`. The verifier accepts that image only when it is itself running in a venv (`sys.prefix != sys.base_prefix`), and still requires a fresh heartbeat, a matching create time, a Python interpreter name, and `-m agent.main`. `tests/test_verify_runtime.py` covers that shape with a fake process. It is not a live resident proof.
2. **Elevated ACL field prove.** The installer contract tests the intended ACL and refuses a writable install tree for a Highest task. A field proof of the live elevated ACL on the target PC is UNCHECKED. Elevated unattended use stays not recommended.
3. **Named-pipe SYSTEM helper.** The helper remains the loopback stub. It is not a SYSTEM service and not a replacement of that stub. The pipe contract still refuses undefined operations.
4. **Privileged auto-update.** TUF verification does not turn this on.
5. **Live binary attestation.** The TUF package hash is metadata. It is not a measurement of the running process.
6. **Engine freshness.** UNKNOWN until compared with a catalog.
7. **Smart App Control reversibility** without a reset. UNKNOWN on current Microsoft Learn.
8. **CFA read or exfiltration blocking.** Not claimed.
9. **Full VPN and IPv6 leakproof behavior** for every client. UNKNOWN.
10. **abuse.ch dumps inside the product.** Not shipped.

Core prevention stays free. No offensive tools.
