# DVielle Function Spec (v0.9.5 — P5 experiences, passkeys, and claims)

**Status:** Function / intelligence first. UI look-and-feel is explicitly out of scope for this document.  
**Date:** 2026-09-29 (v0.9 locked the eight FREE pillars; v0.9.1 records that P1 shipped in 1.9.0; v0.9.2 records that P2 shipped in 2.0.0; v0.9.3 records that P3 shipped in 2.1.0; v0.9.4 records that P4 shipped in 2.2.0; v0.9.5 records that P5 shipped in 2.3.0. The v0.8 keep-on loop remains in force.)  
**Product:** DVielle (DEEP VIGILLANCE) — Windows-primary local guardian. Linux and macOS are limited-mode.  
**Audience:** Mostly non-technical users (laptop first; server = same brain, stricter autonomy profile later)  
**Authority for edition limits and claim language:** primary-source brief dated 2026-09-29 (Microsoft Learn, CISA, TUF, W3C, seL4, AMTSO, abuse.ch). A claim without that basis stays **UNKNOWN**.

---

## 1. One-sentence promise

DVielle watches this machine, **finds real problems, and drives them to a resolution** — safety, speed, privacy/internet abuse, AI data shipping, disk junk, online footprint exposure, and camera misuse — in simple English. The user decides what is **OK to keep on**; DVielle **learns** those choices, stays quiet when activity matches, and when something looks wrong or unexpected shows an **options card** — the user selects, then DVielle performs. Auto-protect may finish a tiny published set of emergencies if opted in. Every finding is a ticket: Found → Fix → Resolved / Monitoring. We do not steal data, do not attack other systems, and we prefer working solutions (local fixes + trusted partner services) over empty warnings.

### Shipped honesty (1.7)

This version does **not** claim a live multi-OS product.

| Surface | What is true now |
|---------|------------------|
| Windows | Primary platform. Installer, Defender/firewall posture, and auth-event collectors are Windows-shaped. |
| Linux / macOS | Limited mode. Shared keep-on logic can run. Windows-only sensors stay unknown. Do not describe them as full adapters. |
| Camera | On Windows, in-use detection is **not available yet**. The collector returns unknown and does not invent an off/on state. Linux may read `/dev/video*` links. No frames are stored. |
| Footprint | The live collector is **empty**. Remote breach, broker, and dark-web rows are drill tickets only. DVielle does not invent hits or search other people. |
| Blocked IPs | The Attacks window does not show an “active now” block count. No gated BLOCK_IP writer is registered. |
| Mutations | Firewall, temp delete, startup disable, smart close, and BLOCK_IP need both a keep-on choice (or published auto-protect for that subject) and Cortex. |

### Shipped honesty (1.8.0)

1.8.0 adds read-only Defender health, a MAPS reachability check, and an edition matrix. It does not enable ASR, CFA, App Control, or Windows Sandbox. A partial or access-denied read is not a clean bill of health. Engine currency is **UNKNOWN** until DVielle compares it with a catalog, which this version does not do. Attestation checksums and TUF are not built. The pass/fail list is [TRUST_GATES.md](TRUST_GATES.md).

### Shipped honesty (1.9.0 — P1)

1.9.0 collects ASR rule actions and CFA mode from `Get-MpPreference`. A missing rule is Not configured, not Audit. Standard-protection Block is a user-approved dual-gate path for the vulnerable-driver rule and the LSASS rule, and only while the live action is still Audit and Defender is Active, real-time protection is on, and MAPS passed. The WMI persistence rule and every other ASR rule can be set to Audit only. DVielle does not blanket-Block them. CFA moves from off to Audit, and from Audit to Enabled. Enabled is a modification and boot-sector shield. DVielle does not claim CFA prevents reading or exfiltration. Offline encrypted backups and a restore test stay required (CISA). BackupConfigured, BackupFresh, and RestoreVerified are separate user-declared states, not a backup engine. Home is not described as lacking ASR. Local PowerShell does not require E5. App Control, Windows Sandbox on Home, TUF, and privileged auto-update are still not built.

### Shipped honesty (2.0.0 — P2)

2.0.0 reads Windows Firewall profiles and existing DVielle app rules. It can propose an outbound Block for one program, on one profile (Domain, Private, Public, or Any), for IPv4, IPv6, or both, with up to four specific remote networks. The apply path is the existing `RESTRICT_NETWORK` dual gate (`safety.restrict_network`, and the privacy and AI block handlers when they are not given a test double). The Limited process does not run `New-NetFirewallRule`. It sends a versioned request to a loopback helper. The helper accepts only `restrict_network`, checks the parameters again, and keeps the rule only when a second `Get-NetFirewallRule` matches. Anything else, including stopping MpsSvc, a Defender exclusion, or a GitHub update, is an undefined operation and is refused. The helper is a stub, not a Windows service. The resident scheduled task stays RunLevel Limited. A rule is not a leakproof block: IPv6 and VPN adapters are called out, and a full leakproof guarantee stays UNKNOWN. Stopping MpsSvc is not done.

The CPU contract is published on the twin. The resident task uses measured scheduling (the existing self-budget: optional collectors defer after three heartbeats over the configured CPU or memory limit). That is not an OS hard cap. The helper may assign its own process to a Windows Job Object hard cap at 20% (`CpuRate` 2000, percentage times 100). If the machine is not Windows, or `SetInformationJobObject` fails (including Remote Desktop Services with Dynamic Fair Share Scheduling), the result stays measured and says so. DVielle does not terminate user applications to make that number look healthy. 20% is DVielle's published helper cap, not a Microsoft-mandated agent budget and not a copied industry figure.

### Shipped honesty (2.1.0 — P3)

2.1.0 is a minor version. Sandbox launch and TUF verification are new capabilities on the same guardian. They do not replace Defender, and they do not change the Limited resident task.

Open unfamiliar is a user-approved `OPEN_SANDBOX` action. On Windows Home the offer is UNAVAILABLE and the checklist names Smart App Control, ASR, CFA, and Firewall. It does not start a process. Windows Defender Application Guard is named only to say it is deprecated and removed starting Windows 11 24H2. Client Hyper-V is not offered as a Home sandbox. On Pro, Enterprise, or Education, a missing optional feature stays LIMITED and is not enabled by DVielle. When the feature is present, DVielle writes one `.wsb` with networking disabled, vGPU disabled, clipboard redirection disabled, and one read-only mapped folder, then starts `WindowsSandbox.exe` with that file. Any other executable is refused. A normal desktop window is not Windows Sandbox. If guest networking is not observed, the result is LIMITED. A probe that reports networking disabled is recorded as verified, with the assumption that Group Policy override of `.wsb` settings was not read (Microsoft documents that an administrator policy can override a sandbox setting). A probe that reports networking enabled is not counted as the requested profile.

TUF verification follows specification 1.0.36. The client checks root, timestamp, snapshot, and targets from a local directory. It rejects a version rollback, an expiration that is not later than the update start time, and a sha256 or length mismatch. Delegations are refused rather than treated as verified. On failure the previously installed file stays. Privileged auto-update stays off. There is no GitHub Release updater. The displayed attestation is the verified package hash and the hash of the trusted targets metadata. Live measurement of the running process stays UNCHECKED. The wire format is [TUF_POUF.md](TUF_POUF.md).

The privileged helper is still not a SYSTEM service. The tested pipe contract grants SYSTEM and one installed-user SID, refuses Everyone, and still refuses every operation other than `restrict_network`. The resident scheduled task stays RunLevel Limited.

### Shipped honesty (2.2.0 — P4)

2.2.0 reads CISA KEV and OSV from local files and can apply one supported privacy choice after the user approves it. It does not replace Defender, and it does not change the Limited resident task.

If `kev.json` and `osv.json` are absent, the report is `intel: unavailable`. Invalid JSON or a catalog row without a real CVE id produces no hits. KEV stays CC0: the report says this is not a CISA or DHS endorsement and DVielle ships no CISA or DHS logo. OSV stays Apache-2.0, and the notice points at the osv-schema license. A match runs only when `inventory.json` lists a name and a version. A KEV product-name overlap is a candidate, not proof that installed copy is exploitable. An OSV hit needs the same ecosystem and name plus an exact `versions` entry or a numeric introduced/fixed range. A version that cannot be compared is not a hit. Fetch is off unless a caller enables it. OSV is queried only for inventory rows. abuse.ch stays off, is not bundled, and is fetched only when that switch is on and the caller supplies an Auth-Key. The response is not saved into the product.

The privacy assistant prefers Required diagnostic data (AllowTelemetry 1). Home and Pro cannot claim Security=Off. Diagnostic data off (0) is offered only on Enterprise, Education, or Server, and the copy still says that is not proof Microsoft traffic stopped. Advertising id and tailored experiences are separate choices. A write counts only when a second read of that value matches. MAPS, Windows Update, and CRL names are not turned into firewall rules. If a request names them, or names Microsoft broadly, the consequence includes the existing `ValidateMapsConnection` result.

### Shipped honesty (2.3.0 — P5)

2.3.0 adds three activity experiences and local passkey guidance. It does not replace Defender, and it does not change the Limited resident task. The dual gate is unchanged.

Everyday observes ASR, CFA, and Firewall and does not propose those mutations. Its alert floor is high, so a medium finding stays quiet. Config cannot turn denylist actions on, and it cannot make CLOSE_PROCESS automatic.

Sensitive can surface a low-severity finding when confidence is medium or high. Auto-protect for the published set requires critical severity, which is tighter than a high-severity protection-off event. CLOSE_PROCESS and Open unfamiliar stay user-approved even if config sets `close_process_auto` or `open_unfamiliar_auto`. When the live CFA plan allows Audit, that proposal is listed first, with `applied: false`. A firewall restrict proposal is listed the same way. Neither is written without the dual gate. CFA copy stays a modification shield.

Open unfamiliar is the existing Pro+ Windows Sandbox path (`safety.open_unfamiliar`). Resolving the experience does not start `WindowsSandbox.exe`. On Home the result is the SAC, ASR, CFA, and Firewall checklist only. A forged ready offer is not accepted on Home. `launch: true` in config is refused.

Passkey guidance tells the user to adopt a passkey where the relying party supports one. WebAuthn is RP-scoped, which resists a lookalike origin. The same guidance says session theft and weak recovery are separate. There is no phishing-impossible badge. Checklist marks do not change an account. There is no browser automation.

The claims page is [CLAIMS.md](CLAIMS.md). It lists each promise, the assumptions, the evidence, and what stays UNCHECKED, including live `verify_runtime`, an elevated ACL field proof, and the named-pipe SYSTEM helper.

A named-pipe SYSTEM helper stays later. Privileged auto-update stays off. Elevated unattended use stays not recommended.

P4 remains closed. P5 is closed for this version.

---

## 1.1 World-class FREE pillars (locked 2026-09-29)

Core prevention is free. DVielle orchestrates Microsoft Defender. It does not replace Defender, and it does not turn real-time protection off to “take over.”

Every promise below has the shape **Promise → Assumptions → Evidence**. Silence about an assumption is an over-claim (seL4 publishes its assumptions; DVielle does the same). An AMTSO Security Features Check proves wiring. It is not a malware-efficacy percentage.

### The eight pillars

| # | Pillar | Promise | Assumptions | Evidence |
|---|--------|---------|-------------|----------|
| 1 | Defender orchestration | Observe Defender and configure only features the edition supports. Never disable real-time protection to replace it. Never add an install-time `ExclusionPath`. | Defender is present. The user consents before a preference change. 1.9.0 changes ASR or CFA only through the dual gate, then re-reads the live preference. | `Get-MpComputerStatus` active mode, real-time, signature age, and the Defender out-of-date flag. Access denial stays partial. |
| 2 | Edition-honest matrix | Show Home vs Pro+ support before any enablement. Windows Sandbox and App Control PowerShell authoring are unavailable on Home. | EditionID / caption classification. Smart App Control is a probe, not an eligibility guess. | `feature_matrix` on the capability report and the console evidence strip. |
| 3 | ASR and CFA | ASR and CFA are Defender features on Home and Pro. CFA is a modification shield. DVielle does not claim CFA prevents reading or exfiltration. Standard rules other than WMI may move to Block only after live Audit. Other rules stay Audit-only. | Defender Active, real-time on, MAPS pass. The user approves the one change. Group Policy or tamper protection may win; the re-read is the result. Offline encrypted backups and a restore drill still required (CISA). | 1.9.0 reads `Get-MpPreference`, plans one next mode, and applies it only inside DualGate. A partial read plans nothing. |
| 4 | Firewall assist | Propose Windows Firewall app rules per profile. DVielle is not a second firewall engine. No “blocked app means no leak on every interface” claim. Do not stop MpsSvc. | Domain / Private / Public profiles. VPN and IPv6 are first-class. A full VPN leakproof guarantee is UNKNOWN. The helper is local and the resident task stays Limited. | 2.0.0 reads rules with `Get-NetFirewallRule` / profile state, proposes a block, and applies it only inside DualGate. Success is the second read. |
| 5 | Isolation honesty | Windows Sandbox profiles are a Pro+ action. Home is told there is no first-party disposable GUI sandbox. WDAG is deprecated and removed starting Windows 11 24H2. Client Hyper-V is not a Home substitute. | Pro, Enterprise, or Education for Sandbox. Default Sandbox networking is on until a `.wsb` disables it. Group Policy can override a `.wsb` file. Guest networking is UNKNOWN unless a probe reports it. | 2.1.0 writes Networking Disable and one ReadOnly folder, and starts only `WindowsSandbox.exe`. Home stays UNAVAILABLE. Unobserved guest networking stays LIMITED. |
| 6 | Privacy, sign-in, recovery | Prefer Required diagnostic data. Do not block MAPS, Windows Update, or CRL endpoints by default. Passkeys are a phishing-resistant ceremony where the relying party supports them, not a promise against stolen session cookies or weak recovery. Backup configured, backup fresh, and restore verified are different states. | Home has no consumer “diagnostic data off” switch. WebAuthn is bound to the relying party. CISA requires a tested restore, not only a successful backup job. The recovery marker is a declaration, not proof a backup file exists. | 2.2.0 reads AllowTelemetry and related settings, prefers Required, refuses Security=Off on Home and Pro, and counts a change only when the second read matches. A broad Microsoft block shows the MAPS result and creates no rule. 2.3.0 adds local passkey guidance with no phishing-impossible badge and no account automation. |
| 7 | Supply chain and intel | No privileged auto-update until TUF verifies root, timestamp, snapshot, and targets. On failure, keep the last good build. Ship CISA KEV (CC0, no CISA/DHS logo) and OSV (Apache-2.0). abuse.ch only with a user-supplied Auth-Key at fetch time, or do not bundle it. | Online update keys are not the root of trust. Redistributing abuse.ch dumps is not assumed to be fair use. The client does not download unless fetch is explicitly enabled. | 2.1.0 verifies a local TUF repository and keeps the previous file when rollback, freeze, or a bad hash is injected. Privileged auto-update stays off. 2.2.0 loads local KEV and OSV with provenance. A missing file is `intel: unavailable`. abuse.ch stays off and is not bundled. |
| 8 | Verification discipline | Public claims map to wiring checks plus an assumptions list. Efficacy language waits for a real test or is omitted. CPU limits are published with the measurement method. | The host matches the assumption list for that claim. Feature checks are not lab efficacy. Job Object hard caps do not apply under RDS Dynamic Fair Share Scheduling. | This spec, [CLAIMS.md](CLAIMS.md), TRUST_GATES, fixture tests, and the twin `cpu_contract`. Live `verify_runtime` and an elevated ACL field proof remain UNCHECKED. The resident mode is measured scheduling unless a helper assignment reports `job_cap_applied`. |

### MVP sequence

| Priority | Build | Why | Breakage control |
|----------|-------|-----|------------------|
| **P0** | Defender health gate, MAPS check, do-no-harm (never displace Defender) | Later prevention depends on active Defender and cloud reachability | Fail closed to Windows defaults. Incomplete collection stays partial. |
| **P0** | Edition matrix and honest Home / Pro pathing | Stops Sandbox and App Control over-claims | Feature flags by edition |
| **P1** | ASR standard-protection Block, other rules Audit then promote; CFA Audit then Block; backup/restore states. **Shipped in 1.9.0** as observation plus a dual-gated one-step promotion. Not a backup product. | Highest OS prevention return on Home | Audit-first. WMI and non-standard rules are not blanket-Blocked. CFA copy stays modification-only. |
| **P2** | Firewall app-rule assistant; privileged helper with an unelevated UI; published CPU contracts. **Shipped in 2.0.0** as observation, a dual-gated `RESTRICT_NETWORK` apply, a loopback helper that refuses undefined operations, and measured-scheduling plus an optional helper Job Object cap. Not a second firewall. Not a Windows service. | Completes the host controls without a new driver | Propose, confirm, apply. One address family is warned. Job Object caps have DFSS/RDS limits and are not claimed when assignment fails. |
| **P3** | Sandbox `.wsb` launcher on Pro+ only. Home gets the “no Sandbox” checklist. TUF verification before any privileged auto-update. **Shipped in 2.1.0** as a dual-gated Open unfamiliar profile and an offline root/timestamp/snapshot/targets client. Not WDAG. Not Hyper-V on Home. Not a GitHub Release updater. Not a live measurement of the running process. | Isolation where the SKU has it. Update integrity before automation. | Home checklist only. Guest network stays LIMITED or UNKNOWN when it is not observed. A failed verification does not replace the installed file. |
| **P4** | KEV and OSV intel. abuse.ch opt-in with Auth-Key. Privacy assistant that leaves Defender cloud reachable. **Shipped in 2.2.0** as local-file feeds with provenance, inventory matches only when an inventory file exists, and a dual-gated privacy choice that re-reads the setting. Not a bundled abuse.ch dump. Not a block of MAPS, Windows Update, or CRL. | Context without a license violation | Provenance labels. A missing feed is `intel: unavailable`. Maps check is shown if a broad Microsoft block is requested, and no such rule is created. |
| **P5** | Passkey education, activity experiences, and the claims page. **Shipped in 2.3.0** as Everyday (quiet observation), Sensitive (tighter auto-protect, sooner CFA Audit and firewall proposals), and Open unfamiliar (the existing Sandbox path; Home checklist only). Not a phishing-impossible badge. Not a browser that changes accounts. Not a SYSTEM helper. | High value, no kernel change | Config cannot enable denylist actions or automatic CLOSE_PROCESS. Proposals stay unapplied until the dual gate. |
| **P6** | AMTSO-style efficacy tests, if a real test is ever run | Trust gates | 2.3.0 already publishes the claims table. Efficacy percentages stay omitted. |
| **Later** | Restricted autonomy (auto-block with undo and rate limits). Funding UX | Only after Audit data and a low false-positive record | A person approves high-impact actions. Donations never paywall P0–P2. |

### What 1.8.0 implements

P0 only, and only the read-only half:

- Defender health from `Get-MpComputerStatus`: AMRunningMode, real-time protection, antivirus signature age, `DefenderSignaturesOutOfDate`, and the observed engine version. Engine freshness stays UNKNOWN.
- MAPS via `MpCmdRun.exe -ValidateMapsConnection`. Exit 0 without a documented failure is pass. Elevation required (80070005), service disabled (800106BA), and unsupported OS (0x80070667) stay unavailable. A documented connection failure is fail. The text tells the user DVielle does not block Defender cloud endpoints.
- Edition matrix: ASR, CFA, and Firewall are edition-supported on Windows Home and Pro. Smart App Control is the `VerifiedAndReputablePolicyState` probe (0 off, 1 enforce, 2 evaluation) or UNKNOWN. Windows Sandbox is UNAVAILABLE on Home. App Control authoring is UNAVAILABLE on Home.
- The console evidence strip shows those states. Collector status `partial` is not rendered as active protection.

### What 1.8.0 does not claim

- Ransomware-proof because CFA might later be enabled.
- Enterprise WDAC authoring on Home.
- Sandbox, WDAG, or Hyper-V as a Home isolation product.
- Passkeys stop account takeover.
- A privacy mode that blocks Microsoft cloud services.
- “AMTSO verified” as a detection-rate claim.
- GitHub Release download as a secure privileged update.
- Bundled abuse.ch indicators.
- “Backup job succeeded” equals “restore will work.”
- A measured CPU contract. No universal percent is copied from another product.
- Smart App Control can be freely toggled back to Evaluation after an April 2026 update. That reversibility is UNKNOWN.
- An explicit Microsoft sentence that “CFA never blocks reads.” The documented scope is modification. Read protection is simply not claimed.

### Laws that stay in force

Dual mutate gate. Resident task RunLevel Limited. No `Add-MpPreference ExclusionPath`. No offensive tools. No elevated unattended / Highest change in this version. No App Control enforcement. ASR and CFA changes are user-approved, one rule or one CFA mode at a time, and counted as applied only when a second `Get-MpPreference` matches. Auto-protect cannot issue them. Firewall app rules use the same dual gate and count only when a second `Get-NetFirewallRule` matches. Auto-protect cannot issue `safety.restrict_network`. The helper does not stop MpsSvc and does not download updates. Open unfamiliar is user-approved and does not run on Home. TUF verification does not enable privileged auto-update. Camera in-use on Windows stays unknown. The footprint collector stays empty. Unknown stays unknown.

---

## 2. Non-negotiable ethics (product law)

| Rule | Meaning |
|------|---------|
| Scope | Only the machine / accounts where DVielle is installed and the user controls. |
| Authorized self-assessment | “Ethical hacking” = posture assessment + safe remediation of *this* host. Not offensive tooling. |
| Default | `monitor_only` / observe-first. Mutations are opt-in or Auto-protect only. |
| Fail closed | If confidence is low or identity of a target is unclear → ask or skip; never guess-mutate. |
| Honesty | Unknown = say unknown. Prefer the next best **working fix**. Never fake a resolution. Windows Home toggles ≠ proof traffic stopped; AI “trained on your file” needs evidence we usually won’t have — still offer block/allow/settings fixes. |
| No data theft by us | No uploading twin dumps, files, chats, or screenshots. The optional cloud-LLM chat path was removed in 2.3.3. |
| Public repo trust | No exploit kits, credential dumpers, outbound attack tools, or “hack back.” |

**Never ship:** exploit PoCs/payloads, mass external scanners, password cracking/dumping, unauthorized lateral movement, silent training on user data.

---

## 3. Pillars (the brain) — each ends in a resolution

1. **Safety** — threats / protection health / persistence / auth → **keep-on learned; options when suspicious → secure**  
2. **Speed** — slowness causes → **known hogs allowed or fixed via options → usable again**  
3. **Privacy & internet** — chatty Microsoft/other apps → **keep-on / block learned; options when unexpected**  
4. **AI data watch** — AI uploading for vendor improvement → **allow/block learned; options when unexpected**  
5. **Storage** — disk pressure / temp junk → **options to free space (safe list) → resolved**  
6. **Footprint** — online exposure → **Resolution Center options + partner paths**  
7. **Camera** — webcam/USB → **keep-on apps quiet when open; options when not / suspicious → act**

Shared pipeline for all pillars:

`Observe → Match learned keep-on → If expected: quiet → If not: Simple English options card → User selects → DVielle performs → Resolved / Monitoring → Log (+ Undo when possible)`

**Doctrine:** no finding without a next fix. No ask_user mutation without an options selection. If the best fix is a specialized website/service (broker removal, dark-web monitor), DVielle opens that path as an option and tracks status — it does not stop at “be careful.”

---

## 4. Finding model

Every finding carries at least:

- **pillar** — safety | speed | privacy | ai_data | storage | footprint | camera  
- **title_simple** — one line a non-tech user understands  
- **why_it_matters** — one short paragraph  
- **evidence_refs** — pointers into twin/store (timestamps, process identity, counters)  
- **severity** — low | medium | high | critical  
- **confidence** — low | medium | high  
- **recommended_action** — the primary fix  
- **resolution_steps** — ordered fixes (local and/or partner)  
- **resolution_status** — `found` | `in_progress` | `resolved` | `monitoring` | `dismissed`  
- **action_class** — `ask_user` | `auto_protect_eligible` | `partner_path` | `observe_only`  
- **options[]** — selectable actions for this finding (label + what DVielle will do); required when `ask_user`  
- **subject_identity** — app/process/path/setting the keep-on decision attaches to (when applicable)  
- **keep_on_match** — `allowed_and_expected` | `denied` | `unknown` | `suspicious_mismatch` | `n/a`  
- **reversible** — yes | partial | no (temp deletes are often “no” or “partial”)

**Ranking for attention:** critical+high-confidence first; low-confidence stays in Activity/log unless user opens Details.  
**Done means:** status is `resolved` or `monitoring` with a clear next check — not merely “user saw the popup.”  
**Quiet means:** `keep_on_match == allowed_and_expected` → no popup (optional Activity note).

---

## 5. Alert policy (when to speak)

Speak only on **real need**. Cry-wolf kills the product.

### Lanes
| Lane | Examples |
|------|----------|
| Slowing you down | Memory/CPU hog, startup pile-up, disk thrash |
| Privacy / internet | Sudden egress spike, chatty unknown app, Microsoft telemetry-heavy use (honest limits) |
| AI data | AI helper uploading while reading personal content / steady AI-cloud pipe |
| Safety | Repeated failed sign-ins, protection off, suspicious new persistence (high confidence) |
| Storage | Free space critically low; large reclaimable safe temp |
| Camera | Camera on while no allowed app is open; unknown process using camera; allowed app name claimed but that app is not running |

### Gates (all should pass for a popup)
- Severity ≥ medium **or** critical storage/safety threshold  
- Confidence ≥ medium (safety auto actions require **high**)  
- Cooldown: same issue updates one card; no spam every minute  
- Under extreme load: prefer tray/badge unless critical; defer DVielle’s own heavy work  

### Decision UI (behavior, not pixels) — all pillars
Every user-facing alert is an **options card**: the user must select one option; DVielle then performs that choice (or starts the partner path). No silent mutation on ask_user findings.

**Universal minimum options** (every pillar):

- **This is OK — keep on / allow** — remember subject as allowed; stay quiet next time when expected  
- **Fix it for me** — run the recommended resolution (or start the partner path)  
- **Not now** — snooze with cooldown; Monitoring  
- **Never for this** — stop nagging this subject / finding type; still log quietly where useful  
- **Show me why** — one plain paragraph + evidence  

**Plus pillar-specific action options** (Safety, Speed, Privacy, AI, Storage, Footprint, Camera — see §5.1 and each pillar section).  
After the user selects, DVielle **performs** the chosen action, logs it, updates keep-on memory if relevant, and sets the ticket to Resolved / Monitoring.  
Auto-protect actions always produce an after-the-fact notice: what we did, when, Undo if possible.

---

## 5.1 Universal keep-on + options-then-act (all pillars)

This is the product interaction model for **Safety, Speed, Privacy, AI data, Storage, Footprint, and Camera** — not Camera alone.

### Loop
1. **Observe** activity on this machine.  
2. **Match** against the user’s learned **keep-on** decisions (allow / deny / ask-always) for that subject (app, process family, setting, cleanup class, partner path, etc.).  
3. If **allowed and expected** (e.g. allowed app is actually open / known hog user accepted / accepted Microsoft channel during Update) → **stay quiet** (optional Activity note).  
4. If **first time**, **denied**, **unknown**, or **suspicious mismatch** (activity looks like an allowed thing but that thing is **not** actually present / open / in the expected state) → open a resolution ticket and show an **options card**.  
5. User **selects** one option.  
6. DVielle **performs** that option (local fix, OS settings deep-link, partner path start, or remember-and-quiet).  
7. **Learn** the decision into local keep-on memory; log; Undo when possible.

### Keep-on memory (local)
- Files under `data/learn/` (e.g. `keep_on.txt` plus pillar files such as `camera_allow.txt`, `privacy_allow.txt`, `ai_allow.txt`, `speed_allow.txt`, `safety_allow.txt`).  
- Fields: pillar, subject identity, decision (`allow` | `deny` | `ask_always` | `never_warn`), timestamp, optional notes.  
- Aggregates only where possible; no screenshots, no camera frames, no cloud upload of these decisions by default.

### Suspicious / unexpected (when to speak even if a name looks familiar)
| Pillar | Example of “suspicious / not expected” |
|--------|----------------------------------------|
| Safety | New startup that looks like a known app but path/signature differs; protection off when user expected it on |
| Speed | Heavy CPU from an app the user did **not** mark keep-on; or named app “busy” but process identity doesn’t match |
| Privacy | Big egress attributed to App X while App X is **not** open; or unknown app phone-home |
| AI data | AI upload pipe while no AI app the user allowed is running; or new AI helper never seen |
| Storage | Disk critically low; large reclaimable junk (always options — cleanup is never silent unless Auto-protect critical) |
| Footprint | New breach/broker hit; exposure ticket not yet resolved |
| Camera | Camera on while allowed app is **not** open; unknown process; mismatched attribution |

### Options shape (same format everywhere)
Plain English: what’s happening → why it matters → what we suggest.  
Then a **list of selectable actions**. User picks **one**. DVielle runs it.

| Common option | Meaning |
|---------------|---------|
| Keep on / Allow | Learn allow; quiet when expected next time |
| Fix / Stop / Block / Clean / Open settings / Start partner | Concrete resolution for this pillar |
| Not now | Snooze |
| Never for this | Persist never-warn for this subject |
| Show me why | Evidence |

### Per-pillar option catalogs (v1 required sets)

**Safety** — Keep protection as-is (if on and OK) · Turn protection back on · Disable this startup · Smart Close this process · Open security settings · Not now · Never for this · Show why  

**Speed** — This is OK (keep on while I work) · Pause / Smart Close this app · Disable at startup · Not now · Never warn for this app · Show why  

**Privacy & internet** — Allow this app’s internet (keep on) · Block this app’s network · Open privacy / firewall settings · Not now · Never for this · Show why  

**AI data** — Allow this AI app (keep on) · Block this AI app’s internet · Open “improve the model” / privacy settings · Not now · Never for this · Show why  

**Storage** — Free safe temp space now · Preview what will be cleaned · Empty Recycle Bin (ask) · Not now · Never auto-clean · Show why  

**Footprint** — Start local lockdown steps · Check breach (opt-in email) · Open DIY opt-out · Start / open partner removal or monitoring · Mark resolved / still monitoring · Not now · Show why  

**Camera** — Allow this app (keep on) · Stop this app’s camera use · Turn off camera access for this app · Cover-lens reminder · Turn camera off in system settings · Not now · Never warn · Show why  

### Auto-protect vs this loop
Auto-protect is a **tiny** emergency bypass of the options card (see §7.2). Default remains: **options first, then act**. Camera and any call-breaking action stay options-only unless the user later pins an explicit Auto-protect rule.

---

## 6. Simple English voice (required)

Every user-visible message answers:

1. What’s wrong  
2. Why it matters  
3. What we suggest  
4. What happens if ignored (brief)

No raw event IDs, CVE dumps, or jargon in the primary text. Technical detail only behind “Show me why” / Details.

**Digital footprint teaching:** light, situational (first AI/privacy alert + quiet periodic summary) — not a course.

---

## 7. Actions: user vs Auto-protect

### 7.1 User always decides (default)
- Close / pause a process (Smart Close: fresh identity check)  
- Block an app’s network / apply firewall helper rules  
- Apply privacy/hardening scripts  
- Disable startup items  
- Clean beyond the safe temp allowlist  
- Recycle Bin / browser cache (ask; optional)  
- Anything that can break Wi‑Fi, banking, updates, Store, or work tools  

### 7.2 Auto-protect allowlist (opt-in at install or Settings)
User must enable: *“Allow DVielle to take a few emergency steps to protect this PC.”*

| May auto (only if opted in + high confidence + identity OK) | Notes |
|------------------------------------------------------------|--------|
| Re-enable clearly disabled core protection (e.g. Defender realtime / Firewall *profile* on) when detected off | Notify + log; do not invent aggressive custom blocklists |
| Pause/isolate a process that matches **high-confidence local safety rules** with verified identity | Same identity bar as Smart Close; then notify |
| Safe temp cleanup when free space is **critically low** | Only §8 allowlist; skip locked files; notify how much freed |
| Defer DVielle’s own heavy collectors under extreme load | Always allowed (self-throttling); not really “mutation” |

### 7.3 Auto-protect denylist (never alone)
- Delete Documents/Desktop/Downloads/Pictures or project trees  
- Blanket “block all Microsoft” or break Windows Update/Store/Defender channels by default  
- Mass process kill  
- Arbitrary firewall rule churn  
- Force-delete locked files  
- Quarantine/delete user documents “to save them”  
- Any offensive / exploit-style action  
- Upload user data to cloud for “AI improvement”  

---

## 8. Storage — safe temp cleanup

**Goal:** free space from leftover junk without reckless cleaner behavior.

### Safe clean allowlist (initial)
- User and system Temp directories (not-in-use files only)  
- Known Windows reclaimable caches that are documented safe (conservative list; expand only with tests)  
- Optional (always ask unless user pinned preference): Recycle Bin, browser caches  

### Rules
- Measure **before**; show reclaimable estimate; report **after** (freed / skipped in-use)  
- Skip locked files; never force  
- Not fully undoable — say so once, clearly  
- Do not classify “large file” as temp merely because it is large  
- Under load: gentle pass; don’t thrash disk for an hour  

### Triggers
- User: “Free up space” / Storage pillar action  
- Auto: only if Auto-protect on **and** free space below critical threshold  

---

## 9. Privacy, Microsoft, and AI data watch

### Privacy & internet
- Visibility: which processes talk out, volume over time, grouped destinations when known  
- Recommendations: allow / block / remind later  
- Honesty: registry/privacy toggles may not stop all telemetry traffic (especially Windows Home)

### AI data watch
**Detect (honest signals):** process + outbound to known/likely AI cloud endpoints; volume; steadiness; coincidence with reading many personal paths (signal, not proof of training).  

**Do not claim:** “They trained their model on your tax PDF” unless you somehow have vendor-proof (you won’t). Prefer: “This AI app appears to be sending data to an online AI service. Companies sometimes use that to improve their AI.”

**Actions:** ask to allow / block network for now / never warn for this app; Auto-protect only for high-confidence *new unknown* helpers that immediately heavy-upload **if** that rule is explicitly enabled (default off even inside Auto-protect).

---

## 10. Speed pillar

- Detect top CPU/RAM/disk/network consumers and heavy startup  
- Explain in plain English why the machine feels slow  
- Recommend: defer / Smart Close / startup trim — user gated  
- DVielle must **not** be the slowdown: workload deferral when the machine is under pressure  

---

## 11. Safety pillar (ethical self-assessment)

Compose existing/observe collectors into ranked posture findings, e.g.:

- Auth failure patterns  
- Listening exposure / risky connectivity (explain, don’t exploit)  
- Persistence anomalies  
- Defender/firewall health  
- Resource abuse that looks like malware-ish pressure (confidence-gated)

Remediation = recommend + user approve, except tiny Auto-protect set in §7.2.

---

## 12. Activity, logging, Undo

- Every user action and Auto-protect action is logged with time, finding id, result  
- Prefer Undo for network blocks / protection toggles / process pause where OS allows  
- Temp deletion: log sizes and paths categories; Undo usually unavailable — disclose  

Quiet periodic summary (e.g. weekly): top internet users, AI-related egress, slow periods, space freed — simple English.

---

## 13. Profiles

| Profile | Popups | Auto-protect |
|---------|--------|--------------|
| **Laptop / home (v1)** | Guided, simple English | Opt-in; small allowlist |
| **Server (later)** | Minimal; admin-oriented | Almost none by default; policy-driven change control |

Same evidence engine; different autonomy + voice.

---

## 14. Out of scope for this Function Spec

- Futuristic visuals, animation, tab chrome, branding polish  
- Cloud LLM chat as the “brain”  
- Full multi-engine architecture wishlist beyond what findings need  
- Offensive security capabilities  

Design may follow **after** this brain is trustworthy in implementation.

---

## 15. Implementation alignment (existing codebase — guidance only)

Prefer extending current patterns rather than inventing a second owner:

- Headless owner: `python -m agent.main` / Nerve collectors → SQLite + `twin.json`  
- Console attaches via controller; mutations through policy gate / handlers  
- Keep autonomous nerve action registry fail-closed; register only approved handlers  
- `docs/AUTONOMY.md` remains the honesty doc for gaps (signature trust, baselines, etc.)  
- Disk cleanup / firewall mutation / RAM trim stay off until wired to this spec’s gates  

*(Exact code changes are a later build phase; this file freezes product behavior.)*

---

## 16. Acceptance checks (function done when…)

1. Findings exist for all five pillars with severity/confidence and simple English fields.  
2. Alerts fire only when gates pass; cooldowns prevent spam.  
3. User decision path works for Fix / Not now / Never / Why.  
4. Auto-protect is opt-in and limited to §7.2; denylist §7.3 never runs alone.  
5. Safe temp clean frees space only from allowlist; reports skipped in-use files.  
6. AI/privacy alerts use honest wording (no false “trained on your file” claims).  
7. No user data leaves the machine unless user explicitly enables a stated cloud feature.  
8. Under load, DVielle defers its own heavy work.  
9. Activity log shows protections and user choices.  

---

## 17. Decided product line (README-ready)

> Windows-primary local guardian (Linux and macOS limited-mode): find what’s wrong and **drive it to a fix** — safety, speed, privacy, AI data shipping, disk junk, online footprint, and camera use — in simple English. You stay in control. Camera on Windows is not available yet. Footprint hits are not invented. Partners handle heavy internet removals/monitoring when needed; we track resolution to done. We don’t use your PC’s data to train AI.

---

---

## 18. Continuous local self-learning (unique per machine)

Every user, work pattern, installed software set, and usage rhythm is different. DVielle must **learn continuously on-device** what “normal” looks like for *this* laptop/computer/server — then use that baseline to spot real problems with fewer false alarms.

### What we learn (aggregates only — not private content)
| Domain | Examples of learned signal |
|--------|----------------------------|
| Speed | Typical CPU/RAM by hour/weekday; usual top apps; normal startup cost |
| Privacy / internet | Usual egress volume; apps that normally talk out; quiet vs busy hours |
| AI data | Which AI apps exist; their usual upload pattern when user is actually using them |
| Storage | Normal free-space floor; how fast temp grows |
| Safety | Usual login success pattern; known-good persistence set; normal listening ports |
| Work pattern | Active hours; docked vs battery-ish load shapes (coarse); server vs interactive |

**Do not store in learning files:** keystrokes, document contents, chat prompts, passwords, screenshots, full URLs with secrets, clipboard, or anything that would let someone reconstruct the user’s private work. Prefer counts, hashes of process paths, app names, buckets, and percentiles.

### Why this is “intelligent”
- First week: mostly observe + gentle learning; fewer aggressive alerts.  
- Over time: “Chrome using 2 GB at 9pm is normal for you” vs “unknown helper uploading 800 MB at 3am is not.”  
- Server profile: learn service baselines; almost no consumer-style popups.

### Learning store format: `.txt` (space-first)
All durable learning lives under something like:

`data/learn/` (exact path at implement time)

Plain UTF-8 `.txt` files, one concern per file (easy to inspect, diff, and trim):

| File | Role |
|------|------|
| `baseline_speed.txt` | CPU/RAM/startup norms |
| `baseline_network.txt` | Usual apps + volume buckets |
| `baseline_ai.txt` | Known AI helpers + usual behavior |
| `baseline_storage.txt` | Free-space / temp growth norms |
| `baseline_safety.txt` | Known-good persistence / listen set (names/paths only) |
| `baseline_schedule.txt` | Active hours / quiet hours |
| `allow_never.txt` | User “Never for this” preferences |
| `auto_protect.txt` | Opt-in flags + last auto actions summary |

**Format rules (keep files tiny):**
- Line-oriented `key=value` or simple `key|value|updated_iso` — no JSON blobs of histories  
- Update in place; do **not** append forever  
- Cap each file (e.g. soft max **256 KB**, hard max **1 MB**); if over, rewrite compressed summary (keep last N keys / top apps only)  
- Atomic replace (write temp → rename) so a crash doesn’t corrupt learning  

Learning is **local only**. Never upload these files to train cloud AI. Optional export for support only if the user explicitly chooses it.

### Learning loop
1. Collectors observe → short-lived evidence (existing twin/store as needed).  
2. Learner updates `.txt` baselines on a schedule / after calm periods (defer under load).  
3. Ranker compares live signals to baselines → findings with better confidence.  
4. User “Never for this” / “Allow” writes into preference `.txt` immediately.

This closes the “learned baselines” gap called out in `docs/AUTONOMY.md` without a heavy ML pack.

---

## 19. Logs in `.txt` — one log family per pillar / tab

For space and clarity, **user-facing and issue logs are plain `.txt`**, split by concern (aligns with future tabs even while UI is later):

Suggested layout:

`data/logs/`

| File | Pillar / purpose |
|------|------------------|
| `safety.txt` | Threats, protection changes, auth anomalies |
| `speed.txt` | Slowness findings and user/auto responses |
| `privacy.txt` | Egress / Microsoft / chatty-app events |
| `ai_data.txt` | AI upload watches and decisions |
| `storage.txt` | Disk pressure, temp cleans, space freed |
| `autoprotect.txt` | Every Auto-protect action |
| `activity.txt` | Short unified timeline (optional thin index: time + pillar + one line) |
| `errors.txt` | DVielle’s own failures (so we don’t hide bugs) |

### Log rules (space discipline)
- One event ≈ **one line** (timestamp + level + short message). Details stay in evidence/twin if needed — not novel-length log rows.  
- **Rotate by size and age** (example defaults): max **1–2 MB per file**, keep **last 3 rotated** (`safety.txt.1`, …) or purge older than N days — pick at implement; document in Settings later.  
- No binary logs for these streams.  
- Under low disk: stop verbose logging first; keep `autoprotect.txt` and `errors.txt` longest.  
- Same honesty: logs stay on device; not phone-home.

### Relationship to SQLite / twin
- Existing `agent.db` / `twin.json` may remain for structured live state **if** kept bounded (retention already in store).  
- **Do not** grow a second huge parallel history in both DB and txt. Prefer: live/structured in DB or twin with retention; **human issue history and learning** in compact `.txt` as specified here.  
- If DB size becomes a problem on free installs, a later pass may slim history toward txt-first — call that out in implementation, don’t silently balloon both.

---

## 20. Extra intelligence rules (added)

1. **Per-profile learning** — Laptop vs Server baselines are separate modes; don’t mix a gaming evening pattern into a server service baseline.  
2. **Cold start** — Until enough samples exist, prefer ask-user over Auto-protect; label confidence lower (“still learning your PC”).  
3. **Concept drift** — If the user installs a major app or changes schedule, baselines adapt gradually (or reset a domain after explicit “I’m changing how I use this PC”).  
4. **Self-space budget** — DVielle’s `data/learn` + `data/logs` combined should stay under a published cap (target: **tens of MB**, not hundreds). If over: rotate/summarize before alerting about *other* apps’ disk use.  
5. **User-readable** — Advanced users can open any `.txt` in Notepad; that builds trust for a free repo.

---

## 21. Acceptance checks (additions for v0.1)

10. Baselines update over time in `data/learn/*.txt` without storing private document/chat content.  
11. Issue logs exist as separate `.txt` files per pillar (+ autoprotect/errors) with rotation/size caps.  
12. After a learning period, identical “normal for you” behavior does not spam alerts; true deviations still can.  
13. Learning/logs never leave the machine unless the user explicitly exports.  
14. Combined learn+logs footprint stays within the published space budget (or DVielle self-trims first).

---

---

## 22. Execute learnings — adaptive self-upgrade (safe definition)

Learning is useless if it only sits in `.txt` files. DVielle must **apply** what it learns so the running app gets smarter for *this* machine.

### What “self-upgrade / self-implement / self-modify” means (allowed)
The app **self-tunes its behavior and configuration** from `data/learn/*.txt`, for example:

| Learning signal | Adaptive action (local) |
|-----------------|-------------------------|
| User’s quiet hours | Run deep scans only then; stay lighter in active hours |
| Machine often under CPU/RAM pressure | Lower collector frequency; longer deferrals; smaller batches |
| Powerful/idle machine | Allow slightly richer observation within caps |
| “Never for this” preferences | Suppress that alert class permanently (until reset) |
| Known-good apps / normal egress | Raise confidence bar before privacy/AI popups |
| Server vs interactive use | Switch profile: fewer popups, stricter change control |
| Repeated false-ish signals | Demote that detector’s weight until evidence strengthens |
| Disk space budget pressure | Tighten log rotation and learning file caps automatically |

These adaptations are written as **control `.txt` / config overlays** (e.g. `data/learn/runtime_tune.txt`, `data/learn/schedule_tune.txt`) that the runtime reads every cycle — so the app “upgrades itself” for this user **without** shipping a new installer every time.

Optional later: offer **user-approved** update of the installed app from the official free repo (version bump). That is a normal update channel — not the learner rewriting code.

### Default rule (always)
Learnings change **policy, thresholds, schedules, and resource budgets** via `data/learn/*_tune.txt`. This path needs **no** extra consent beyond normal install.

Cold start: adaptations start gentle; more Auto-protect-class autonomy only after baselines are stable and opt-in remains on.

### Optional: Deep personalization (“grow with this machine’s personality”)
Some users want the app to go further and **implement personality-specific behavior modules** for their system. This is **allowed only as an explicit advanced option**.

| Control | Requirement |
|---------|-------------|
| Default | **OFF** |
| Enable | User turns on “Deep personalization” in Settings |
| Double verify | Second confirm dialog stating risks + what folder may change; must type/confirm **Agree** again |
| Scope | Writes only under a sandbox: `data/personality/` (modules, rule packs, local hooks) — **not** overwriting core install/binaries under the program directory |
| Review | Before apply: show short plain-English summary of what will change; user Confirm #2 |
| Rollback | One-click “Disable deep personalization & restore defaults” removes/ignores sandbox modules |
| Log | Every apply → `autoprotect.txt` or `activity.txt` + `data/logs/personality.txt` |
| Network | Still **no** downloading unexplained remote code to “self-edit”; modules are generated/updated **locally** from learnings + allowed templates |
| Safety | Sandbox modules cannot bypass Auto-protect denylist (§7.3) or ethics (§2) |

**Still blocked even when Deep personalization is ON:**
- Silent rewrite of core `.py` / signed binaries / installer without the double-confirm flow  
- Remote phone-home training that pushes control back to the machine  
- Using deep personalization to perform denylisted system mutations  

**Beneficial growth (intended):** per-user detector weights, custom quiet schedules, host-specific resource governor, optional local rule modules that encode “how this PC is used” — so the app’s *behavior personality* matches the individual Windows/Linux/macOS machine, while core code stays inspectable and updateable via normal releases.



---

## 23. Background load governor (protect the host from DVielle)

DVielle runs whenever the machine is on. It must **define and enforce how much load it may use** so it does not become the reason the CPU feels bad.

### Fixed safety caps (always on)
- Hard ceilings on CPU %, memory MB, and disk IO for the agent process group (platform-appropriate measurement).  
- When the machine is busy (user load high): **defer** non-critical collectors (existing workload philosophy — make it first-class and learned).  
- When the machine is cool/idle: may do deeper learning passes within caps.  
- Never spin hot loops; prefer event/timer driven work.  
- GUI/demo must not run a second heavy owner (single monitoring ownership stays).

### Learned load budget (from usage pattern)
From `baseline_speed.txt` + live pressure, maintain `runtime_tune.txt` fields such as:

- `max_cpu_percent_idle` / `max_cpu_percent_busy`  
- `collector_interval_scale` (1.0 normal → 2.0+ when busy)  
- `deep_scan_allowed` (true only in quiet windows)  
- `learning_pass_allowed`  

If DVielle approaches its own cap: shed work, log one line to `errors.txt` or `speed.txt` (“DVielle reduced its own load”), do not fight the user for CPU.

**Acceptance feel:** after install, users should not notice DVielle in Task Manager as a top consumer during normal work.

---

## 24. Operating system awareness and multi-OS goal

### Identify OS and adapt
At start (and on major change), detect:

- Family: Windows / macOS / Linux (and later others if feasible)  
- Edition/version where useful (e.g. Windows Home vs Pro — honesty about privacy limits)  
- Form factor profile: laptop | desktop | server (user or heuristic)

Collectors, logs, Auto-protect actions, and wording **switch by OS adapter**. Same five pillars; different sensors.

### Platforms for this product version
**Windows is primary.** Linux and macOS are limited-mode: the shared keep-on brain can run, and any sensor that is not implemented stays unknown. This version does not claim live feature parity on three operating systems.

One shared brain (pillars, learning `.txt`, logs `.txt`, alert gates, load governor, ethics, optional deep personalization).  
Where an OS adapter exists, use it. If a sub-feature is not ready, show a limited-mode note — never call Windows-only APIs on Linux/macOS, and never invent a reading.

| Family | Notes |
|--------|--------|
| **Windows** | Existing agent baseline; Defender/firewall/auth events where available; Home vs Pro honesty |
| **Linux** | proc/net/systemd (or service manager) adapters; no Windows Event Log dependency |
| **macOS** | Permission honesty (e.g. Full Disk Access / notifications); adapter-based collectors |

**Out of scope unless later agreed:** mobile OS (iOS/Android), obscure BSDs, etc.

README claim for this version: Windows-primary, with Linux and macOS named as limited-mode. “Works on Windows, Linux, and macOS” is not a claim until each adapter is installable and smoke-tested.

Shared across OS:
- Function Spec pillars, alert gates, learning `.txt`, log `.txt`, load governor, no data theft by us, optional deep personalization sandbox  
Different per OS:
- How we observe (APIs), how we remediate safely, installer, tray/notifications  

Server on any OS: same brain, quieter UI, stricter auto actions (see §13).

---

## 25. Acceptance checks (additions for v0.2)

15. Learnings change runtime tune files (intervals, quiet hours, suppressions, load caps) and the running agent honors them by default without touching core install files.  
16. Under user load, DVielle CPU stays within published busy caps; evidence in logs when it self-throttles.  
17. OS family is detected; Windows, Linux, and macOS each have an adapter path (full or clearly limited — never wrong-OS APIs).  
18. Deep personalization defaults OFF; enabling requires double verification; changes confined to `data/personality/` with rollback and logging.  
19. With deep personalization OFF, no personality modules load and behavior matches tune `.txt` only.  
20. Product docs list Windows, Linux, and macOS as targets for this version and accurately state feature parity per OS.

---

---

## 26. Free distribution vs reverse-engineering / resale (honesty + strategy)

### Hard truth (must stay in docs/README mindset)
If users run DVielle on their machine, **it cannot be made undecodable**. Determined reverse-engineering of any client app is always possible. Anyone claiming “impossible to crack/decode” is selling false certainty.

Your real risks as a **free** publisher:
1. Someone copies the idea/UI and sells a rip-off.  
2. Someone repackages your build and sells it.  
3. Someone forks and strips credit / injects malware (hurts your brand).

### Choose a distribution model (product decision)
These conflict — pick deliberately:

| Model | User gets | Remake/resale risk | Notes |
|-------|-----------|--------------------|-------|
| **A. Public open-source repo** | Full source | Highest for “remake” (source is there) | Best trust for a security app; fight resale with **license + trademark + brand**, not secrecy |
| **B. Free proprietary binary** (source not public, or delayed) | Free installer | Lower casual copy; skilled RE still possible | Use license forbidding commercial resale; technical packaging/obfuscation raises cost of theft |
| **C. Open-core** | Core ethics/engine docs + some modules open; premium/hardened build free or paid | Balanced | Common for security tools |

**Recommendation (advisory only, not locked):**  
- Prefer **B or C** if commercial rip-offs are the main fear.  
- If you keep a **public GitHub repo of all code (A)**, accept that remakes are easy; win on **official brand, updates, trust, and license**. Do not promise unreproducibility.

**Decision status (2026-09-26): DEFERRED.** Owner chose to keep options open. Do **not** lock the repo, packaging, or license to A, B, or C until they explicitly pick one. Implementation may proceed on product behavior; release/distribution stays configurable. When chosen, record the model here and in release docs.

### Legal / brand protections (do these regardless)
- Clear **LICENSE** (e.g. proprietary freeware terms, or GPL/AGPL/Apache with explicit no-warranty; if proprietary free: “free for personal/org use; **no commercial resale/rebrand**”)  
- **Trademark** the name DVielle / DEEP VIGILLANCE where practical  
- Copyright notices in UI, installer, About, logs header  
- README: official download only from *your* site/repo; warn that third-party paid copies are unauthorized  
- Optional: simple “About → Official build” checksum / version attestation page you control  

Legal friction stops many sellers even when technical RE is possible.

### Technical hardening (raise cost of casual theft — not magic)
High-level only; details at implement time:

- Ship **release builds** as frozen/compiled artifacts per OS (not a loose editable source tree on end-user machines) when using model B/C  
- Prefer packaging that is harder than “open the `.py` folder” for normal users  
- Keep **secrets out of the client** (there should be almost none; local guardian)  
- Do **not** rely on security-through-obscurity for user safety ethics — ethics and Auto-protect rules stay enforced in logic users can still trust  
- Optional integrity check: detect tampered official binary and warn (“build modified — download official”) — honesty, not DRM theater  
- Avoid heavy DRM that breaks offline use, privacy goals, or looks hostile to legitimate free users  

**Still impossible to guarantee:** a skilled person unpacking/decompiling a build, or reimplementing from behavior. Plan for that with license + brand.

### What we will not do
- Promise “cannot be reverse-engineered” in marketing  
- Add invasive phone-home license servers that fight the “we don’t steal data” promise (unless user opts into a separate paid channel later)  
- Weaken on-device privacy to enable DRM  

### Acceptance checks (v0.4)
21. Distribution model stays **deferred** until the owner picks A/B/C; then it is written in this spec and release docs. Until then, do not assume public source or private binary.  
22. LICENSE explicitly addresses commercial resale/rebrand.  
23. Marketing does not claim the app is undecodable/un-reversible.  
24. Official build attestation or checksum page exists (or is ticketed before public free launch).

---

---

## 27. Digital footprint — Resolution Center (solutions first)

**Current build:** `collect_footprint_facts()` returns no rows. Remote kinds (breach, broker, public search, dark web) are drill tickets only and must be marked synthetic before a ticket opens. The collector does not invent hits.

**Product stance:** Users want **find → fix → verify**, not a lecture. DVielle’s job is to drive **resolutions**. Specialized websites/services already do deep broker scanning, opt-outs, and dark-web *monitoring* (Aura, LifeLock/Norton, DeleteMe, Incogni, REMOVE, and similar). We treat those as **solution partners**, not competitors we dismiss — and as the engines for heavy internet-side research a local free app cannot rebuild overnight.

**How the industry actually solves this (so we solve with them):**  
- Broker removal services scan large known broker/people-search catalogs, submit opt-outs (API/forms/CCPA-style demands), and **rescan** because data reappears (Aura, LifeLock, DeleteMe, Incogni, REMOVE, etc.).  
- Dark-web / exposure monitors watch identifiers the user enrolls and **alert + remediation steps**; they do not magically delete every copy on earth (Aura’s own help notes that once data is out, removal from the dark web itself often isn’t possible — the solution is lock down accounts, freeze credit, change credentials).  
DVielle’s unique free value: **local machine control + simple English + a Resolution Center that tracks every fix to done**, and opens the best next solution (local action or partner service).

### Resolution pipeline (what we ship)
Every footprint item is a ticket: **Found → Recommended fix → In progress → Resolved / Monitoring**.

| Layer | Solution DVielle drives |
|-------|-------------------------|
| **This PC** | Sign-out unused accounts, revoke app sessions, tighten browser/OS privacy — DVielle can open settings and walk the user to **done**. |
| **Breaches (HIBP / similar)** | Opt-in email check → for each hit: change password, turn on 2FA, stop reuse — checklist marked resolved when user confirms. |
| **Public web (DIY)** | Guided self-search + Google Alerts; each finding gets a remove/opt-out/request-takedown step with status. |
| **Account dashboards** | Deep-link Google / Microsoft / Apple privacy tools; track “opened / completed checkup.” |
| **Brokers & people-search** | **Resolution path:** connect user to a removal partner (DeleteMe, Incogni, Aura, LifeLock, REMOVE, etc.) OR a built-in broker checklist for free DIY opt-outs where links are stable. Prefer partnership/API when available so DVielle shows **removal status**, not only “go elsewhere.” |
| **Dark-web style exposure** | Do not fake our own dark-web crawler on day one. **Solution:** partner monitor (or user-chosen service) + DVielle turns every alert into local resolutions (password, bank, credit freeze links, session revoke). |
| **Ongoing** | Rescan schedule + “still exposed?” so the app keeps working after the first cleanup. |

### Build order (solutions, not theater)
1. Resolution Center UI/data model + local PC + HIBP resolutions.  
2. Official dashboard deep-links with completion tracking.  
3. Broker DIY opt-out playbooks where free removal links exist.  
4. Partner integrations for automated broker removal / monitoring (so we deliver the same class of outcome those websites sell — through them or with them).  

### Still refuse (ethics, not defeatism)
- Looking up **other people** (stalkerware).  
- Storing user PII on our servers by default.  
- Marketing “we scrape and erase the entire internet alone inside this free local binary.” That isn’t how DeleteMe/Aura/LifeLock work either — they are cloud ops + lists + rescans. We win by **orchestrating real resolutions**, including those engines.

### Log
`data/logs/footprint.txt` — findings and **resolution outcomes**.  
`data/learn/baseline_footprint.txt` — progress state (checklist/partner enrolled), not raw PII dumps.

### Simple English (solution voice)
“We found your email in a known breach. Let’s change that password and turn on 2FA — I’ll walk you through it.”  
“Your name shows up on people-search sites. Free path: we’ll open each opt-out. Faster path: connect a removal service that keeps re-removing when they put you back.”  
“If something shows up in a dark-web alert from your monitor, here’s how we lock the account on this PC and your bank/email next.”

---

## 28. Camera Guard (webcam / USB camera — user decides, then we act)

**Current build:** Camera in-use detection on Windows is not available yet. The Windows collector returns unknown and stores no picture. Do not describe a live Windows camera watch in this version. Linux `/dev/video*` links are best-effort. macOS is limited-mode.

**Added because:** users fear the camera is on and streaming.  
**Hard limit:** software cannot guarantee a camera was never compromised (firmware, kernel, physical access). A **hardware shutter or cover** plus **OS camera off** is the strongest practical block (Microsoft camera privacy guidance: shutters must work in hardware because software can be compromised).

### Device classes (do not mix them)
| Class | v1 scope |
|-------|----------|
| Built-in webcam + USB webcam | **Yes — Camera Guard** |
| Network/IP cameras on the LAN | **Later, separate.** Different problem (device firmware, default passwords, cloud). Do not pretend laptop camera APIs cover them. |

### Core rule: the user decides what stays allowed
1. When DVielle first sees an app using the camera (or the user opens Camera settings), it asks in plain English whether this app is **OK to keep using the camera**.
2. The user’s choice is **remembered** locally (learned allow / deny / ask-always).
3. Allowed apps = “keep on” list the product learns from the user — e.g. Zoom, Meet, Teams if they said yes.
4. Denied apps stay blocked from quiet use; next camera use from them opens an options card again (unless “Never for this”).

Stored under something like `data/learn/camera_allow.txt` (and mirrored in Activity): app identity, decision, timestamp. No video frames, no images.

### Quiet when the allowed app is actually open
If the camera turns on **and** the process matches an **allowed** app that is **actually running / open** (best-effort OS check):

- Do **not** interrupt with a scary popup.
- Optional tray/Activity note: “Camera on — Zoom (allowed).”
- Hardware cover reminder stays available in Settings, not as spam.

First-time use of a never-seen app always asks once before learning.

### Suspicious: camera activity when the allowed app is NOT open
Speak up when confidence is enough that something is off, for example:

- Camera in use, but **no** allowed camera app is running  
- Camera attributed to App X, but App X is **not** actually open / not in the process list  
- Unknown or unexpected process holding the camera  
- Camera on + unusual outbound while no video call app is open (heuristic — **ask**, don’t auto-kill)

Then DVielle **informs the user** and shows an **options card**. The user must select; only then does DVielle perform.

### Options card (Camera Guard — required shape)
Plain English first: what’s happening, why it matters, what we suggest.

Then **selectable actions** (user picks exactly one primary action; secondary “Show me why” always available):

| Option (example labels) | What DVielle does after selection |
|-------------------------|-----------------------------------|
| **This is OK — allow this app** | Add/update allowlist; quiet next time when that app is open |
| **Stop this app from using the camera** | Identity-checked stop/close of the camera-holding process when safe |
| **Turn off camera access for this app** | Open OS camera privacy settings focused on that app / revoke where the OS allows |
| **Remind me to cover the lens** | Show cover/shutter reminder; mark Monitoring until user confirms covered or dismisses |
| **Turn camera off in system settings** | Deep-link OS global camera privacy toggle |
| **Not now** | Snooze with cooldown; keep Monitoring |
| **Never warn for this app** | Persist deny-of-alerts for that app identity (still log quietly) |
| **Show me why** | Evidence: time, device, process name/path if known, whether claimed app was running |

DVielle **never** silently disables the whole camera or kills a live video call without this selection (Auto-protect exception only if user later pins an explicit high-confidence rule — default off).

### Detection notes (honest)
- Detect when a local camera becomes **in use** (best-effort, OS-specific; say so in Details).
- Try to name the app/process when the OS exposes it; separately verify whether that app is **running**.
- Windows: desktop apps are weaker than Store-app permission prompts — be honest. Registry “camera in use” tricks are best-effort, not a guaranteed API.
- macOS: green menu-bar indicator is the OS truth; which-app attribution may be incomplete.
- Linux: `fuser`/`lsof` on `/dev/video*` for native apps; Flatpak/portal apps may differ.

### Auto-protect
Default: **alert + options only**. Do not silently disable the camera (breaks real calls). Optional later: user-pinned “block unknown camera apps when no allowed app is open” still needs identity check + Undo + after-notice.

### Forbidden
- “Your webcam can never be hacked”
- “We see inside encrypted video”
- Recording the camera ourselves
- Claiming we protect every IP camera on the internet
- Acting on a Camera finding without a user option selection (unless a published Auto-protect camera rule is explicitly on)

### Log
`data/logs/camera.txt` — time, device class, process name/path if known, whether claimed app was running, user option chosen, action result. No video frames, no images.

### Simple English
“Zoom is using the camera and you already said Zoom is OK — no action needed.”  
“The camera turned on, but Zoom isn’t open. That can mean another app is using it. Choose what you want me to do.”  
“A physical cover or shutter is still the surest way to make sure nobody sees you.”

---

## 29. Acceptance checks (v0.5)

25. Footprint flow never searches third parties’ identities; email breach check is opt-in and says the email leaves the device.  
26. Copy promises resolutions and partner/DIY removal paths; never claims a solo free binary scraped/erased all human data on earth. Partner outcomes may be described accurately (e.g. broker opt-outs in progress).  
27. Camera Guard alerts on local webcam/USB use without storing images; IP cameras are not claimed as covered in v1.  
28. Camera copy states that a hardware cover/shutter plus OS off is stronger than software alerts. (v0.7 adds learned allowlist + options-before-act — see §32.)

---

---

## 30. Master Solutions & Resolutions Map (whole chat → product)

Everything decided since kickoff, rewritten as **problems we solve** and **how we resolve them**. UI looks remain later.

### 30.1 Cross-cutting engine (always on)
| Need | Solution |
|------|----------|
| Non-tech users don’t understand the background | Simple English: problem → why → fix → if ignored |
| Cry-wolf | Alert gates + cooldowns + learned baselines |
| User said what’s OK to keep on | **All pillars:** persist allow/deny; quiet when expected; options card when first-time / denied / suspicious mismatch; act only after select (§5.1) |
| Unique user / machine | Continuous local learning in `data/learn/*.txt`; apply via tune files |
| Optional deeper growth | Deep personalization OFF by default; double-confirm; sandbox `data/personality/` only |
| App must not slow the PC | Load governor; defer under pressure; learned CPU budgets |
| Space | Issue logs as rotating `.txt` per pillar; learning files size-capped |
| Multi-OS | Windows-primary now; Linux and macOS limited-mode until an adapter is smoke-tested |
| Free + anti-resale worry | License + trademark + packaging options A/B/C **deferred** until owner picks |
| Ethics | Authorized self-defense of this host only; no offensive kits; we don’t steal data |

### 30.2 Safety (ethical self-assessment → harden)
| Finding | Resolution |
|---------|------------|
| Defender / firewall protection off | Options: Turn protection on / Not now / Never warn / Show why (or Auto-protect if opted in) → verify → Resolved |
| Failed sign-in burst | Options: Open account review / Change password guidance / Lock screen tip / Not now → Resolved / Monitoring |
| Suspicious new startup / persistence | Options: Disable startup / Smart Close / Keep on if user trusts / Not now / Never / Show why → Resolved |
| Risky listening / exposure | Options: Close service / Firewall rule / Keep on / Not now / Show why → Resolved |
| Posture gaps from collectors | Each row = ticket with options card → user selects → act |

### 30.3 Speed
| Finding | Resolution |
|---------|------------|
| Top CPU/RAM hog | Options: Keep on while I work / Pause or Smart Close / Disable at startup / Not now / Never warn / Show why → learn → Resolved |
| Heavy startup pile | Options per item: Disable / Keep on / Not now → reboot note → Resolved |
| Named hog but identity mismatch | Treat as suspicious → options (do not quiet on name alone) |
| DVielle itself heavy | Self-throttle first; log “we reduced our load” → Resolved |
| Disk thrash from junk | Hand off to Storage options card |

### 30.4 Privacy & internet (Microsoft + other apps)
| Finding | Resolution |
|---------|------------|
| Chatty / unexpected egress | Options: Allow keep-on / Block network / Open firewall-privacy settings / Not now / Never / Show why → learn → Resolved |
| Egress named as App X but App X not open | Suspicious mismatch → same options card (do not quiet) |
| Microsoft telemetry-heavy use | Options with honest tradeoff; user-gated blocks that don’t break Update/Defender by default; deep-link privacy dashboards → Resolved / Accepted |
| Unknown app phone-home | Options: Block / Uninstall guidance / Keep on / Not now → Resolved |

### 30.5 AI data watch
| Finding | Resolution |
|---------|------------|
| AI app uploading to cloud AI | Options: Allow keep-on / Block internet / Open “improve model” settings / Not now / Never / Show why → learn → Resolved |
| Upload while no allowed AI app is running | Suspicious → options card → act |
| New unknown AI helper heavy upload | Options first; Auto-protect only if user pinned that rule → Resolved |

### 30.6 Storage
| Finding | Resolution |
|---------|------------|
| Safe temp reclaimable | Options: Free space now / Preview first / Not now / Never auto-clean / Show why → report freed/skipped → Resolved |
| Critical low disk | Same options; Auto-protect eligible only if opted in → Resolved |
| Recycle Bin / browser cache | Always options (unless user pinned keep-on preference) → Resolved |

### 30.7 Footprint (online exposure)
| Finding | Resolution |
|---------|------------|
| Local account residue | Options: Open sign-out / revoke steps / Not now / Show why → Resolved |
| Breach hit (opt-in email) | Options: Password+2FA checklist / Open partner monitor / Not now → Resolved |
| Public search hit | Options: Takedown / DIY opt-out / Google Alert / Partner / Not now → In progress → Resolved / Monitoring |
| Broker listings | Options: DIY opt-out **and/or** partner removal (DeleteMe, Incogni, Aura, LifeLock, REMOVE, etc.) → track → Monitoring |
| Dark-web style alert | Options: Partner monitor + local lockdown / Not now → Resolved / Monitoring |

### 30.8 Camera Guard
| Finding | Resolution |
|---------|------------|
| First time an app uses the camera | Options: Allow keep-on / Stop / Revoke OS access / Cover reminder / Not now / Never warn → learn decision → Resolved |
| Allowed app is open and using camera | Stay quiet (optional Activity note) → Resolved |
| Camera on but allowed app is **not** open / unknown process | Options card → user selects → DVielle performs → Resolved / Monitoring |
| User wants maximum safety | Guide: shutter/cover + OS camera off → Resolved |
| IP / network cameras | Out of v1 Camera Guard; later LAN module — until then, do not claim covered |

### 30.9 Partner solutions (when local alone isn’t enough)
DVielle **orchestrates** specialized services instead of pretending one free binary replaced them:

- Breach intelligence: Have I Been Pwned (and similar)  
- Broker removal / continuous opt-out: DeleteMe, Incogni, Aura, LifeLock, REMOVE, etc.  
- Exposure / dark-web **monitoring**: Aura, Norton/LifeLock, Identity Guard-class tools — DVielle turns their alerts into local resolutions  
- Vendor privacy consoles: Google, Microsoft, Apple  

Partners are chosen at implement/release time; Resolution Center stays partner-agnostic in data model.

### 30.10 What “done” looks like for the free app
A non-technical user can open DVielle and see: **open issues**, **fixes in progress**, **resolved**, **still monitoring** — across Safety, Speed, Privacy, AI, Storage, Footprint, and Camera — without reading jargon. That is the product.

---

## 31. Acceptance checks (v0.6)

29. Every pillar can open a resolution ticket with status, not only an alert.  
30. Master map §30 is the backlog source for implementation priority (engine → Safety/Speed/Storage → Privacy/AI → Footprint/Camera → partners).  
31. Partner paths are first-class resolutions (status tracked), not dead-end “go search the web” dumps.  
32. Marketing and UI lead with fixes completed / monitoring, not fear without a button.

---

## 32. Acceptance checks (v0.7 — Camera decisions)

33. Camera Guard stores user allow/deny (“keep on”) decisions locally and stays quiet when an allowed app is **actually open** and using the camera.  
34. When camera use looks suspicious (allowed app not open, unknown process, or mismatched attribution), DVielle shows an **options card**; it performs an action only after the user selects an option (unless an explicit Auto-protect camera rule is on).  
35. Options include at least: allow this app, stop this app’s camera use, open/revoke OS camera access, cover-lens reminder, not now, never warn, show why.  
36. Camera logs never store video frames or images; hardware shutter/cover + OS off remain stated as the strongest practical block.

---

## 33. Acceptance checks (v0.8 — universal options loop)

37. §5.1 applies to **all seven pillars**: keep-on memory → quiet when expected → options when not → perform after select.  
38. Every `ask_user` finding carries an `options[]` list; mutation does not run until the user selects (except published Auto-protect).  
39. Suspicious mismatch (named subject not actually open / identity doesn’t match) never counts as quiet keep-on.  
40. Keep-on decisions persist under `data/learn/`; per-pillar option catalogs in §5.1 are implemented as the default card contents.  
41. Safety, Speed, Privacy, AI, Storage, Footprint, and Camera each use the same card format with pillar-specific actions.

---

## 34. Acceptance checks (1.7.1 — honesty and elevated-task lockdown)

42. The resident scheduled task defaults to RunLevel **Limited** (`TASK_RUNLEVEL_LUA`). `TASK_RUNLEVEL_HIGHEST` is created only when `-RunLevel Highest` is passed and `Protect-DvielleInstallForElevation` has locked the install tree so only Administrators and SYSTEM can write. A failed lockdown does not create or enable that task. Elevated unattended operation is not recommended until that lockdown is proven on the target PC. See Microsoft Learn: [Principal.RunLevel](https://learn.microsoft.com/en-us/windows/win32/taskschd/principal-runlevel) and [Security Contexts for Running Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). The setup executable, when built, calls that installer with `-RunLevel Limited` only. It is not a frozen agent. See [WINDOWS_INSTALLER.md](WINDOWS_INSTALLER.md).
43. Start, verify, and stop share one selected install root. Config and data from another tree are not used as a silent fallback.
44. Resource advice stays schedulable during host pressure, on a background worker, no faster than 30 seconds, and still yields when the agent's own budget is exceeded.
45. CPU advice uses a timestamped heartbeat sample. An unprimed or failed sample is not treated as zero load.
46. Access-denied connection scans and failed DNS or route probes stay partial or unavailable. Empty results are not published as a fresh healthy success.
47. Attacks and Why copy do not reassure from empty or stale evidence, and do not label a stopped snapshot as current.
48. Cloud redaction removes IPv4 and IPv6 addresses even when a port follows them.
49. A mutation handler does not run unless the decision row was saved first.
50. `scripts/block-ip.ps1` is not a product guarantee. It reports success only after the live rule is verified to block the requested address.

*End of Function Spec — 1.7.1 honesty addendum.*

---

## 35. Acceptance checks (1.8.0 — FREE pillar lock and P0 observe)

51. `docs/FUNCTION_SPEC.md` states the eight pillars, the P0→Later sequence, and Promise → Assumptions → Evidence for each pillar.
52. `docs/TRUST_GATES.md` is the pass/fail list. Attestation checksum and TUF stay unchecked until those mechanisms exist.
53. `docs/DECISIONS.md` records the 2026-09-29 lock: core prevention is not paywalled; orchestrate Defender rather than replace it; Home has no Windows Sandbox; CFA is not a read/exfiltration claim; TUF comes before privileged auto-update; KEV and OSV are acceptable; abuse.ch requires a user Auth-Key.
54. Defender health reports active mode, real-time protection, signature age when `AntivirusSignatureAge` is present, and engine version as an observation. Engine freshness remains UNKNOWN.
55. Access denial or a timed-out Defender read is partial coverage. The evidence strip does not call that an all-clear, and the Defender row does not show ACTIVE.
56. MAPS uses `ValidateMapsConnection` or reports unavailable. Failure copy does not recommend blocking Defender cloud endpoints.
57. The Home matrix marks Windows Sandbox UNAVAILABLE and App Control authoring UNAVAILABLE, and marks ASR, CFA, and Firewall as edition-supported. Smart App Control stays a probe.
58. No new mutator ships in 1.8.0. ASR, CFA, and App Control are not enforced. `ExclusionPath` is still absent.

*End of Function Spec — v0.9 / 1.8.0 FREE prevention lock.*

---

## 36. Acceptance checks (1.9.0 — P1 ASR, CFA, recovery)

59. ASR and CFA are read from `Get-MpPreference`. Access denial, a timeout, and a mismatched id/action count stay partial. A partial read does not describe every rule as Off.
60. Windows Home and Windows Pro share the same ASR promotion rules. The product does not say Home lacks ASR and does not require Microsoft 365 E5 for the local PowerShell path.
61. The vulnerable-driver rule and the LSASS rule may be set to Block only when the live action is Audit and Defender Active, real-time protection, and MAPS all pass. The WMI rule is not set to Block. Other rules may be set to Audit and are not blanket-Blocked. Warn is not Audit evidence.
62. CFA off or disk-only audit moves to folder Audit first. Full Enabled is offered only from live Audit mode. Copy states the modification/delete shield and states that offline backups plus a restore test remain required.
63. BackupConfigured, BackupFresh, and RestoreVerified are separate. A backup timestamp does not set RestoreVerified. A missing marker is unknown. Clearing the marker returns the states to unknown.
64. ASR and CFA writes go through DualGate and Cortex persist-before-mutate. Auto-protect cannot issue them. The apply path re-reads the live preference. A denied or non-matching re-read is not recorded as applied. The previous mode can be restored where the plan still allows that non-Block value.
65. No `ExclusionPath`, no ASR path exclusion, and no rule that blocks Defender cloud endpoints. Windows Sandbox stays unavailable on Home. TUF and privileged auto-update stay unchecked.

*End of Function Spec — v0.9.1 / 1.9.0 P1.*

---

## 37. Acceptance checks (2.0.0 — P2 firewall, helper, CPU)

66. Firewall observation reads profiles, MpsSvc status, and DVielle app rules. It does not stop or start MpsSvc, and it does not create a rule. An incomplete read proposes nothing.
67. A proposal can name one program, one profile, IPv4 and/or IPv6, and up to four specific remote networks. Applying it uses `RESTRICT_NETWORK` through DualGate. Auto-protect cannot issue `safety.restrict_network`.
68. The Limited process sends the request to the helper. The helper refuses every operation other than `restrict_network`, refuses a bad token, and refuses parameters outside the schema. Success is a second `Get-NetFirewallRule` read. A partial read removes the DVielle rules from that attempt and is not counted as applied.
69. Copy states that the block is not leakproof. A single address family is warned. A VPN-like adapter is named when the read sees one. Home Sandbox stays unavailable. CFA copy stays a modification shield.
70. The twin publishes `cpu_contract`. The resident task's mode is measured scheduling. The published analysis cap is 20% (`CpuRate` 2000). `terminates_other_processes` is false. A Job Object hard cap is claimed only when assignment on the helper succeeded.
71. No `ExclusionPath`, no MAPS endpoint block, and no GitHub auto-update in the P2 modules. The resident scheduled task default stays RunLevel Limited. TUF and Sandbox `.wsb` stay P3.

*End of Function Spec — v0.9.2 / 2.0.0 P2.*

---

## 38. Acceptance checks (2.1.0 — P3 Sandbox and TUF)

72. Home Open unfamiliar is UNAVAILABLE. The checklist names SAC, ASR, CFA, and Firewall. It does not start a process, and it does not call a desktop window Windows Sandbox. WDAG and Client Hyper-V are not substitutes.
73. On Pro or higher, a missing Windows Sandbox feature is LIMITED and is not enabled. A present feature launches only `WindowsSandbox.exe` with a `.wsb` whose networking is Disable and whose single mapped folder is read-only. Auto-protect cannot issue `safety.open_unfamiliar`. A direct call without Cortex does not start the process.
74. If guest networking is not observed, the launch result is LIMITED. A probe that reports networking disabled is verified and still says Group Policy override was not read. A probe that reports networking enabled is not counted as the requested profile.
75. TUF verification accepts a fixture repository only when root, timestamp, snapshot, and targets signatures, versions, expiry, and sha256 lengths agree. Rollback, freeze, a bad hash, a mix-and-match snapshot version, a bad signature, and a delegation are rejected. The previous package bytes stay. Privileged auto-update is false. Live binary attestation is UNCHECKED.
76. The named-pipe contract refuses a caller who is not on the ACL and refuses every operation other than `restrict_network`. The SDDL does not grant Everyone. The helper is not a SYSTEM service. The resident task default stays RunLevel Limited.
77. No `ExclusionPath`, no MAPS endpoint block, and no GitHub Release download in the P3 modules.

*End of Function Spec — v0.9.3 / 2.1.0 P3.*

---

## 39. Acceptance checks (2.2.0 — P4 intel and privacy)

78. With no `kev.json` and no `osv.json`, the report is `intel: unavailable` and the match list is empty. An invalid catalog does not become a hit.
79. KEV copy is CC0, says it is not a CISA or DHS endorsement, and ships no logo. OSV copy names Apache-2.0 and the osv-schema license. A KEV name overlap is a candidate. An OSV hit needs a comparable version. No inventory file means matches were not evaluated.
80. Feed fetch is off by default and does not call the network. abuse.ch is off, bundled is false, and a fetch runs only with an Auth-Key. The body is not saved into the product.
81. Home and Pro cannot apply Security=Off. Required, advertising off, and tailored off are supported choices. Enterprise may set diagnostic data off, and the copy says that is not proof traffic stopped. Success is the second read. Auto-protect cannot issue `privacy.set_choice`. A direct call without Cortex writes nothing.
82. A request that names MAPS, Windows Update, CRL, or Microsoft broadly creates no firewall rule and includes the `ValidateMapsConnection` result. The evidence strip shows observed settings and unknown ones separately.
83. No `ExclusionPath`, no `Add-MpPreference`, and no GitHub Release download in the P4 modules. Home Sandbox stays unavailable. CFA stays a modification shield. Privileged auto-update stays off. As of 2.2.0, passkeys, activity experiences, the claims page, and a named-pipe SYSTEM helper stayed later. 2.3.0 ships the first three (§40). The helper stays later.

*End of Function Spec — v0.9.4 / 2.2.0 P4.*

---

## 40. Acceptance checks (2.3.0 — P5 experiences, passkeys, claims)

84. Everyday observes ASR, CFA, and Firewall and does not propose those mutations. A medium-severity finding stays held. `denylist_actions: true` does not enable a denylist handler. `close_process_auto: true` does not make CLOSE_PROCESS automatic.
85. Sensitive can surface a low-severity finding when confidence is medium or high. A low-confidence finding stays held. Auto-protect for the published set requires critical severity. `close_process_auto: true` is refused. A dual-gate perform with an automatic CLOSE_PROCESS token does not run the mutator. CFA Audit and firewall restrict proposals stay `applied: false` and still require user approval.
86. Open unfamiliar on Home is the checklist only (SAC, ASR, CFA, Firewall) and does not start a process. A forged READY offer on Home is ignored. On Pro+, the named handler is `safety.open_unfamiliar` and resolving the experience still does not launch. `launch: true` is refused. Auto-protect cannot issue it.
87. Passkey guidance says adopt a passkey where the relying party supports one, says the credential is RP-scoped, and warns that session theft and weak recovery are separate. `phishing_impossible` is false, `badge` is null, and browser automation is false. Marking every checklist row reviewed does not set those flags and does not change an account.
88. `docs/CLAIMS.md` lists promise, assumptions, evidence, and UNCHECKED for the pillars, including live `verify_runtime` and an elevated ACL field proof. README points at it. No `ExclusionPath`, no `Set-MpPreference`, no `New-NetFirewallRule`, and no GitHub Release download in the P5 modules. The named-pipe helper stays the loopback stub. Privileged auto-update stays off. The resident task stays Limited.

*End of Function Spec — v0.9.5 / 2.3.0 P5.*





