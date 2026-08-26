# VIGILLANCE Master Architecture Specification

**Product:** DVielle / VIGILLANCE  
**Date:** 2026-08-24  
**Status:** Binding product thesis for design and code review going forward  
**Canonical repo:** https://github.com/DVILLIE/VIGILLANCE  

---

## 0. Product thesis (non-negotiable)

VIGILLANCE is **not** primarily an antivirus, a firewall appliance, or a “PC cleaner.”

> **VIGILLANCE is a resident Windows system guardian that continuously observes resource usage, network activity, background behavior, privacy exposure, security posture, and workload contention — then explains what is happening and applies conservative corrective actions only when evidence and confidence are strong.**

Primary job: keep the PC **responsive** while identifying and controlling **unnecessary, risky, or abusive** system behavior.

Differentiator: **workload-aware** protection of performance, privacy, and security at the same time.

---

## 1. Design laws

1. **Observe → Explain → Recommend → (User-authorize) → Act → Verify → Rollback**
2. High RAM / CPU alone is **not** a problem; **pressure / unjustified contention** is.
3. Microsoft / cloud traffic is **classified by purpose**, not labeled “malicious” by default.
4. Never replace Defender; **orchestrate and audit** Windows defenses. Do **not** weaken them.
5. VIGILLANCE itself must stay inside a hard **resource budget** (never become the slowdown).
6. Destructive / irreversible actions require **confidence threshold + policy / explicit approval**.
7. Every decision leaves an **evidence chain** (explainability / digital forensics).
8. Chat / TTS / demo are **optional surfaces**, not the product core.

### Action hierarchy

| Level | Name | Behavior |
|------:|------|----------|
| 0 | Observe | Log only |
| 1 | Explain | Plain-English narrative |
| 2 | Recommend | Ask / suggest |
| 3 | Reversible act | Priority, EcoQoS, suspend candidate, defer update |
| 4 | Admin act | Firewall, service, hosts — explicit approval |
| 5 | Emergency | High-confidence security only (e.g. ransomware-like) |

---

## 2. Target intelligence pipeline

Replace module-centric “rule → toast” with:

```text
COLLECTION → NORMALIZATION → CORRELATION → BASELINE
    → RISK / RESOURCE SCORE → CONFIDENCE → IMPACT
    → DECISION → ACTION → VERIFY → ROLLBACK
```

### Evidence bus (common event model)

Every observation should eventually normalize to:

```text
timestamp, entity, process, parent, executable, publisher, signature, hash,
cpu, ram, gpu, threads, disk, network, user, foreground/background,
event_type, category, risk, confidence, impact, action, result
```

SQLite today (`events`, `connections`, `failed_logons`, …) is the seed store; evolve toward this common schema rather than inventing per-module “suspicious” meanings.

---

## 3. Ten engines (target product model)

| # | Engine | Purpose |
|---|--------|---------|
| A | **Resource Intelligence** | CPU / RAM / GPU / disk / thread contention & pressure |
| B | **Workload Orchestrator** | Protect active user workloads (AI, gaming, office, idle) |
| C | **Process Intelligence** | Active / idle / background / essential / suspicious / leaking |
| D | **Storage Intelligence** | I/O pressure, caches, bloat with *performance impact* |
| E | **Network Intelligence** | Process → publisher → destination → purpose → policy |
| F | **Privacy & Telemetry Control** | Categories + observe/recommend/apply/verify |
| G | **Security / Attack Surface** | Local defensive assessment (not offensive hacking) |
| H | **Vulnerability Intelligence** | Inventory + known exposure (when sources reliable) |
| I | **System Health** | Thermal, battery, stability, hardware signals |
| J | **Adaptive Controller** | How deep/often VIGILLANCE itself runs |

Plus cross-cutting: **Policy/Response Engine**, **Evidence / Explainability**.

### Adaptive Nerve (scheduler) — pointer only

**Cadence authority:** [`VIGILLANCE_FUTURE_ARCHITECTURE.md` § Adaptive Nerve Plane](VIGILLANCE_FUTURE_ARCHITECTURE.md)  
(event-driven · fast heartbeat · pulse · idle-deep · emergency; **per-collector**, not global).

Do **not** redefine cadence tables here. Implementation and code review must conform to that section.

---

## 3a. Architecture Review Rules

Binding for audits, PRs, and engineering passes:

1. **Establish exact ref under review** (commit SHA, branch, or `main@date`).
2. **Inspect current implementation first** before historical commits.
3. **Compare implementation against binding architecture** (this doc + Future Architecture).
4. **Validate configuration and installer behavior**, not only Python modules.
5. **Check tests against intended behavior**, not only against current accidental behavior.
6. **Use historical commits only for regression analysis** (*“Was X still present after Y?”*).
7. **Label every historical conclusion explicitly:**
   - `CURRENT` — verified against the named current ref / `main`
   - `REGRESSION` — present in commit X; absent/present after commit Y
   - `HISTORICAL` — older ref; **not** asserted against current `main`
8. **Never recommend a rename merely for terminology cleanup.**
9. **Prefer semantic migration over file churn** (change contracts first; rename when the replacement abstraction exists).
10. **Treat Future Architecture § Adaptive Nerve as the cadence authority** — no global collector cadence; no literal “full collection every N seconds.”
11. **Self-budget is a hard constraint** — designs that compete with the protected workload are rejected.
12. **Docs may lead code**; undocumented contradiction is not allowed — either fix code or mark `STATUS: planned / gap`.
13. **Level ≥ 2 decisions** require evidence and confidence. **Mutations require Level ≥ 3**,
    typed action + registered handler, Authorization (not a free-form policy string), and
    rollback semantics when reversible. **Level 2 = recommend only — never mutates.**

**Module naming example:** keep `agent/modules/microsoft_guard.py` until a Privacy Control Plane exists; treat it as a provider adapter under the new *contract*, then migrate behind `privacy_control` (or equivalent) when real.

---

## 4. Repository map — what exists vs what is missing

### Legend

- **KEEP** — survives as collection / UI building block  
- **REDESIGN** — keep data, change intelligence semantics  
- **GAP** — required by thesis; not built  
- **REMOVE / AVOID** — conflicts with thesis  

### Collection layer (today’s `agent/modules/`)

| Current module | Maps toward | Status | Notes |
|----------------|-------------|--------|-------|
| `ram.py` | A Resource / Memory Pressure | **REDESIGN** | Today: % thresholds / optional trim. Need available/commit/hard faults/standby/compression/growth, not “RAM high = bad.” |
| `resource_advisor.py` | A + C + B | **REDESIGN** | Smart Close + AppGroup is a start (foreground, families, voice). Still kill-oriented; evolve to efficiency score + workload classes. |
| `disk.py` | D Storage | **REDESIGN** | Free-space alerts only. Need I/O pressure / impact, not cleaner-first. |
| `connections.py` | E Network | **KEEP + EXTEND** | LAN/CDN/router classification is aligned. Need publisher, purpose (Update/DO/telemetry/browser), bytes, frequency, ALLOW/AUDIT/RESTRICT/BLOCK policy. |
| `connection_intel.py` | E Network | **MERGE** | Overlaps `connections.classify_remote`; fold into one Network Intelligence path. |
| `network_info.py` | E + I | **KEEP** | VPN/public IP/DNS snapshot — topology context. |
| `privacy_guard.py` | F Privacy | **REDESIGN** | Registry drift checks. Expand to category taxonomy (telemetry vs required service data vs ads) + verify/rollback. |
| `microsoft_guard.py` | F + E | **REDESIGN** (keep filename) | Contract → Privacy Control Plane provider adapter. Soften block/terminate; preserve Update/Defender/CRL. Rename only after `privacy_control` exists. |
| `attacks.py` | G Security | **KEEP + EXTEND** | 4625/4776 is authentication slice only. |
| `security.py` | G Security | **KEEP + EXTEND** | Defender/firewall health — orchestrate, don’t replace. |
| `browser_guard.py` | C + G (browser) | **KEEP + EXTEND** | Heuristic stealer/adware; no keylogging (correct). Needs extension/inventory later. |
| `agent/main.py` `run_once` | J Adaptive (stub) | **REDESIGN** | Fixed interval, all modules every tick. Must become adaptive scheduler + decision layer. |
| `agent/store/db.py` | Evidence bus seed | **EXTEND** | Add scores, confidence, evidence blobs, action audit. |
| `agent/controller.py` | GUI cycle driver | **KEEP** | Thin; decision engine should not live only in GUI. |

### Scripts / installer

| Asset | Status | Notes |
|-------|--------|-------|
| `scripts/harden-once.ps1` | **REDESIGN** | Remains optional Level-4 surgery with restore point. Never day-one auto. Honesty on Home telemetry floor. |
| `scripts/block-telemetry-firewall.ps1` | **RESTRICT** | Expert/allowlisted only; Update-safe lists must stay. |
| `scripts/block-ip.ps1` | **KEEP** | Level-4/5 only after policy. |
| `installer/install-dvielle.ps1` Defender `ExclusionPath` | **REMOVE** | Weakens trust boundary; security product must not carve itself out of Defender by default. |
| Headless scheduled task | **KEEP** | Correct runtime shape. |

### GUI / product surface

| Asset | Status | Notes |
|-------|--------|-------|
| `dvielle/gui/app.py` | **REDESIGN** | Evolve from “START + Smart Close + feed” toward Explain/Recommend consoles per engine. |
| `attacks_window.py` | **RENAME/EXPAND** | Becomes Security + Network Review console (not only “attacks”). |
| Chat / demo | **DEFER** | `docs/CHAT_DEFERRED.md` still correct. |

### Explicit GAPs (not in repo yet)

| Gap | Engine |
|-----|--------|
| Memory pressure model (available, commit, hard faults, compression, standby) | A |
| Thread / wakeup / EcoQoS awareness | A / C |
| Workload profiles (AI / gaming / office / idle) + resource budgets | B |
| Process efficiency score + lifetime trends | C |
| File/I/O behavior intelligence (ETW-light later) | D |
| Delivery Optimization / Update purpose classification | E / F |
| Privacy categories (required vs optional diagnostic, ads, sync) | F |
| Attack surface: listeners, RDP/SMB/WinRM, persistence graph, ASR audit | G |
| Software inventory + CVE mapping | H |
| Thermal / battery / SMART | I |
| Adaptive scheduler + self-budget telemetry | J |
| Unified scoring + evidence-chain UI (“Why did VIGILLANCE do this?”) | Cross-cutting |

---

## 5. Engine briefs (implementation intent)

### A. Memory Pressure Engine (not “RAM used”)

Distinguish: useful cache / reclaimable / working-set pressure / leak / standby / compressed / background / critical.

Answer: **Why consumed, how much reclaimable, what is safe?**

Actions: advise → optional reversible trim of *classified disposable* only — never MemCompression / System.

### B. Workload Orchestrator

Detect active profile (AI development, gaming, editing, office, idle). Protect intentional high compute (LLM/GPU). Reduce *around* the workload (sync, indexing, telemetry, dormant apps) via priority/QoS — not blind kills.

### C. Process Intelligence

Classify: Essential / Active / Background / Dormant / Suspicious / Leaking / Disposable.

Score ≈ cost × duration × foreground × user activity × expected workload × trust.

### E. Network Purpose Engine

Chain: process → exe → publisher → destination → domain/IP/ASN → port → frequency/bytes → reason → reputation → policy `{ALLOW,AUDIT,RESTRICT,BLOCK}`.

Special cases: router/LAN/phone/extender (already started), Cloudflare/CDN (already started), Delivery Optimization peer share, Defender, Update.

### F. Privacy & Telemetry Control Plane

Categories: telemetry, diagnostics, advertising ID, activity history, personalization, cloud sync, crash reporting, search/assistant, browser, app telemetry.

Separate: Microsoft vs third-party vs browser vs malicious exfiltration.

### G. Local Defensive Attack-Surface Engine

**Not** an offensive / ethical-hacking toolkit against other hosts.

Continuous local assessment: listeners, exposure (RDP/SMB/WinRM), persistence, auth (4625+), Defender/ASR posture, suspicious execution. Responses: ALERT → … → QUARANTINE with thresholds.

### J. Adaptive Controller + self-budget

Idle footprint target: very low CPU, bounded RAM, batched DB writes, sparse I/O. Suppress noncritical work during AI/gaming profiles.

---

## 6. Migration plan (phased)

### Phase 0 — Correct the thesis in-repo *(this document)*

- Adopt this spec + Architecture Review Rules as review standard.  
- Defender install exclusion: **resolved / verified on current main** (do not reintroduce).  
- Update `docs/DECISIONS.md` product framing.  
- Cadence: Future Architecture § Adaptive Nerve is sole authority.

### Phase 1 — Evidence + Memory Pressure + Adaptive tick

- Introduce normalized event writer / score fields.  
- Replace RAM-%-only alerts with pressure signals (best-effort via counters/`psutil` first; ETW later).  
- Split `run_once` into light tick vs deferred heavy jobs.

### Phase 2 — Network Purpose + Privacy Control Plane

- Merge connection intel; add publisher/signer and purpose tags.  
- Soften microsoft_guard defaults to AUDIT/RESTRICT recommendations.  
- UI: Network Review with ALLOW/AUDIT/RESTRICT/BLOCK (persisted policy).

### Phase 3 — Process Intelligence + Workload Orchestrator

- Efficiency scores; AI workload profile; EcoQoS / priority for disposable background.  
- Smart Close becomes “Recommend suspend/lower” with evidence dialog (keep voice).

### Phase 4 — Attack Surface + Explainability console

- Persistence graph, listeners, Defender ASR audit.  
- “Why did VIGILLANCE do this?” evidence viewer.

### Phase 5 — Storage / Health / Vulnerability (as data sources allow)

- Impact-ranked storage; battery/thermal; inventory+CVE when offline-capable source exists.

---

## 7. What code review must judge against

Use **§3a Architecture Review Rules** first (ref label, CURRENT vs REGRESSION vs HISTORICAL).

When reviewing code, also ask:

1. Does this improve **observe/explain/score/confidence** — or only add another toast rule?  
2. Does it respect **workload intent** (especially AI)?  
3. Does it risk **false “Microsoft = evil”** or break Update/Defender/CRL?  
4. Does it stay inside **self-budget** and Future Architecture **Adaptive Nerve** cadence?  
5. Is there an **evidence chain** for Level ≥ 2 decisions, and Authorization + typed handler for Level ≥ 3 mutations?  
6. Is rollback / monitor-first preserved (and is Level 2 kept recommend-only)?  
7. Is any rename justified by a real abstraction migration — not terminology alone?

---

## 8. Immediate non-goals

- Replacing Microsoft Defender  
- Offensive scanning of other machines  
- Keylogging / password capture / content sniffing  
- Blind EmptyStandbyList loops  
- Auto-disable arbitrary Windows services  
- Chat-first product definition  

---

## 9. Bottom line

Current repo = **solid collection + early classification UI** (connections, smart close, attacks console, privacy drift, headless install).

Target product = **system intelligence + resource governance + privacy control + defensive assessment + workload orchestration**, with a shared evidence bus and adaptive controller.

Do **not** add more modules that only toast on thresholds until Phase 1 pipeline exists.
