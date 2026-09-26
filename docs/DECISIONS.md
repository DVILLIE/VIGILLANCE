# Project Decisions

Canonical product thesis and engine map: **[VIGILLANCE_MASTER_ARCHITECTURE.md](VIGILLANCE_MASTER_ARCHITECTURE.md)**.

Futuristic cadence / Twin: **[VIGILLANCE_FUTURE_ARCHITECTURE.md](VIGILLANCE_FUTURE_ARCHITECTURE.md)** (Adaptive Nerve is cadence authority).

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Product identity | System intelligence + resource governance + privacy + defensive security — **not** AV-first | User workload (esp. AI) must stay responsive |
| Version source | `pyproject.toml` → runtime `agent.version` → installer DisplayVersion | One authoritative semver (1.5.0+) |
| F1 runtime | CapabilityReport + Digital Twin v0 + Adaptive Nerve + evidence schema | Docs→code; per-collector cadence |
| P0 safety contract | Collectors observe; Cortex decides; Action Executor mutates with Decision ID | Fail-closed; no module Level ≥2 bypass |
| Automatic RAM trim | **DISABLED** (EmptyWorkingSet / EmptyStandbyList) | Microsoft: testing/tuning; use pressure analysis |
| 4776 handling | Source Workstation = hostname only; never IP block | Microsoft Learn Event 4776 |
| Intelligence shape | Collection → correlate → score → confidence → recommend → act | Module toasts alone are insufficient |
| Windows edition | 10/11 Home & Pro | Same agent; Home registry/`auditpol`; Pro may use GPO |
| Stack | **Python 3.12** + PowerShell | 3.14 unsupported until deps proven |
| Install path | **`C:\DVILLIE`** only | Single story |
| Runtime | Headless `agent.main` + optional GUI | Silent background; adaptive scheduler is next |
| Cadence authority | **Future Architecture § Adaptive Nerve only** | No duplicate cadence docs; per-collector, not global “2–5s full scan” |
| Review discipline | Master § Architecture Review Rules | CURRENT / REGRESSION / HISTORICAL labels; audit named refs |
| Module renames | Semantics before filenames | Keep `microsoft_guard.py` until Privacy Control Plane exists |
| Default posture | Monitor-first / Observe–Explain | Auto-block/trim off until baseline + flags + confidence |
| Memory | **Pressure**, not “RAM % used” | Windows cache/standby is often healthy |
| Network | Purpose classification + user policy | Not “block Microsoft” |
| Privacy | Control plane: observe → recommend → authorize → verify | Home telemetry floor honesty |
| Security | Local attack-surface / defensive assessment | Not offensive ethical hacking toolkit |
| Defender | Work **with** Defender; **no** install-time path exclusion | Verified resolved on current main (no ExclusionPath) |
| Alerts | Evidence-backed logs + optional toasts | Explainability required |
| Chat / VILL | Deferred | See `CHAT_DEFERRED.md` |
| Scope v1→v2 | Laptop guardian; expand engines per architecture phases | Avoid feature spray |
