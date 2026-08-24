# Project Decisions

Canonical product thesis and engine map: **[VIGILLANCE_MASTER_ARCHITECTURE.md](VIGILLANCE_MASTER_ARCHITECTURE.md)**.

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Product identity | System intelligence + resource governance + privacy + defensive security — **not** AV-first | User workload (esp. AI) must stay responsive |
| Intelligence shape | Collection → correlate → score → confidence → recommend → act | Module toasts alone are insufficient |
| Windows edition | 10/11 Home & Pro | Same agent; Home registry/`auditpol`; Pro may use GPO |
| Stack | **Python 3.12** + PowerShell | 3.14 unsupported until deps proven |
| Install path | **`C:\DVILLIE`** only | Single story |
| Runtime | Headless `agent.main` + optional GUI | Silent background; adaptive scheduler is next |
| Default posture | Monitor-first / Observe–Explain | Auto-block/trim off until baseline + flags + confidence |
| Memory | **Pressure**, not “RAM % used” | Windows cache/standby is often healthy |
| Network | Purpose classification + user policy | Not “block Microsoft” |
| Privacy | Control plane: observe → recommend → authorize → verify | Home telemetry floor honesty |
| Security | Local attack-surface / defensive assessment | Not offensive ethical hacking toolkit |
| Defender | Work **with** Defender; **no** install-time path exclusion | Do not weaken trust boundary |
| Alerts | Evidence-backed logs + optional toasts | Explainability required |
| Chat / VILL | Deferred | See `CHAT_DEFERRED.md` |
| Scope v1→v2 | Laptop guardian; expand engines per architecture phases | Avoid feature spray |
