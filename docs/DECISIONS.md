# Project Decisions (defaults applied for v1)

These defaults follow the co-owner research plan. Override via `config/config.yaml`.

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Windows edition | 10/11 Home & Pro | Same agent; Home uses registry/`auditpol`; Pro may use GPO UI |
| Stack | **Python 3.12** + PowerShell | 3.14 unsupported until deps proven |
| Install path | **`C:\DVILLIE`** only | No Fortoro / Program Files dual path |
| Runtime | Scheduled **headless** `agent.main` + optional GUI | Silent background matches monitor-first |
| Interface | Silent background + optional toasts | Full Jarvis GUI is polish, not the engine |
| Aggressiveness | Monitor-first | Auto-block/trim off until baseline (7 days) + flags |
| Alerts | SQLite + rotating logs + smart CPU/RAM toasts | No external webhooks in v1 |
| Microsoft privacy | Reduce + drift detect; Update preserved | Never claim zero Microsoft traffic; Home floor = Required |
| Logon audit | Enable on install/harden | Attacks module needs Event 4625 |
| Chat / VILL | **Deferred** | See `docs/CHAT_DEFERRED.md` |
| Scope | Personal laptop | Wi-Fi/ARP / USB / DNS stubs not in v1 |
