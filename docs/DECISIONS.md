# Project Decisions (defaults applied for v1)

These defaults follow the plan's recommendations. Override via `config/config.yaml`.

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Windows edition | 10/11 Home & Pro | Registry-based hardening works on all; Pro Group Policy paths documented in scripts |
| Stack | Python 3.12 + PowerShell | Python for monitor loop; PS for native hardening/firewall |
| Interface | Silent background + optional toasts | Low resource; tray/dashboard deferred to v2 |
| Aggressiveness | Monitor-first | Auto-block disabled until baseline complete and explicitly enabled |
| Alerts | SQLite log + rotating file + optional Windows toasts | No external webhooks in v1 |
| Scope | Personal laptop, trusted + untrusted network modules available | Wi-Fi/ARP modules off by default |
