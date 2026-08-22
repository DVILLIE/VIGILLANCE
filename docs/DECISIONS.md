# Project Decisions (defaults applied for v1)

These defaults follow the plan's recommendations. Override via `config/config.yaml`.

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Windows edition | 10/11 Home & Pro | Registry-based hardening works on all; Pro Group Policy paths documented in scripts |
| Stack | Python 3.12 + PowerShell | Python for monitor loop; PS for native hardening/firewall |
| Interface | Silent background + optional toasts | Low resource; tray/dashboard deferred to v2 |
| Aggressiveness | Monitor-first | Auto-block disabled until baseline complete and explicitly enabled |
| Alerts | SQLite log + rotating file + smart CPU/RAM toasts | No external webhooks in v1 |
| Microsoft privacy | Strict guard after baseline | Hosts + firewall + service disable; Windows Update preserved |
| Scope | Personal laptop | Wi-Fi/ARP modules off by default |
