# D'Vielle — Protected Authorization and Service Implementation

10 October 2026 • Source and verification record • Protected deployment pending

## Delivered behavior

The native source route binds a network-restriction request to a Windows pipe
client token and a server-owned, expiring, one-use administrative grant. The
request cannot supply identity, consent, shell text, grant creation or recovery
commands. Grant creation alone performs no firewall mutation. The old bearer
token loopback route remains a non-elevated contract adapter.

The service entry point requires SYSTEM. Administrative approval requires an
administrative token and protected runtime paths. Neither entry point elevates
itself, installs a service, downloads an executable or launches a mutable
checkout under another identity. The current development session is not
elevated, and this work has not deployed a SYSTEM service or changed host
firewall policy.

## Components and responsibilities

| Source | Responsibility |
|---|---|
| `agent/privilege/protected_paths.py` | Read-only ownership, effective writer and reparse-path checks for protected inputs and ancestors |
| `agent/privilege/target.py` | Bounded executable hash, file identity and actual Windows sharing leases held through an operation |
| `agent/privilege/grants.py` | Installation-user binding, schema version, expiry/revocation, atomic one-use consumption and durable operation intent |
| `agent/privilege/service_dispatch.py` | Closed request schema, native-peer requirement, pending-operation hold and scoped executor dispatch |
| `agent/privilege/native_channel.py` | Bounded request/reply messages, cancellation completion and receive-thread ownership |
| `agent/privilege/native_client.py` | Server PID, SCM registration, SYSTEM token and protected process image checks before sending grant or program path |
| `agent/privilege/service_host.py` | SCM service class, protected startup gate and serialized request loop |
| `agent/privilege/admin.py` | Trusted administrative approve, revoke and recover commands; absent from resident pipe protocol |
| `agent/privilege/recovery.py` | Exact operation/journal scope binding and conditional owned-rule restoration |
| `agent/privilege/broker.py` | Native route only when a grant is supplied and the existing local mutate gate is active |
| `agent/engine/net_block.py` | Grant forwarding and explicit unknown-outcome reporting |

## Authorization transaction

1. The administrative entry point checks its token and protected runtime roots.
2. It reads the protected installation user SID from the Windows known common
   application-data folder, `DVielle/privileged/installation.json`. Environment
   variables do not select the production state directory.
3. It validates the exact program, firewall profile, address families and remote
   networks. It hashes the actual file under a Windows lease.
4. It records a grant bound to normalized request hash, executable SHA-256,
   file identifier, size, modification time and installation user. Expiry is at
   most five minutes. The identifier conveys no authority without the record.
5. The client authenticates the actual pipe server against the running SCM
   service and SYSTEM process token before transmitting the request.
6. The server authenticates the pipe client token. Caller fields cannot replace
   this observation. Its identity record alone confers no action permission.
7. The dispatcher holds a serialized service lock, refuses unresolved earlier
   operations, and leases the executable again through execution.
8. SQLite `BEGIN IMMEDIATE` consumes the grant and inserts `intent_durable` in
   one committed transaction before any firewall command.
9. A separately flushed owned-rule journal precedes the executor. Configuration
   readback records `configuration_verified`; uncertainty is retained.
10. A lost reply never makes the grant reusable and never proves no change.

Clock reversal before issuance causes refusal; expiry still depends on the
Windows wall clock. This is not a claim of tamper-proof time. Leases prevent
write/replacement during the operation, not changes after the lease ends.
Windows Firewall program rules remain path rules rather than persistent
cryptographic identity enforcement.

## Recovery transaction

Administrative recovery identifies one protected operation and holds the same
service lock. It requires the journal's parameters to match the operation
record, then checks version, ownership token, derived rule names and expected
settings. Conditional removal retains edited/conflicting rules. A missing,
damaged or mismatched journal remains unresolved; there is no automatic replay
or declaration of an unchanged machine.

The original executable need not remain installed for owned-rule removal:
recovery validates the saved local path without executing or opening it. The
normal restriction validator still requires an existing file. Successful
cleanup marks the operation restored. Failed cleanup retains the pending hold.
If cleanup succeeded but database persistence failed, the retained intent is
reconciled again rather than treated as permission for another mutation.

## Evidence actually obtained

- Actual Windows pipe client token and message transport were exercised in
  temporary child processes without elevated rights.
- An actual native request/reply round trip reached the dispatcher, consumed a
  grant and refused replay. Its executor was explicitly injected: it changed no
  Windows Firewall rule and is not evidence of privileged enforcement.
- A user-session pipe server was refused by the production server-authentication
  routine before any request was transmitted. Positive authentication against
  a deployed SYSTEM service has not been exercised.
- A real Windows executable lease refused writes and rename while held and
  permitted changes after release. Fixture bytes were never executed.
- Contract checks cover competing claims, expiry, revocation, wrong user,
  altered request, replaced executable, transactional insertion failure,
  installation-user/schema mismatch and user-writable production-state refusal.
- Recovery contracts cover missing/mismatched journals, edited-rule conflicts,
  verified cleanup and deleted original executable. Runners are non-production
  fixtures, not actual packet or Windows-policy measurements.
- A disconnected-client case exposed pywin32's distinct exception type. The
  service loop now handles it and remains available for another connection.

Exact aggregate results are in `TEST_RESULTS_2026-10-10.txt`. Source-file hashes
and saved-log identity are in `IMPLEMENTATION_EVIDENCE_MANIFEST_2026-10-10.json`.
Neither is an installed binary attestation or signed release manifest.

## Remaining activation and acceptance work

The SCM source host is implemented, but a trusted installed artifact is not
available in this record. Before activation, the release pipeline must verify
runtime/package provenance, every dependency and executable load path,
protected recursive ACLs, service registration/DACL, protected state migration,
rollback and uninstall. Path ACL checks alone do not prove publisher identity
or exclude unsafe pre-existing dependency files.

The GUI does not auto-launch an administrative approval program or collect
administrative credentials. Its existing handlers do not silently mint grants.
A deployment-approved consent journey must pass the exact protected approval
result through the local policy gate to the native broker. The source APIs can
carry the grant; the existing resident path without one remains refused.

Required live acceptance includes actual SYSTEM-client authentication,
multi-account and remote refusal, pipe squatting, service-stop interruption,
storage failure, independent rule inspection, edited-rule restoration and
IPv4/IPv6 TCP/UDP/QUIC outcomes with VPN/proxy and competing Windows policies.
Configuration verification alone does not establish packet containment.

## Primary engineering references

- [Microsoft CreateFile sharing semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew): incompatible access fails while a lease is held; delete sharing covers rename.
- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html): transaction durability assumptions and failure recovery.
- [SQLite transactions](https://www.sqlite.org/lang_transaction.html): immediate writer transaction and commit failure behavior.
- [Windows service security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights): service configuration authority and access rights.
- [GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid): actual pipe server PID rather than an endpoint-file claim.
- [Microsoft named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights): explicit client rights and server-instance creation authority.

These sources support design choices. They are not substitutes for the live
activation and acceptance evidence above.
