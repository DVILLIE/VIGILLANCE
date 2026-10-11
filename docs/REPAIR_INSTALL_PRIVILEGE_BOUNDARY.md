# Installation and helper safety hold — 2026-10-09

These changes are source repairs and unit checks. No installer, elevated helper,
ACL mutation, task change, or Windows security setting was deployed to the host.

## Implemented

- The installer refuses `Highest` before any installation mutation. Private
  mutable state is not a protected approval boundary for an elevated resident.
- A new code root is created with its protected descriptor atomically. Only
  the exact `data` and `config` subtrees become private writable state, owned by
  the installed user and accessible to that user, Administrators and SYSTEM.
  All other code/interpreter objects require protected owners and permissions.
- New private subtrees are converted bottom-up while still protected. Existing
  user-mutable private trees are validated without elevated ACL rewrites or
  writes of missing config defaults, avoiding admin writes through those paths.
- Administrator shutdown/uninstall no longer invokes an existing installation's
  Python executable or modules. It requests normal window closure and refuses
  to proceed when the resident remains running; exit it through its existing
  Limited session before retrying.
- The installer checks source, destination, and selected interpreter trees
  before elevated execution. The check requires protected owners and rejects
  mutation rights, reparse points, and ancestors that could replace the tree.
  It does not repair a writable checkout's ACL and then assume its existing
  contents are trustworthy.
- ACL validation compares individual mutation rights. `ReadAndExecute` no
  longer overlaps a composite `FullControl` mask and gets rejected as write.
  Intended protected descriptors are owned by Administrators.
- Production helper dispatch and broker submissions refuse the token-only
  loopback path. The CLI starts no listener. Unit loopback adapters require
  explicit `test_harness=True` and refuse elevated Windows tokens. Malformed
  payloads and adapter failures cannot terminate the listener thread.
- The proposed pipe DACL uses specific client rights excluding
  `FILE_CREATE_PIPE_INSTANCE`. Pipe descriptions report `defined_only` and
  explicitly report that remote rejection and an OS server are not deployed.
- Bootstrap uses the same trusted Python probe and verifies protected staging
  of the pinned installer. Native auditpol/PowerShell paths come from Windows'
  System known folder, not PATH. The rcedit hash pin is mandatory.
- The existing setup wrapper aborts with `InitializeSetup=False`; its elevated
  temporary-script hook was removed. Wrapper builds stop before downloading or
  installing a compiler, pending a protected bootstrap/compiler staging design.

## Remaining work before deployment

An existing broadly writable checkout will intentionally fail the elevated
installer preflight. A trusted, protected package staging and activation process
is required; changing ACLs is not an authenticity check. The interpreter check
supports protected system Python discovered as `python3.12` or `python`; it does
not execute `py` to discover an unvalidated per-user interpreter.

The normal Limited script has permission separation without moving the data
root. Its viability is source/unit-checked for a protected stage, not proven by
a real installation. Existing broadly writable installations are refused rather
than retrospectively trusted; migration remains required. Source
provenance, pinned wheels, transactional activation/recovery, and a reviewed
unprivileged build process remain separate work. The installer still executes
build tooling as Administrator after its permission preflight; this safety hold
is not certification of that architecture. The invoked installer itself must
come from a trusted distribution.

The published 2.4.2 archives were not rebuilt or changed. Extracting a source
archive into a user-owned folder does not satisfy these new stage requirements.
Inno's former `{tmp}` payload path is not an accepted protected execution stage.
The wrapper is deliberately held before payload installation instead of claiming
its historical flow will pass the new checks.

The real helper needs a reviewed OS service, caller-token authentication,
expiring one-use approval in protected server state, impersonation handling,
remote-client rejection, bounded requests, and operation-specific authorization.
An in-process caller string, bearer token, or client-side context is not that
boundary. The test adapters do not establish firewall enforcement on Windows.

## Primary material

- [Windows owner has implicit WRITE_DAC](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object).
- [Individual filesystem rights](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights).
- [Pipe generic-write rights include server-instance creation](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
- [CreateNamedPipe remote-client rejection](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea).
- [Inno InitializeSetup can abort setup during initialization](https://jrsoftware.org/ishelp/topic_scriptevents.htm).
- [Inno directory Permissions add grants and can fail silently](https://jrsoftware.org/ishelp/topic_dirssection.htm).

The regression tests use in-memory ACL descriptors, temporary fixture files,
explicit test adapters, and PowerShell parsing. They do not call Set-Acl or
security mutation cmdlets on the real host.
