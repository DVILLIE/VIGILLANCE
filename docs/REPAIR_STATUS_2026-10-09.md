# D'Vielle researched repair batch — 2026-10-09

Implemented in `C:\DVILLIE-main-repairs`, branch
`codex/researched-repairs-20261009`, based on main commit
`ea3dedbc32849bea4961e3c27d65866877ca2eae`.
The three original project checkouts were not changed by this work. No repair
was deployed to the installed runtime.
These are reviewable source repairs. This batch is not a claim that every audit
finding is resolved or that the application has been deployed or certified.

## Implemented behavior

| Area | Result and verification boundary |
| --- | --- |
| Protection preferences | ASR retains the entire configured map, including unknown catalog IDs. ASR/CFA journal before writing, serialize D'Vielle changes, detect intervening state changes, and verify unrelated settings. Unreadable/corrupt/pending journals refuse further changes. Windows offers no atomic comparison against external policy writers. |
| Firewall | Uses supported per-family RemoteAddress arrays, exact normalized filters, ownership tags, and verified invocation-owned rollback. A failed cleanup reports uncertain state. The production privileged transport remains held. |
| Sandbox | Uses the Windows system location, unique configuration files, explicit disabled network/clipboard/audio/video/printer redirection, and read-only maps. Finding text cannot impersonate a guest probe. Actual guest networking remains unknown without independent observation. |
| Intelligence | OSV batch IDs are hydrated, outstanding pages followed, and query associations preserved. Invalid or oversized refreshes retain the old cache. Version matching handles supported interval/prerelease semantics and reports unsupported comparisons as unassessed. Source-specific advisory licenses are retained. |
| Offline updates | Trusted equal-timestamp metadata can resume incomplete target work. A store lock and activation journal coordinate target bytes and their installation record; interruption either completes or restores both. This remains the existing limited custom TUF verifier. |
| Action ownership | SQLite transactions create one active subject and acquire a unique durable claim before dispatch. Finalizations compare claim tokens. Stale observers/owners cannot overwrite a later claim. Duplicate legacy tickets cannot dispatch concurrently. Ambiguous effects remain reserved; legacy unclassified in-progress actions require review. |
| Checklist workflow | Completed checklist progress is distinct from a currently claimed action. Evidence remains readable during recovery without changing workflow status. Known pre-dispatch refusals release their claim. Returned unknown-state/recovery flags prevent automatic retries. |
| Local persistence | Keep-on and footprint writes merge under process/thread locks and use unique atomic temporary files. Readers refresh. First startup baselines cannot be overwritten by a stale instance. A failed convenience mirror is reported while the authoritative saved choice remains effective. |
| Collection health | An unreadable source or malformed row no longer cancels other source findings. Failed refreshes invalidate their previous sample. Stale/incomplete snapshots are withheld from the action engine; failures appear in runtime health and pulse status. Findings retain actual sample receipt timestamps when available. |
| Paths and footprint | Quoted Windows startup paths use CommandLineToArgvW. Egress uses the real resolver signature. Engine logs rotate at 1 MiB with two backups. Budget output explicitly describes resident-process measurement and unmeasured helper costs. |
| Installation | Protected executable owners/ACLs/ancestors, exact private data/config subtrees, trusted interpreter/native executable selection, and mandatory rcedit pin verification replace permissive checks. Highest, token-only production helpers, and unsafe setup/build entry points are explicitly held. |

Detailed evidence and source contracts:

- [Windows controls](REPAIR_WINDOWS_CONTROLS.md)
- [Intelligence and updates](REPAIR_INTEL_UPDATES.md)
- [Installation and privileged boundary](REPAIR_INSTALL_PRIVILEGE_BOUNDARY.md)

## Verification

Python 3.12.10 was used from the existing main environment. The imported
`agent` path was verified to belong to this isolated repair checkout.
Tests use temporary databases/files, actual concurrent threads/processes,
in-memory ACL descriptors, explicit control adapters, and injected I/O failures.
Adapter outcomes are fixtures; they do not prove Windows remediation efficacy.

Final full suite: **523 passed, 1 skipped, 7 warnings in 53.89 seconds**.
The skipped check was in the logo/Tk group; all three logo/Tk checks subsequently
passed in focused reruns. The warnings concern existing Pillow test APIs.
Python AST parsing checked 154 sources without errors. All 12 project
PowerShell scripts parsed without errors; the controls slice also parsed seven
generated scripts. `git diff --check` passed.

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
C:\DVILLIE-main\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider
```

PowerShell source parsing and generated-script parsing are read-only checks.
No installer, threat sample, security-setting change, privileged helper,
scheduled-task replacement, or release publication was executed.

## Deployment gates and remaining work

1. Build dependencies without Administrator execution, pin all transitive wheel
   hashes, and design protected package/compiler staging and transactional
   activation. The existing Inno wrapper and its builder intentionally refuse;
   the Limited script requires trusted protected staging. Broadly writable
   existing installations require an explicit migration design.
2. Implement the real privileged service with OS-authenticated callers and
   protected, expiring, one-use authorization. The named-pipe contract is a
   design, not a running service. Keep Highest and privileged auto-update held.
3. Validate controls and recovery on disposable Windows machines, across
   supported editions, IPv4/IPv6, VPNs, managed policies, denied access,
   timeout, reboot, and interrupted changes. Preserve exact before/after
   evidence. Configuration readback is not proof of stopped packets or malware.
4. Review the custom TUF client independently and migrate to the maintained
   reference client. Test real activation/recovery durability and a release
   channel. Metadata attestation does not measure the live process.
5. Complete helper/process-tree resource accounting, source-specific freshness
   policies, inventory coverage, event-log capability provisioning, and recovery
   UI. A claim left by a crash or legacy unknown action is deliberately not
   cleared by a timer. Review actual effects before any explicit recovery.

The free application can gain stronger measurable protections through these
steps. Passing this suite proves the tested software contracts; it does not
establish universal protection or complete coverage of this computer.

## Primary contracts used for the root repairs

- [SQLite write transactions](https://sqlite.org/lang_transaction.html)
- [Python temporary-file creation](https://docs.python.org/3.12/library/tempfile.html)
- [Windows file locking](https://docs.python.org/3.12/library/msvcrt.html#msvcrt.locking)
- [Windows command-line parsing](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw)
- [Secure dependency installation](https://pip.pypa.io/en/stable/topics/secure-installs/)

These sources informed the implementation. They are not certification of it.
