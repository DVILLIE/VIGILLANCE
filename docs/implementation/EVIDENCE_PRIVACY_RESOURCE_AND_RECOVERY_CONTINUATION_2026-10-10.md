# D'Vielle — Evidence, Privacy, Resource Accounting and Recovery Continuation

10 October 2026 • Implemented source and actual verification record

## Result and scope

This continuation implements history controls, process-tree accounting,
shared evidence envelopes, snapshot freshness, evidence-linked recommendation
ordering and an installed-service readiness view. It also adds actual
child-process crash/reopen tests for the protected authorization ledger.
The original checkouts, approved branding and existing source repairs remain
preserved. No SYSTEM service was installed, no administrator token obtained,
no host firewall policy changed and no third-party assessment initiated.

These changes advance implementation-plan steps 1, 6, 12, 13, 14 and 18. They
do not satisfy every exit criterion of those steps, and do not complete the
twenty-step release plan.

## History retention and deletion

The Ethical Hacking workspace now includes **Privacy & costs**. Automatic
history cleanup defaults off. Users can choose a retention age and maximum
number of saved terminal runs, preview matching records and delete exactly
the previewed batch after confirming. Saving a policy performs no deletion.
Enabling automatic cleanup requires a confirmation explaining the selected
age, count and batch limit. The saved policy is reloaded on a later launch.

Deletion is limited to 200 distinct records per batch. Running assessments and
unknown states are excluded. A shared assessment lock prevents a legitimate
concurrent worker from overlapping settings changes or deletion. A SQLite
immediate transaction rechecks every explicitly selected record before
deleting; stale selection, active records or incomplete deletion rolls back
the entire transaction. Actual affected-row counts are recorded.

Opted-in automatic cleanup runs after a completed/partial report is durably
saved and preserves that run even if its wall-clock timestamp becomes old
relative to another record. Cleanup failure does not relabel the assessment
as successful maintenance or silently replace its observation state.
The retention policy applies only to the assessment database. It never deletes
protected grants, operation journals, exports or another application's data.

`PRAGMA secure_delete=ON` is used for database deletion. This is not secure
erasure of exports, backups, filesystem snapshots, old journal copies or
storage-device remapping. No such erasure claim appears in the UI or result.

## Resource observations

`ProcessTreeSampler` reads the current assessment process and descendants
visible at checkpoints, bounded to 128 process samples. It tracks PID plus
creation time internally so PID reuse cannot connect unrelated CPU counters.
It records RSS sum, observed process count, elapsed interval, unreadable
processes, process arrivals/departures and CPU deltas for stable identities.
Process IDs are not emitted in these resource records.

CPU percentage per logical core and percentage normalized over available
logical cores have separate fields. A first sample, unreadable identities or
an unstable process set yields unknown aggregate CPU rather than an invented
zero. A separately labeled observed lower bound can retain measured deltas.
Unreadable memory remains unknown. These fields do not enforce an OS hard cap.

RSS can count shared pages more than once. Peaks are checkpoint peaks. Short
lived processes between checkpoints, final CPU of departed processes and
separately launched D'Vielle processes are not fully accounted for. A CLI run
does not benchmark the graphical application, foreground work or every
supported machine. These qualifications are part of the stored report and UI.

## Evidence lifecycle and recommendation ordering

Assessment checkpoints use the existing shared `agent.evidence.Observation`
schema. Each currently recorded observation has a source path, payload digest,
coverage category, observation identifier, checkpoint timestamp and run
identity. Findings reference those identifiers. Unchanged payloads keep their
checkpoint identity; changed payloads receive a new record and finding links
are updated. These are latest run snapshots, not an append-only forensic log
or continuous sensor event stream.

The UI calculates snapshot age from run start. The five-minute recent/stale
boundary is an explicit product review policy, not a statistical confidence
interval. Malformed timestamps, missing timezone or reversed clocks remain
unknown/uncertain. Historical evidence cannot authorize a mutation.

Recommendations require existing evidence identifiers. Unqueried, unavailable
or missing support produces a review-evidence-first item. Supported high
severity observations precede ordinary review items. Every recommendation
states that no action permission exists and requires renewed target/control
observation, scope/disruption/recovery review and operation-specific approval.
No fabricated risk probability, successful exploit, causal attack path or
optimized disruption measurement is claimed.

Redacted export re-derives hashes and evidence links from the redacted payload,
including the target scope. Raw private listener/header/certificate/origin
hashes are not intentionally retained as a fingerprint in the exported
record. The original database report is unchanged.

## Actual deployment baseline observation

`scripts/check_release_readiness.py` performs read-only Windows prerequisites
checks. The UI's **Check protection service** button runs the same inspection
in its worker and displays the evidence without creating a history assessment,
installing anything or elevating. It distinguishes Windows error 1060
(service not installed) from access or query failure (unavailable).

The actual saved observation in `INSTALLED_READINESS_2026-10-10.json` records
Windows version `10.0.26200`, a non-elevated session, helper error 1060,
missing protected installation-user configuration, and rejected protected ACL
checks for the current interpreter and source package. Its state is
`activation_held`, with an observation timestamp and no mutations. These are
specific observed prerequisites; they are not an assumption from an old report.

The check does not prove publisher provenance, recursive dependency safety,
positive native peer authentication, effective firewall policy or packet
containment. A running service alone would not certify any of those.

## Verification obtained

- Real SQLite preview/delete/policy tests cover default-off behavior, bounded
  batches, active-run preservation, stale selection, lock contention, partial
  deletion rollback, policy persistence and preservation of the current run
  across a timestamp shift. Fixture rows are retention contract inputs.
- An actual owned child process was sampled alongside the real test process.
  It exited through its normal input-controlled path; no unrelated process was
  terminated.
- Actual child processes exited abruptly after committed and uncommitted
  SQLite authorization transactions. Reopening the ledger preserved committed
  consumed grants/intents and rolled back the uncommitted changes. This is
  process-exit recovery evidence, not power-loss or storage-hardware proof.
- Real Tk tests exercised the privacy controls, policy preview, widget bounds
  and the asynchronous read-only service-readiness button.
- Evidence tests cover shared schema, stable/changed identifiers, missing or
  unqueried support, stale/uncertain timestamps and re-derived redacted hashes.
- A real local assessment completed with ID
  `8f2c0f16-7fc7-4d26-be03-2074519e9483`, 21 review items, eight evidence
  records and evidence identifiers on all 21 findings. It recorded eight
  resource samples and a sampled RSS-sum peak of 39,780,352 bytes. Automatic
  retention was off and deleted zero records. No runtime-version sharing,
  external website request or system mutation was enabled.

The final full-suite log records **640 passed, no skips, 9 warnings**; the source
manifest binds its hash and the latest local report/readiness observation.
Tests and this source manifest do not certify an installed release.

## Remaining work and acceptance dependency

Trusted runtime/package provenance, protected installation/state migration,
SCM activation and the deployed approval journey remain prerequisites for
privileged execution. The observed development interpreter/source fail those
checks. Changing their ACLs alone would not establish trusted provenance.

Independent traffic tests, rule restoration with real competing edits,
multi-account/remote/squatting tests, full application-process accounting,
foreground workload benchmarks, cryptographic interoperability, accessibility
acceptance, trusted updates and supported-environment pilot/release decisions
remain open. The evidence-linked review list is an initial prioritizer rather
than the completed consequential-path optimization framework.

## Primary material

- [SQLite PRAGMA documentation](https://www.sqlite.org/pragma.html): secure deletion semantics and limitations.
- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html): transaction recovery assumptions; process-exit testing is narrower than power loss.
- [psutil reference](https://psutil.readthedocs.io/stable/index.html): process identity, CPU times, memory information and descendant enumeration.

The implementation and actual evidence above, rather than the existence of
these references, determine the recorded completion status.
