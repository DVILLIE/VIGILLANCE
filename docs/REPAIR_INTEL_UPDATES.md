# Intelligence and offline-update repairs

Implementation slice: 2026-10-09. Worktree: `C:\DVILLIE-main-repairs`.
These are source changes and regression checks, not deployment or efficacy certification.

## Intelligence

The opt-in downloader now treats OSV batch results as summaries, retains each
package/version query's advisory IDs, follows only outstanding pagination tokens,
and retrieves full records from `/v1/vulns/{id}`. Mismatched IDs/modification
timestamps, repeated page tokens, HTTP errors, incomplete schemas, and exceeded
budgets reject the candidate refresh. Each validated feed is published through a
unique temporary file and atomic replacement; failure of one feed does not
discard its previous cache or prevent the other feed's independent refresh.

Budget ceilings: 16 MiB per feed and total OSV response bytes, 1,000 inventory
queries, 100 queries per batch, 20 pages per batch, and 2,000 OSV records. These
are operational caps, not promises of complete coverage. An exceeded cap is a
reported failed refresh, not a truncated clean result. Input files and provenance
sidecars use bounded reads. Sidecars are accepted only when their content hash
matches the feed, so an interrupted two-file publication cannot attach an old
retrieval timestamp to a newer feed.

Matching evaluates every sorted introduced/fixed/last-affected interval, including
open-ended intervals and limit boundaries. PyPI ECOSYSTEM ranges use the
maintained `packaging.version.Version` implementation of PEP 440. SEMVER ranges
use strict SemVer precedence, including prerelease identifiers and ignored build
metadata. Other ecosystem comparisons and Git graph comparisons remain
unassessed unless an exact affected-version entry is available.

Reports distinguish affected, unaffected within the loaded records/completed
query, and unassessed packages. Negative results explicitly describe their cache
scope. The inventory is operator-supplied; it is not a complete device census.
There is no automatic network fetch, stale-cache expiration guarantee, complete
operating-system vulnerability assessment, or malware-detection claim.

Advisory records retain full source content, database identity, and references.
Notices distinguish the Apache-2.0 OSV schema from advisory data: aggregated data
retains source-specific terms. Unknown redistribution terms are not declared
Apache-2.0. Bundling/public redistribution still requires source-license review.

## Offline updates

Equal-version remote timestamp metadata is discarded as before, while the client
can resume incomplete target work using the trusted cached timestamp. Its cached
signatures and expiration are rechecked; lower timestamp versions, lower referenced
versions, bad signatures, mismatched hashes, and expired metadata remain rejected.
An unchanged result requires matching installed bytes and installation metadata,
not merely a timestamp version match.

An OS-backed, nonblocking store lock prevents overlapping verification/activation
cycles. Metadata and artifacts use unique atomic temporary writes with file
flush/fsync. Before replacing a target, an activation journal records the previous
installation record, a hash-checked artifact backup, and the next record. Recovery
either recognizes a complete commit or restores both previous bytes and their
record. Storage failure reports whether the previous artifact was preserved;
failed recovery reports `recovery_required` and does not start another update.

This is a bounded repair of the existing Ed25519 top-level-role verifier. It does
not adopt the maintained TUF reference client, add delegations, install a running
application, enable privileged updates, attest the live process, or validate a
public release channel. The trusted store requires protected ownership/ACLs.
Regression fault injection covers interruption boundaries; it is not a real
power-loss, disk-firmware, filesystem durability, or adversarial host test.
Independent TUF conformance review and a reference-client migration remain work.

## Verification performed

Commands executed with the existing main Python environment, from the repair
worktree, with bytecode and pytest cache writes disabled:

```powershell
C:\DVILLIE-main\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_repair_intel_updates.py tests/test_worldclass_p4.py
C:\DVILLIE-main\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_worldclass_p3.py -k tuf
```

Most recent results: 34 passed; 4 passed with 11 non-TUF tests deselected.
The new tests use explicit contract fixtures and injected I/O interruptions.
They check hydration, query association/pagination, previous-cache preservation,
empty completed query coverage, malformed summary rejection, range boundaries,
prerelease ordering, same-timestamp retry, freeze/mix-and-match rejection,
activation rollback/recovery, bounded reads, and concurrent update refusal.
No live OSV/KEV feed requests, installer execution, privileged operation, or
Windows protection mutation were performed by these checks.

## Primary material consulted

- OSV batch results/order/pagination: https://google.github.io/osv.dev/post-v1-querybatch/
- OSV version evaluation and limit semantics: https://ossf.github.io/osv-schema/#evaluation
- OSV source identity/terms index: https://google.github.io/osv.dev/data/
- TUF trusted timestamp and rollback/freeze rules: https://theupdateframework.github.io/specification/latest/#update-the-timestamp-role
- PyPI version ordering: https://packaging.pypa.io/en/stable/version.html

These sources define contracts. They do not certify this implementation.
