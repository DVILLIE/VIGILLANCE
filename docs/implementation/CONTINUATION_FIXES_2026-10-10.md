# D'Vielle — Continuation repairs and actual observations

## Delivered in the repair checkout

- Readiness now distinguishes inaccessible Administrator/SYSTEM-private configuration from rejected configuration. It still holds certification until independent verification; an access denial is not proof of a failed installation.
- Resource sampling retains at most 1,024 checkpoint details by default, accepts explicitly bounded capacities, preserves the lifetime sampled RSS peak and reports discarded details. Partial coverage from earlier checkpoints remains visible after eviction.
- Resolution ordering requires recent evidence. Old timestamps and future clock values require evidence review before high-priority recommendations.
- Resolution ordering also compares referenced evidence digests with the current report payload. A modified payload cannot reuse its old evidence identifier for supported priority. These self-contained digests detect inconsistency; they do not authenticate a maliciously rewritten report.
- `scripts/measure_process_costs.py` measures an explicitly selected actual process tree with bounded duration/history, detects root exit/replacement and writes observations without host mutation.
- `scripts/export_runtime_sbom.py` exports actual runtime distribution metadata as an SPDX 2.3 package inventory. No installation, upload, dependency completeness, publisher provenance or license clearance is implied.

## Actual execution evidence

The installed SYSTEM helper was running during this continuation. Ten actual samples over approximately five seconds observed a sampled peak RSS sum of 15,646,720 bytes for PID 20492 and its visible descendants. The result is in `LIVE_HELPER_SAMPLED_COSTS_2026-10-10.json`. This is a snapshot under the host's current activity, not a controlled everyday-workload, battery or continuous-peak benchmark. The root creation time is included to distinguish process reuse.

The SPDX exporter was executed using `C:\Program Files\DVielle\.venv\Scripts\python.exe` (Python 3.14.8). It observed 19 distributions, recorded in `INSTALLED_RUNTIME_SBOM_2026-10-10.spdx.json`. License text is retained as unverified metadata with NOASSERTION license decisions. This follows the [SPDX package-information specification](https://spdx.github.io/spdx-spec/v2.3/package-information/).

Targeted readiness, privacy/cost, workspace and evidence tests passed: 47 tests. The earlier full continuation suite passed 666 tests. The final suite passed **668 tests**, with nine existing Pillow warnings, in 81.65 seconds. Exact output is recorded in `CONTINUATION_FINAL_REGRESSION_2026-10-10.txt`. Both new reporting scripts passed compilation; the actual SPDX inventory had 19 unique package identifiers and consistent relationships. This relationship check is not full schema certification.

## Deployment and remaining acceptance

These source changes have not replaced the installed protected runtime. Its previous approved identity remains authoritative. Protected deployment must inventory the exact replacement bytes and preserve recoverable predecessors; copying changes into a running SYSTEM installation would invalidate that baseline.

Actual packet blocking, deployed crash/recovery matrices, controlled workload/battery benchmarks, GUI/accessibility journeys, optional model admission, authenticated PQ protocol adapters, signed update roots and public multi-build acceptance remain open in the twenty-step project plan. Neither this document nor the metadata inventory marks them complete.

Microsoft distinguishes actual blocked-connection/drop audit evidence from configuration readback: [Filter Origin Audit Log](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation). NIST separates discovery from migration interoperability: [Migration to Post-Quantum Cryptography](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc).
