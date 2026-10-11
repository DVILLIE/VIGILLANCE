# D’Vielle Offline Dependency Release Preparation

## Implemented changes

`scripts/prepare_offline_dependencies.py` runs under a non-administrator Windows
Python 3.12 process. It pins project runtime, Windows and build requirements to
the versions actually present in the development runtime, constrains transitive
dependencies to observed versions, and downloads wheels from the official PyPI
index without installing them. Source distributions are refused.

Each top-level wheel metadata identity is checked against its filename. Its
actual SHA256 and size must match the official version-specific PyPI metadata;
yanked artifacts are refused. All selected project/build roots must appear.
An exact-version SHA256 requirements lock is generated, and pip then verifies
the complete dependency closure offline with hash checking enabled.

The Administrator installer now requires an existing protected dependency
bundle before it disables tasks or copies application files. Its preflight
rejects reparse paths, empty/unsafe/duplicate pins, missing wheels, unlisted
artifacts and changed hashes. Dependencies install with no index, no cache,
binary-only distributions and required hashes. The protected local editable
project installs separately without dependency resolution or build isolation;
its build tools are included in the verified dependency bundle.

## Actual artifact evidence

Candidate directory:
`C:\DVILLIE-main-repairs\dist\offline-dependencies-20261010`.
Seventeen wheels were downloaded and verified against official PyPI metadata.
The offline pip closure check exited successfully. No wheel was installed by
preparation, and the existing development environment was not changed.

The initial verification correctly stopped before producing a manifest because
setuptools contains nested vendor metadata. The verifier was corrected to select
only top-level distribution metadata and rerun on the existing downloaded files.
The corrected verification completed successfully.

The candidate's `manifest.json` records filenames, versions, sizes, hashes,
requirements and actual index/artifact URLs. `requirements.lock` is the complete
hashed dependency set. The bundle remains an unsigned release candidate in a
mutable development directory; it has not been authenticated as a publisher
release or installed as a protected service.

## Validation and activation boundary

Fifteen installer contract tests passed, including rejection of changed bytes,
missing/unlisted artifacts and requirement-file options that could alter the
package index. These bounded tests do not claim wheel execution or protection.
Actual downloaded wheel verification is separate from those contract tests.

An additional real installation check created the separate, non-elevated
`dist/offline-install-validation` virtual environment. All 17 dependencies
installed there using the hashed offline lock. D’Vielle 2.4.2 then built and
installed editable with no index, no dependencies and no build isolation.
`pip check` reported no broken requirements, and all 24 non-collecting smoke
checks passed. This verifies local package installation and imports, not a
protected machine deployment or an installed SYSTEM service. The original
development virtual environment was preserved.

The final full regression suite completed with **641 passed, one skipped and
nine existing Pillow deprecation warnings in 88.99 seconds**. The saved full
log is `OFFLINE_DEPENDENCY_TEST_RESULTS_2026-10-10.txt`; the skipped case reported
unavailable Tk support. Earlier test results describe earlier source checkpoints.

Use `-DependencyBundle` to identify the independently trusted, protected copy
during an authorized Administrator installation. The installer refuses the
current mutable checkout and wheel candidate. Do not change their ACLs merely
to relabel them trusted. Protected staging, release authentication, native service
installation, actual SYSTEM peer acceptance and packet enforcement remain open.

## Primary sources

[pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
documents complete hash requirements, exact pins, binary-only distributions and
the difference between remote index hashes and locally trusted pins.
[pip download](https://pip.pypa.io/en/stable/cli/pip_download/)
documents preparing dependencies without installing them and hash-checking mode.
This implementation uses those free tools; it does not assert entire-web coverage.
