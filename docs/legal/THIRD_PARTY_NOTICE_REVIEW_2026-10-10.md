# D'Vielle installed third-party notice evidence

## 12 October implementation update

The protected dependency migration is now complete. All four legacy packages are
absent from the active environment. A new actual metadata notice inventory contains
**47 notice files for all 15 active distributions**, with no package missing a
notice in the inspected metadata paths. See
`installed-third-party-2026-10-12/inventory.json` and the
[completed migration acceptance](../implementation/STEP_01_DEPENDENCY_MIGRATION_ACCEPTANCE_AND_RECOVERY_2026-10-12.md).
The older inventory below remains historical evidence. Native/OS dependency
completeness and final shipped-artifact licensing review are not certified here.

### Earlier native candidate checkpoint

The notification/speech migration removes win10toast and pyttsx3 from the source
dependency declaration. Actual wheel closure verification of the new candidate
also excludes pypiwin32 and comtypes. The inspected thirteen-wheel candidate is
recorded under `dist/offline-dependencies-native-20261012/manifest.json`.
This resolves the need for the two problematic artifacts in future clean installs;
it does not authorize omitting their notices from a distribution of the existing
installed environment, which still contains the unused packages. Transactional
environment migration and final shipped-artifact notice reconciliation remain open.
See [native integration evidence](../implementation/NATIVE_NOTIFICATION_AND_SPEECH_INTEGRATION_2026-10-12.md).

## Original installed inventory

The actual protected installation contains 19 Python distributions. A read-only
inventory copied 62 license/notice files from their installed distribution metadata
directories into `installed-third-party/`. `inventory.json` records package names,
versions, declared license metadata, source-relative paths, exact byte counts and
SHA256 values. Installed runtime files were not modified by this collection.

These retained documents support redistribution review. They do not constitute a
complete OS/native dependency inventory or a completed legal clearance. The
installed SPDX inventory remains separately available under implementation evidence.

Two installed distributions did not contain a license/notice file in the inspected
metadata paths:

| Distribution | Actual installed evidence | Required resolution |
| --- | --- | --- |
| pypiwin32 223 | License and homepage both UNKNOWN; requires pywin32 >=223 | Obtain exact artifact permission/provenance or remove this metadata dependency through a tested notification migration. Do not assume pywin32's license automatically grants permission for a different artifact. |
| win10toast 0.9 | Metadata says BSD and identifies the original project, but the installed wheel lacks an inspected license file | Obtain the license matching the exact 0.9 source/artifact and retain its notice, or replace the dependency through a tested migration. |

Primary references: [win10toast original project](https://github.com/jithurjacob/Windows-10-Toast-Notifications)
and [pywin32 publisher package information](https://pypi.org/project/pywin32/).
Current upstream metadata is not proof of the contents or permission of a different
historical installed artifact. Public redistribution review remains open until
the exact artifacts and retained notices are reconciled.
