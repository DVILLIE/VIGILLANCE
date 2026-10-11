# D'Vielle installed third-party notice evidence

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
