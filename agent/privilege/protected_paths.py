"""Read-only Windows trust preflight; never converts mutable data into trust."""
from __future__ import annotations

import os
from pathlib import Path

TRUSTED_OWNERS = frozenset({"S-1-5-18", "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"})
MUTATION_RIGHTS = 0x000D0156
# Ancestors must deny replacement/deletion and ownership/DACL changes.
# Windows permits metadata writes on ProgramData; those are not child-file
# write authority. Target objects still reject all mutation rights above.
ANCESTOR_RIGHTS = 0x000D0040


def assert_protected_path(path: Path) -> None:
    """Reject untrusted owners/writers, missing objects and reparse ancestors."""
    if os.name != "nt":
        raise OSError("Protected service storage requires Windows ACL verification.")
    import win32security
    target = Path(os.path.abspath(path))
    if not Path(path).is_absolute():
        raise ValueError("A protected path must be absolute.")
    for index, item in enumerate((target, *target.parents)):
        if item.lstat().st_file_attributes & 0x400:
            raise PermissionError("Reparse objects cannot be protected service inputs.")
        descriptor = win32security.GetNamedSecurityInfo(str(item), win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
        owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
        if owner not in TRUSTED_OWNERS:
            raise PermissionError("An untrusted owner can replace service inputs.")
        acl = descriptor.GetSecurityDescriptorDacl()
        if acl is None:
            raise PermissionError("A null DACL does not protect service inputs.")
        for offset in range(acl.GetAceCount()):
            header, mask, sid = acl.GetAce(offset)
            kind, flags = header
            if flags & 0x8:  # INHERIT_ONLY: does not grant this object's rights.
                continue
            if kind == win32security.ACCESS_DENIED_ACE_TYPE:
                continue
            if kind != win32security.ACCESS_ALLOWED_ACE_TYPE:
                raise PermissionError("An unsupported effective ACE requires review.")
            if mask & 0x10000000:  # GENERIC_ALL
                mask |= 0x001F01FF
            if mask & 0x40000000:  # GENERIC_WRITE
                mask |= 0x00120116
            rights = MUTATION_RIGHTS if index == 0 else ANCESTOR_RIGHTS
            if mask & rights and win32security.ConvertSidToStringSid(sid) not in TRUSTED_OWNERS:
                raise PermissionError("An untrusted principal can mutate service inputs.")
