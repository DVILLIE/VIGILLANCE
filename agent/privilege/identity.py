"""Windows pipe peer identity. Authentication does not confer action permission.

Call only on the server handle after reading the client's bounded request.
No service is installed or mutation dispatcher enabled by this module.
"""
from __future__ import annotations

import os

from agent.privilege.pipe import build_pipe_sddl


def authenticate_pipe_peer(handle, installed_user_sid: str) -> dict:
    build_pipe_sddl(installed_user_sid)
    if os.name != "nt":
        raise OSError("Windows pipe authentication is unavailable.")
    import pywintypes
    import win32api
    import win32con
    import win32pipe
    import win32security

    # Never overwrite an existing thread impersonation context.
    try:
        existing = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True)
    except pywintypes.error as exc:
        if exc.winerror != 1008:  # ERROR_NO_TOKEN; other errors are not absence.
            raise
    else:
        existing.Close()
        raise PermissionError("The caller-authentication thread is already impersonating.")

    impersonated = False
    try:
        # Pywin32 raises on API failure. No request executes after that failure.
        win32security.ImpersonateNamedPipeClient(handle)
        impersonated = True
        token = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True)
        try:
            sid, _attributes = win32security.GetTokenInformation(token, win32security.TokenUser)
            level = win32security.GetTokenInformation(token, win32security.TokenImpersonationLevel)
            peer_sid = win32security.ConvertSidToStringSid(sid)
            if level < win32security.SecurityIdentification or peer_sid != installed_user_sid:
                raise PermissionError("The pipe client's OS identity is not the installed user.")
            process_id = win32pipe.GetNamedPipeClientProcessId(handle)
            result = {"sid": peer_sid, "process_id": process_id,
                      "identity_source": "Windows pipe client token", "authorized": False}
        finally:
            token.Close()
    finally:
        if impersonated:
            try:
                win32security.RevertToSelf()
            except Exception:
                # Microsoft requires termination rather than continuing as the
                # client. A catchable exception would not enforce that rule.
                os._exit(70)
    return result
