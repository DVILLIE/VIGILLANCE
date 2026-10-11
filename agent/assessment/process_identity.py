"""Read-only owner identity observations; never mutation authority."""
from __future__ import annotations

import psutil


def observe_process(pid: int | None) -> dict:
    if type(pid) is not int or pid <= 0:
        return {'state': 'unavailable', 'reason': 'owner_pid_not_observed'}
    try:
        process = psutil.Process(pid)
        created = process.create_time()
        name = process.name()
        try:
            executable = {'state': 'observed', 'path': process.exe(),
                          'scope': 'Executable path rules affect all instances; launchers and child images may differ.'}
        except (psutil.Error, OSError):
            executable = {'state': 'unavailable', 'reason': 'image_path_access_denied_or_owner_exited'}
        # A fresh Process object avoids cached create_time masking PID reuse.
        if psutil.Process(pid).create_time() != created:
            return {'state': 'identity_changed', 'reason': 'pid_reused_during_observation'}
        return {'state': 'observed', 'pid': pid,
                'created_epoch_seconds': created, 'name': name,
                'executable_image': executable,
                'meaning': 'Owner identity at a later checkpoint; socket-owner association is not atomic or permission to act.'}
    except (psutil.Error, OSError):
        return {'state': 'unavailable', 'reason': 'owner_exited_or_access_denied'}
