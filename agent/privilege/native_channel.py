"""Bounded Windows request reception, without a privileged action dispatcher.

This implements transport and identity only. Protected deployment, server-owned
grants and operation-specific authorization remain separate prerequisites.
No application startup path creates this listener automatically.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass

from agent.privilege.contract import PIPE_NAME
from agent.privilege.identity import authenticate_pipe_peer
from agent.privilege.pipe import build_pipe_sddl

MAX_FRAME = 65536
LOCAL_PIPE_PREFIX = "\\\\.\\pipe\\"


@dataclass(frozen=True)
class ReceivedRequest:
    peer: dict
    body: dict


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate request keys are refused.")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("Nonfinite JSON is refused.")


class NativeRequestChannel:
    """One server instance and one request; close before another operation.

    A real protected service must create the object under its own identity.
    Creating it in a user session is transport testing, not service deployment.
    """

    def __init__(self, user_sid: str, *, name: str = PIPE_NAME):
        sddl = build_pipe_sddl(user_sid)
        if os.name != "nt":
            raise OSError("Windows native pipe transport is unavailable.")
        if (not isinstance(name, str) or not name.startswith(LOCAL_PIPE_PREFIX)
                or len(name) > 200 or any(ord(ch) < 32 for ch in name)
                or "\\" in name[len(LOCAL_PIPE_PREFIX):]):
            raise ValueError("Use one local named-pipe object.")
        import win32pipe
        import win32security
        attrs = win32security.SECURITY_ATTRIBUTES()
        attrs.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
        attrs.bInheritHandle = False
        self.user_sid = user_sid
        self.name = name
        self.used = False
        self.owner_thread = threading.get_ident()
        self.handle = win32pipe.CreateNamedPipe(name,
            win32pipe.PIPE_ACCESS_DUPLEX | 0x00080000 | 0x40000000,  # first instance, overlapped
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | 0x8,  # reject remote
            1, MAX_FRAME, MAX_FRAME, 1000, attrs)

    def _wait(self, overlapped, deadline, stop):
        import win32event
        import win32file
        while True:
            remaining = deadline - time.monotonic()
            if stop.is_set() or remaining <= 0:
                # All calls are on this same receiving thread, so CancelIo is
                # sufficient. Keep the OVERLAPPED alive until completion.
                self._cancel_and_drain(overlapped)
                raise TimeoutError("Request reception stopped or exceeded its deadline.")
            state = win32event.WaitForSingleObject(overlapped.hEvent, min(100, max(1, int(remaining * 1000))))
            if state == win32event.WAIT_OBJECT_0:
                return win32file.GetOverlappedResult(self.handle, overlapped, False)
            if state != win32event.WAIT_TIMEOUT:
                self._cancel_and_drain(overlapped)
                raise OSError("Unexpected pipe wait state.")

    def _cancel_and_drain(self, overlapped):
        import win32event
        import win32file
        try:
            win32file.CancelIo(self.handle)
        except Exception:
            os._exit(70)
        if win32event.WaitForSingleObject(overlapped.hEvent, 2000) != win32event.WAIT_OBJECT_0:
            os._exit(70)
        try:
            win32file.GetOverlappedResult(self.handle, overlapped, False)
        except Exception:
            pass  # The event established completion; the result may be aborted.

    def receive(self, *, timeout: float = 5, stop: threading.Event | None = None) -> ReceivedRequest:
        import math
        import pywintypes
        import win32event
        import win32file
        import win32pipe
        if threading.get_ident() != self.owner_thread:
            raise RuntimeError("Receive on the channel's creating thread.")
        if self.used or self.handle is None:
            raise RuntimeError("This channel has already received its one request.")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("Request deadline must be within thirty seconds.")
        self.used = True
        stop = stop if stop is not None else threading.Event()
        if stop.is_set():
            raise TimeoutError("Request reception was stopped.")
        deadline = time.monotonic() + timeout
        connect = pywintypes.OVERLAPPED()
        connect.hEvent = win32event.CreateEvent(None, True, False, None)
        try:
            try:
                status = win32pipe.ConnectNamedPipe(self.handle, connect)
            except pywintypes.error as exc:
                if exc.winerror == 535:  # Client connected before ConnectNamedPipe.
                    pass
                elif exc.winerror == 997:
                    self._wait(connect, deadline, stop)
                else:
                    raise
            else:
                if status == 997:
                    self._wait(connect, deadline, stop)
                elif status not in {0, 535}:
                    raise OSError("Unexpected pipe connection status.")
        finally:
            connect.hEvent.Close()
        read = pywintypes.OVERLAPPED()
        read.hEvent = win32event.CreateEvent(None, True, False, None)
        buffer = win32file.AllocateReadBuffer(MAX_FRAME + 1)
        try:
            status, _buffer = win32file.ReadFile(self.handle, buffer, read)
            if status not in {0, 997}:
                raise ValueError("The request message exceeded the permitted frame.")
            count = self._wait(read, deadline, stop) if status == 997 else win32file.GetOverlappedResult(self.handle, read, False)
            if not 0 < count <= MAX_FRAME:
                raise ValueError("The request frame has an invalid length.")
            peer = authenticate_pipe_peer(self.handle, self.user_sid)
            body = json.loads(bytes(buffer[:count]).decode("utf-8"), object_pairs_hook=_object,
                              parse_constant=_nonfinite)
            if not isinstance(body, dict):
                raise ValueError("The request must be a JSON object.")
            if stop.is_set() or time.monotonic() >= deadline:
                raise TimeoutError("Request authority must be checked again after reception.")
            return ReceivedRequest(peer, body)
        finally:
            read.hEvent.Close()

    def close(self):
        if threading.get_ident() != self.owner_thread:
            raise RuntimeError("Close on the channel's creating thread.")
        if self.handle is not None:
            self.handle.Close()
            self.handle = None

    def respond(self, result: dict, *, timeout: float = 5, stop: threading.Event | None = None):
        """One bounded response on the authenticated connection; no automatic flush."""
        import math
        import pywintypes
        import win32event
        import win32file
        if threading.get_ident() != self.owner_thread or not self.used or self.handle is None:
            raise RuntimeError("Respond on the receiving thread and its live connection.")
        if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("Response deadline must be within thirty seconds.")
        blob = json.dumps(result, separators=(',', ':'), allow_nan=False).encode('utf-8')
        if not 0 < len(blob) <= MAX_FRAME:
            raise ValueError("The response exceeds the permitted frame.")
        stop = stop if stop is not None else threading.Event()
        if stop.is_set():
            raise TimeoutError("Response was stopped.")
        write = pywintypes.OVERLAPPED()
        write.hEvent = win32event.CreateEvent(None, True, False, None)
        try:
            status, count = win32file.WriteFile(self.handle, blob, write)
            if status == 997:
                count = self._wait(write, time.monotonic() + timeout, stop)
            elif status != 0:
                raise OSError("Unexpected pipe response status.")
            if count != len(blob):
                raise OSError("The response was not completely written.")
        finally:
            write.hEvent.Close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
