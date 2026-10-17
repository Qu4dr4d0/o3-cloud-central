"""Local-only, bounded Windows service control pipe (never HTTP/TCP)."""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from pathlib import Path

from .windows_branding import PIPE_NAME, SERVICE_NAME, LEGACY_NAME, PRODUCT_NAME

PIPE_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100183;;;IU)S:(ML;;NW;;;ME)"
ALLOWED_COMMANDS = {"status", "log", "connect", "disconnect", "reconnect"}
MAX_REPLY = 128 << 10


def decode_command(raw: bytes) -> str:
    if not raw or len(raw) > 512:
        raise ValueError("Pedido inválido.")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"command"} or value["command"] not in ALLOWED_COMMANDS:
        raise ValueError("Comando não permitido.")
    return value["command"]


def log_tail(path: Path) -> str:
    try:
        with path.open("rb") as source:
            source.seek(0, 2)
            source.seek(max(0, source.tell() - 16000))
            return source.read(16000).decode("utf-8", errors="replace")
    except OSError:
        return ""


class ControlPipe:
    def __init__(self, loop, control, log_path: Path):
        if os.name != "nt":
            raise OSError("controle local disponível apenas no Windows")
        import pywintypes
        import win32pipe
        import win32security
        self.loop, self.control, self.log_path = loop, control, log_path
        self.stop = threading.Event()
        security = pywintypes.SECURITY_ATTRIBUTES()
        security.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PIPE_SDDL, 1)
        self.handle = win32pipe.CreateNamedPipe(PIPE_NAME, 3 | 0x00080000,
            4 | 2 | 1 | 8, 1, MAX_REPLY, 512, 0, security)
        self.thread = threading.Thread(target=self.serve, name=SERVICE_NAME + ".LocalControl", daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(14)

    def serve(self):
        import pywintypes
        import win32file
        import win32pipe
        try:
            while not self.stop.is_set():
                try:
                    win32pipe.ConnectNamedPipe(self.handle, None)
                except pywintypes.error as exc:
                    if exc.winerror != 535:  # ERROR_PIPE_CONNECTED
                        if exc.winerror == 232:
                            win32pipe.DisconnectNamedPipe(self.handle)
                        self.stop.wait(.04)
                        continue
                try:
                    raw = self._read(512, 3)
                    reply = {"status": self.control.snapshot()}
                    try:
                        command = decode_command(raw)
                        if command == "log":
                            reply["log"] = log_tail(self.log_path)
                        elif command != "status":
                            future = asyncio.run_coroutine_threadsafe(self.control.command(command), self.loop)
                            try:
                                future.result(11)
                            except Exception:
                                future.cancel()
                                raise RuntimeError("O serviço não concluiu o comando.")
                        reply["status"] = self.control.snapshot()
                    except (ValueError, TypeError, RuntimeError) as exc:
                        reply["error"] = str(exc)[:500]
                    data = json.dumps(reply, ensure_ascii=False).encode("utf-8")
                    if len(data) > MAX_REPLY:
                        data = b'{"error":"Resposta excede o limite.","status":{}}'
                    win32file.WriteFile(self.handle, data)
                    self._read(1, 1)  # Receipt acknowledgement before disconnect.
                except (pywintypes.error, TimeoutError, ValueError):
                    pass
                finally:
                    win32pipe.DisconnectNamedPipe(self.handle)
        finally:
            win32file.CloseHandle(self.handle)

    def _read(self, size: int, timeout: float) -> bytes:
        import pywintypes
        import win32file
        until = time.monotonic() + timeout
        while not self.stop.is_set() and time.monotonic() < until:
            try:
                return win32file.ReadFile(self.handle, size)[1]
            except pywintypes.error as exc:
                if exc.winerror != 232:
                    raise
                self.stop.wait(.02)
        raise TimeoutError()


def trusted_service_pipe(handle, *, server_pid=None, service_pid=None):
    """A user-created pipe cannot impersonate the LocalSystem product service."""
    if server_pid is None:
        import ctypes
        from ctypes import wintypes
        pid = wintypes.ULONG()
        function = ctypes.WinDLL("kernel32", use_last_error=True).GetNamedPipeServerProcessId
        function.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG))
        function.restype = wintypes.BOOL
        if not function(int(handle), ctypes.byref(pid)):
            raise ctypes.WinError(ctypes.get_last_error())
        server_pid = pid.value
    if service_pid is None:
        import pywintypes
        import win32service
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            try:
                service = win32service.OpenService(manager, SERVICE_NAME, win32service.SERVICE_QUERY_STATUS)
            except pywintypes.error as exc:
                if exc.winerror != 1060:
                    raise
                # The new tray can control an older install before an upgrade.
                service = win32service.OpenService(manager, LEGACY_NAME, win32service.SERVICE_QUERY_STATUS)
            try:
                service_pid = win32service.QueryServiceStatusEx(service)["ProcessId"]
            finally:
                win32service.CloseServiceHandle(service)
        finally:
            win32service.CloseServiceHandle(manager)
    if not server_pid or server_pid != service_pid:
        raise PermissionError("O controle local não pertence ao serviço " + PRODUCT_NAME + ".")


def local_request(command: str) -> dict:
    if os.name != "nt":
        raise OSError("controle local disponível apenas no Windows")
    if command not in ALLOWED_COMMANDS:
        raise ValueError("Comando não permitido.")
    import pywintypes
    import win32file
    import win32pipe
    deadline = time.monotonic() + 4
    while True:
        try:
            # Explicit rights: GENERIC_WRITE would also grant pipe-instance creation.
            handle = win32file.CreateFile(PIPE_NAME, 0x100183, 0, None, 3, 0, None)
            break
        except pywintypes.error as exc:
            if exc.winerror != 231 or time.monotonic() >= deadline:
                raise ConnectionError("Serviço " + PRODUCT_NAME + " indisponível.") from exc
            time.sleep(.05)
    try:
        trusted_service_pipe(handle)
        win32pipe.SetNamedPipeHandleState(handle, 2 | 1, None, None)
        win32file.WriteFile(handle, json.dumps({"command": command}).encode())
        until = time.monotonic() + 12
        while True:
            try:
                raw = win32file.ReadFile(handle, MAX_REPLY)[1]
                break
            except pywintypes.error as exc:
                if exc.winerror != 232:
                    raise
                if time.monotonic() > until:
                    raise TimeoutError("Controle local sem resposta.") from exc
                time.sleep(.02)
        win32file.WriteFile(handle, b"\x00")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Resposta local inválida.")
        if value.get("error"):
            raise RuntimeError(value["error"])
        return value
    finally:
        win32file.CloseHandle(handle)
