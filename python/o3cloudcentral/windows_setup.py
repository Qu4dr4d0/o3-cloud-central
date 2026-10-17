"""Machine-wide Windows setup. Privileged mutations occur only after UAC.

All recursive removal targets come from Windows Known Folders, are validated
again immediately before deletion, and reject junctions/reparse points. The
uninstaller runs from a new administrator-only directory outside the product.
"""
from __future__ import annotations

import asyncio
import contextlib
import ctypes
import hashlib
import json
import os
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    from . import __version__
except ImportError:
    __version__ = "0.7.0"

from .windows_branding import PRODUCT_NAME, SERVICE_NAME, EXECUTABLE_NAME, resource_root

UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
APP_KEY = UNINSTALL_KEY + "\\" + SERVICE_NAME
RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
MAGIC = b"O3CC001!"
PRIVATE_SDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
_LAUNCH_ENVIRONMENT_LOCK = threading.Lock()


def independent_environment() -> dict[str, str]:
    """A child that outlives setup must own its extracted onefile runtime."""
    return {**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"}


@contextlib.contextmanager
def independent_shell_environment():
    # ShellExecuteEx has no explicit environment parameter. Keep this mutation
    # scoped to its launch call and serialize O3CloudCentral's own ShellExecute calls.
    with _LAUNCH_ENVIRONMENT_LOCK:
        previous = os.environ.get("PYINSTALLER_RESET_ENVIRONMENT")
        os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
            else:
                os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = previous


def _windows():
    if os.name != "nt":
        raise OSError("instalação disponível apenas no Windows")


def product_locations(*, legacy=False) -> dict[str, Path]:
    _windows()
    from win32com.shell import shell, shellcon
    if legacy: raise ValueError("Versões antigas exigem reinstalação limpa.")
    name = PRODUCT_NAME
    locations = {
        "programs": (shellcon.CSIDL_PROGRAM_FILES, name),
        "data": (shellcon.CSIDL_COMMON_APPDATA, name),
        "local": (shellcon.CSIDL_LOCAL_APPDATA, name),
        "menu": (shellcon.CSIDL_COMMON_PROGRAMS, name + ".lnk"),
        "desktop": (shellcon.CSIDL_COMMON_DESKTOPDIRECTORY, name + ".lnk"),
    }
    result = {name: Path(shell.SHGetFolderPath(0, code, None, 0)) / leaf for name, (code, leaf) in locations.items()}
    for path in result.values():
        if not valid_product_path(path):
            raise ValueError("Pastas do Windows indisponíveis.")
    return result


def valid_product_path(path: Path | str) -> bool:
    path = Path(path)
    return path.is_absolute() and not any(c in str(path) for c in '\x00\r\n"') and path.parent != path


def validate_product_tree(path: Path):
    if not valid_product_path(path) or path.name != PRODUCT_NAME:
        raise ValueError("Caminho de remoção O3 Cloud Central inválido.")
    # Checking every ancestor prevents a writable junction redirecting the tree.
    for item in [path, *path.parents]:
        if item.exists() or item.is_symlink():
            info = item.lstat()
            if item.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("A pasta O3 Cloud Central contém um ponto de redirecionamento.")
    if path.exists():
        for folder, directories, files in os.walk(path, followlinks=False):
            for name in directories + files:
                item = Path(folder) / name
                info = item.lstat()
                if item.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise ValueError("A pasta O3 Cloud Central contém um ponto de redirecionamento.")


def executable_payload(path: Path | None = None) -> bytes:
    data = (path or Path(sys.executable)).read_bytes()
    if len(data) >= 16 and data[-8:] == MAGIC:
        size = struct.unpack("<Q", data[-16:-8])[0]
        if size > 128 << 10 or size > len(data) - 16:
            raise ValueError("Cadastro embutido inválido.")
        data = data[:-16-size]
    return data


def setup_dialog(upgrade: bool, desktop_shortcut=True) -> tuple[bool, bool]:
    import tkinter as tk
    window = tk.Tk()
    window.title(PRODUCT_NAME + " — Instalação")
    window.iconbitmap(str(resource_root() / "assets" / "O3CloudCentral.ico"))
    window.resizable(False, False)
    window.geometry("540x250")
    frame = tk.Frame(window, padx=24, pady=22)
    frame.pack(fill="both", expand=True)
    tk.Label(frame, text=("Atualizar " if upgrade else "Instalar ") + PRODUCT_NAME, font=("Segoe UI", 16, "bold")).pack(anchor="w")
    tk.Label(frame, text="O O3 Cloud Central conecta este computador aos serviços autorizados.\nA conexão inicia automaticamente com o Windows.", justify="left", pady=14).pack(anchor="w")
    checked = tk.BooleanVar(value=desktop_shortcut)
    tk.Checkbutton(frame, text="Criar ícone na área de trabalho", variable=checked).pack(anchor="w")
    accepted = [False]
    def confirm():
        accepted[0] = True
        window.destroy()
    row = tk.Frame(frame)
    row.pack(anchor="e", pady=20)
    tk.Button(row, text="Cancelar", command=window.destroy, width=11).pack(side="left", padx=8)
    tk.Button(row, text="Atualizar" if upgrade else "Instalar", command=confirm, width=11).pack(side="left")
    window.mainloop()
    return accepted[0], checked.get()


def is_admin() -> bool:
    _windows()
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def _self_command(*args) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, *args]
    return [sys.executable, "-m", "o3cloudcentral", *args]


def elevate(arguments: list[str], *, wait=True):
    from win32com.shell import shell, shellcon
    import win32con
    import win32event
    import win32process
    import pythoncom
    command = _self_command(*arguments)
    pythoncom.CoInitialize()
    try:
        with independent_shell_environment():
            result = shell.ShellExecuteEx(fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                lpVerb="runas", lpFile=command[0], lpParameters=subprocess.list2cmdline(command[1:]), nShow=0)
    finally:
        pythoncom.CoUninitialize()
    handle = result["hProcess"]
    try:
        if wait:
            win32event.WaitForSingleObject(handle, win32event.INFINITE)
            if win32process.GetExitCodeProcess(handle):
                raise RuntimeError("A instalação não foi concluída; consulte o registro de instalação.")
    finally:
        handle.Close()


def protect_directory(path: Path, public=False):
    validate_product_tree(path)
    path.mkdir(parents=True, exist_ok=True)
    import win32security
    # Replace the DACL, including old explicit ACEs. Merely adding admin grants
    # would preserve a user-writable pre-existing installation directory.
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        PRIVATE_SDDL + ("(A;OICI;GRGX;;;BU)" if public else ""), 1)
    targets = [path]
    for directory, folders, files in os.walk(path, followlinks=False):
        targets.extend(Path(directory) / name for name in folders + files)
    for target in targets:
        if target.is_symlink() or getattr(target.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("A pasta O3 Cloud Central contém um ponto de redirecionamento.")
        win32security.SetNamedSecurityInfo(str(target), win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION |
            win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.GetSecurityDescriptorOwner(), None, descriptor.GetSecurityDescriptorDacl(), None)


@contextlib.contextmanager
def setup_lock():
    import pywintypes
    import win32event
    import win32security
    security = pywintypes.SECURITY_ATTRIBUTES()
    security.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PRIVATE_SDDL, 1)
    mutex = win32event.CreateMutex(security, False, r"Global\O3CloudCentral.Setup.v1")
    result = win32event.WaitForSingleObject(mutex, 0)
    if result not in (0, 128):
        mutex.Close()
        raise RuntimeError("Outra instalação ou remoção O3 Cloud Central está em andamento.")
    try:
        yield
    finally:
        win32event.ReleaseMutex(mutex)
        mutex.Close()


def _stop_service(service):
    import pywintypes
    import win32service
    status = win32service.QueryServiceStatusEx(service)
    if status["CurrentState"] != win32service.SERVICE_STOPPED:
        try:
            win32service.ControlService(service, win32service.SERVICE_CONTROL_STOP)
        except pywintypes.error as exc:
            if exc.winerror != 1062:
                raise
        until = time.monotonic() + 30
        while win32service.QueryServiceStatusEx(service)["CurrentState"] != win32service.SERVICE_STOPPED:
            if time.monotonic() > until:
                raise TimeoutError("O serviço não encerrou; atualização interrompida.")
            time.sleep(.15)


def _configure_recovery(service):
    import win32service
    win32service.ChangeServiceConfig2(service, win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
        {"ResetPeriod": 86400, "RebootMsg": "", "Command": "", "Actions": [(1, 5000), (1, 10000), (1, 30000)]})
    from ctypes import wintypes
    function = ctypes.WinDLL("advapi32", use_last_error=True).ChangeServiceConfig2W
    function.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p)
    function.restype = wintypes.BOOL
    enabled = wintypes.BOOL(True)
    if not function(int(service), 4, ctypes.byref(enabled)):
        raise ctypes.WinError(ctypes.get_last_error())


def _service_binary(executable: Path, config: Path) -> str:
    return subprocess.list2cmdline([str(executable), "windows-service", "--config", str(config)])


def _registration(executable: Path, locations: dict):
    import winreg
    view = winreg.KEY_WOW64_64KEY
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, RUN_KEY, 0, winreg.KEY_SET_VALUE | view) as key:
        winreg.SetValueEx(key, SERVICE_NAME, 0, winreg.REG_SZ, subprocess.list2cmdline([str(executable), "tray"]))
    values = {"DisplayName": PRODUCT_NAME, "Publisher": "O3 Cloud", "DisplayVersion": __version__,
        "DisplayIcon": '"' + str(executable) + '",0', "InstallLocation": str(locations["programs"]),
        "UninstallString": subprocess.list2cmdline([str(executable), "uninstall"])}
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, APP_KEY, 0, winreg.KEY_SET_VALUE | view) as key:
        for name, value in values.items():
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)


def create_shortcuts(executable: Path, locations: dict, desktop=True):
    import pythoncom
    import win32com.client
    pythoncom.CoInitialize()
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        paths = [locations["menu"]]
        if desktop or locations["desktop"].exists():
            paths.append(locations["desktop"])
        for path in paths:
            shortcut = shell.CreateShortCut(str(path))
            shortcut.Targetpath = str(executable)
            shortcut.Arguments = "tray"
            shortcut.WorkingDirectory = str(executable.parent)
            shortcut.IconLocation = str(executable) + ",0"
            shortcut.Description = PRODUCT_NAME
            shortcut.save()
    finally:
        pythoncom.CoUninitialize()


def _launch_tray(executable: Path):
    subprocess.Popen([str(executable), "tray"], creationflags=0x08000000, close_fds=True, env=independent_environment())


def _open_service(manager, name):
    import pywintypes
    import win32service
    try:
        return win32service.OpenService(manager, name, win32service.SERVICE_ALL_ACCESS)
    except pywintypes.error as exc:
        if exc.winerror != 1060:
            raise
        return None


def installed_service_name() -> str | None:
    """Public SCM metadata detects an upgrade before UAC; no private data read."""
    _windows()
    import pywintypes
    import win32service
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        for name, old in ((SERVICE_NAME, False),):
            try:
                service = win32service.OpenService(manager, name, win32service.SERVICE_QUERY_CONFIG)
            except pywintypes.error as exc:
                if exc.winerror != 1060:
                    raise
                continue
            try:
                verify_service_installation(service, product_locations(legacy=old), legacy=old)
                return name
            finally:
                win32service.CloseServiceHandle(service)
        return None
    finally:
        win32service.CloseServiceHandle(manager)


def verify_service_installation(service, locations: dict, *, legacy=False):
    """A similarly named third-party service is never stopped or overwritten."""
    import win32api
    import win32service
    configuration = win32service.QueryServiceConfig(service)
    command = win32api.CommandLineToArgv(configuration[3])
    if legacy: raise ValueError("Versões antigas exigem reinstalação limpa.")
    expected = EXECUTABLE_NAME
    image = Path(command[0]) if command else Path()
    modes = {"windows-service"}
    if (not image.is_absolute() or image.name.casefold() != expected.casefold() or
            not image.is_relative_to(locations["programs"]) or
            len(command) != 4 or command[1] not in modes or command[2] != "--config" or
            Path(command[3]) != locations["data"] / "config.json"):
        raise ValueError("O serviço existente não pertence a esta instalação; nenhuma alteração foi feita.")
    return configuration


def copy_upgrade_data(source: Path, destination: Path):
    """Stage the existing identity; never overwrite a different installed identity."""
    validate_product_tree(source)
    validate_product_tree(destination)
    original = source / "config.json"
    if not original.is_file():
        raise ValueError("Não foi encontrada a configuração da instalação anterior.")
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("A nova pasta já contém dados; atualização interrompida para preservar as identidades.")
    protect_directory(destination, public=False)
    try:
        for item in source.iterdir():
            target = destination / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)
        protect_directory(destination, public=False)
        if (destination / "config.json").read_bytes() != original.read_bytes():
            raise ValueError("A configuração mudou durante a cópia; atualização interrompida.")
    except Exception:
        _safe_remove_tree(destination)
        raise


def _start_service_ready(service):
    import win32service
    from .windows_control import local_request
    win32service.StartService(service, None)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = win32service.QueryServiceStatusEx(service)
        if status["CurrentState"] == win32service.SERVICE_STOPPED:
            raise RuntimeError("O novo serviço encerrou durante a inicialização.")
        if status["CurrentState"] == win32service.SERVICE_RUNNING:
            try:
                # Also proves that the new PID owns the protected control pipe.
                local_request("status")
                return
            except (OSError, RuntimeError, ValueError):
                pass
        time.sleep(.15)
    raise TimeoutError("O novo serviço não confirmou a inicialização; a instalação anterior será restaurada.")


def _remove_registration(*, legacy=False):
    import winreg
    name = SERVICE_NAME
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RUN_KEY, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass
    try:
        winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, APP_KEY, winreg.KEY_WOW64_64KEY)
    except FileNotFoundError:
        pass


def _remove_shortcuts(locations: dict):
    for name in ("menu", "desktop"):
        locations[name].unlink(missing_ok=True)


def _restore_service(service, previous):
    import win32service
    win32service.ChangeServiceConfig(service, previous[0], previous[1], previous[2],
        previous[3], previous[4], 0, previous[6], None, None, previous[8])
    win32service.StartService(service, None)


async def prepare_direct_upgrade(path: Path) -> dict:
    """One-time legacy bootstrap during explicit upgrade, never agent runtime."""
    from .common import api_request, atomic_json, valid_endpoint
    from .crypto import valid_public_key
    original = path.read_bytes()
    config = json.loads(original)
    if (not isinstance(config, dict) or config.get("kind") != "agent" or
            any(not isinstance(config.get(name), str) or not config[name] for name in ("id", "private_key", "token", "url", "ca"))):
        raise ValueError("Não foi encontrada uma identidade de terminal instalada.")
    endpoint, host_key = config.get("gateway_endpoint", ""), config.get("gateway_host_key", "")
    if endpoint and host_key:
        if not valid_endpoint(endpoint) or not valid_public_key(host_key):
            raise ValueError("A identidade existente do pfSense é inválida; configuração preservada.")
        return config
    try:
        policy = await api_request(config, "POST", "/api/agent/policy", {"status": "atualizando para controle pelo pfSense"})
    except Exception:
        raise ValueError("Não foi possível consultar a central antiga durante a atualização. Verifique o acesso pela rede/VPN; identidade e configuração foram preservadas.") from None
    new_endpoint, new_key = policy.get("endpoint", ""), policy.get("host_key", "")
    if (policy.get("id", config["id"]) != config["id"] or not valid_endpoint(new_endpoint) or
            not valid_public_key(new_key) or type(policy.get("lease_seconds")) is not int or not 1 <= policy["lease_seconds"] <= 300):
        raise ValueError("A central não forneceu um pfSense válido para este terminal; configuração preservada.")
    if host_key:
        import asyncssh
        if not valid_public_key(host_key) or asyncssh.import_public_key(host_key) != asyncssh.import_public_key(new_key):
            raise ValueError("A chave do pfSense mudou durante a atualização; configuração preservada.")
    updated = {**config, "gateway_endpoint": new_endpoint, "gateway_host_key": host_key or new_key}
    if path.read_bytes() != original:
        raise ValueError("A configuração mudou durante a atualização; tente novamente.")
    atomic_json(path, updated)
    return updated


async def install_agent(bundle=None, *, upgrade=False, desktop_shortcut=True, confirmed=False, quiet=False):
    _windows()
    if not quiet and not confirmed:
        accepted, desktop_shortcut = setup_dialog(upgrade, desktop_shortcut)
        if not accepted:
            return
    if not is_admin():
        if not getattr(sys, "frozen", False):
            raise PermissionError("Execute a instalação empacotada como administrador.")
        if not upgrade:
            from .common import embedded_bundle
            try:
                embedded_bundle()
            except (OSError, ValueError) as exc:
                raise PermissionError("Para usar um cadastro em arquivo, execute O3CloudCentral.exe como administrador.") from exc
        arguments = ["upgrade" if upgrade else "install", "--setup-confirmed", "--quiet",
                     "--desktop-shortcut=" + str(desktop_shortcut).lower()]
        await asyncio.to_thread(elevate, arguments)
        if not quiet:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RUN_KEY, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                command = winreg.QueryValueEx(key, SERVICE_NAME)[0]
            import win32api
            _launch_tray(Path(win32api.CommandLineToArgv(command)[0]))
        return
    if not getattr(sys, "frozen", False):
        raise RuntimeError("Instale usando O3CloudCentral.exe empacotado.")
    from .common import enroll
    import win32service
    locations = product_locations()
    config = locations["data"] / "config.json"
    with setup_lock():
        for name in ("programs", "data"):
            validate_product_tree(locations[name])
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        current = service = None
        created = False
        old_configuration = None
        try:
            current = _open_service(manager, SERVICE_NAME)
            if upgrade:
                if not current:
                    raise ValueError("Nao ha instalacao O3 Cloud Central para atualizar; use o instalador completo.")
                old_configuration = verify_service_installation(current, locations)
                await prepare_direct_upgrade(config)
            elif current or config.exists():
                raise ValueError("O3 Cloud Central ja instalado; atualize para preservar sua identidade.")
            elif not isinstance(bundle, dict) or bundle.get("kind") != "agent":
                raise ValueError("Cadastro nao e de terminal.")
            protect_directory(locations["data"], public=False)
            protect_directory(locations["programs"], public=True)
            payload = executable_payload()
            version_dir = locations["programs"] / hashlib.sha256(payload).hexdigest()[:16]
            version_dir.mkdir(exist_ok=True)
            destination = version_dir / EXECUTABLE_NAME
            if destination.exists():
                if destination.read_bytes() != payload:
                    raise ValueError("Arquivo existente de outra versao.")
            else:
                with destination.open("xb") as output:
                    output.write(payload); output.flush(); os.fsync(output.fileno())
            if not upgrade:
                await enroll(bundle, config)
            if current:
                _stop_service(current)
                _stop_owned_trays(locations["programs"])
                service = current
                win32service.ChangeServiceConfig(service, win32service.SERVICE_NO_CHANGE,
                    win32service.SERVICE_AUTO_START, win32service.SERVICE_NO_CHANGE,
                    _service_binary(destination, config), None, 0, None, None, None, PRODUCT_NAME)
            else:
                service = win32service.CreateService(manager, SERVICE_NAME, PRODUCT_NAME, win32service.SERVICE_ALL_ACCESS,
                    win32service.SERVICE_WIN32_OWN_PROCESS, win32service.SERVICE_AUTO_START,
                    win32service.SERVICE_ERROR_NORMAL, _service_binary(destination, config), None, 0, None, None, None)
                created = True
            win32service.ChangeServiceConfig2(service, win32service.SERVICE_CONFIG_DESCRIPTION,
                "Conexao TCP por SSH com recuperacao automatica e controle local.")
            _configure_recovery(service)
            _start_service_ready(service)
            create_shortcuts(destination, locations, desktop_shortcut)
            _registration(destination, locations)
        except Exception:
            if service:
                try:
                    _stop_service(service)
                except Exception as error:
                    raise RuntimeError("Falha ao parar o servico durante a recuperacao; arquivos e identidade preservados.") from error
                if created:
                    win32service.DeleteService(service)
                    _remove_registration()
                    _remove_shortcuts(locations)
                elif old_configuration:
                    _restore_service(service, old_configuration)
            raise
        finally:
            handles = {int(handle):handle for handle in (service,current) if handle}
            for handle in handles.values(): win32service.CloseServiceHandle(handle)
            win32service.CloseServiceHandle(manager)
    if not quiet:
        _launch_tray(destination)


def _safe_remove_tree(path: Path):
    validate_product_tree(path)
    if path.exists():
        def writable(function, value, exc):
            os.chmod(value, stat.S_IWRITE)
            function(value)
        shutil.rmtree(path, onerror=writable)


def _schedule_delete(path: Path):
    from ctypes import wintypes
    move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    move.restype = wintypes.BOOL
    if not move(str(path), None, 4):
        raise ctypes.WinError(ctypes.get_last_error())


def _remove_or_schedule_tree(path: Path):
    validate_product_tree(path)
    try:
        _safe_remove_tree(path)
    except OSError:
        # Setup may itself run from an old version directory. Only these checked
        # product files are deferred; no command strings or wildcard removals.
        validate_product_tree(path)
        for folder, directories, files in os.walk(path, topdown=False):
            for name in files + directories:
                _schedule_delete(Path(folder) / name)
        _schedule_delete(path)


def owned_product_image(image: Path, programs: Path) -> bool:
    return (programs.name == PRODUCT_NAME and image.is_absolute() and
            image.name.casefold() == EXECUTABLE_NAME.casefold() and
            image.is_relative_to(programs))


def _stop_owned_trays(programs: Path):
    """Terminate only tray processes whose actual image is inside this product."""
    validate_product_tree(programs)
    import win32api
    import win32con
    import win32process
    import win32event
    from ctypes import wintypes
    query = ctypes.WinDLL("kernel32", use_last_error=True).QueryFullProcessImageNameW
    query.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
    query.restype = wintypes.BOOL
    for pid in win32process.EnumProcesses():
        if not pid or pid == os.getpid():
            continue
        handle = None
        try:
            handle = win32api.OpenProcess(0x1000 | 1 | 0x100000, False, pid)
            buffer = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buffer))
            if not query(int(handle), 0, buffer, ctypes.byref(size)):
                continue
            name = Path(buffer.value)
            if owned_product_image(name, programs):
                win32api.TerminateProcess(handle, 0)
                win32event.WaitForSingleObject(handle, 5000)
        except Exception:
            # Unrelated or protected system processes are never a removal target.
            pass
        finally:
            if handle:
                handle.Close()


def _helper_directory(base: Path) -> Path:
    import pywintypes
    import win32file
    import win32security
    security = pywintypes.SECURITY_ATTRIBUTES()
    security.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PRIVATE_SDDL, 1)
    result = base / (SERVICE_NAME + "-Uninstall-" + secrets.token_hex(12))
    win32file.CreateDirectory(str(result), security)
    return result


def validate_helper(executable: Path, base: Path):
    folder = executable.parent
    suffix = folder.name.removeprefix(SERVICE_NAME + "-Uninstall-")
    if (executable.name != EXECUTABLE_NAME or folder.parent != base or len(suffix) != 24 or
            not folder.name.startswith(SERVICE_NAME + "-Uninstall-") or any(c not in "0123456789abcdef" for c in suffix)):
        raise ValueError("Auxiliar de remoção em caminho inválido.")
    for item in [executable, folder, *folder.parents]:
        info = item.lstat()
        if item.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Auxiliar contém ponto de redirecionamento.")
    verify_helper_acl(folder)
    verify_helper_acl(executable)


def verify_helper_acl(path: Path):
    """The privileged worker must never execute from a user-writable directory."""
    import win32security
    descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    trusted = {"S-1-5-18", "S-1-5-32-544"}
    if win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in trusted:
        raise PermissionError("O auxiliar de remoção não pertence ao administrador.")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise PermissionError("O auxiliar de remoção não tem proteção de acesso.")
    seen = set()
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        if ace[0][0] not in (0, 1):
            raise PermissionError("Permissão não reconhecida no auxiliar de remoção.")
        if ace[0][0] == 0:  # ACCESS_ALLOWED_ACE_TYPE
            sid = win32security.ConvertSidToStringSid(ace[-1])
            if sid not in trusted:
                raise PermissionError("O auxiliar de remoção permite acesso não administrativo.")
            seen.add(sid)
    if seen != trusted:
        raise PermissionError("Permissões incompletas no auxiliar de remoção.")


def uninstall_agent(*, confirmed=False, quiet=False, parent_pid=0, origin_pid=0):
    _windows()
    if not confirmed and not quiet:
        answer = ctypes.windll.user32.MessageBoxW(0,
            "Remover o O3 Cloud Central deste computador?\n\nSerão removidos serviço, ícone, atalhos, configurações e arquivos locais. O cadastro permanece na central.",
            PRODUCT_NAME + " — Desinstalar", 0x124)
        if answer != 6:
            return
    if not is_admin():
        elevate(["uninstall", "--setup-confirmed", "--origin-pid", str(os.getpid()), *( ["--quiet"] if quiet else [])], wait=False)
        return
    if not getattr(sys, "frozen", False):
        raise RuntimeError("Use o desinstalador O3CloudCentral.exe empacotado.")
    locations = product_locations()
    for name in ("programs", "data"):
        validate_product_tree(locations[name])
    helper_folder = _helper_directory(locations["data"].parent)
    helper = helper_folder / EXECUTABLE_NAME
    helper.write_bytes(executable_payload())
    import win32security
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PRIVATE_SDDL, 1)
    win32security.SetFileSecurity(str(helper), win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION, descriptor)
    validate_helper(helper, locations["data"].parent)
    subprocess.Popen([str(helper), "uninstall-worker", "--parent-pid", str(os.getpid()),
        "--origin-pid", str(origin_pid), *(["--quiet"] if quiet else [])], creationflags=0x08000000, close_fds=True, env=independent_environment())


def _wait_process(pid: int):
    if pid <= 0 or pid == os.getpid():
        return
    import pywintypes
    import win32api
    import win32event
    try:
        process = win32api.OpenProcess(0x100000, False, pid)
    except pywintypes.error:
        return
    try:
        if win32event.WaitForSingleObject(process, 60000) == 258:
            raise TimeoutError("O processo de desinstalação anterior ainda está aberto.")
    finally:
        process.Close()


def uninstall_worker(*, parent_pid=0, origin_pid=0, quiet=False):
    _windows()
    if not is_admin():
        raise PermissionError("A remoção requer confirmação administrativa.")
    import win32service
    locations = product_locations()
    executable = Path(sys.executable)
    validate_helper(executable, locations["data"].parent)
    _wait_process(parent_pid)
    _wait_process(origin_pid)
    with setup_lock():
        for roots in (locations,):
            for name in ("programs", "data"):
                validate_product_tree(roots[name])
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        services = []
        try:
            # Verify all ownership before stopping or deleting either service.
            for name, roots, old in ((SERVICE_NAME, locations, False),):
                service = _open_service(manager, name)
                if service:
                    services.append(service)
                    verify_service_installation(service, roots, legacy=old)
            for service in services:
                _stop_service(service)
                win32service.DeleteService(service)
        finally:
            for service in services:
                win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(manager)
        for roots, old in ((locations, False),):
            _stop_owned_trays(roots["programs"])
            _remove_registration(legacy=old)
            _remove_shortcuts(roots)
            for name in ("programs", "data"):
                _remove_or_schedule_tree(roots[name])
    # The protected helper is outside both product trees and deletes on reboot.
    _schedule_delete(executable)
    _schedule_delete(executable.parent)
    if not quiet:
        ctypes.windll.user32.MessageBoxW(0, "O3 Cloud Central removido deste computador.", PRODUCT_NAME, 0x40)
