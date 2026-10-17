"""Native Windows service, visible tray and explicit installer entry points."""
from __future__ import annotations

import asyncio
import logging
import logging.handlers
import os
import threading
from pathlib import Path

from .agent import AgentControl, run_agent
from .windows_control import ControlPipe, local_request
from .windows_branding import PRODUCT_NAME, SERVICE_NAME, resource_root


def native_service(config_path: str | Path | None = None):
    if os.name != "nt":
        raise OSError("serviço nativo disponível apenas no Windows")
    import servicemanager
    import win32service
    import win32serviceutil
    from .windows_setup import product_locations
    config = Path(config_path) if config_path else product_locations()["data"] / "config.json"

    class O3CloudCentralService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = PRODUCT_NAME
        _svc_description_ = "Conexão TCP por SSH com recuperação automática e controle local."

        def __init__(self, args):
            super().__init__(args)
            self.loop = None
            self.stop_event = None
            self.stopping = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=15000)
            self.stopping.set()
            if self.loop and self.stop_event:
                self.loop.call_soon_threadsafe(self.stop_event.set)

        def SvcShutdown(self):
            self.SvcStop()

        def SvcDoRun(self):
            handler = logging.handlers.RotatingFileHandler(config.parent / "agent.log", maxBytes=2 << 20, backupCount=3, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logging.getLogger().addHandler(handler)
            logging.getLogger().setLevel(logging.INFO)
            try:
                asyncio.run(self.main())
            except Exception:
                logging.exception("Serviço O3 Cloud Central encerrado por falha")
                raise
            finally:
                handler.close()

        async def main(self):
            self.loop = asyncio.get_running_loop()
            self.stop_event = asyncio.Event()
            if self.stopping.is_set():
                self.stop_event.set()
            control = AgentControl()
            pipe = ControlPipe(self.loop, control, config.parent / "agent.log")
            pipe.start()
            try:
                await run_agent(config, self.stop_event, control)
            finally:
                await asyncio.to_thread(pipe.close)

    servicemanager.Initialize(SERVICE_NAME, None)
    servicemanager.PrepareToHostSingle(O3CloudCentralService)
    servicemanager.StartServiceCtrlDispatcher()


def tray_image(connected: bool):
    """Keep the supplied purple logo; a small badge communicates connectivity."""
    from PIL import Image, ImageDraw, ImageOps
    with Image.open(resource_root() / "assets" / "O3CloudCentral.png") as source:
        logo = ImageOps.contain(source.convert("RGBA"), (60, 60), Image.Resampling.LANCZOS)
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    image.alpha_composite(logo, ((64 - logo.width) // 2, (64 - logo.height) // 2))
    draw = ImageDraw.Draw(image)
    draw.ellipse((42, 42, 63, 63), fill="white")
    draw.ellipse((44, 44, 61, 61), fill="#12b981" if connected else "#dc3545")
    return image


def show_text(title: str, text: str):
    import tkinter as tk
    from tkinter.scrolledtext import ScrolledText
    window = tk.Tk()
    window.title(title)
    window.iconbitmap(str(resource_root() / "assets" / "O3CloudCentral.ico"))
    window.geometry("620x390")
    area = ScrolledText(window, wrap="word", padx=12, pady=12)
    area.pack(fill="both", expand=True)
    area.insert("1.0", text)
    area.configure(state="disabled")
    tk.Button(window, text="Fechar", command=window.destroy).pack(pady=10)
    window.mainloop()


def run_tray():
    if os.name != "nt":
        raise OSError("ícone disponível apenas no Windows")
    import pystray
    import win32api
    import win32event
    import win32ts
    session = win32ts.ProcessIdToSessionId(os.getpid())
    mutex = win32event.CreateMutex(None, False, rf"Local\O3CloudCentral.Python.Tray.{session}")
    if win32api.GetLastError() == 183:
        mutex.Close()
        return
    stopped = threading.Event()
    view = {"state": "offline"}

    def action(command):
        try:
            response = local_request(command)
            if command == "log":
                show_text(PRODUCT_NAME + " — Log", response.get("log", "Sem registros."))
            elif command == "status":
                current = response.get("status", {})
                details = ["Estado: " + current.get("state", "offline"),
                    "pfSense: " + current.get("endpoint", "—"), "Versão: " + current.get("version", "—")]
                details.extend("• " + str(s.get("name", "Serviço")) + ": 127.0.0.1:" + str(s.get("local_port", ""))
                               for s in current.get("services", []))
                if current.get("error"):
                    details.append("Último erro: " + current["error"])
                show_text(PRODUCT_NAME + " — Status", "\n\n".join(details))
        except Exception as exc:
            show_text(PRODUCT_NAME, str(exc))

    def invoke(command):
        return lambda icon, item: threading.Thread(target=action, args=(command,), daemon=True).start()

    def leave(icon, item):
        stopped.set()
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem("Conectar", invoke("connect"), enabled=lambda item: view.get("state") != "conectado"),
        pystray.MenuItem("Desconectar", invoke("disconnect"), enabled=lambda item: not view.get("paused", False)),
        pystray.MenuItem("Reconectar", invoke("reconnect")),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Mostrar status", invoke("status"), default=True),
        pystray.MenuItem("Visualizar log", invoke("log")),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Sair do ícone", leave))
    icon = pystray.Icon(SERVICE_NAME, tray_image(False), PRODUCT_NAME + " — desconectado", menu)

    def poll():
        connected = None
        while not stopped.is_set():
            try:
                current = local_request("status").get("status", {})
            except Exception:
                current = {"state": "offline"}
            view.clear()
            view.update(current)
            now_connected = current.get("state") == "conectado"
            if connected != now_connected:
                icon.icon = tray_image(now_connected)
                connected = now_connected
            icon.title = PRODUCT_NAME + " — " + str(current.get("state", "offline"))[:80]
            icon.update_menu()
            stopped.wait(2)

    def setup(icon):
        icon.visible = True
        threading.Thread(target=poll, name=SERVICE_NAME + ".TrayStatus", daemon=True).start()

    try:
        icon.run(setup=setup)
    finally:
        stopped.set()
        mutex.Close()


async def install_agent(bundle=None, *, upgrade=False, desktop_shortcut=True, confirmed=False, quiet=False):
    from .windows_setup import install_agent as implementation
    return await implementation(bundle, upgrade=upgrade, desktop_shortcut=desktop_shortcut, confirmed=confirmed, quiet=quiet)


def uninstall_agent(*, confirmed=False, quiet=False, parent_pid=0, origin_pid=0):
    from .windows_setup import uninstall_agent as implementation
    return implementation(confirmed=confirmed, quiet=quiet, parent_pid=parent_pid, origin_pid=origin_pid)
