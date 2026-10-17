"""O3 Cloud Central command line. Secrets stay in protected configuration."""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import secrets
import signal
import ssl
import sys
from pathlib import Path

from . import __version__


def boolean(value):
    if isinstance(value, bool):
        return value
    if str(value).lower() in {"true", "yes", "1"}:
        return True
    if str(value).lower() in {"false", "no", "0"}:
        return False
    raise argparse.ArgumentTypeError("Use true ou false.")


def parser():
    result = argparse.ArgumentParser(prog="O3 Cloud Central", description="O3 Cloud Central — central e agentes Python")
    result.add_argument("command", nargs="?", choices=("version", "probe", "init-central", "configure-central", "migrate-state",
        "central", "enroll", "configure-gateway", "gateway", "agent", "windows-service", "tray", "control", "install", "upgrade", "uninstall", "uninstall-worker"))
    result.add_argument("--version", action="store_true", dest="version_only")
    result.add_argument("--dir", default="state")
    result.add_argument("--listen", default=":8443")
    result.add_argument("--url", default="")
    result.add_argument("--names", default="localhost,127.0.0.1")
    result.add_argument("--config", default="config.json")
    result.add_argument("--cache", default="/var/db/edgehub/policy.json")
    result.add_argument("--bundle", default="")
    result.add_argument("--database-url", default=os.environ.get("EDGEHUB_DATABASE_URL", ""))
    result.add_argument("--legacy", default="")
    result.add_argument("--dry-run", action="store_true")
    result.add_argument("--internal-only", type=boolean, nargs="?", const=True, default=False)
    result.add_argument("--desktop-shortcut", type=boolean, nargs="?", const=True, default=True)
    result.add_argument("--setup-confirmed", action="store_true")
    result.add_argument("--quiet", action="store_true")
    result.add_argument("--parent-pid", "--uninstall-parent", type=int, default=0)
    result.add_argument("--origin-pid", "--uninstall-origin", type=int, default=0)
    result.add_argument("--action", choices=("status", "log", "connect", "disconnect", "reconnect"), default="status")
    result.add_argument("--output", default="", help="Arquivo de saída apenas para version/probe")
    return result


def resource_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    configured = os.environ.get("EDGEHUB_RESOURCE_ROOT")
    return Path(configured) if configured else Path(__file__).resolve().parents[2]


def emit(value, output=""):
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, dict) else str(value)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    elif sys.stdout is not None:
        print(text)


def open_repository(dsn: str, *, initialize=True):
    if not dsn:
        raise ValueError("Configure EDGEHUB_DATABASE_URL com MariaDB/MySQL.")
    from .storage import StateRepository
    repository = StateRepository(dsn)
    try:
        if initialize:
            repository.initialize_schema()
        return repository
    except Exception:
        repository.close()
        raise


def certificate_names(value: str) -> list[str]:
    names = list(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))
    if not names or any(any(c.isspace() or c in "/\\@?#\x00" for c in name) for name in names):
        raise ValueError("Informe nomes DNS e IPs válidos em --names.")
    return names


def configure_central(arguments, initialize=False):
    from .common import valid_url
    from .crypto import hash_admin_password, initialize_pki, issue_server
    from .storage import empty_state
    if initialize and not valid_url(arguments.url):
        raise ValueError("Informe a URL HTTPS da central em --url.")
    if arguments.url and not valid_url(arguments.url):
        raise ValueError("URL HTTPS da central inválida.")
    names = certificate_names(arguments.names)
    folder = Path(arguments.dir)
    repository = open_repository(arguments.database_url)
    try:
        current = repository.read()
        if initialize:
            if current != empty_state():
                raise ValueError("Banco já contém cadastros; inicialização cancelada.")
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            password_file = folder / "admin-password.txt"
            if password_file.exists():
                raise ValueError("Arquivo de senha inicial já existe; inicialização cancelada.")
            initialize_pki(folder, names)
            password = "admin"
            state = empty_state()
            state.update(url=arguments.url.rstrip("/"), admin_hash="bootstrap$" + hash_admin_password(password))
            descriptor = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    output.write(password + "\n")
                    output.flush()
                    os.fsync(output.fileno())
                repository.initialize(state)
            except Exception:
                password_file.unlink(missing_ok=True)
                raise
            emit("Central inicializada. Senha inicial no arquivo protegido: " + str(password_file))
        else:
            if not current.get("url") or not current.get("admin_hash"):
                raise ValueError("Importe ou inicialize o banco antes de configurar a central.")
            issue_server(folder, names)
            if arguments.url:
                repository.transaction(lambda state: state.update(url=arguments.url.rstrip("/")))
            emit("URL e certificado da central configurados; cadastros preservados.")
    finally:
        repository.close()


class PrivateOnly:
    """Opt-in only. Peer address is checked without trusting forwarded headers."""
    NETWORKS = tuple(ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"))

    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            try:
                address = ipaddress.ip_address(scope.get("client", ("", 0))[0])
                if getattr(address, "ipv4_mapped", None):
                    address = address.ipv4_mapped
                allowed = any(address in network for network in self.NETWORKS)
            except ValueError:
                allowed = False
            if not allowed:
                await send({"type": "http.response.start", "status": 404,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"cache-control", b"no-store")]})
                await send({"type": "http.response.body", "body": b"Central disponivel somente pela rede interna.\n"})
                return
        await self.application(scope, receive, send)


def run_central(arguments):
    import uvicorn
    from .central import create_app
    from .central_tls import create_tls_contexts, make_uvicorn_server
    from .common import split_endpoint
    address = arguments.listen
    if address.startswith(":"):
        address = "0.0.0.0" + address
    host, port = split_endpoint(address)
    repository = open_repository(arguments.database_url)
    try:
        current = repository.read()
        if not current.get("url") or not current.get("admin_hash"):
            raise ValueError("Banco não contém uma central inicializada.")
        folder = Path(arguments.dir)
        application = create_app(repository, folder, version=__version__, artifacts={
            "web_dir": resource_root() / "web", "icon": resource_root() / "assets" / "O3CloudCentral.ico"})
        if arguments.internal_only:
            application = PrivateOnly(application)
        contexts = create_tls_contexts((folder / "server.crt").read_text(encoding="ascii"),
            (folder / "server.key").read_text(encoding="ascii"))
        config = uvicorn.Config(application, host=host, port=port, ssl_certfile=str(folder / "server.crt"),
            ssl_keyfile=str(folder / "server.key"), ssl_version=ssl.PROTOCOL_TLS_SERVER,
            proxy_headers=False, server_header=False, limit_concurrency=256,
            timeout_keep_alive=15, timeout_graceful_shutdown=15, log_level="info", http="h11")
        from .log_security import install_log_filters
        install_log_filters()
        make_uvicorn_server(config, contexts).run()
    finally:
        repository.close()


async def async_node(arguments):
    from .common import load_json
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(name, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    if arguments.command == "agent":
        from .agent import run_agent
        await run_agent(arguments.config, stop)
    else:
        from .gateway import run_gateway
        await run_gateway(load_json(arguments.config), arguments.cache, stop)


def _default_command():
    from .common import embedded_bundle
    try:
        embedded_bundle()
        return "install"
    except (ValueError, OSError):
        if os.name == "nt":
            from .windows_setup import product_locations, installed_service_name
            locations = product_locations()
            service_name = installed_service_name()
            if service_name:
                executable = Path(sys.executable)
                if service_name == "O3CloudCentral" and executable.is_relative_to(locations["programs"]):
                    return "tray"
                return "upgrade"
        return None


def main(argv=None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.version_only:
        arguments.command = "version"
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    from .log_security import install_log_filters
    install_log_filters()
    try:
        if arguments.command is None:
            arguments.command = _default_command()
        command = arguments.command
        if command == "version":
            emit(__version__, arguments.output)
        elif command == "probe":
            import asyncssh
            import cryptography
            report = {"name": "O3 Cloud Central", "version": __version__, "language": "Python", "python": sys.version.split()[0],
                "ssh": asyncssh.__version__, "cryptography": cryptography.__version__, "platform": sys.platform,
                "web_assets": (resource_root() / "web" / "index.html").is_file(),
                "icon": (resource_root() / "assets" / "O3CloudCentral.ico").is_file()}
            if os.name == "nt":
                import servicemanager
                import win32security
                import tkinter
                from .windows import tray_image
                from .windows_control import PIPE_SDDL
                from .windows_setup import product_locations
                report["windows_native"] = bool(servicemanager and product_locations())
                report["local_control_acl"] = bool(win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PIPE_SDDL, 1))
                report["tray_icons"] = tray_image(True).tobytes() != tray_image(False).tobytes()
                report["tcl"] = tkinter.Tcl().eval("info patchlevel")
            emit(report, arguments.output)
        elif command in {"init-central", "configure-central"}:
            configure_central(arguments, initialize=command == "init-central")
        elif command == "migrate-state":
            if not arguments.legacy:
                raise ValueError("Informe o arquivo local --legacy state.json.")
            repository = open_repository(arguments.database_url, initialize=not arguments.dry_run)
            try:
                emit(repository.import_legacy(arguments.legacy, dry_run=arguments.dry_run))
            finally:
                repository.close()
        elif command == "central":
            run_central(arguments)
        elif command == "enroll":
            from .common import enroll, load_json
            if not arguments.bundle:
                raise ValueError("Informe --bundle com o cadastro de uso único.")
            asyncio.run(enroll(load_json(arguments.bundle), arguments.config))
            emit("Cadastro concluído; configuração protegida gravada.")
        elif command == "configure-gateway":
            from .common import configure_gateway
            asyncio.run(configure_gateway(arguments.config, arguments.url))
            emit("pfSense atualizado; identidade preservada.")
        elif command in {"agent", "gateway"}:
            asyncio.run(async_node(arguments))
        elif command == "windows-service":
            from .windows import native_service
            native_service(arguments.config if arguments.config != "config.json" else None)
        elif command == "tray":
            from .windows import run_tray
            run_tray()
        elif command == "control":
            from .windows_control import local_request
            emit(local_request(arguments.action))
        elif command in {"install", "upgrade"}:
            from .windows import install_agent
            bundle = None
            if command == "install":
                from .common import embedded_bundle, load_json
                bundle = load_json(arguments.bundle) if arguments.bundle else embedded_bundle()
            asyncio.run(install_agent(bundle, upgrade=command == "upgrade", desktop_shortcut=arguments.desktop_shortcut,
                confirmed=arguments.setup_confirmed, quiet=arguments.quiet))
        elif command == "uninstall":
            from .windows import uninstall_agent
            uninstall_agent(confirmed=arguments.setup_confirmed, quiet=arguments.quiet,
                parent_pid=arguments.parent_pid, origin_pid=arguments.origin_pid)
        elif command == "uninstall-worker":
            from .windows_setup import uninstall_worker
            uninstall_worker(parent_pid=arguments.parent_pid, origin_pid=arguments.origin_pid, quiet=arguments.quiet)
        else:
            parser().print_help()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        # Database tracebacks/DSNs may contain credentials. Operator diagnostics
        # receive the category, while enrollment/interactive errors are useful.
        safe = str(exc)[:500] if isinstance(exc, (ValueError, PermissionError, FileNotFoundError, RuntimeError)) else type(exc).__name__
        logging.error("%s", safe)
        if os.name == "nt" and arguments.command in {"install", "upgrade", "uninstall", "uninstall-worker", "tray"}:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, safe, "O3 Cloud Central", 0x10)
        return 1
