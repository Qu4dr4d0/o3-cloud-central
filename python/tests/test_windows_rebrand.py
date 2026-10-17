"""Upgrade behaviour is exercised without elevation or real SCM mutations."""
import asyncio
import contextlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from o3cloudcentral import windows_setup as setup
from o3cloudcentral.windows_branding import PRODUCT_NAME, SERVICE_NAME, EXECUTABLE_NAME


def locations(root: Path, name: str):
    return {"programs": root / "programs" / name, "data": root / "data" / name,
            "local": root / "local" / name, "menu": root / "menu" / (name + ".lnk"),
            "desktop": root / "desktop" / (name + ".lnk")}


class MigrationDataTests(unittest.TestCase):
    def test_identity_copy_is_byte_exact_and_destination_collision_preserves_both(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old, new = root / "source" / PRODUCT_NAME, root / "destination" / PRODUCT_NAME
            old.mkdir(parents=True)
            raw = b'{"id":"keep","private_key":"keep-key","token":"keep-token"}\n'
            (old / "config.json").write_bytes(raw)
            (old / "agent.log").write_text("old log")
            def protect(path, public=False):
                setup.validate_product_tree(path)
                path.mkdir(parents=True,exist_ok=True)
            with patch.object(setup, "protect_directory", side_effect=protect) as protection:
                setup.copy_upgrade_data(old, new)
                self.assertEqual((new / "config.json").read_bytes(), raw)
                self.assertEqual((old / "config.json").read_bytes(), raw)
                self.assertEqual((new / "agent.log").read_text(), "old log")
                self.assertTrue(all(call.kwargs == {"public": False} for call in protection.call_args_list))
                with self.assertRaises(ValueError):
                    setup.copy_upgrade_data(old, new)
            self.assertEqual((new / "config.json").read_bytes(), raw)
            self.assertEqual((old / "config.json").read_bytes(), raw)

    def test_owned_image_requires_known_product_name_and_actual_product_root(self):
        root = Path(tempfile.gettempdir()).absolute()
        programs = root / PRODUCT_NAME
        self.assertTrue(setup.owned_product_image(programs / "abc" / EXECUTABLE_NAME, programs))
        self.assertFalse(setup.owned_product_image(root / "Unrelated" / "abc" / EXECUTABLE_NAME, root / "Unrelated"))
        for image, candidate in ((root / EXECUTABLE_NAME, programs),
                                 (programs / "other.exe", programs),
                                 (root / "unrelated" / EXECUTABLE_NAME, root / "unrelated")):
            with self.subTest(image=image):
                self.assertFalse(setup.owned_product_image(image, candidate))

    @unittest.skipUnless(importlib.util.find_spec("PIL"), "Pillow is a Windows tray dependency")
    def test_tray_retains_logo_pixels_except_the_status_badge(self):
        from o3cloudcentral.windows import tray_image
        offline, online = tray_image(False), tray_image(True)
        self.assertEqual(offline.size, (64, 64))
        self.assertEqual(online.getpixel((53, 53)), (18, 185, 129, 255))
        self.assertEqual(offline.getpixel((53, 53)), (220, 53, 69, 255))
        self.assertTrue(any(online.getpixel((x, y))[3] for y in range(42) for x in range(64)))
        for y in range(64):
            for x in range(64):
                if x < 42 or y < 42:
                    self.assertEqual(offline.getpixel((x, y)), online.getpixel((x, y)))


@unittest.skipUnless(os.name == "nt", "mocked Windows SCM APIs")
class RebrandServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_agent_mode_and_old_product_layout_are_refused(self):
        import subprocess
        root = Path(tempfile.gettempdir()).absolute()
        for old in (False, True):
            roots = locations(root, "O3CloudCentral" if old else PRODUCT_NAME)
            executable = roots["programs"] / "version" / ("O3CloudCentral.exe" if old else EXECUTABLE_NAME)
            command = subprocess.list2cmdline([str(executable), "agent", "--config", str(roots["data"] / "config.json")])
            configuration = (16, 2, 1, command, None, None, None, None, PRODUCT_NAME)
            with self.subTest(legacy=old), patch("win32service.QueryServiceConfig", return_value=configuration):
                if old:
                    with self.assertRaises(ValueError): setup.verify_service_installation(12, roots, legacy=True)
                else:
                    with self.assertRaises(ValueError):
                        setup.verify_service_installation(12, roots)

    async def test_cli_generic_executable_selects_upgrade_without_private_config_stat(self):
        from o3cloudcentral.cli import _default_command
        root = Path(tempfile.gettempdir()).absolute()
        roots = locations(root, PRODUCT_NAME)
        for service, image, expected in (("O3CloudCentral", root / EXECUTABLE_NAME, "upgrade"),
                                         (SERVICE_NAME, root / EXECUTABLE_NAME, "upgrade"),
                                         (SERVICE_NAME, roots["programs"] / "version" / EXECUTABLE_NAME, "tray"),
                                         (None, root / EXECUTABLE_NAME, None)):
            with self.subTest(service=service, expected=expected), patch("o3cloudcentral.common.embedded_bundle", side_effect=ValueError("no bundle")), patch.object(setup, "installed_service_name", return_value=service), patch.object(setup, "product_locations", return_value=roots), patch("sys.executable", str(image)), patch.object(Path, "is_file", side_effect=AssertionError("private stat")):
                self.assertEqual(_default_command(), expected)

    async def test_public_scm_detection_does_not_read_protected_configuration(self):
        import pywintypes
        import win32service
        root = Path(tempfile.gettempdir()).absolute()
        for old in (False, True):
            roots = locations(root, "O3CloudCentral" if old else PRODUCT_NAME)
            image = roots["programs"] / "version" / ("O3CloudCentral.exe" if old else EXECUTABLE_NAME)
            config = (16, 2, 1, setup._service_binary(image, roots["data"] / "config.json"), None, None, None, None, PRODUCT_NAME)
            opened = []
            def open_service(manager, name, access):
                self.assertEqual(access, win32service.SERVICE_QUERY_CONFIG)
                opened.append(name)
                if old and name == SERVICE_NAME:
                    raise pywintypes.error(1060, "OpenService", "missing")
                return 12
            with self.subTest(legacy=old), patch("win32service.OpenSCManager", return_value=10), patch("win32service.OpenService", side_effect=open_service), patch("win32service.QueryServiceConfig", return_value=config), patch("win32service.CloseServiceHandle"), patch.object(setup, "product_locations", return_value=roots), patch.object(Path, "read_bytes", side_effect=AssertionError("private read")), patch.object(Path, "is_file", side_effect=AssertionError("private stat")):
                self.assertEqual(setup.installed_service_name(), None if old else SERVICE_NAME)
                self.assertEqual(opened, [SERVICE_NAME])

    async def test_native_service_registers_the_new_scm_name(self):
        from o3cloudcentral.windows import native_service
        with patch("servicemanager.Initialize") as initialized, patch("servicemanager.PrepareToHostSingle") as prepared, patch("servicemanager.StartServiceCtrlDispatcher") as dispatcher:
            native_service(Path("C:/ProgramData/O3 Cloud Central/config.json"))
        initialized.assert_called_once_with(SERVICE_NAME, None)
        service_class = prepared.call_args.args[0]
        self.assertEqual(service_class._svc_name_, SERVICE_NAME)
        self.assertEqual(service_class._svc_display_name_, PRODUCT_NAME)
        dispatcher.assert_called_once()

    async def test_startup_waits_for_verified_pipe_before_committing(self):
        import win32service
        with patch("win32service.StartService") as start, patch("win32service.QueryServiceStatusEx", return_value={"CurrentState": win32service.SERVICE_RUNNING}), patch("o3cloudcentral.windows_control.local_request", side_effect=[PermissionError("wrong service PID"), {"status": {"state": "offline"}}]) as control, patch("time.sleep"):
            setup._start_service_ready(13)
        start.assert_called_once_with(13, None)
        self.assertEqual(control.call_count, 2)

    async def _upgrade(self, *, failure=False, both=False, wrong_image=False, rollback_stop_failure=False):
        import pywintypes
        import win32service
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); current=locations(root,PRODUCT_NAME)
            current["data"].mkdir(parents=True)
            original=current["programs"]/"original"/EXECUTABLE_NAME
            original.parent.mkdir(parents=True);original.write_bytes(b"MZ-original")
            raw=b'{"kind":"agent","id":"retained","private_key":"fixture","token":"fixture"}'
            (current["data"]/"config.json").write_bytes(raw)
            image=root/"unrelated"/EXECUTABLE_NAME if wrong_image else original
            old_config=(16,2,1,setup._service_binary(image,current["data"]/"config.json"),None,None,None,None,PRODUCT_NAME)
            events=[];stops=[]
            def stop(handle):
                stops.append(handle)
                if rollback_stop_failure and len(stops)>1:raise TimeoutError("stop failed")
            def opened(*args):
                if both:raise pywintypes.error(1060,"OpenService","missing")
                return 12
            def ready(handle):
                events.append("ready")
                self.assertEqual((current["data"]/"config.json").read_bytes(),raw)
                if failure:raise RuntimeError("new runtime failed")
            with contextlib.ExitStack() as stack:
                def mock(target,*args,**kwargs):return stack.enter_context(patch(target,*args,**kwargs))
                mock("o3cloudcentral.windows_setup.is_admin",return_value=True)
                mock("sys.frozen",True,create=True)
                mock("o3cloudcentral.windows_setup.setup_lock",side_effect=contextlib.nullcontext)
                mock("o3cloudcentral.windows_setup.product_locations",return_value=current)
                mock("o3cloudcentral.windows_setup.prepare_direct_upgrade",new=AsyncMock(return_value=json.loads(raw)))
                mock("o3cloudcentral.windows_setup.protect_directory",side_effect=lambda path,**kw:path.mkdir(parents=True,exist_ok=True))
                enrolled=mock("o3cloudcentral.common.enroll",new=AsyncMock())
                mock("o3cloudcentral.windows_setup.executable_payload",return_value=b"MZ-new")
                mock("win32service.OpenSCManager",return_value=10)
                mock("win32service.OpenService",side_effect=opened)
                mock("win32service.QueryServiceConfig",return_value=old_config)
                changed=mock("win32service.ChangeServiceConfig")
                mock("win32service.ChangeServiceConfig2")
                mock("win32service.CloseServiceHandle")
                created=mock("win32service.CreateService")
                deleted=mock("win32service.DeleteService")
                restarted=mock("win32service.StartService")
                mock("o3cloudcentral.windows_setup._configure_recovery")
                mock("o3cloudcentral.windows_setup._stop_service",side_effect=stop)
                mock("o3cloudcentral.windows_setup._stop_owned_trays")
                mock("o3cloudcentral.windows_setup._start_service_ready",side_effect=ready)
                mock("o3cloudcentral.windows_setup.create_shortcuts")
                mock("o3cloudcentral.windows_setup._registration")
                if failure or both or wrong_image:
                    with self.assertRaises((RuntimeError,ValueError)):await setup.install_agent(upgrade=True,quiet=True,confirmed=True)
                    if failure and not rollback_stop_failure:restarted.assert_called_once_with(12,None)
                    else:restarted.assert_not_called()
                    if both or wrong_image:self.assertEqual(stops,[])
                else:
                    await setup.install_agent(upgrade=True,quiet=True,confirmed=True)
                    self.assertEqual(events,["ready"])
                    changed.assert_called_once()
                enrolled.assert_not_awaited();created.assert_not_called();deleted.assert_not_called()
                self.assertTrue(original.exists())
                self.assertEqual((current["data"]/"config.json").read_bytes(),raw)

    async def test_upgrade_preserves_identity_and_waits_for_new_runtime(self):
        await self._upgrade()

    async def test_failed_new_service_rolls_back_and_preserves_original_identity(self):
        await self._upgrade(failure=True)

    async def test_failed_rollback_stop_preserves_both_configs_and_never_starts_second_agent(self):
        await self._upgrade(failure=True, rollback_stop_failure=True)

    async def test_upgrade_requires_an_installed_product_service(self):
        await self._upgrade(both=True)

    async def test_similarly_named_unrelated_service_is_untouched(self):
        await self._upgrade(wrong_image=True)

    async def test_control_pipe_requires_the_canonical_service(self):
        import pywintypes
        from o3cloudcentral.windows_control import trusted_service_pipe
        for absent in (False, True):
            opened = []
            def service(manager, name, access):
                opened.append(name)
                if absent and name == SERVICE_NAME:
                    raise pywintypes.error(1060, "OpenService", "missing")
                return 12
            with self.subTest(legacy=absent), patch("win32service.OpenSCManager", return_value=10), patch("win32service.OpenService", side_effect=service), patch("win32service.QueryServiceStatusEx", return_value={"ProcessId": 42}), patch("win32service.CloseServiceHandle"):
                if absent:
                    with self.assertRaises(PermissionError): trusted_service_pipe(None, server_pid=42)
                else: trusted_service_pipe(None, server_pid=42)
                self.assertEqual(opened, [SERVICE_NAME])
