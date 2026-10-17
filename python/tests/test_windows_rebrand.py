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

from edgehub import windows_setup as setup
from edgehub.windows_branding import PRODUCT_NAME, SERVICE_NAME, EXECUTABLE_NAME


def locations(root: Path, name: str):
    return {"programs": root / "programs" / name, "data": root / "data" / name,
            "local": root / "local" / name, "menu": root / "menu" / (name + ".lnk"),
            "desktop": root / "desktop" / (name + ".lnk")}


class MigrationDataTests(unittest.TestCase):
    def test_identity_copy_is_byte_exact_and_destination_collision_preserves_both(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old, new = root / "EdgeHub", root / PRODUCT_NAME
            old.mkdir()
            raw = b'{"id":"keep","private_key":"keep-key","token":"keep-token"}\n'
            (old / "config.json").write_bytes(raw)
            (old / "agent.log").write_text("old log")
            def protect(path, public=False):
                setup.validate_product_tree(path)
                path.mkdir(exist_ok=True)
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
        self.assertTrue(setup.owned_product_image(root / "EdgeHub" / "abc" / "EdgeHub.exe", root / "EdgeHub"))
        for image, candidate in ((root / EXECUTABLE_NAME, programs),
                                 (programs / "other.exe", programs),
                                 (root / "unrelated" / EXECUTABLE_NAME, root / "unrelated")):
            with self.subTest(image=image):
                self.assertFalse(setup.owned_product_image(image, candidate))

    @unittest.skipUnless(importlib.util.find_spec("PIL"), "Pillow is a Windows tray dependency")
    def test_tray_retains_logo_pixels_except_the_status_badge(self):
        from edgehub.windows import tray_image
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
    async def test_legacy_go_agent_service_is_owned_but_canonical_agent_mode_is_refused(self):
        import subprocess
        root = Path(tempfile.gettempdir()).absolute()
        for old in (False, True):
            roots = locations(root, "EdgeHub" if old else PRODUCT_NAME)
            executable = roots["programs"] / "version" / ("EdgeHub.exe" if old else EXECUTABLE_NAME)
            command = subprocess.list2cmdline([str(executable), "agent", "--config", str(roots["data"] / "config.json")])
            configuration = (16, 2, 1, command, None, None, None, None, PRODUCT_NAME)
            with self.subTest(legacy=old), patch("win32service.QueryServiceConfig", return_value=configuration):
                if old:
                    self.assertEqual(setup.verify_service_installation(12, roots, legacy=True), configuration)
                else:
                    with self.assertRaises(ValueError):
                        setup.verify_service_installation(12, roots)

    async def test_cli_generic_executable_selects_upgrade_without_private_config_stat(self):
        from edgehub.cli import _default_command
        root = Path(tempfile.gettempdir()).absolute()
        roots = locations(root, PRODUCT_NAME)
        for service, image, expected in (("EdgeHub", root / EXECUTABLE_NAME, "upgrade"),
                                         (SERVICE_NAME, root / EXECUTABLE_NAME, "upgrade"),
                                         (SERVICE_NAME, roots["programs"] / "version" / EXECUTABLE_NAME, "tray"),
                                         (None, root / EXECUTABLE_NAME, None)):
            with self.subTest(service=service, expected=expected), patch("edgehub.common.embedded_bundle", side_effect=ValueError("no bundle")), patch.object(setup, "installed_service_name", return_value=service), patch.object(setup, "product_locations", return_value=roots), patch("sys.executable", str(image)), patch.object(Path, "is_file", side_effect=AssertionError("private stat")):
                self.assertEqual(_default_command(), expected)

    async def test_public_scm_detection_does_not_read_protected_configuration(self):
        import pywintypes
        import win32service
        root = Path(tempfile.gettempdir()).absolute()
        for old in (False, True):
            roots = locations(root, "EdgeHub" if old else PRODUCT_NAME)
            image = roots["programs"] / "version" / ("EdgeHub.exe" if old else EXECUTABLE_NAME)
            config = (16, 2, 1, setup._service_binary(image, roots["data"] / "config.json"), None, None, None, None, PRODUCT_NAME)
            opened = []
            def open_service(manager, name, access):
                self.assertEqual(access, win32service.SERVICE_QUERY_CONFIG)
                opened.append(name)
                if old and name == SERVICE_NAME:
                    raise pywintypes.error(1060, "OpenService", "missing")
                return 12
            with self.subTest(legacy=old), patch("win32service.OpenSCManager", return_value=10), patch("win32service.OpenService", side_effect=open_service), patch("win32service.QueryServiceConfig", return_value=config), patch("win32service.CloseServiceHandle"), patch.object(setup, "product_locations", return_value=roots), patch.object(Path, "read_bytes", side_effect=AssertionError("private read")), patch.object(Path, "is_file", side_effect=AssertionError("private stat")):
                self.assertEqual(setup.installed_service_name(), "EdgeHub" if old else SERVICE_NAME)
                self.assertEqual(opened, [SERVICE_NAME, "EdgeHub"] if old else [SERVICE_NAME])

    async def test_native_service_registers_the_new_scm_name(self):
        from edgehub.windows import native_service
        with patch("servicemanager.Initialize") as initialized, patch("servicemanager.PrepareToHostSingle") as prepared, patch("servicemanager.StartServiceCtrlDispatcher") as dispatcher:
            native_service(Path("C:/ProgramData/O3 Cloud Central/config.json"))
        initialized.assert_called_once_with(SERVICE_NAME, None)
        service_class = prepared.call_args.args[0]
        self.assertEqual(service_class._svc_name_, SERVICE_NAME)
        self.assertEqual(service_class._svc_display_name_, PRODUCT_NAME)
        dispatcher.assert_called_once()

    async def test_startup_waits_for_verified_pipe_before_committing(self):
        import win32service
        with patch("win32service.StartService") as start, patch("win32service.QueryServiceStatusEx", return_value={"CurrentState": win32service.SERVICE_RUNNING}), patch("edgehub.windows_control.local_request", side_effect=[PermissionError("wrong service PID"), {"status": {"state": "offline"}}]) as control, patch("time.sleep"):
            setup._start_service_ready(13)
        start.assert_called_once_with(13, None)
        self.assertEqual(control.call_count, 2)

    async def _upgrade(self, *, failure=False, both=False, wrong_image=False, rollback_stop_failure=False):
        import pywintypes
        import win32service
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            new, old = locations(root, PRODUCT_NAME), locations(root, "EdgeHub")
            old["data"].mkdir(parents=True)
            old_image = old["programs"] / "old-version" / "EdgeHub.exe"
            old_image.parent.mkdir(parents=True)
            old_image.write_bytes(b"MZ-old-runtime")
            raw = b'{"kind":"agent","id":"retained-id","private_key":"retained-key","token":"retained-token"}\n'
            (old["data"] / "config.json").write_bytes(raw)
            (old["data"] / "agent.log").write_text("retained log")
            old_command = setup._service_binary(old_image, old["data"] / "config.json")
            if wrong_image:
                old_command = setup._service_binary(root / "unrelated" / "EdgeHub.exe", old["data"] / "config.json")
            old_configuration = (16, 2, 1, old_command, None, None, None, None, "EdgeHub")
            events = []
            services = {"EdgeHub": 12}
            if both:
                services[SERVICE_NAME] = 11
            def open_service(manager, name, access):
                if name not in services:
                    raise pywintypes.error(1060, "OpenService", "missing")
                return services[name]
            def protect(path, public=False):
                setup.validate_product_tree(path)
                path.mkdir(parents=True, exist_ok=True)
            def create_service(*arguments):
                events.append(("create", arguments[1], arguments[2], arguments[7]))
                services[SERVICE_NAME] = 13
                return 13
            def ready(service):
                events.append(("ready", service))
                self.assertEqual((new["data"] / "config.json").read_bytes(), raw)
                self.assertEqual((old["data"] / "config.json").read_bytes(), raw)
                if failure:
                    raise RuntimeError("new service failed")
            with contextlib.ExitStack() as stack:
                def mocked(target, *args, **kwargs):
                    return stack.enter_context(patch(target, *args, **kwargs))
                mocked("edgehub.windows_setup.is_admin", return_value=True)
                mocked("sys.frozen", True, create=True)
                mocked("edgehub.windows_setup.setup_lock", side_effect=contextlib.nullcontext)
                mocked("edgehub.windows_setup.product_locations", side_effect=lambda legacy=False: old if legacy else new)
                mocked("edgehub.windows_setup.protect_directory", side_effect=protect)
                mocked("edgehub.windows_setup.prepare_direct_upgrade", new=AsyncMock(return_value=json.loads(raw)))
                enrolled = mocked("edgehub.common.enroll", new=AsyncMock())
                mocked("edgehub.windows_setup.executable_payload", return_value=b"MZ-new-runtime")
                mocked("win32service.OpenSCManager", return_value=10)
                mocked("win32service.OpenService", side_effect=open_service)
                mocked("win32service.QueryServiceConfig", return_value=old_configuration)
                mocked("win32service.QueryServiceStatusEx", return_value={"CurrentState": win32service.SERVICE_STOPPED})
                mocked("win32service.CreateService", side_effect=create_service)
                mocked("win32service.ChangeServiceConfig2")
                mocked("win32service.CloseServiceHandle")
                mocked("win32service.StartService", side_effect=lambda handle, _: events.append(("restart", handle)))
                mocked("win32service.DeleteService", side_effect=lambda handle: events.append(("delete", handle)))
                mocked("edgehub.windows_setup._configure_recovery")
                def stop_service(handle):
                    events.append(("stop", handle))
                    if rollback_stop_failure and handle == 13:
                        raise TimeoutError("new service did not stop")
                stopped = mocked("edgehub.windows_setup._stop_service", side_effect=stop_service)
                mocked("edgehub.windows_setup._stop_owned_trays")
                mocked("edgehub.windows_setup._start_service_ready", side_effect=ready)
                mocked("edgehub.windows_setup.create_shortcuts", side_effect=lambda *args: events.append(("shortcuts",)))
                mocked("edgehub.windows_setup._registration", side_effect=lambda *args: events.append(("registration",)))
                mocked("edgehub.windows_setup._remove_registration", side_effect=lambda **kwargs: events.append(("unregister", kwargs.get("legacy", False))))
                mocked("edgehub.windows_setup._remove_shortcuts")
                if failure or both or wrong_image:
                    with self.assertRaises((RuntimeError, ValueError)):
                        await setup.install_agent(upgrade=True, quiet=True, confirmed=True)
                    self.assertEqual((old["data"] / "config.json").read_bytes(), raw)
                    self.assertTrue(old_image.exists())
                    self.assertNotIn(("delete", 12), events)
                    if rollback_stop_failure:
                        self.assertNotIn(("delete", 13), events)
                        self.assertNotIn(("restart", 12), events)
                        self.assertEqual((new["data"] / "config.json").read_bytes(), raw)
                        self.assertNotIn(("unregister", False), events)
                        self.assertNotIn(("unregister", True), events)
                    elif failure:
                        self.assertIn(("delete", 13), events)
                        self.assertIn(("restart", 12), events)
                        self.assertFalse(new["data"].exists())
                    else:
                        stopped.assert_not_called()
                else:
                    await setup.install_agent(upgrade=True, quiet=True, confirmed=True)
                    self.assertEqual((new["data"] / "config.json").read_bytes(), raw)
                    self.assertEqual((new["data"] / "agent.log").read_text(), "retained log")
                    self.assertFalse(old["data"].exists())
                    self.assertFalse(old["programs"].exists())
                    self.assertLess(events.index(("ready", 13)), events.index(("delete", 12)))
                    self.assertLess(events.index(("registration",)), events.index(("delete", 12)))
                    created = next(item for item in events if item[0] == "create")
                    self.assertEqual(created[1:3], (SERVICE_NAME, PRODUCT_NAME))
                    self.assertIn(EXECUTABLE_NAME, created[3])
                    self.assertIn(str(new["data"] / "config.json"), created[3])
                    self.assertIn(("unregister", True), events)
                enrolled.assert_not_awaited()

    async def test_upgrade_migrates_identity_then_commits_only_after_new_service_ready(self):
        await self._upgrade()

    async def test_failed_new_service_rolls_back_and_preserves_original_identity(self):
        await self._upgrade(failure=True)

    async def test_failed_rollback_stop_preserves_both_configs_and_never_starts_second_agent(self):
        await self._upgrade(failure=True, rollback_stop_failure=True)

    async def test_ambiguous_two_services_are_untouched(self):
        await self._upgrade(both=True)

    async def test_similarly_named_unrelated_service_is_untouched(self):
        await self._upgrade(wrong_image=True)

    async def test_control_pipe_prefers_new_service_and_only_falls_back_if_absent(self):
        import pywintypes
        from edgehub.windows_control import trusted_service_pipe
        for absent in (False, True):
            opened = []
            def service(manager, name, access):
                opened.append(name)
                if absent and name == SERVICE_NAME:
                    raise pywintypes.error(1060, "OpenService", "missing")
                return 12
            with self.subTest(legacy=absent), patch("win32service.OpenSCManager", return_value=10), patch("win32service.OpenService", side_effect=service), patch("win32service.QueryServiceStatusEx", return_value={"ProcessId": 42}), patch("win32service.CloseServiceHandle"):
                trusted_service_pipe(None, server_pid=42)
                self.assertEqual(opened, [SERVICE_NAME, "EdgeHub"] if absent else [SERVICE_NAME])
