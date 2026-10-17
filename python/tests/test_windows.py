import json
import asyncio
import io
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from o3cloudcentral.windows_control import PIPE_SDDL, decode_command, log_tail, trusted_service_pipe
from o3cloudcentral.windows_setup import executable_payload, validate_product_tree, _service_binary


class WindowsSafetyTests(unittest.TestCase):
    def test_independent_process_environment_does_not_reuse_parent_runtime(self):
        from o3cloudcentral.windows_setup import independent_environment, independent_shell_environment, _launch_tray
        with patch.dict(os.environ, {"PYINSTALLER_RESET_ENVIRONMENT": "previous", "O3CLOUDCENTRAL_TEST_VALUE": "retained"}):
            child = independent_environment()
            self.assertEqual(child["PYINSTALLER_RESET_ENVIRONMENT"], "1")
            self.assertEqual(child["O3CLOUDCENTRAL_TEST_VALUE"], "retained")
            self.assertEqual(os.environ["PYINSTALLER_RESET_ENVIRONMENT"], "previous")
            with self.assertRaises(RuntimeError):
                with independent_shell_environment():
                    self.assertEqual(os.environ["PYINSTALLER_RESET_ENVIRONMENT"], "1")
                    raise RuntimeError("launch cancelled")
            self.assertEqual(os.environ["PYINSTALLER_RESET_ENVIRONMENT"], "previous")
            with patch("subprocess.Popen") as started:
                _launch_tray(Path("C:/Program Files/O3CloudCentral/123/O3CloudCentral.exe"))
            self.assertEqual(started.call_args.kwargs["env"]["PYINSTALLER_RESET_ENVIRONMENT"], "1")
    def test_control_fixed_commands_and_bounded_input(self):
        self.assertEqual(decode_command(b'{"command":"disconnect"}'), "disconnect")
        for data in (b"", b"x" * 513, b'{"command":"shell"}', b'{"command":"status","path":"C:/private"}', b"[]"):
            with self.subTest(data=data), self.assertRaises((ValueError, TypeError)):
                decode_command(data)

    def test_pipe_refuses_same_user_impostor(self):
        trusted_service_pipe(None, server_pid=42, service_pid=42)
        for server, service in ((0, 0), (31, 42), (42, 0)):
            with self.subTest(server=server), self.assertRaises(PermissionError):
                trusted_service_pipe(None, server_pid=server, service_pid=service)
        self.assertIn("0x100183;;;IU", PIPE_SDDL)
        self.assertNotIn("GW;;;IU", PIPE_SDDL)

    def test_payload_strips_only_valid_one_use_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "O3CloudCentral.exe"
            base, bundle = b"MZ-pyinstaller-runtime", b'{"kind":"agent"}'
            executable.write_bytes(base + bundle + struct.pack("<Q", len(bundle)) + b"O3CC001!")
            self.assertEqual(executable_payload(executable), base)
            executable.write_bytes(base + struct.pack("<Q", 1 << 20) + b"O3CC001!")
            with self.assertRaises(ValueError):
                executable_payload(executable)

    def test_recursive_removal_rejects_other_names_and_redirects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            product = root / "O3 Cloud Central"
            product.mkdir()
            validate_product_tree(product)
            with self.assertRaises(ValueError):
                validate_product_tree(root)
            target = root / "other"
            target.mkdir()
            try:
                (product / "redirect").symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("O Windows não permite criar links sem privilégio nesta sessão")
            with self.assertRaises(ValueError):
                validate_product_tree(product)

    def test_log_is_tail_only_and_service_command_is_quoted(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "agent.log"
            log.write_bytes(b"old" * 10000 + b"latest")
            value = log_tail(log)
            self.assertLessEqual(len(value), 16000)
            self.assertTrue(value.endswith("latest"))
        command = _service_binary(Path("C:/Program Files/O3CloudCentral/abc/O3CloudCentral.exe"), Path("C:/ProgramData/O3CloudCentral/config.json"))
        self.assertIn('"C:', command)
        self.assertIn("windows-service --config", command)


class CommandLineTests(unittest.TestCase):
    def test_cli_native_flags_and_private_mode_are_explicit(self):
        from o3cloudcentral.cli import parser
        arguments = parser().parse_args(["install", "--desktop-shortcut=false", "--setup-confirmed", "--quiet"])
        self.assertFalse(arguments.desktop_shortcut)
        self.assertTrue(arguments.setup_confirmed)
        self.assertFalse(arguments.internal_only)
        self.assertFalse(parser().parse_args(["central", "--internal-only=false"]).internal_only)
        self.assertTrue(parser().parse_args(["central", "--internal-only"]).internal_only)

    def test_cli_migration_dry_run_never_initializes_or_exports_state(self):
        from o3cloudcentral.cli import main
        repository = MagicMock()
        repository.import_legacy.return_value = {"sites": 2, "devices": 3, "services": 4, "tickets": 0, "dry_run": True}
        output = io.StringIO()
        with patch("o3cloudcentral.cli.open_repository", return_value=repository) as opened, patch("sys.stdout", output):
            result = main(["migrate-state", "--legacy", "private/state.json", "--database-url", "mysql+pymysql://private", "--dry-run"])
        self.assertEqual(result, 0)
        opened.assert_called_once_with("mysql+pymysql://private", initialize=False)
        repository.import_legacy.assert_called_once_with("private/state.json", dry_run=True)
        repository.close.assert_called_once()
        self.assertEqual(json.loads(output.getvalue())["sites"], 2)
        self.assertNotIn("admin_hash", output.getvalue())


class PrivateModeTests(unittest.IsolatedAsyncioTestCase):
    async def test_optional_peer_filter_never_trusts_forwarded_for(self):
        from o3cloudcentral.cli import PrivateOnly
        seen = []
        async def application(scope, receive, send):
            seen.append(scope["client"][0])
        wrapper = PrivateOnly(application)
        sent = []
        async def send(value):
            sent.append(value)
        async def receive():
            return {"type": "http.request", "body": b""}
        for address in ("10.20.0.20", "127.0.0.1", "::1", "::ffff:192.168.5.3"):
            await wrapper({"type": "http", "client": (address, 4000), "headers": []}, receive, send)
        self.assertEqual(len(seen), 4)
        await wrapper({"type": "http", "client": ("8.8.8.8", 4000), "headers": [(b"x-forwarded-for", b"10.20.0.20")]}, receive, send)
        self.assertEqual(len(seen), 4)
        self.assertEqual(sent[0]["status"], 404)


class LegacyUpgradeTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_bootstrap_is_once_and_preserves_all_identity_material(self):
        import asyncssh
        from o3cloudcentral.windows_setup import prepare_direct_upgrade
        key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        initial = {"kind": "agent", "id": "agent-old", "private_key": "unchanged-private-key", "token": "unchanged-token",
            "url": "https://legacy-central.invalid:8443", "ca": "unchanged-ca"}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps(initial))
            request = AsyncMock(return_value={"endpoint": "pf.example:2222", "host_key": key, "lease_seconds": 300})
            with patch("o3cloudcentral.common.api_request", request):
                updated = await prepare_direct_upgrade(path)
                self.assertEqual(await prepare_direct_upgrade(path), updated)
            request.assert_awaited_once()
            self.assertEqual(request.call_args.args[2], "/api/agent/policy")
            for name, value in initial.items():
                self.assertEqual(updated[name], value)
            self.assertEqual(updated["gateway_host_key"], key)

    async def test_failed_or_wrong_identity_lookup_never_changes_config(self):
        import asyncssh
        from o3cloudcentral.windows_setup import prepare_direct_upgrade
        key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        initial = {"kind": "agent", "id": "agent-old", "private_key": "keep", "token": "keep", "url": "https://old.invalid:8443", "ca": "keep"}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            raw = json.dumps(initial, indent=2).encode()
            path.write_bytes(raw)
            for response in (OSError("offline"), {"id": "different-agent", "endpoint": "pf.example:2222", "host_key": key, "lease_seconds": 300},
                             {"endpoint": "pf.example", "host_key": key, "lease_seconds": 300}):
                request = AsyncMock(side_effect=response) if isinstance(response, Exception) else AsyncMock(return_value=response)
                with self.subTest(response=type(response).__name__), patch("o3cloudcentral.common.api_request", request), self.assertRaises(ValueError):
                    await prepare_direct_upgrade(path)
                self.assertEqual(path.read_bytes(), raw)


@unittest.skipUnless(os.name == "nt", "Windows-specific APIs")
class WindowsNativeTests(unittest.TestCase):
    def test_uac_launch_gets_independent_environment_without_real_elevation(self):
        from o3cloudcentral.windows_setup import elevate
        from win32com.shell import shell
        process = MagicMock()
        def fake_launch(**arguments):
            self.assertEqual(arguments["lpVerb"], "runas")
            self.assertEqual(os.environ.get("PYINSTALLER_RESET_ENVIRONMENT"), "1")
            return {"hProcess": process}
        with patch.dict(os.environ, {"PYINSTALLER_RESET_ENVIRONMENT": "previous"}), patch.object(shell, "ShellExecuteEx", side_effect=fake_launch), patch("o3cloudcentral.windows_setup._self_command", return_value=["O3CloudCentral.exe", "uninstall"]):
            elevate(["uninstall"], wait=False)
            self.assertEqual(os.environ["PYINSTALLER_RESET_ENVIRONMENT"], "previous")
        process.Close.assert_called_once()
    def test_native_locations_and_pipe_descriptor(self):
        import win32security
        from o3cloudcentral.windows_setup import product_locations
        locations = product_locations()
        self.assertEqual(locations["programs"].name, "O3 Cloud Central")
        self.assertEqual(locations["data"].name, "O3 Cloud Central")
        self.assertEqual(locations["menu"].name, "O3 Cloud Central.lnk")
        with self.assertRaises(ValueError): product_locations(legacy=True)
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PIPE_SDDL, 1)
        self.assertIsNotNone(descriptor.GetSecurityDescriptorDacl())

    def test_offline_and_online_icons_are_distinct(self):
        from o3cloudcentral.windows import tray_image
        offline, online = tray_image(False), tray_image(True)
        self.assertEqual(offline.size, (64, 64))
        self.assertNotEqual(offline.getpixel((53, 53)), online.getpixel((53, 53)))

    def test_application_registration_has_uninstaller_startup_and_64_bit_view(self):
        import winreg
        from o3cloudcentral.windows_setup import _registration, APP_KEY, RUN_KEY
        recorded = []
        opened = []
        class Key:
            def __init__(self, path):
                self.path = path
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
        def create(hive, path, reserved, rights):
            opened.append((hive, path, rights))
            return Key(path)
        def write(key, name, reserved, value_type, value):
            recorded.append((key.path, name, value_type, value))
        executable = Path("C:/Program Files/O3 Cloud Central/12345678/O3CloudCentral.exe")
        with patch("winreg.CreateKeyEx", side_effect=create), patch("winreg.SetValueEx", side_effect=write):
            _registration(executable, {"programs": executable.parent.parent})
        values = {(key, name): value for key, name, value_type, value in recorded}
        self.assertEqual(values[APP_KEY, "DisplayName"], "O3 Cloud Central")
        self.assertEqual(values[APP_KEY, "DisplayIcon"], '"' + str(executable) + '",0')
        self.assertTrue(values[APP_KEY, "UninstallString"].endswith('" uninstall'))
        self.assertTrue(values[RUN_KEY, "O3CloudCentral"].endswith('" tray'))
        self.assertTrue(all(rights & winreg.KEY_WOW64_64KEY for hive, path, rights in opened))

    def test_privileged_uninstall_helper_rejects_other_allowed_identities(self):
        import win32security
        from o3cloudcentral.windows_setup import verify_helper_acl
        owner = win32security.ConvertStringSidToSid("S-1-5-32-544")
        admin = win32security.ConvertStringSidToSid("S-1-5-32-544")
        system = win32security.ConvertStringSidToSid("S-1-5-18")
        users = win32security.ConvertStringSidToSid("S-1-5-32-545")
        acl = MagicMock()
        acl.GetAceCount.return_value = 2
        acl.GetAce.side_effect = [((0, 0), 0x1F01FF, admin), ((0, 0), 0x1F01FF, system)]
        descriptor = MagicMock()
        descriptor.GetSecurityDescriptorOwner.return_value = owner
        descriptor.GetSecurityDescriptorDacl.return_value = acl
        with patch("win32security.GetNamedSecurityInfo", return_value=descriptor):
            verify_helper_acl(Path("C:/ProgramData/fixture"))
            acl.GetAceCount.return_value = 3
            acl.GetAce.side_effect = [((0, 0), 0x1F01FF, admin), ((0, 0), 0x1F01FF, system), ((0, 0), 0x1F01FF, users)]
            with self.assertRaises(PermissionError):
                verify_helper_acl(Path("C:/ProgramData/fixture"))
