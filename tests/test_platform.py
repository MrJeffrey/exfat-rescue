from __future__ import annotations

import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

from exfat_rescue import cli, recovery
from exfat_rescue.errors import OutputError


class PlatformTests(unittest.TestCase):
    def test_windows_operational_command_is_a_usage_error(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(cli.sys, "platform", "win32"), redirect_stderr(stderr):
            code = cli.main(["inspect", "missing.img", "--json"])
        self.assertEqual(code, 2)
        self.assertIn("Linux or macOS", stderr.getvalue())

    def test_missing_fcntl_import_keeps_help_and_version_available(self) -> None:
        script = """
import builtins
import contextlib
import io
original_import = builtins.__import__
def blocked(name, *args, **kwargs):
    if name == 'fcntl':
        raise ImportError('simulated missing fcntl')
    return original_import(name, *args, **kwargs)
builtins.__import__ = blocked
from exfat_rescue import cli
assert not cli.LOCKING_AVAILABLE
with contextlib.redirect_stdout(io.StringIO()):
    for arguments in (['--help'], ['--version']):
        try:
            cli.main(arguments)
        except SystemExit as error:
            assert error.code == 0
        else:
            raise AssertionError('help/version should exit')
assert cli.main(['recover', 'missing.img', '--output', 'unused', '--json']) == 2
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        error = json.loads(result.stderr)
        self.assertEqual(error["error_code"], "usage_error")
        self.assertIn("Linux or macOS", error["error"])

    def test_locking_fails_closed_when_fcntl_is_unavailable(self) -> None:
        with (
            mock.patch.object(recovery, "fcntl", None),
            self.assertRaisesRegex(OutputError, "locking is unavailable"),
        ):
            recovery._lock_directory(-1, "Recovery output")
