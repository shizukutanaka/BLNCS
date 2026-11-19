#!/usr/bin/env python3
"""
Regression tests for running ``python blncs_main.py <subcommand>``.

The README, docker-compose healthcheck and systemd unit invoke the
subcommand CLI (``status``, ``info``, ``server`` ...), but the script
exited through an earlier ``--mode``-only parser, and the subcommand
parser itself crashed (duplicate aliases, undefined globals/helpers).
"""

import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "blncs_main.py"


def run_cli(cwd, *argv):
    env = dict(os.environ)
    env.pop("BLNCS_CLI_TOKEN", None)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *argv],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


class TestSubcommandEntryPoint(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_status_in_fresh_directory_creates_config_and_succeeds(self):
        result = run_cli(self.cwd, "status")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("API Port: 3000", result.stdout)
        config = json.loads(
            (self.cwd / "config" / "blncs.json").read_text(encoding="utf-8")
        )
        self.assertEqual(config["api"]["host"], "127.0.0.1")
        self.assertNotIn("jwt_secret", json.dumps(config))

    def test_help_lists_subcommands(self):
        result = run_cli(self.cwd, "--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        for command in (
            "status",
            "config",
            "backup",
            "invoice",
            "connect",
            "maintenance",
        ):
            self.assertIn(command, result.stdout)

    def test_short_aliases_reach_documented_commands(self):
        info = run_cli(self.cwd, "i")
        self.assertEqual(info.returncode, 0, info.stdout + info.stderr)
        self.assertIn("Using alias: info", info.stdout)

        config = run_cli(self.cwd, "c", "--get", "api.port")
        self.assertEqual(config.returncode, 0, config.stdout + config.stderr)
        self.assertIn("api.port = 3000", config.stdout)

    def test_read_only_backup_list_needs_no_token(self):
        result = run_cli(self.cwd, "backup", "--list")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Authentication token required", result.stdout)

    def test_privileged_command_still_requires_token(self):
        result = run_cli(self.cwd, "config", "--template")

        self.assertEqual(result.returncode, 1)
        self.assertIn("Authentication token required", result.stdout)
        self.assertFalse((self.cwd / "config" / "template.json").exists())


class TestAppModeRouting(unittest.TestCase):
    def setUp(self):
        self.blncs_main = importlib.import_module("blncs_main")

    def test_mode_and_interactive_flags_route_to_app(self):
        for argv in (
            ["--mode", "server"],
            ["-m", "status"],
            ["--mode=status"],
            ["--config", "x.json", "--mode", "server"],
            ["-i"],
        ):
            self.assertTrue(self.blncs_main._uses_app_mode(argv), argv)

    def test_subcommands_route_to_cli(self):
        for argv in (
            [],
            ["status"],
            ["server", "--config", "x.json"],
            ["backup", "--list"],
            ["--help"],
        ):
            self.assertFalse(self.blncs_main._uses_app_mode(argv), argv)


if __name__ == "__main__":
    unittest.main()
