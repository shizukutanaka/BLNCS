"""
Tests for CLI commands
"""

import pytest
from click.testing import CliRunner
from blrcs.cli.main import cli


def test_cli_help():
    """Test CLI help command"""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "BLRCS Lightning CLI" in result.output


def test_start_command():
    """Test start command"""
    runner = CliRunner()
    result = runner.invoke(cli, ["start", "--dry-run"])
    assert result.exit_code == 0
    assert "Starting" in result.output or "Would start" in result.output


def test_status_command():
    """Test status command"""
    runner = CliRunner()
    result = runner.invoke(cli, ["status"])
    assert result.exit_code == 0
    assert "Status" in result.output or "disconnected" in result.output.lower()


def test_channels_command():
    """Test channels command"""
    runner = CliRunner()
    result = runner.invoke(cli, ["channels"])
    assert result.exit_code == 0


def test_rebalance_command():
    """Test rebalance command"""
    runner = CliRunner()
    result = runner.invoke(cli, ["rebalance", "--dry-run"])
    assert result.exit_code == 0


def test_config_command():
    """Test config command"""
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "--show"])
    assert result.exit_code == 0
    assert "Configuration" in result.output or "Config" in result.output