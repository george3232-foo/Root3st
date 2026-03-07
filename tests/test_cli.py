"""Tests for root3st.cli module -- smoke tests for CLI commands."""

from click.testing import CliRunner

from root3st.cli import cli


class TestCliSmoke:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "root3st" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "OSINT" in result.output or "osint" in result.output.lower()

    def test_ip_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["ip", "not-an-ip"])
        assert result.exit_code != 0

    def test_domain_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["domain", "not a domain"])
        assert result.exit_code != 0

    def test_email_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["email", "notanemail"])
        assert result.exit_code != 0

    def test_subcommands_exist(self):
        runner = CliRunner()
        for cmd in ["ip", "domain", "email", "username", "phone", "name", "social"]:
            result = runner.invoke(cli, [cmd, "--help"])
            assert result.exit_code == 0, f"{cmd} --help failed"
