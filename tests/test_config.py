"""Tests for root3st.config module."""

from pathlib import Path

from root3st.config import COMMON_PORTS, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, Config


class TestConfigDefaults:
    def test_default_values(self):
        cfg = Config()
        assert cfg.timeout == DEFAULT_TIMEOUT
        assert cfg.user_agent == DEFAULT_USER_AGENT
        assert cfg.shodan_api_key == ""
        assert cfg.ports == COMMON_PORTS
        assert cfg.max_concurrent == 20

    def test_load_returns_config(self):
        # Load with a non-existent path should return defaults
        cfg = Config.load(Path("/tmp/nonexistent_root3st_config.yaml"))
        assert isinstance(cfg, Config)
        assert cfg.timeout == DEFAULT_TIMEOUT

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "test-key-123")
        cfg = Config.load(Path("/tmp/nonexistent_root3st_config.yaml"))
        assert cfg.shodan_api_key == "test-key-123"
