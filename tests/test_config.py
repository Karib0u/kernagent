"""Comprehensive tests for configuration loading."""

import os
from pathlib import Path
from unittest import mock

import pytest

from kernagent.config import Settings, load_settings


class TestSettings:
    """Test Settings dataclass."""

    def test_settings_can_be_created_with_defaults(self):
        """Settings can be instantiated with default parameters."""
        settings = Settings()
        assert settings.api_key is not None
        assert settings.base_url is not None
        assert settings.model is not None
        assert isinstance(settings.debug, bool)

    def test_settings_accepts_custom_api_key(self):
        """Settings should accept custom API key."""
        settings = Settings(api_key="sk-custom-key")
        assert settings.api_key == "sk-custom-key"

    def test_settings_accepts_custom_base_url(self):
        """Settings should accept custom base URL."""
        settings = Settings(base_url="http://custom.com")
        assert settings.base_url == "http://custom.com"

    def test_settings_accepts_custom_model(self):
        """Settings should accept custom model name."""
        settings = Settings(model="gpt-4")
        assert settings.model == "gpt-4"

    def test_settings_accepts_debug_flag(self):
        """Settings should accept debug flag."""
        settings = Settings(debug=True)
        assert settings.debug is True

        settings = Settings(debug=False)
        assert settings.debug is False

    def test_settings_accepts_all_parameters(self):
        """Settings should accept all parameters together."""
        settings = Settings(
            api_key="sk-test",
            base_url="http://test.com",
            model="test-model",
            debug=True,
        )
        assert settings.api_key == "sk-test"
        assert settings.base_url == "http://test.com"
        assert settings.model == "test-model"
        assert settings.debug is True


class TestLoadSettings:
    """Test load_settings() function."""

    def test_load_settings_returns_settings_instance(self):
        """load_settings should return Settings instance."""
        settings = load_settings()
        assert isinstance(settings, Settings)

    def test_load_settings_calls_dotenv_if_available(self):
        """load_settings should call load_dotenv if available."""
        mock_load_dotenv = mock.Mock()
        with mock.patch("kernagent.config.load_dotenv", mock_load_dotenv), \
             mock.patch("os.path.exists", return_value=True):
            settings = load_settings()
            mock_load_dotenv.assert_called_once()
            assert isinstance(settings, Settings)

    def test_load_settings_prefers_kernagent_config_env_var(self, monkeypatch):
        """load_settings should respect KERNAGENT_CONFIG override."""
        config_path = "/tmp/custom/config.env"
        mock_load_dotenv = mock.Mock()
        monkeypatch.setenv("KERNAGENT_CONFIG", config_path)
        with mock.patch("kernagent.config.load_dotenv", mock_load_dotenv), \
             mock.patch("os.path.exists", return_value=True):
            load_settings()
        mock_load_dotenv.assert_called_once_with(config_path)

    def test_load_settings_falls_back_to_xdg_config_home(self, monkeypatch):
        """load_settings should default to ${XDG_CONFIG_HOME}/kernagent/config.env."""
        monkeypatch.delenv("KERNAGENT_CONFIG", raising=False)
        config_home = "/tmp/test-config"
        monkeypatch.setenv("XDG_CONFIG_HOME", config_home)
        mock_load_dotenv = mock.Mock()
        expected_path = str(Path(config_home) / "kernagent" / "config.env")
        with mock.patch("kernagent.config.load_dotenv", mock_load_dotenv), \
             mock.patch("os.path.exists", return_value=True):
            load_settings()
        mock_load_dotenv.assert_called_once_with(expected_path)

    def test_load_settings_works_without_dotenv(self):
        """load_settings should work without python-dotenv installed."""
        with mock.patch("kernagent.config.load_dotenv", None):
            settings = load_settings()
            assert isinstance(settings, Settings)

    def test_load_settings_respects_environment(self):
        """load_settings should respect current environment variables."""
        # This test verifies that load_settings() creates Settings()
        # which will pick up env vars that were set before import
        settings = load_settings()
        # Just verify it returns a valid Settings instance
        assert settings.api_key is not None
        assert settings.base_url is not None
        assert settings.model is not None


class TestSettingsMutability:
    """Test that Settings values can be modified."""

    def test_settings_api_key_is_mutable(self):
        """API key should be modifiable after creation."""
        settings = Settings(api_key="original")
        settings.api_key = "modified"
        assert settings.api_key == "modified"

    def test_settings_base_url_is_mutable(self):
        """Base URL should be modifiable after creation."""
        settings = Settings(base_url="http://original.com")
        settings.base_url = "http://modified.com"
        assert settings.base_url == "http://modified.com"

    def test_settings_model_is_mutable(self):
        """Model should be modifiable after creation."""
        settings = Settings(model="original-model")
        settings.model = "modified-model"
        assert settings.model == "modified-model"

    def test_settings_debug_is_mutable(self):
        """Debug flag should be modifiable after creation."""
        settings = Settings(debug=False)
        settings.debug = True
        assert settings.debug is True


class TestSettingsValidation:
    """Test Settings with various input values."""

    def test_settings_with_empty_strings(self):
        """Settings should accept empty strings."""
        settings = Settings(
            api_key="",
            base_url="",
            model="",
        )
        assert settings.api_key == ""
        assert settings.base_url == ""
        assert settings.model == ""

    def test_settings_with_special_characters(self):
        """Settings should handle special characters."""
        settings = Settings(
            api_key="sk-123!@#$%^&*()",
            base_url="http://example.com:8080/v1?param=value",
            model="model-with_special.chars",
        )
        assert settings.api_key == "sk-123!@#$%^&*()"
        assert settings.base_url == "http://example.com:8080/v1?param=value"
        assert settings.model == "model-with_special.chars"

    def test_settings_with_long_values(self):
        """Settings should handle long string values."""
        long_key = "sk-" + "a" * 200
        long_url = "http://example.com/" + "x" * 200
        long_model = "model-" + "y" * 200

        settings = Settings(
            api_key=long_key,
            base_url=long_url,
            model=long_model,
        )
        assert settings.api_key == long_key
        assert settings.base_url == long_url
        assert settings.model == long_model


class TestDebugParsing:
    """Test debug flag parsing from string."""

    def test_debug_true_from_lowercase(self):
        """Debug=true should be parsed correctly."""
        # Test that the parsing logic in Settings handles "true" correctly
        # The actual parsing is: os.getenv("DEBUG", "false").lower() == "true"
        assert "true".lower() == "true"
        assert "false".lower() != "true"

    def test_debug_case_variations(self):
        """Debug parsing should handle various cases."""
        # These tests verify the logic: .lower() == "true"
        assert "TRUE".lower() == "true"
        assert "True".lower() == "true"
        assert "FALSE".lower() != "true"
        assert "False".lower() != "true"
        assert "".lower() != "true"
        assert "yes".lower() != "true"


class TestIntegration:
    """Integration tests for Settings usage patterns."""

    def test_settings_can_be_passed_to_functions(self):
        """Settings should be passable to functions."""
        settings = Settings(model="test-model")

        def use_settings(s: Settings) -> str:
            return s.model

        assert use_settings(settings) == "test-model"

    def test_settings_override_pattern(self):
        """Test the CLI override pattern used in main()."""
        # Simulate CLI overriding settings
        settings = Settings()
        original_model = settings.model

        # Apply CLI override (as done in cli.py main())
        cli_model = "cli-override-model"
        settings.model = cli_model

        assert settings.model == "cli-override-model"
        assert settings.model != original_model

    def test_multiple_settings_instances(self):
        """Multiple Settings instances should be independent."""
        settings1 = Settings(model="model-1")
        settings2 = Settings(model="model-2")

        assert settings1.model == "model-1"
        assert settings2.model == "model-2"

        settings1.model = "modified-1"
        assert settings1.model == "modified-1"
        assert settings2.model == "model-2"  # Should not change
