# Volatility plugin registry tests.

import pytest

from app.volatility.registry import PluginSelectionError, select_plugins


def test_windows_default_profile_excludes_optional_yarascan() -> None:
    plugins = select_plugins("windows", plugin_profile=None, requested_plugins=None)
    plugin_names = [plugin.name for plugin in plugins]

    assert "windows.pslist" in plugin_names
    assert "windows.malfind" in plugin_names
    assert "yarascan" not in plugin_names


def test_requested_yarascan_is_available_as_optional_plugin() -> None:
    plugins = select_plugins("windows", requested_plugins=["yarascan"])

    assert plugins[0].name == "yarascan"
    assert plugins[0].requires_yara_rules is True
    assert plugins[0].optional is True


def test_unknown_os_without_requested_plugins_fails_cleanly() -> None:
    with pytest.raises(PluginSelectionError, match="unknown OS family"):
        select_plugins("unknown", plugin_profile=None, requested_plugins=None)


def test_linux_profile_is_registered_as_placeholder() -> None:
    plugins = select_plugins("linux", plugin_profile=None, requested_plugins=None)

    assert plugins[0].name == "linux.pslist"
    assert all(plugin.implemented is False for plugin in plugins)

