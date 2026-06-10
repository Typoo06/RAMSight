# Volatility plugin registry tests.

import pytest

from app.volatility.registry import PluginSelectionError, get_plugin_definition, select_plugins


WINDOWS_CLI_PLUGIN_NAMES = {
    "windows.pslist": "windows.pslist.PsList",
    "windows.psscan": "windows.psscan.PsScan",
    "windows.pstree": "windows.pstree.PsTree",
    "windows.cmdline": "windows.cmdline.CmdLine",
    "windows.netscan": "windows.netscan.NetScan",
    "windows.dlllist": "windows.dlllist.DllList",
    "windows.handles": "windows.handles.Handles",
    "windows.malfind": "windows.malware.malfind.Malfind",
    "windows.vadyarascan": "windows.vadyarascan.VadYaraScan",
}


def test_windows_default_profile_excludes_optional_yarascan() -> None:
    plugins = select_plugins("windows", plugin_profile=None, requested_plugins=None)
    plugin_names = [plugin.name for plugin in plugins]

    assert "windows.pslist" in plugin_names
    assert "windows.malfind" in plugin_names
    assert "yarascan" not in plugin_names
    assert "windows.vadyarascan" not in plugin_names


def test_windows_plugins_keep_logical_and_cli_names_separate() -> None:
    for logical_name, cli_name in WINDOWS_CLI_PLUGIN_NAMES.items():
        plugin = get_plugin_definition(logical_name)

        assert plugin.name == logical_name
        assert plugin.command_name == cli_name


def test_requested_yarascan_is_available_as_optional_plugin() -> None:
    plugins = select_plugins("windows", requested_plugins=["yarascan"])

    assert plugins[0].name == "yarascan"
    assert plugins[0].requires_yara_rules is True
    assert plugins[0].optional is True


def test_requested_windows_vadyarascan_is_available() -> None:
    plugins = select_plugins("windows", requested_plugins=["windows.vadyarascan"])

    assert plugins[0].name == "windows.vadyarascan"
    assert plugins[0].command_name == "windows.vadyarascan.VadYaraScan"


def test_windows_vadyarascan_is_registered_as_optional_process_memory_yara() -> None:
    plugin = get_plugin_definition("windows.vadyarascan")

    assert plugin.name == "windows.vadyarascan"
    assert plugin.command_name == "windows.vadyarascan.VadYaraScan"
    assert plugin.requires_yara_rules is True
    assert plugin.optional is True


def test_explicit_windows_memory_yara_profile_includes_vadyarascan() -> None:
    plugins = select_plugins("windows", plugin_profile="windows_memory_yara", requested_plugins=None)
    plugin_names = [plugin.name for plugin in plugins]

    assert "windows.vadyarascan" in plugin_names
    assert "windows.malfind" in plugin_names


def test_third_party_yara_profiles_include_vadyarascan() -> None:
    for profile in [
        "windows_memory_yara_elastic",
        "windows_memory_yara_neo23x0",
        "windows_memory_yara_third_party_all",
    ]:
        plugin_names = [plugin.name for plugin in select_plugins("windows", plugin_profile=profile, requested_plugins=None)]

        assert "windows.vadyarascan" in plugin_names
        assert "windows.pslist" in plugin_names


def test_deep_windows_profiles_add_memory_malware_plugins() -> None:
    plugin_names = [plugin.name for plugin in select_plugins("windows", plugin_profile="windows_memory_deep", requested_plugins=None)]

    assert "windows.vadinfo" in plugin_names
    assert "windows.hollowprocesses" in plugin_names
    assert "windows.processghosting" in plugin_names
    assert "windows.vadyarascan" not in plugin_names


def test_deep_third_party_yara_profile_is_deep_and_yara_enabled() -> None:
    plugin_names = [
        plugin.name
        for plugin in select_plugins("windows", plugin_profile="windows_memory_deep_yara_third_party_all", requested_plugins=None)
    ]

    assert "windows.vadinfo" in plugin_names
    assert "windows.suspicious_threads" in plugin_names
    assert "windows.vadyarascan" in plugin_names


def test_specialized_windows_profiles_cover_evasion_kernel_and_context() -> None:
    evasion = [plugin.name for plugin in select_plugins("windows", plugin_profile="windows_malware_evasion", requested_plugins=None)]
    kernel = [plugin.name for plugin in select_plugins("windows", plugin_profile="windows_kernel_rootkit", requested_plugins=None)]
    context_plugins = [plugin.name for plugin in select_plugins("windows", plugin_profile="windows_investigation_context", requested_plugins=None)]

    assert "windows.etwpatch" in evasion
    assert "windows.unhooked_system_calls" in evasion
    assert "windows.drivermodule" in kernel
    assert "windows.timers" in kernel
    assert "windows.svcscan" in context_plugins
    assert "windows.scheduled_tasks" in context_plugins


def test_plugin_metadata_describes_product_coverage() -> None:
    plugin = get_plugin_definition("windows.etwpatch")

    assert plugin.category == "Evasion/Hooking"
    assert plugin.parser_strategy == "none"
    assert plugin.available is True
    assert "ETW" in plugin.product_purpose


def test_unknown_os_without_requested_plugins_fails_cleanly() -> None:
    with pytest.raises(PluginSelectionError, match="unknown OS family"):
        select_plugins("unknown", plugin_profile=None, requested_plugins=None)


def test_linux_profile_is_registered_as_placeholder() -> None:
    plugins = select_plugins("linux", plugin_profile=None, requested_plugins=None)

    assert plugins[0].name == "linux.pslist"
    assert all(plugin.implemented is False for plugin in plugins)
