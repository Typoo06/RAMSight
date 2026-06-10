# OS-aware Volatility plugin registry.

from dataclasses import dataclass


@dataclass(frozen=True)
class PluginDefinition:
    name: str
    command_name: str
    os_family: str
    implemented: bool = True
    optional: bool = False
    requires_yara_rules: bool = False


PLUGIN_REGISTRY = {
    "windows.pslist": PluginDefinition("windows.pslist", "windows.pslist.PsList", "windows"),
    "windows.psscan": PluginDefinition("windows.psscan", "windows.psscan.PsScan", "windows"),
    "windows.pstree": PluginDefinition("windows.pstree", "windows.pstree.PsTree", "windows"),
    "windows.cmdline": PluginDefinition("windows.cmdline", "windows.cmdline.CmdLine", "windows"),
    "windows.netscan": PluginDefinition("windows.netscan", "windows.netscan.NetScan", "windows"),
    "windows.dlllist": PluginDefinition("windows.dlllist", "windows.dlllist.DllList", "windows"),
    "windows.handles": PluginDefinition("windows.handles", "windows.handles.Handles", "windows"),
    "windows.malfind": PluginDefinition("windows.malfind", "windows.malfind.Malfind", "windows"),
    "windows.vadyarascan": PluginDefinition(
        "windows.vadyarascan",
        "windows.vadyarascan.VadYaraScan",
        "windows",
        optional=True,
        requires_yara_rules=True,
    ),
    "yarascan": PluginDefinition(
        "yarascan",
        "yarascan.YaraScan",
        "all",
        optional=True,
        requires_yara_rules=True,
    ),
    "linux.pslist": PluginDefinition("linux.pslist", "linux.pslist.PsList", "linux", implemented=False),
    "linux.bash": PluginDefinition("linux.bash", "linux.bash.Bash", "linux", implemented=False),
    "linux.lsmod": PluginDefinition("linux.lsmod", "linux.lsmod.Lsmod", "linux", implemented=False),
    "linux.lsof": PluginDefinition("linux.lsof", "linux.lsof.Lsof", "linux", implemented=False),
    "linux.elfs": PluginDefinition("linux.elfs", "linux.elfs.Elfs", "linux", implemented=False),
    "linux.check_creds": PluginDefinition(
        "linux.check_creds", "linux.check_creds.Check_creds", "linux", implemented=False
    ),
    "linux.check_syscall": PluginDefinition(
        "linux.check_syscall", "linux.check_syscall.Check_syscall", "linux", implemented=False
    ),
    "linux.check_modules": PluginDefinition(
        "linux.check_modules", "linux.check_modules.Check_modules", "linux", implemented=False
    ),
    "linux.hidden_modules": PluginDefinition(
        "linux.hidden_modules", "linux.hidden_modules.Hidden_modules", "linux", implemented=False
    ),
    "linux.vmayarascan": PluginDefinition(
        "linux.vmayarascan",
        "linux.vmayarascan.VmaYaraScan",
        "linux",
        implemented=False,
        optional=True,
        requires_yara_rules=True,
    ),
}

PLUGIN_PROFILES = {
    "windows_default": [
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.cmdline",
        "windows.netscan",
        "windows.dlllist",
        "windows.handles",
        "windows.malfind",
    ],
    "windows_memory_yara": [
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.cmdline",
        "windows.netscan",
        "windows.dlllist",
        "windows.handles",
        "windows.malfind",
        "windows.vadyarascan",
    ],
    "windows_memory_yara_elastic": [
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.cmdline",
        "windows.netscan",
        "windows.dlllist",
        "windows.handles",
        "windows.malfind",
        "windows.vadyarascan",
    ],
    "windows_memory_yara_neo23x0": [
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.cmdline",
        "windows.netscan",
        "windows.dlllist",
        "windows.handles",
        "windows.malfind",
        "windows.vadyarascan",
    ],
    "windows_memory_yara_third_party_all": [
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.cmdline",
        "windows.netscan",
        "windows.dlllist",
        "windows.handles",
        "windows.malfind",
        "windows.vadyarascan",
    ],
    "linux_default": [
        "linux.pslist",
        "linux.bash",
        "linux.lsmod",
        "linux.lsof",
        "linux.elfs",
        "linux.check_creds",
        "linux.check_syscall",
        "linux.check_modules",
        "linux.hidden_modules",
        "linux.vmayarascan",
    ],
}

DEFAULT_PROFILE_BY_OS = {
    "windows": "windows_default",
    "linux": "linux_default",
}


class PluginSelectionError(ValueError):
    pass


def get_plugin_definition(plugin_name: str) -> PluginDefinition:
    try:
        return PLUGIN_REGISTRY[plugin_name]
    except KeyError as exc:
        raise PluginSelectionError(f"unknown Volatility plugin: {plugin_name}") from exc


def select_plugins(
    os_family: str | None,
    plugin_profile: str | None = None,
    requested_plugins: list[str] | None = None,
) -> list[PluginDefinition]:
    if requested_plugins:
        return [get_plugin_definition(plugin_name) for plugin_name in requested_plugins]

    profile_name = plugin_profile or DEFAULT_PROFILE_BY_OS.get(os_family or "unknown")
    if profile_name is None:
        raise PluginSelectionError("unknown OS family has no default Volatility plugin profile")
    if profile_name not in PLUGIN_PROFILES:
        raise PluginSelectionError(f"unknown Volatility plugin profile: {profile_name}")
    return [get_plugin_definition(plugin_name) for plugin_name in PLUGIN_PROFILES[profile_name]]
