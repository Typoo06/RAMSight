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
    category: str = "Core triage"
    timeout_policy: str = "standard"
    parser_strategy: str = "none"
    available: bool = True
    product_purpose: str = "Volatility memory analysis plugin"


def plugin(
    name: str,
    command_name: str,
    os_family: str = "windows",
    *,
    category: str = "Core triage",
    timeout_policy: str = "standard",
    parser_strategy: str = "none",
    product_purpose: str = "Volatility memory analysis plugin",
    implemented: bool = True,
    optional: bool = False,
    requires_yara_rules: bool = False,
    available: bool = True,
) -> PluginDefinition:
    return PluginDefinition(
        name=name,
        command_name=command_name,
        os_family=os_family,
        implemented=implemented,
        optional=optional,
        requires_yara_rules=requires_yara_rules,
        category=category,
        timeout_policy=timeout_policy,
        parser_strategy=parser_strategy,
        available=available,
        product_purpose=product_purpose,
    )


PLUGIN_REGISTRY = {
    "windows.pslist": plugin("windows.pslist", "windows.pslist.PsList", parser_strategy="process_artifacts", product_purpose="Enumerate active processes."),
    "windows.psscan": plugin("windows.psscan", "windows.psscan.PsScan", parser_strategy="process_artifacts", product_purpose="Scan for process objects and hidden-process candidates."),
    "windows.pstree": plugin("windows.pstree", "windows.pstree.PsTree", parser_strategy="process_artifacts", product_purpose="Show parent-child process relationships."),
    "windows.cmdline": plugin("windows.cmdline", "windows.cmdline.CmdLine", category="Core triage", parser_strategy="command_artifacts", product_purpose="Recover command-line context."),
    "windows.netscan": plugin("windows.netscan", "windows.netscan.NetScan", category="Network", parser_strategy="network_artifacts", product_purpose="Identify network endpoints and process ownership."),
    "windows.dlllist": plugin("windows.dlllist", "windows.dlllist.DllList", category="Module/DLL", parser_strategy="module_artifacts", product_purpose="List loaded user-mode modules."),
    "windows.handles": plugin("windows.handles", "windows.handles.Handles", parser_strategy="no_artifacts", product_purpose="Collect handle context without creating first-class artifacts."),
    "windows.malfind": plugin("windows.malfind", "windows.malware.malfind.Malfind", category="Injection/Hollowing", parser_strategy="memory_region_artifacts", product_purpose="Identify executable/private memory regions compatible with injection."),
    "windows.vadinfo": plugin("windows.vadinfo", "windows.vadinfo.VadInfo", category="Memory/VAD", parser_strategy="memory_region_artifacts", timeout_policy="deep", product_purpose="Enumerate VAD ranges for memory-only payload context."),
    "windows.vadwalk": plugin("windows.vadwalk", "windows.vadwalk.VadWalk", category="Memory/VAD", parser_strategy="memory_region_artifacts", timeout_policy="deep", product_purpose="Walk VAD trees for suspicious memory ranges."),
    "windows.ldrmodules": plugin("windows.ldrmodules", "windows.malware.ldrmodules.LdrModules", category="Module/DLL", parser_strategy="module_artifacts", product_purpose="Detect unlinked or inconsistent process modules."),
    "windows.hollowprocesses": plugin("windows.hollowprocesses", "windows.malware.hollowprocesses.HollowProcesses", category="Injection/Hollowing", parser_strategy="process_artifacts", product_purpose="Find process hollowing candidates."),
    "windows.psxview": plugin("windows.psxview", "windows.malware.psxview.PsXView", category="Core triage", parser_strategy="process_artifacts", product_purpose="Cross-view process comparison for hidden process candidates."),
    "windows.suspicious_threads": plugin("windows.suspicious_threads", "windows.malware.suspicious_threads.SuspiciousThreads", category="Thread analysis", parser_strategy="none", product_purpose="Identify suspicious userland threads."),
    "windows.suspended_threads": plugin("windows.suspended_threads", "windows.suspended_threads.SuspendedThreads", category="Thread analysis", parser_strategy="none", product_purpose="Enumerate suspended threads for injection/hollowing context."),
    "windows.threads": plugin("windows.threads", "windows.threads.Threads", category="Thread analysis", parser_strategy="none", product_purpose="List process threads for correlation."),
    "windows.thrdscan": plugin("windows.thrdscan", "windows.thrdscan.ThrdScan", category="Thread analysis", parser_strategy="none", product_purpose="Scan for thread objects that may not be linked normally."),
    "windows.pebmasquerade": plugin("windows.pebmasquerade", "windows.malware.pebmasquerade.PebMasquerade", category="Injection/Hollowing", parser_strategy="process_artifacts", product_purpose="Detect PEB/process identity masquerade candidates."),
    "windows.processghosting": plugin("windows.processghosting", "windows.malware.processghosting.ProcessGhosting", category="Injection/Hollowing", parser_strategy="process_artifacts", product_purpose="Detect process ghosting candidates."),
    "windows.direct_system_calls": plugin("windows.direct_system_calls", "windows.malware.direct_system_calls.DirectSystemCalls", category="Evasion/Hooking", parser_strategy="none", product_purpose="Detect direct syscall evasion indicators."),
    "windows.indirect_system_calls": plugin("windows.indirect_system_calls", "windows.malware.indirect_system_calls.IndirectSystemCalls", category="Evasion/Hooking", parser_strategy="none", product_purpose="Detect indirect syscall evasion indicators."),
    "windows.unhooked_system_calls": plugin("windows.unhooked_system_calls", "windows.malware.unhooked_system_calls.UnhookedSystemCalls", category="Evasion/Hooking", parser_strategy="none", product_purpose="Detect unhooked or hooked syscall stub indicators."),
    "windows.iat": plugin("windows.iat", "windows.iat.IAT", category="Evasion/Hooking", parser_strategy="none", timeout_policy="deep", product_purpose="Inspect import tables for suspicious API usage context."),
    "windows.etwpatch": plugin("windows.etwpatch", "windows.etwpatch.EtwPatch", category="Evasion/Hooking", parser_strategy="none", product_purpose="Detect ETW patching evasion indicators."),
    "windows.callbacks": plugin("windows.callbacks", "windows.callbacks.Callbacks", category="Kernel/Rootkit", parser_strategy="none", product_purpose="List kernel callbacks for rootkit/evasion context."),
    "windows.ssdt": plugin("windows.ssdt", "windows.ssdt.SSDT", category="Kernel/Rootkit", parser_strategy="none", product_purpose="Inspect system service descriptor table entries."),
    "windows.modules": plugin("windows.modules", "windows.modules.Modules", category="Kernel/Rootkit", parser_strategy="module_artifacts", product_purpose="List loaded kernel modules."),
    "windows.modscan": plugin("windows.modscan", "windows.modscan.ModScan", category="Kernel/Rootkit", parser_strategy="module_artifacts", product_purpose="Scan for kernel module objects."),
    "windows.driverscan": plugin("windows.driverscan", "windows.driverscan.DriverScan", category="Kernel/Rootkit", parser_strategy="module_artifacts", product_purpose="Scan for driver objects."),
    "windows.drivermodule": plugin("windows.drivermodule", "windows.malware.drivermodule.DriverModule", category="Kernel/Rootkit", parser_strategy="none", product_purpose="Compare drivers/modules for hidden rootkit candidates."),
    "windows.driverirp": plugin("windows.driverirp", "windows.driverirp.DriverIrp", category="Kernel/Rootkit", parser_strategy="none", product_purpose="Inspect driver IRP hooks."),
    "windows.unloadedmodules": plugin("windows.unloadedmodules", "windows.unloadedmodules.UnloadedModules", category="Kernel/Rootkit", parser_strategy="module_artifacts", product_purpose="List recently unloaded kernel modules."),
    "windows.orphan_kernel_threads": plugin("windows.orphan_kernel_threads", "windows.orphan_kernel_threads.Threads", category="Kernel/Rootkit", parser_strategy="none", product_purpose="Find kernel threads without expected ownership context."),
    "windows.timers": plugin("windows.timers", "windows.timers.Timers", category="Kernel/Rootkit", parser_strategy="none", product_purpose="Inspect kernel timers and DPC module context."),
    "windows.envars": plugin("windows.envars", "windows.envars.Envars", category="Persistence/Context", parser_strategy="none", product_purpose="Collect process environment context."),
    "windows.getsids": plugin("windows.getsids", "windows.getsids.GetSIDs", category="Persistence/Context", parser_strategy="none", product_purpose="Collect process token SID context."),
    "windows.privileges": plugin("windows.privileges", "windows.privileges.Privs", category="Persistence/Context", parser_strategy="none", product_purpose="Collect process privilege context."),
    "windows.sessions": plugin("windows.sessions", "windows.sessions.Sessions", category="Persistence/Context", parser_strategy="none", product_purpose="Collect session context."),
    "windows.svcscan": plugin("windows.svcscan", "windows.svcscan.SvcScan", category="Persistence/Context", parser_strategy="none", product_purpose="Scan for service records."),
    "windows.svclist": plugin("windows.svclist", "windows.svclist.SvcList", category="Persistence/Context", parser_strategy="none", product_purpose="List services from linked structures."),
    "windows.svcdiff": plugin("windows.svcdiff", "windows.malware.svcdiff.SvcDiff", category="Persistence/Context", parser_strategy="none", product_purpose="Compare service walking/scanning for rootkit service context."),
    "windows.scheduled_tasks": plugin("windows.scheduled_tasks", "windows.registry.scheduled_tasks.ScheduledTasks", category="Persistence/Context", parser_strategy="none", product_purpose="Decode scheduled task registry context."),
    "windows.mutantscan": plugin("windows.mutantscan", "windows.mutantscan.MutantScan", category="Persistence/Context", parser_strategy="none", product_purpose="Scan mutex objects for investigation context."),
    "windows.symlinkscan": plugin("windows.symlinkscan", "windows.symlinkscan.SymlinkScan", category="Persistence/Context", parser_strategy="none", product_purpose="Scan symbolic links for investigation context."),
    "windows.amcache": plugin("windows.amcache", "windows.registry.amcache.Amcache", category="Persistence/Context", parser_strategy="none", product_purpose="Extract AmCache execution context."),
    "windows.shimcachemem": plugin("windows.shimcachemem", "windows.shimcachemem.ShimcacheMem", category="Persistence/Context", parser_strategy="none", product_purpose="Read Shimcache memory context."),
    "windows.mftscan": plugin("windows.mftscan", "windows.mftscan.MFTScan", category="Persistence/Context", parser_strategy="none", product_purpose="Scan MFT records for file-system investigation context."),
    "windows.cmdscan": plugin("windows.cmdscan", "windows.cmdscan.CmdScan", category="Persistence/Context", parser_strategy="command_artifacts", product_purpose="Recover console command history."),
    "windows.consoles": plugin("windows.consoles", "windows.consoles.Consoles", category="Persistence/Context", parser_strategy="command_artifacts", product_purpose="Recover console buffers."),
    "windows.vadyarascan": PluginDefinition(
        "windows.vadyarascan",
        "windows.vadyarascan.VadYaraScan",
        "windows",
        optional=True,
        requires_yara_rules=True,
        category="YARA",
        timeout_policy="yara",
        parser_strategy="yara_matches",
        product_purpose="Scan process memory VADs with the selected YARA pack.",
    ),
    "yarascan": PluginDefinition(
        "yarascan",
        "yarascan.YaraScan",
        "all",
        optional=True,
        requires_yara_rules=True,
        category="YARA",
        timeout_policy="yara",
        parser_strategy="yara_matches",
        product_purpose="Scan kernel memory with the selected YARA pack.",
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

WINDOWS_BASELINE_PLUGINS = [
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.dlllist",
    "windows.handles",
    "windows.malfind",
]
WINDOWS_DEEP_MEMORY_PLUGINS = [
    "windows.vadinfo",
    "windows.vadwalk",
    "windows.ldrmodules",
    "windows.hollowprocesses",
    "windows.psxview",
    "windows.suspicious_threads",
    "windows.suspended_threads",
    "windows.threads",
    "windows.thrdscan",
    "windows.pebmasquerade",
    "windows.processghosting",
]
WINDOWS_MALWARE_EVASION_PLUGINS = [
    "windows.direct_system_calls",
    "windows.indirect_system_calls",
    "windows.unhooked_system_calls",
    "windows.iat",
    "windows.etwpatch",
    "windows.callbacks",
    "windows.ssdt",
]
WINDOWS_KERNEL_ROOTKIT_PLUGINS = [
    "windows.modules",
    "windows.modscan",
    "windows.driverscan",
    "windows.drivermodule",
    "windows.driverirp",
    "windows.unloadedmodules",
    "windows.orphan_kernel_threads",
    "windows.timers",
]
WINDOWS_INVESTIGATION_CONTEXT_PLUGINS = [
    "windows.envars",
    "windows.getsids",
    "windows.privileges",
    "windows.sessions",
    "windows.svcscan",
    "windows.svclist",
    "windows.svcdiff",
    "windows.scheduled_tasks",
    "windows.mutantscan",
    "windows.symlinkscan",
    "windows.amcache",
    "windows.shimcachemem",
    "windows.mftscan",
    "windows.cmdscan",
    "windows.consoles",
]


def with_yara(plugin_names: list[str]) -> list[str]:
    return [*plugin_names, "windows.vadyarascan"]


PLUGIN_PROFILES = {
    "windows_default": WINDOWS_BASELINE_PLUGINS,
    "windows_memory_yara": with_yara(WINDOWS_BASELINE_PLUGINS),
    "windows_memory_yara_elastic": with_yara(WINDOWS_BASELINE_PLUGINS),
    "windows_memory_yara_neo23x0": with_yara(WINDOWS_BASELINE_PLUGINS),
    "windows_memory_yara_third_party_all": with_yara(WINDOWS_BASELINE_PLUGINS),
    "windows_memory_deep": [*WINDOWS_BASELINE_PLUGINS, *WINDOWS_DEEP_MEMORY_PLUGINS],
    "windows_memory_deep_yara_elastic": with_yara([*WINDOWS_BASELINE_PLUGINS, *WINDOWS_DEEP_MEMORY_PLUGINS]),
    "windows_memory_deep_yara_neo23x0": with_yara([*WINDOWS_BASELINE_PLUGINS, *WINDOWS_DEEP_MEMORY_PLUGINS]),
    "windows_memory_deep_yara_third_party_all": with_yara([*WINDOWS_BASELINE_PLUGINS, *WINDOWS_DEEP_MEMORY_PLUGINS]),
    "windows_malware_evasion": [*WINDOWS_BASELINE_PLUGINS, *WINDOWS_MALWARE_EVASION_PLUGINS],
    "windows_kernel_rootkit": [*WINDOWS_BASELINE_PLUGINS, *WINDOWS_KERNEL_ROOTKIT_PLUGINS],
    "windows_investigation_context": [*WINDOWS_BASELINE_PLUGINS, *WINDOWS_INVESTIGATION_CONTEXT_PLUGINS],
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
