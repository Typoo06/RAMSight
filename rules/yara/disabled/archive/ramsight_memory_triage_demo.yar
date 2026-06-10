/*
  RAMSight YARA rules for defensive memory-only malware triage.

  Archived: this file is retained for project history only. It is not included
  in active runtime packs and must not be passed to Volatility/YARA detection
  profiles.

  These rules are intentionally heuristic and lab/demo oriented. They are not
  conclusive malware signatures. A match should be correlated with Volatility
  process, command-line, network, module, and malfind artifacts before making
  an incident conclusion.
*/

rule RAMSight_Memory_PowerShell_EncodedCommand_Context : ramsight memory script powershell demo
{
    meta:
        description = "PowerShell or pwsh encoded-command traces with decoding/execution context in memory"
        author = "RAMSight"
        category = "script_in_memory"
        severity = "medium"
        scope = "memory"
        thesis_topic = "memory-only malware triage"
        false_positive_note = "Administrative scripts and automation can use encoded commands; correlate with parent process, command line, and network activity."
        updated = "2026-06-09"
        confidence = "candidate"
        noisy = false
        requires_correlation = true
        performance = "light"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-encodedcommand" ascii wide nocase
        $enc3 = "/encodedcommand" ascii wide nocase
        $decode1 = "FromBase64String" ascii wide nocase
        $decode2 = "[Convert]::" ascii wide nocase
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX" ascii wide nocase
    condition:
        1 of ($ps*) and 1 of ($enc*) and (1 of ($decode*) or 1 of ($exec*))
}

rule RAMSight_Memory_PowerShell_DownloadCradle_Context : ramsight memory script network demo
{
    meta:
        description = "PowerShell download cradle strings in memory with URL or network transfer context"
        author = "RAMSight"
        category = "script_in_memory"
        severity = "medium"
        scope = "memory"
        thesis_topic = "memory-only malware triage"
        false_positive_note = "Software deployment and admin scripts can download content; validate process ancestry, user context, and destination reputation."
        updated = "2026-06-09"
        confidence = "candidate"
        noisy = false
        requires_correlation = true
        performance = "light"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $download1 = "DownloadString" ascii wide nocase
        $download2 = "DownloadData" ascii wide nocase
        $download3 = "Invoke-WebRequest" ascii wide nocase
        $download4 = "Net.WebClient" ascii wide nocase
        $net1 = "http://" ascii wide nocase
        $net2 = "https://" ascii wide nocase
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX" ascii wide nocase
    condition:
        1 of ($ps*) and 1 of ($download*) and 1 of ($net*) and (1 of ($exec*) or 2 of ($download*))
}

rule RAMSight_Memory_ProcessInjection_API_Cluster : ramsight memory injection api demo
{
    meta:
        description = "Cluster of Windows process-injection related API names visible in memory"
        author = "RAMSight"
        category = "process_injection"
        severity = "high"
        scope = "memory"
        thesis_topic = "memory-only malware triage"
        false_positive_note = "Debuggers, EDR, installers, profilers, and legitimate admin tools can use these APIs; require malfind/process correlation."
        updated = "2026-06-09"
        confidence = "candidate"
        noisy = false
        requires_correlation = true
        performance = "light"
    strings:
        $api1 = "VirtualAllocEx" ascii wide nocase
        $api2 = "WriteProcessMemory" ascii wide nocase
        $api3 = "CreateRemoteThread" ascii wide nocase
        $api4 = "VirtualProtectEx" ascii wide nocase
        $api5 = "NtQueueApcThread" ascii wide nocase
        $api6 = "OpenProcess" ascii wide nocase
        $perm1 = "PAGE_EXECUTE_READWRITE" ascii wide nocase
        $perm2 = "PROCESS_VM_WRITE" ascii wide nocase
    condition:
        3 of ($api*) and (1 of ($perm*) or ($api1 and $api2 and $api3))
}

rule RAMSight_Memory_ReflectiveLoading_ImportCluster : ramsight memory reflective_loader pe demo
{
    meta:
        description = "PE-like memory context with reflective-loading import strings"
        author = "RAMSight"
        category = "reflective_loading"
        severity = "medium"
        scope = "memory"
        thesis_topic = "memory-only malware triage"
        false_positive_note = "Legitimate PE images in process memory can expose import strings; use as context only unless correlated with suspicious VAD/malfind output."
        updated = "2026-06-09"
        confidence = "candidate"
        noisy = true
        requires_correlation = true
        performance = "light"
    strings:
        $mz = { 4D 5A }
        $dos = "This program cannot be run in DOS mode" ascii
        $loader1 = "ReflectiveLoader" ascii wide nocase
        $loader2 = "LoadLibraryA" ascii wide nocase
        $loader3 = "GetProcAddress" ascii wide nocase
        $loader4 = "VirtualProtect" ascii wide nocase
    condition:
        ($mz or $dos) and ($loader1 or (2 of ($loader2, $loader3, $loader4)))
}

rule RAMSight_Memory_CredentialDumping_Context : ramsight memory credential_access demo
{
    meta:
        description = "Credential dumping context strings visible in memory"
        author = "RAMSight"
        category = "credential_access"
        severity = "high"
        scope = "memory"
        thesis_topic = "memory-only malware triage"
        false_positive_note = "Forensic tools, EDR, and admin utilities may contain these strings; validate process name, signer/path, and LSASS access context."
        updated = "2026-06-09"
        confidence = "candidate"
        noisy = false
        requires_correlation = true
        performance = "light"
    strings:
        $target1 = "lsass.exe" ascii wide nocase
        $target2 = "sekurlsa::" ascii wide nocase
        $dump1 = "MiniDumpWriteDump" ascii wide nocase
        $dump2 = "comsvcs.dll" ascii wide nocase
        $cred1 = "logonpasswords" ascii wide nocase
        $cred2 = "wdigest" ascii wide nocase
        $cred3 = "kerberos" ascii wide nocase
    condition:
        (1 of ($target*) and 1 of ($dump*)) or ($target2 and 1 of ($cred*))
}

rule RAMSight_Memory_LivingOffLand_Command_Context : ramsight memory command_line lolbin demo
{
    meta:
        description = "Living-off-the-land command traces with suspicious scriptlet, URL, or DLL execution context"
        author = "RAMSight"
        category = "command_line_trace"
        severity = "medium"
        scope = "memory"
        thesis_topic = "memory-only malware triage"
        false_positive_note = "Enterprise administration can use these binaries; correlate with command-line artifacts, parent process, and network endpoints."
        updated = "2026-06-09"
        confidence = "candidate"
        noisy = false
        requires_correlation = true
        performance = "light"
    strings:
        $lol1 = "rundll32.exe" ascii wide nocase
        $lol2 = "regsvr32.exe" ascii wide nocase
        $lol3 = "mshta.exe" ascii wide nocase
        $lol4 = "wscript.exe" ascii wide nocase
        $ctx1 = "javascript:" ascii wide nocase
        $ctx2 = "scrobj.dll" ascii wide nocase
        $ctx3 = "/i:http" ascii wide nocase
        $ctx4 = "http://" ascii wide nocase
        $ctx5 = "https://" ascii wide nocase
        $ctx6 = ".sct" ascii wide nocase
    condition:
        1 of ($lol*) and 1 of ($ctx*) and (1 of ($ctx1, $ctx2, $ctx3, $ctx6) or 2 of ($ctx*))
}

rule RAMSight_Memory_PackedObfuscated_PE_Context : ramsight memory packed obfuscation demo
{
    meta:
        description = "Packed or obfuscated PE-like strings in memory, intended as low-confidence context"
        author = "RAMSight"
        category = "packed_or_obfuscated_memory"
        severity = "low"
        scope = "memory"
        thesis_topic = "memory-only malware triage"
        false_positive_note = "Legitimate packed software and installers can match; treat as context and require additional suspicious artifacts."
        updated = "2026-06-09"
        confidence = "candidate"
        noisy = true
        requires_correlation = true
        performance = "light"
    strings:
        $mz = { 4D 5A }
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        $pack1 = ".packed" ascii wide nocase
        $pack2 = "Themida" ascii wide nocase
    condition:
        $mz and (2 of ($upx*) or 1 of ($pack*))
}
