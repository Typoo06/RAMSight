/*
  RAMSight demo YARA rules for memory-only malware triage.

  These rules are intentionally generic and benign. They are not definitive
  malware signatures. A match is a candidate signal that requires analyst
  validation with process, command-line, network, and memory-region context.
*/

rule RAMSight_Demo_Injection_API_Cluster
{
    meta:
        description = "Demo triage rule for multiple memory injection API strings"
        severity = "medium"
        triage_severity = "medium"
        confidence = "candidate"
        noisy = false
        requires_correlation = true
    strings:
        $alloc = "VirtualAlloc" ascii wide nocase
        $protect = "VirtualProtect" ascii wide nocase
        $write = "WriteProcessMemory" ascii wide nocase
        $thread = "CreateRemoteThread" ascii wide nocase
    condition:
        2 of them
}

rule RAMSight_Demo_Encoded_PowerShell_Memory_Context
{
    meta:
        description = "Demo triage rule for PowerShell encoded-command strings in memory"
        severity = "medium"
        triage_severity = "medium"
        confidence = "candidate"
        noisy = false
        requires_correlation = true
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-encodedcommand" ascii wide nocase
        $b64 = "FromBase64String" ascii wide nocase
    condition:
        1 of ($ps*) and (1 of ($enc*) or $b64)
}

rule RAMSight_Demo_PE_Header_In_Memory_Candidate
{
    meta:
        description = "Low-severity demo rule for PE-like headers in scanned memory; expected to be noisy"
        severity = "low"
        triage_severity = "low"
        confidence = "candidate"
        noisy = true
        requires_correlation = true
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe in (0..1024)
}
