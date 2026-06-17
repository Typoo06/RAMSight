# HTML report rendering tests.

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.reports.context import build_report_context
from app.reports.render import render_technical_report


def templates_dir() -> Path:
    container_templates = Path("/reports/templates")
    if container_templates.exists():
        return container_templates
    return Path(__file__).parents[2] / "reports" / "templates"


def test_html_rendering_escapes_untrusted_values_and_includes_sections() -> None:
    case_id = uuid4()
    evidence_id = uuid4()
    job_id = uuid4()
    completed_at = datetime(2026, 5, 24, 12, 30, tzinfo=timezone.utc)
    context = build_report_context(
        case={"id": case_id, "case_code": "CASE-<1>", "name": "<script>alert(1)</script>", "status": "open"},
        evidence={"id": evidence_id, "case_id": case_id, "original_filename": "memory.raw", "source_type": "upload", "md5": "a" * 32, "sha256": "b" * 64, "os_family": "windows"},
        analysis_job={
            "id": job_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "status": "completed",
            "os_family": "windows",
            "duration_ms": 1234,
            "completed_at": completed_at,
        },
        plugin_results=[
            {
                "plugin_name": "windows.pslist",
                "status": "completed",
                "raw_output_bucket": "raw-outputs",
                "raw_output_key": "case-a/job-b/raw/windows_pslist.json",
                "parsed_output_bucket": "raw-outputs",
                "parsed_output_key": "case-a/job-b/parsed/windows_pslist.json",
            }
        ],
        artifacts={"process_artifacts": [], "network_artifacts": [], "module_artifacts": [], "memory_region_artifacts": [], "command_artifacts": [], "yara_matches": []},
        risk_findings=[{"rule_name": "Encoded <PowerShell>", "severity": "high", "score": 8, "artifact_type": "command_artifacts", "source_plugin": "windows.cmdline", "recommendation": "Check <parent>"}],
        iocs=[{"ioc_type": "command_line", "value": "powershell <bad>", "confidence": 85, "source_plugin": "windows.cmdline", "context": "encoded"}],
        analyst_notes=[{"body": "Analyst note with <script>bad()</script>"}],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    html = render_technical_report(context, templates_dir())

    assert "RAMSight Technical Analysis Report" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "powershell &lt;bad&gt;" in html
    assert "case-a/job-b/raw/windows_pslist.json" in html
    assert "case-a/job-b/parsed/windows_pslist.json" in html
    assert "<th>Job ID</th>" in html
    assert "<th>Status</th><td>completed</td>" in html
    assert "<th>Duration ms</th><td>1234</td>" in html
    assert f"<th>Completed</th><td>{completed_at}</td>" in html
    assert "<script>alert(1)</script>" not in html


def test_html_report_distinguishes_yara_timeout_from_no_match() -> None:
    case_id = uuid4()
    evidence_id = uuid4()
    job_id = uuid4()
    context = build_report_context(
        case={"id": case_id, "case_code": "CASE-YARA-TIMEOUT", "name": "YARA timeout", "status": "open"},
        evidence={"id": evidence_id, "case_id": case_id, "original_filename": "memory.raw", "source_type": "upload", "os_family": "windows"},
        analysis_job={"id": job_id, "case_id": case_id, "evidence_id": evidence_id, "status": "completed", "os_family": "windows", "plugin_profile": "windows_memory_yara"},
        plugin_results=[
            {
                "plugin_name": "windows.vadyarascan",
                "source_plugin": "windows.vadyarascan",
                "status": "failed",
                "error_message": "Volatility plugin timed out after 900s",
                "extra_data": {"timeout_seconds": 900, "timeout_reason": "plugin_timeout", "is_yara_plugin": True},
            }
        ],
        artifacts={"process_artifacts": [], "network_artifacts": [], "module_artifacts": [], "memory_region_artifacts": [], "command_artifacts": [], "yara_matches": []},
        risk_findings=[],
        iocs=[],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    html = render_technical_report(context, templates_dir())

    assert "YARA scanning was selected but windows.vadyarascan timed out after 900 seconds." in html
    assert "No YARA match artifacts were recorded." not in html



def test_html_report_renders_process_summary_without_raw_dict_text() -> None:
    case_id = uuid4()
    evidence_id = uuid4()
    job_id = uuid4()
    process_summary = {
        "id": uuid4(),
        "category": "process_risk_summary",
        "severity": "critical",
        "score": 21,
        "title": "Critical risk process: WinRAR.exe (PID 2924)",
        "description": "Aggregated process-level risk for WinRAR.exe.",
        "recommendation": "Review this process first.",
        "extra_data": {
            "pid": 2924,
            "process_name": "WinRAR.exe",
            "evidence_groups": ["memory_region", "yara_match", "network_endpoint"],
            "component_rule_ids": ["MEMORY_PROCESS_INJECTION_CANDIDATE", "YARA_MATCH_IN_PROCESS_MEMORY"],
            "memory_region_count": 1,
            "network_endpoint_count": 1,
            "yara_rule_count": 1,
            "yara_raw_match_count": 2,
        },
    }
    context = build_report_context(
        case={"id": case_id, "case_code": "CASE-REPORT", "name": "Report", "status": "open"},
        evidence={"id": evidence_id, "case_id": case_id, "original_filename": "memory.raw", "source_type": "upload", "os_family": "windows"},
        analysis_job={"id": job_id, "case_id": case_id, "evidence_id": evidence_id, "status": "completed", "os_family": "windows", "plugin_profile": "windows_memory_yara"},
        plugin_results=[{"plugin_name": "windows.vadyarascan", "status": "completed", "parsed_record_count": 2, "extra_data": {"is_yara_plugin": True}}],
        artifacts={
            "process_artifacts": [],
            "network_artifacts": [{"id": uuid4(), "pid": 2924, "remote_address": "8.8.8.8", "remote_port": 443}],
            "module_artifacts": [],
            "memory_region_artifacts": [{"id": uuid4(), "pid": 2924, "process_name": "WinRAR.exe", "start_address": "0x400000", "end_address": "0x401000", "protection": "PAGE_EXECUTE_READWRITE", "is_executable": True, "source_plugin": "windows.malfind"}],
            "command_artifacts": [],
            "yara_matches": [{"id": uuid4(), "rule_name": "RuleA", "target_identifier": "PID 2924", "offset": 0x400120, "source_plugin": "windows.vadyarascan"}],
        },
        risk_findings=[process_summary],
        iocs=[{"ioc_type": "network_endpoint", "value": "8.8.8.8:443", "confidence": 85, "source_plugin": "windows.netscan", "extra_data": {"pid": 2924}}],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    html = render_technical_report(context, templates_dir())

    assert "Executive Summary" in html
    assert "Plugin Results" in html
    assert "Memory-only Evidence Chains" in html
    assert "Critical risk process: WinRAR.exe" in html
    assert "WinRAR.exe (PID 2924)" in html
    assert "memory_region" in html
    assert "YARA scanning completed." in html
    assert "Third-party YARA rules are defensive triage aids" in html
    assert "{&#39;pid&#39;" not in html
    assert "{'pid':" not in html


def test_html_report_includes_plugin_status_table_without_filtering_notes() -> None:
    case_id = uuid4()
    evidence_id = uuid4()
    job_id = uuid4()
    findings = [
        {
            "id": uuid4(),
            "rule_id": "MEMORY_PROCESS_INJECTION_CANDIDATE",
            "rule_name": "Process injection candidate",
            "severity": "high",
            "score": 8,
            "artifact_type": "memory_region_artifacts",
            "category": "memory_only",
            "extra_data": {"pid": 2924, "process_name": "WinRAR.exe", "address_range": "0x400000-0x401000"},
        }
        for _ in range(22)
    ]
    context = build_report_context(
        case={"id": case_id, "case_code": "CASE-CAP", "name": "Cap", "status": "open"},
        evidence={"id": evidence_id, "case_id": case_id, "original_filename": "memory.raw", "source_type": "upload", "os_family": "windows"},
        analysis_job={"id": job_id, "case_id": case_id, "evidence_id": evidence_id, "status": "completed", "os_family": "windows"},
        plugin_results=[{"plugin_name": "windows.pslist", "status": "completed", "parsed_record_count": 3, "duration_ms": 12}],
        artifacts={"process_artifacts": [], "network_artifacts": [], "module_artifacts": [], "memory_region_artifacts": [], "command_artifacts": [], "yara_matches": []},
        risk_findings=findings,
        iocs=[],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    html = render_technical_report(context, templates_dir())

    assert "Parsed records" in html
    assert "windows.pslist" in html
    forbidden_terms = ["false positive", "filtered for demo", "hidden findings", "noise reduction applied", "additional similar or lower-priority findings were omitted"]
    assert all(term not in html.lower() for term in forbidden_terms)


def test_html_report_renders_capped_artifact_sections_with_context_notes() -> None:
    case_id = uuid4()
    evidence_id = uuid4()
    job_id = uuid4()
    module_id = uuid4()
    listener_rows = [
        {
            "id": uuid4(),
            "protocol": "TCPv4",
            "local_address": "0.0.0.0",
            "local_port": 135,
            "remote_address": "0.0.0.0",
            "remote_port": None,
            "state": "LISTENING",
            "pid": 888,
            "process_name": "svchost.exe",
            "source_plugin": "windows.netscan",
        }
        for _ in range(4)
    ]
    context = build_report_context(
        case={"id": case_id, "case_code": "CASE-DISPLAY", "name": "Display", "status": "open"},
        evidence={"id": evidence_id, "case_id": case_id, "original_filename": "memory.raw", "source_type": "upload", "os_family": "windows"},
        analysis_job={"id": job_id, "case_id": case_id, "evidence_id": evidence_id, "status": "completed", "os_family": "windows"},
        plugin_results=[],
        artifacts={
            "process_artifacts": [],
            "network_artifacts": listener_rows
            + [
                {
                    "id": uuid4(),
                    "protocol": "TCPv4",
                    "local_address": "10.0.2.15",
                    "local_port": 49222,
                    "remote_address": "8.8.8.8",
                    "remote_port": 443,
                    "state": "ESTABLISHED",
                    "pid": 2924,
                    "process_name": "WinRAR.exe",
                    "source_plugin": "windows.netscan",
                }
            ],
            "module_artifacts": [
                {
                    "id": uuid4(),
                    "pid": 6620,
                    "process_name": "OneDrive.exe",
                    "module_name": "FileSyncShell64.dll",
                    "module_path": "C:\\Users\\analyst\\AppData\\Local\\Microsoft\\OneDrive\\24.1\\FileSyncShell64.dll",
                    "source_plugin": "windows.dlllist",
                },
                {
                    "id": uuid4(),
                    "pid": 6620,
                    "process_name": "OneDrive.exe",
                    "module_name": "Telemetry.dll",
                    "module_path": "C:\\Users\\analyst\\AppData\\Local\\Microsoft\\OneDrive\\24.1\\Telemetry.dll",
                    "source_plugin": "windows.dlllist",
                },
                {
                    "id": module_id,
                    "pid": 2924,
                    "process_name": "WinRAR.exe",
                    "module_name": "payload.dll",
                    "module_path": "C:\\Users\\analyst\\AppData\\Local\\OddVendor\\payload.dll",
                    "source_plugin": "windows.dlllist",
                },
            ],
            "memory_region_artifacts": [],
            "command_artifacts": [],
            "yara_matches": [],
        },
        risk_findings=[{"id": uuid4(), "artifact_type": "module_artifacts", "artifact_id": module_id, "severity": "high", "score": 8, "extra_data": {"pid": 2924, "process_name": "WinRAR.exe"}}],
        iocs=[{"ioc_type": "network_endpoint", "value": "8.8.8.8:443", "confidence": 80, "source_plugin": "windows.netscan", "extra_data": {"pid": 2924, "remote_address": "8.8.8.8", "remote_port": 443}}],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    html = render_technical_report(context, templates_dir())

    assert "Executive Summary" in html
    assert "Memory-only Evidence Chains" in html
    assert "Threat-Oriented IOCs" in html
    assert "Investigation Artifacts" in html
    assert "Public remote endpoint" in html
    assert "Listening service socket shown as context" in html
    assert "Known Microsoft AppData context (onedrive)" not in html
    assert "Known Microsoft AppData module paths are shown as context" not in html
    assert "Unknown or user-writable module path" in html
    assert "standalone proof of compromise" not in html
    assert "omitted" not in html.lower()
    assert "filtered" not in html.lower()
    assert "false positive" not in html.lower()
    assert "{&#39;pid&#39;" not in html
    assert "{'pid':" not in html
