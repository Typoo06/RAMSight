# Report context tests.

from datetime import datetime, timezone
from uuid import uuid4

from app.reports.context import build_report_context


def base_rows() -> tuple[dict, dict, dict]:
    case_id = uuid4()
    evidence_id = uuid4()
    job_id = uuid4()
    return (
        {"id": case_id, "case_code": "CASE-1", "name": "Investigation", "status": "open", "description": "Lab case"},
        {"id": evidence_id, "case_id": case_id, "original_filename": "memory.raw", "source_type": "upload", "md5": "a" * 32, "sha256": "b" * 64, "os_family": "windows"},
        {
            "id": job_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "status": "completed",
            "os_family": "windows",
            "plugin_profile": "windows",
            "duration_ms": 1234,
            "completed_at": datetime(2026, 5, 24, 12, 30, tzinfo=timezone.utc),
        },
    )


def test_report_context_summary_counts_and_top_findings_ordering() -> None:
    case, evidence, job = base_rows()
    artifacts = {
        "process_artifacts": [{"id": uuid4(), "name": "sample.exe"}],
        "network_artifacts": [{"id": uuid4(), "remote_address": "8.8.8.8"}],
        "module_artifacts": [],
        "memory_region_artifacts": [],
        "command_artifacts": [],
        "yara_matches": [],
    }
    findings = [
        {"id": uuid4(), "severity": "medium", "score": 5, "rule_name": "Medium", "category": "command"},
        {"id": uuid4(), "severity": "critical", "score": 13, "rule_name": "Critical", "category": "yara"},
        {"id": uuid4(), "severity": "high", "score": 9, "rule_name": "High", "category": "memory"},
    ]

    context = build_report_context(
        case,
        evidence,
        job,
        plugin_results=[{"status": "completed"}, {"status": "failed"}],
        artifacts=artifacts,
        risk_findings=findings,
        iocs=[{"ioc_type": "ip_address", "value": "8.8.8.8"}],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    assert context["summary"]["total_plugin_results"] == 2
    assert context["summary"]["completed_plugins"] == 1
    assert context["summary"]["failed_plugins"] == 1
    assert context["summary"]["total_parsed_artifacts"] == 2
    assert context["summary"]["total_risk_findings"] == 3
    assert context["summary"]["total_ioc_records"] == 1
    assert [finding["rule_name"] for finding in context["top_findings"]] == ["Critical", "High", "Medium"]


def test_report_context_preserves_final_job_status_metadata() -> None:
    case, evidence, job = base_rows()

    context = build_report_context(
        case,
        evidence,
        job,
        plugin_results=[],
        artifacts={"process_artifacts": [], "network_artifacts": [], "module_artifacts": [], "memory_region_artifacts": [], "command_artifacts": [], "yara_matches": []},
        risk_findings=[],
        iocs=[],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    assert context["analysis_job"]["status"] == "completed"
    assert context["analysis_job"]["duration_ms"] == 1234
    assert context["analysis_job"]["completed_at"] == datetime(2026, 5, 24, 12, 30, tzinfo=timezone.utc)


def test_report_context_marks_yara_timeout_status() -> None:
    case, evidence, job = base_rows()
    job["plugin_profile"] = "windows_memory_yara"

    context = build_report_context(
        case,
        evidence,
        job,
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

    assert context["yara_status"]["status"] == "failed_timeout"
    assert context["yara_status"]["timeout_seconds"] == 900
    assert "timed out after 900 seconds" in context["yara_status"]["message"]


def test_report_context_marks_yara_completed_zero_matches() -> None:
    case, evidence, job = base_rows()
    job["plugin_profile"] = "windows_memory_yara"

    context = build_report_context(
        case,
        evidence,
        job,
        plugin_results=[{"plugin_name": "windows.vadyarascan", "source_plugin": "windows.vadyarascan", "status": "completed", "extra_data": {"is_yara_plugin": True}}],
        artifacts={"process_artifacts": [], "network_artifacts": [], "module_artifacts": [], "memory_region_artifacts": [], "command_artifacts": [], "yara_matches": []},
        risk_findings=[],
        iocs=[],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    assert context["yara_status"]["status"] == "completed_no_matches"
    assert context["yara_status"]["message"] == "YARA scanning completed; no YARA match artifacts were recorded."



def test_report_context_builds_executive_summary_and_process_chains() -> None:
    case, evidence, job = base_rows()
    job["plugin_profile"] = "windows_memory_yara"
    memory_region_id = uuid4()
    artifacts = {
        "process_artifacts": [],
        "network_artifacts": [{"id": uuid4(), "pid": 2924, "remote_address": "8.8.8.8", "remote_port": 443}],
        "module_artifacts": [],
        "memory_region_artifacts": [
            {
                "id": memory_region_id,
                "pid": 2924,
                "process_name": "WinRAR.exe",
                "start_address": "0x400000",
                "end_address": "0x401000",
                "protection": "PAGE_EXECUTE_READWRITE",
                "is_executable": True,
                "source_plugin": "windows.malfind",
            }
        ],
        "command_artifacts": [],
        "yara_matches": [
            {
                "id": uuid4(),
                "rule_name": "RAMSight_Demo_Injection_API_Cluster",
                "target_identifier": "PID 2924",
                "offset": 0x400120,
                "source_plugin": "windows.vadyarascan",
            }
        ],
    }
    findings = [
        {
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
                "total_score": 21,
                "evidence_groups": ["memory_region", "yara_match", "network_endpoint"],
                "component_rule_ids": ["MEMORY_PROCESS_INJECTION_CANDIDATE", "YARA_MATCH_IN_PROCESS_MEMORY"],
                "memory_region_count": 1,
                "network_endpoint_count": 1,
                "yara_rule_count": 1,
                "yara_raw_match_count": 3,
            },
        }
    ]

    context = build_report_context(
        case,
        evidence,
        job,
        plugin_results=[{"plugin_name": "windows.vadyarascan", "status": "completed", "parsed_record_count": 1, "extra_data": {"is_yara_plugin": True}}],
        artifacts=artifacts,
        risk_findings=findings,
        iocs=[{"ioc_type": "network_endpoint", "value": "8.8.8.8:443", "confidence": 85, "source_plugin": "windows.netscan", "extra_data": {"pid": 2924}}],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    assert context["executive_summary"]["job_status"] == "completed"
    assert "triage indicators" in context["executive_summary"]["analyst_note"]
    assert context["executive_summary"]["high_critical_count"] == 1
    assert context["plugin_status_rows"][0]["plugin_name"] == "windows.vadyarascan"
    assert context["plugin_status_rows"][0]["is_yara_plugin"] is True
    process_group = context["process_finding_groups"][0]
    assert process_group["identity"] == "WinRAR.exe (PID 2924)"
    assert process_group["evidence_groups"] == ["memory_region", "yara_match", "network_endpoint"]
    assert process_group["memory_region_count"] == 1
    chain = context["memory_evidence_chains"][0]
    assert chain["identity"] == "WinRAR.exe (PID 2924)"
    assert chain["memory_regions"][0]["address_range"] == "0x400000-0x401000"
    assert chain["network_endpoints"] == ["8.8.8.8:443"]
    assert chain["ioc_references"][0]["ioc_type"] == "network_endpoint"


def test_report_context_groups_yara_rules_and_counts() -> None:
    case, evidence, job = base_rows()
    job["plugin_profile"] = "windows_memory_yara"
    artifacts = {
        "process_artifacts": [],
        "network_artifacts": [],
        "module_artifacts": [],
        "memory_region_artifacts": [],
        "command_artifacts": [],
        "yara_matches": [
            {"id": uuid4(), "rule_name": "RuleA", "target_identifier": "PID 10", "offset": 0x10, "source_plugin": "windows.vadyarascan"},
            {"id": uuid4(), "rule_name": "RuleA", "target_identifier": "PID 10", "offset": 0x20, "source_plugin": "windows.vadyarascan"},
            {"id": uuid4(), "rule_name": "RuleB", "target_identifier": "PID 11", "offset": 0x30, "source_plugin": "windows.vadyarascan"},
        ],
    }

    context = build_report_context(
        case,
        evidence,
        job,
        plugin_results=[{"plugin_name": "windows.vadyarascan", "status": "completed", "extra_data": {"is_yara_plugin": True}}],
        artifacts=artifacts,
        risk_findings=[],
        iocs=[],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    assert context["yara_status"]["status"] == "completed_with_matches"
    assert context["yara_summary"][0]["rule_name"] == "RuleA"
    assert context["yara_summary"][0]["match_count"] == 2
    assert context["yara_summary"][0]["sample_offsets"] == ["0x10", "0x20"]


def test_report_context_separates_threat_iocs_from_investigation_artifacts() -> None:
    case, evidence, job = base_rows()
    context = build_report_context(
        case,
        evidence,
        job,
        plugin_results=[],
        artifacts={"process_artifacts": [], "network_artifacts": [], "module_artifacts": [], "memory_region_artifacts": [], "command_artifacts": [], "yara_matches": []},
        risk_findings=[],
        iocs=[
            {"ioc_type": "network_endpoint", "value": "8.8.8.8:443", "confidence": 85, "source_plugin": "windows.netscan", "extra_data": {"ioc_role": "threat_ioc"}},
            {"ioc_type": "yara_rule", "value": "CobaltStrike_Beacon", "confidence": 90, "source_plugin": "windows.vadyarascan", "extra_data": {"ioc_role": "threat_ioc"}},
            {"ioc_type": "pid", "value": "14484", "confidence": 60, "source_plugin": "windows.pslist", "extra_data": {"ioc_role": "investigation_artifact"}},
            {"ioc_type": "memory_region", "value": "14484:0x1-0x2", "confidence": 60, "source_plugin": "windows.malfind", "extra_data": {"ioc_role": "investigation_artifact"}},
            {"ioc_type": "plugin_reference", "value": "windows.malfind", "confidence": 45, "source_plugin": "windows.malfind", "extra_data": {"ioc_role": "investigation_artifact"}},
            {"ioc_type": "yara_rule", "value": "Generic_PE_Header", "confidence": 45, "source_plugin": "windows.vadyarascan", "extra_data": {"ioc_role": "investigation_artifact"}},
        ],
        generated_at=datetime(2026, 5, 24, tzinfo=timezone.utc),
    )

    assert {row["ioc_type"] for row in context["threat_ioc_summary"]} == {"network_endpoint", "yara_rule"}
    investigation_types = {row["ioc_type"] for row in context["investigation_artifact_summary"]}
    assert {"pid", "memory_region", "plugin_reference", "yara_rule"} <= investigation_types


def test_report_context_deduplicates_and_caps_top_findings_for_display() -> None:
    case, evidence, job = base_rows()
    artifacts = {"process_artifacts": [], "network_artifacts": [], "module_artifacts": [], "memory_region_artifacts": [], "command_artifacts": [], "yara_matches": []}
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
        for _ in range(25)
    ]

    context = build_report_context(case, evidence, job, plugin_results=[], artifacts=artifacts, risk_findings=findings, iocs=[])

    assert len(context["display_top_findings"]) == 1
    assert context["top_findings_omitted_count"] == 24
    assert context["display_top_findings"][0]["context_parts"] == ["PID 2924", "WinRAR.exe", "region 0x400000-0x401000"]


def test_report_context_caps_and_prioritizes_network_display() -> None:
    case, evidence, job = base_rows()
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
        for _ in range(12)
    ]
    public_row = {
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
    artifacts = {
        "process_artifacts": [],
        "network_artifacts": listener_rows + [public_row],
        "module_artifacts": [],
        "memory_region_artifacts": [],
        "command_artifacts": [],
        "yara_matches": [],
    }

    context = build_report_context(
        case,
        evidence,
        job,
        plugin_results=[],
        artifacts=artifacts,
        risk_findings=[],
        iocs=[{"ioc_type": "network_endpoint", "value": "8.8.8.8:443", "extra_data": {"pid": 2924, "remote_address": "8.8.8.8", "remote_port": 443}}],
    )

    display = context["network_display"]
    assert display["total_count"] == 13
    assert display["displayed_count"] == 2
    assert display["omitted_count"] == 11
    assert display["rows"][0]["remote_endpoint"] == "8.8.8.8:443"
    assert display["rows"][0]["reason"] == "Public remote endpoint"
    assert display["rows"][1]["reason"] == "Listening service socket shown as context"
    assert display["rows"][1]["similar_count"] == 12


def test_report_context_groups_module_paths_and_annotates_microsoft_context() -> None:
    case, evidence, job = base_rows()
    unknown_module_id = uuid4()
    onedrive_modules = [
        {
            "id": uuid4(),
            "pid": 6620,
            "process_name": "OneDrive.exe",
            "module_name": f"component{index}.dll",
            "module_path": f"C:\\Users\\analyst\\AppData\\Local\\Microsoft\\OneDrive\\24.1\\component{index}.dll",
            "source_plugin": "windows.dlllist",
        }
        for index in range(5)
    ]
    modules = onedrive_modules + [
        {
            "id": uuid4(),
            "pid": 7000,
            "process_name": "msedge.exe",
            "module_name": "msedge.dll",
            "module_path": "C:/Users/analyst/AppData/Local/Microsoft/Edge/Application/msedge.dll",
            "source_plugin": "windows.dlllist",
        },
        {
            "id": unknown_module_id,
            "pid": 2924,
            "process_name": "WinRAR.exe",
            "module_name": "payload.dll",
            "module_path": "C:\\Users\\analyst\\AppData\\Local\\OddVendor\\payload.dll",
            "source_plugin": "windows.dlllist",
        },
        {
            "id": uuid4(),
            "pid": 500,
            "process_name": "system.exe",
            "module_name": "kernel32.dll",
            "module_path": "C:\\Windows\\System32\\kernel32.dll",
            "source_plugin": "windows.dlllist",
        },
    ]
    artifacts = {"process_artifacts": [], "network_artifacts": [], "module_artifacts": modules, "memory_region_artifacts": [], "command_artifacts": [], "yara_matches": []}
    findings = [{"id": uuid4(), "artifact_type": "module_artifacts", "artifact_id": unknown_module_id, "severity": "high", "score": 8}]

    context = build_report_context(case, evidence, job, plugin_results=[], artifacts=artifacts, risk_findings=findings, iocs=[])

    display = context["module_display"]
    assert display["total_count"] == 8
    assert display["selected_count"] == 7
    assert display["displayed_count"] == 3
    assert display["omitted_count"] == 4
    assert display["known_context_count"] == 6
    assert display["suspicious_count"] == 1
    assert display["rows"][0]["classification"] == "Unknown or user-writable module path"
    assert display["rows"][0]["module_path"].endswith("OddVendor\\payload.dll")
    known_rows = [row for row in display["rows"] if row["classification"].startswith("Known Microsoft AppData context")]
    assert known_rows
    assert any(row["similar_count"] == 5 and "onedrive" in row["classification"] for row in known_rows)
    assert all("standalone proof of compromise" in row["context_note"] for row in known_rows)
