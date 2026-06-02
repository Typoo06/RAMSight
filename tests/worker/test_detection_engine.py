# Detection engine tests.

from pathlib import Path
from uuid import uuid4

from app.detection.engine import (
    COMMAND_TABLE,
    MEMORY_REGION_TABLE,
    MODULE_TABLE,
    NETWORK_TABLE,
    PROCESS_TABLE,
    YARA_TABLE,
    command_has_encoded_powershell,
    evaluate_rules,
    is_public_remote_address,
)
from app.detection.loader import load_detection_rules, load_risk_scoring_config
from app.detection.rules import FindingDraft, applies_to_os
from app.detection.scoring import build_process_risk_summaries


def rules_dir() -> Path:
    container_rules = Path("/rules")
    if container_rules.exists():
        return container_rules
    return Path(__file__).parents[2] / "rules"


def context() -> dict:
    return {"analysis_job_id": uuid4(), "evidence_id": uuid4(), "os_family": "windows"}


def rule_by_id(rule_id: str):
    return next(rule for rule in load_detection_rules(rules_dir()) if rule.id == rule_id)


def test_rules_loader_and_os_scope_filtering() -> None:
    rules = load_detection_rules(rules_dir())
    scoring = load_risk_scoring_config(rules_dir())

    assert {rule.id for rule in rules} >= {"WIN_SYSTEM_PROCESS_WRONG_PATH", "EXTERNAL_NETWORK_CONNECTION"}
    assert applies_to_os(rule_by_id("WIN_SYSTEM_PROCESS_WRONG_PATH"), "windows") is True
    assert applies_to_os(rule_by_id("WIN_SYSTEM_PROCESS_WRONG_PATH"), "linux") is False
    assert scoring["severity_scores"]["high"] == 8


def test_system_process_wrong_path_is_case_insensitive_and_skips_missing_or_placeholder_path() -> None:
    artifacts = {
        PROCESS_TABLE: [
            {
                "id": uuid4(),
                "pid": 500,
                "name": "LSASS.EXE",
                "image_path": "C:\\Users\\Public\\lsass.exe",
                "source_plugin": "windows.pslist",
            },
            {
                "id": uuid4(),
                "pid": 501,
                "name": "lsass.exe",
                "image_path": None,
                "source_plugin": "windows.pslist",
            },
            {
                "id": uuid4(),
                "pid": 502,
                "name": "lsass.exe",
                "image_path": "Disabled",
                "source_plugin": "windows.pslist",
            },
        ]
    }

    findings = evaluate_rules([rule_by_id("WIN_SYSTEM_PROCESS_WRONG_PATH")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].rule_id == "WIN_SYSTEM_PROCESS_WRONG_PATH"
    assert findings[0].extra_data["pid"] == 500


def test_system_process_wrong_path_only_applies_to_known_system_processes() -> None:
    artifacts = {
        PROCESS_TABLE: [
            {"id": uuid4(), "pid": 600, "name": "DumpIt.exe", "image_path": "C:\\Users\\Public\\DumpIt.exe"},
            {"id": uuid4(), "pid": 601, "name": "WinRAR.exe", "image_path": "C:\\Users\\lab\\Downloads\\WinRAR.exe"},
            {"id": uuid4(), "pid": 602, "name": "explorer.exe", "image_path": "C:\\Windows\\explorer.exe"},
        ]
    }

    findings = evaluate_rules([rule_by_id("WIN_SYSTEM_PROCESS_WRONG_PATH")], artifacts, context())

    assert findings == []


def test_encoded_powershell_forms_and_long_base64() -> None:
    long_base64 = "SQBFAFgA" * 8

    assert command_has_encoded_powershell(f"powershell.exe -enc {long_base64}") is True
    assert command_has_encoded_powershell(f"pwsh /encodedcommand {long_base64}") is True
    assert command_has_encoded_powershell(f"powershell.exe {long_base64}") is True
    assert command_has_encoded_powershell("powershell.exe -noprofile short") is False

    artifacts = {COMMAND_TABLE: [{"id": uuid4(), "pid": 10, "process_name": "powershell.exe", "command": f"powershell.exe -enc {long_base64}"}]}
    findings = evaluate_rules([rule_by_id("WIN_ENCODED_POWERSHELL")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].category == "command_line"


def test_external_public_ip_detection_and_private_ip_ignored() -> None:
    assert is_public_remote_address("8.8.8.8") is True
    assert is_public_remote_address("192.168.1.10") is False
    assert is_public_remote_address("127.0.0.1") is False
    assert is_public_remote_address("0.0.0.0") is False

    artifacts = {
        NETWORK_TABLE: [
            {"id": uuid4(), "pid": 10, "remote_address": "8.8.8.8", "remote_port": 443, "process_name": "browser.exe"},
            {"id": uuid4(), "pid": 11, "remote_address": "10.0.0.5", "remote_port": 445, "process_name": "system"},
        ]
    }
    findings = evaluate_rules([rule_by_id("EXTERNAL_NETWORK_CONNECTION")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].extra_data["remote_address"] == "8.8.8.8"


def test_memory_region_finding_uses_cautious_wording() -> None:
    artifacts = {
        MEMORY_REGION_TABLE: [
            {
                "id": uuid4(),
                "pid": 222,
                "process_name": "sample.exe",
                "source_plugin": "windows.malfind",
                "start_address": "0x1000",
                "end_address": "0x2000",
                "protection": "PAGE_EXECUTE_READWRITE",
                "is_executable": True,
                "is_private": True,
            }
        ]
    }

    findings = evaluate_rules([rule_by_id("SUSPICIOUS_EXECUTABLE_MEMORY_REGION")], artifacts, context())

    assert len(findings) == 1
    assert "injection candidate" in findings[0].description
    assert "requires analyst validation" in findings[0].description
    assert findings[0].extra_data["is_executable"] is True


def test_yara_match_finding_supports_critical_metadata() -> None:
    artifacts = {
        YARA_TABLE: [
            {
                "id": uuid4(),
                "plugin_result_id": uuid4(),
                "source_plugin": "yarascan",
                "rule_name": "SuspiciousRule",
                "target_type": "process",
                "target_identifier": "1234",
                "offset": 4096,
                "extra_data": {"severity": "critical", "confidence": "high"},
            }
        ]
    }

    findings = evaluate_rules([rule_by_id("YARA_MATCH")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].score == 13


def test_broad_demo_yara_matches_are_summarized_per_rule() -> None:
    yara_rows = [
        {
            "id": uuid4(),
            "source_plugin": "windows.vadyarascan",
            "rule_name": "RAMSight_Demo_PE_Header_In_Memory_Candidate",
            "target_type": "process_memory",
            "target_identifier": f"PID {400 + index}",
            "offset": 0x1000 + index,
            "extra_data": {"offset_raw": hex(0x1000 + index)},
        }
        for index in range(10)
    ]
    artifacts = {YARA_TABLE: yara_rows}

    findings = evaluate_rules([rule_by_id("YARA_MATCH")], artifacts, context())

    assert len(findings) == 1
    assert len(artifacts[YARA_TABLE]) == 10
    assert findings[0].severity == "low"
    assert findings[0].title == "YARA triage summary: RAMSight_Demo_PE_Header_In_Memory_Candidate"
    assert findings[0].extra_data["rule_name"] == "RAMSight_Demo_PE_Header_In_Memory_Candidate"
    assert findings[0].extra_data["affected_pid_count"] == 10
    assert findings[0].extra_data["total_match_count"] == 10
    assert findings[0].extra_data["sample_pids"] == [400, 401, 402, 403, 404]
    assert findings[0].extra_data["sample_offsets"] == ["0x1000", "0x1001", "0x1002", "0x1003", "0x1004"]
    assert len(findings[0].extra_data["yara_match_artifact_ids"]) == 10
    assert findings[0].extra_data["noisy"] is True
    assert findings[0].extra_data["requires_correlation"] is True


def test_high_confidence_non_noisy_yara_can_emit_per_process_findings() -> None:
    artifacts = {
        YARA_TABLE: [
            {
                "id": uuid4(),
                "source_plugin": "windows.vadyarascan",
                "rule_name": "Analyst_High_Confidence_Memory_Rule",
                "target_type": "process_memory",
                "target_identifier": "PID 1200",
                "offset": 0x5000,
                "extra_data": {"severity": "high", "confidence": "high", "noisy": False, "requires_correlation": False},
            },
            {
                "id": uuid4(),
                "source_plugin": "windows.vadyarascan",
                "rule_name": "Analyst_High_Confidence_Memory_Rule",
                "target_type": "process_memory",
                "target_identifier": "PID 1300",
                "offset": 0x6000,
                "extra_data": {"severity": "high", "confidence": "high", "noisy": False, "requires_correlation": False},
            },
        ]
    }

    findings = evaluate_rules([rule_by_id("YARA_MATCH")], artifacts, context())

    assert len(findings) == 2
    assert {finding.extra_data["pid"] for finding in findings} == {1200, 1300}
    assert {finding.severity for finding in findings} == {"high"}


def test_psscan_only_hidden_process_candidate_compares_by_pid() -> None:
    artifacts = {
        PROCESS_TABLE: [
            {"id": uuid4(), "pid": 100, "name": "known.exe", "source_plugin": "windows.pslist"},
            {"id": uuid4(), "pid": 100, "name": "known.exe", "source_plugin": "windows.psscan"},
            {"id": uuid4(), "pid": 777, "name": "odd.exe", "source_plugin": "windows.psscan"},
            {"id": uuid4(), "pid": None, "name": "missing.exe", "source_plugin": "windows.psscan"},
        ]
    }

    findings = evaluate_rules([rule_by_id("WIN_PSSCAN_ONLY_PROCESS")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "hidden process candidate" in findings[0].description
    assert findings[0].extra_data["pid"] == 777


def test_process_risk_aggregation_creates_summary_finding_with_identity() -> None:
    artifacts = {
        PROCESS_TABLE: [
            {
                "id": uuid4(),
                "pid": 777,
                "name": "lsass.exe",
                "image_path": "C:\\Temp\\lsass.exe",
                "source_plugin": "windows.psscan",
            }
        ],
    }
    rules = [rule_by_id("WIN_SYSTEM_PROCESS_WRONG_PATH"), rule_by_id("WIN_PSSCAN_ONLY_PROCESS")]
    findings = evaluate_rules(rules, artifacts, context())
    summaries = build_process_risk_summaries(findings, load_risk_scoring_config(rules_dir()))

    assert len(summaries) == 1
    assert summaries[0].rule_id == "PROCESS_RISK_SUMMARY"
    assert summaries[0].extra_data["total_score"] == 16
    assert "lsass.exe" in summaries[0].title
    assert summaries[0].extra_data["pid"] == 777
    assert summaries[0].extra_data["process_name"] == "lsass.exe"
    assert set(summaries[0].extra_data["component_rule_ids"]) == {"WIN_SYSTEM_PROCESS_WRONG_PATH", "WIN_PSSCAN_ONLY_PROCESS"}


def test_process_risk_aggregation_deduplicates_repeated_components() -> None:
    ctx = context()
    first = FindingDraft(
        analysis_job_id=ctx["analysis_job_id"],
        evidence_id=ctx["evidence_id"],
        plugin_result_id=None,
        os_family="windows",
        os_scope="windows",
        source_plugin="windows.pslist",
        rule_id="WIN_SYSTEM_PROCESS_WRONG_PATH",
        rule_name="System process running from wrong path",
        category="process",
        severity="high",
        score=8,
        title="System process path anomaly: lsass.exe (PID 777)",
        description="test",
        artifact_type=PROCESS_TABLE,
        artifact_id="one",
        recommendation="test",
        extra_data={"pid": 777, "process_name": "lsass.exe", "image_path": "C:\\Temp\\lsass.exe"},
    )
    duplicate = FindingDraft(**{**first.__dict__, "id": uuid4(), "artifact_id": "two"})

    summaries = build_process_risk_summaries([first, duplicate], load_risk_scoring_config(rules_dir()))

    assert summaries == []


def memory_region(pid: int = 2924) -> dict:
    return {
        "id": uuid4(),
        "pid": pid,
        "process_name": "WinRAR.exe",
        "source_plugin": "windows.malfind",
        "start_address": "0x400000",
        "end_address": "0x401000",
        "protection": "PAGE_EXECUTE_READWRITE",
        "is_executable": True,
        "is_private": True,
    }


def test_process_injection_candidate_from_malfind_region() -> None:
    artifacts = {MEMORY_REGION_TABLE: [memory_region()]}

    findings = evaluate_rules([rule_by_id("MEMORY_PROCESS_INJECTION_CANDIDATE")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].rule_id == "MEMORY_PROCESS_INJECTION_CANDIDATE"
    assert "WinRAR.exe" in findings[0].title
    assert findings[0].extra_data["pid"] == 2924
    assert findings[0].extra_data["address_range"] == "0x400000-0x401000"
    assert findings[0].extra_data["requires_validation"] is True


def test_memory_region_network_correlation_by_pid() -> None:
    network_id = uuid4()
    artifacts = {
        MEMORY_REGION_TABLE: [memory_region()],
        NETWORK_TABLE: [
            {"id": network_id, "pid": 2924, "remote_address": "8.8.8.8", "remote_port": 443, "source_plugin": "windows.netscan"},
            {"id": uuid4(), "pid": 2924, "remote_address": "192.168.1.2", "remote_port": 445, "source_plugin": "windows.netscan"},
        ],
    }

    findings = evaluate_rules([rule_by_id("MEMORY_REGION_WITH_NETWORK_ACTIVITY")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].extra_data["linked_artifacts"]["network_artifact_id"] == str(network_id)
    assert findings[0].extra_data["linked_artifacts"]["remote_address"] == "8.8.8.8"


def test_memory_region_suspicious_command_correlation_by_pid() -> None:
    command_id = uuid4()
    artifacts = {
        MEMORY_REGION_TABLE: [memory_region()],
        COMMAND_TABLE: [
            {
                "id": command_id,
                "pid": 2924,
                "process_name": "WinRAR.exe",
                "command": "powershell.exe -enc " + "SQBFAFgA" * 8,
                "source_plugin": "windows.cmdline",
            }
        ],
    }

    findings = evaluate_rules([rule_by_id("MEMORY_REGION_WITH_SUSPICIOUS_COMMAND")], artifacts, context())

    assert len(findings) == 1
    assert "suspicious command line" in findings[0].title.lower()
    assert findings[0].extra_data["linked_artifacts"]["command_artifact_id"] == str(command_id)


def test_memory_region_module_correlation_by_pid() -> None:
    module_id = uuid4()
    artifacts = {
        MEMORY_REGION_TABLE: [memory_region()],
        MODULE_TABLE: [
            {
                "id": module_id,
                "pid": 2924,
                "process_name": "WinRAR.exe",
                "module_name": "odd.dll",
                "module_path": "C:\\Users\\Public\\odd.dll",
                "source_plugin": "windows.dlllist",
            }
        ],
    }

    findings = evaluate_rules([rule_by_id("MEMORY_REGION_WITH_SUSPICIOUS_MODULE")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].extra_data["linked_artifacts"]["module_artifact_id"] == str(module_id)


def test_memory_correlation_deduplicates_same_region_and_network() -> None:
    region = memory_region()
    artifacts = {
        MEMORY_REGION_TABLE: [region, {**region, "id": uuid4()}],
        NETWORK_TABLE: [
            {"id": uuid4(), "pid": 2924, "remote_address": "8.8.8.8", "remote_port": 443},
            {"id": uuid4(), "pid": 2924, "remote_address": "8.8.8.8", "remote_port": 443},
        ],
    }

    findings = evaluate_rules([rule_by_id("MEMORY_REGION_WITH_NETWORK_ACTIVITY")], artifacts, context())

    assert len(findings) == 1


def test_yara_match_in_process_memory_finding_and_no_fabricated_matches() -> None:
    findings = evaluate_rules([rule_by_id("YARA_MATCH_IN_PROCESS_MEMORY")], {YARA_TABLE: []}, context())
    assert findings == []

    yara_ids = [uuid4(), uuid4()]
    artifacts = {
        MEMORY_REGION_TABLE: [memory_region()],
        YARA_TABLE: [
            {
                "id": yara_ids[0],
                "source_plugin": "windows.vadyarascan",
                "rule_name": "RAMSight_Demo_Injection_API_Cluster",
                "target_type": "process_memory",
                "target_identifier": "2924",
                "offset": 0x400120,
            },
            {
                "id": yara_ids[1],
                "source_plugin": "windows.vadyarascan",
                "rule_name": "RAMSight_Demo_Injection_API_Cluster",
                "target_type": "process_memory",
                "target_identifier": "2924",
                "offset": 0x400220,
            }
        ],
    }

    findings = evaluate_rules([rule_by_id("YARA_MATCH_IN_PROCESS_MEMORY")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].artifact_id == str(yara_ids[0])
    assert findings[0].extra_data["pid"] == 2924
    assert findings[0].extra_data["yara_match_count"] == 2
    assert findings[0].extra_data["sample_offsets"] == ["0x400120", "0x400220"]
    assert findings[0].extra_data["linked_memory_region_artifact_ids"]


def test_process_risk_summary_aggregates_memory_only_signals() -> None:
    artifacts = {
        MEMORY_REGION_TABLE: [memory_region()],
        NETWORK_TABLE: [{"id": uuid4(), "pid": 2924, "remote_address": "8.8.8.8", "remote_port": 443}],
    }
    rules = [rule_by_id("MEMORY_PROCESS_INJECTION_CANDIDATE"), rule_by_id("MEMORY_REGION_WITH_NETWORK_ACTIVITY")]

    findings = evaluate_rules(rules, artifacts, context())
    summaries = build_process_risk_summaries(findings, load_risk_scoring_config(rules_dir()))

    assert len(summaries) == 1
    assert summaries[0].extra_data["pid"] == 2924
    assert summaries[0].extra_data["process_name"] == "WinRAR.exe"
    assert summaries[0].extra_data["total_score"] == 21
    assert summaries[0].severity == "critical"
    assert summaries[0].extra_data["unique_component_count"] == 2
    assert summaries[0].extra_data["memory_region_count"] == 1
    assert summaries[0].extra_data["network_endpoint_count"] == 1
    assert summaries[0].extra_data["yara_match_count"] == 0


def test_process_risk_summary_does_not_inflate_repeated_memory_only_rows() -> None:
    region_one = memory_region()
    region_two = {**memory_region(), "id": uuid4(), "start_address": "0x500000", "end_address": "0x501000"}
    artifacts = {MEMORY_REGION_TABLE: [region_one, region_two, {**region_two, "id": uuid4()}]}
    rules = [rule_by_id("SUSPICIOUS_EXECUTABLE_MEMORY_REGION"), rule_by_id("MEMORY_PROCESS_INJECTION_CANDIDATE")]

    findings = evaluate_rules(rules, artifacts, context())
    summaries = build_process_risk_summaries(findings, load_risk_scoring_config(rules_dir()))

    assert len(summaries) == 1
    assert summaries[0].severity == "high"
    assert summaries[0].extra_data["total_score"] == 8
    assert summaries[0].extra_data["memory_region_count"] == 2
    assert summaries[0].extra_data["network_endpoint_count"] == 0
    assert set(summaries[0].extra_data["component_rule_ids"]) == {
        "SUSPICIOUS_EXECUTABLE_MEMORY_REGION",
        "MEMORY_PROCESS_INJECTION_CANDIDATE",
    }


def test_process_risk_summary_counts_unique_yara_rules_not_offsets() -> None:
    yara_rows = [
        {
            "id": uuid4(),
            "source_plugin": "windows.vadyarascan",
            "rule_name": "RAMSight_Demo_Injection_API_Cluster",
            "target_type": "process_memory",
            "target_identifier": "2924",
            "offset": 0x500000 + index,
        }
        for index in range(12)
    ]
    artifacts = {MEMORY_REGION_TABLE: [memory_region()], YARA_TABLE: yara_rows}
    rules = [rule_by_id("MEMORY_PROCESS_INJECTION_CANDIDATE"), rule_by_id("YARA_MATCH_IN_PROCESS_MEMORY")]

    findings = evaluate_rules(rules, artifacts, context())
    summaries = build_process_risk_summaries(findings, load_risk_scoring_config(rules_dir()))

    assert len([finding for finding in findings if finding.rule_id == "YARA_MATCH_IN_PROCESS_MEMORY"]) == 1
    assert len(summaries) == 1
    assert summaries[0].severity == "high"
    assert summaries[0].extra_data["unique_component_count"] == 2
    assert summaries[0].extra_data["yara_rule_count"] == 1
    assert summaries[0].extra_data["yara_match_count"] == 1
    assert summaries[0].extra_data["yara_raw_match_count"] == 12
    assert summaries[0].extra_data["yara_rules"] == ["RAMSight_Demo_Injection_API_Cluster"]


def test_yara_only_demo_matches_do_not_create_process_critical_summaries() -> None:
    yara_rows = [
        {
            "id": uuid4(),
            "source_plugin": "windows.vadyarascan",
            "rule_name": "RAMSight_Demo_PE_Header_In_Memory_Candidate",
            "target_type": "process_memory",
            "target_identifier": f"PID {600 + index}",
            "offset": 0x700000 + index,
        }
        for index in range(30)
    ]

    findings = evaluate_rules([rule_by_id("YARA_MATCH"), rule_by_id("YARA_MATCH_IN_PROCESS_MEMORY")], {YARA_TABLE: yara_rows}, context())
    summaries = build_process_risk_summaries(findings, load_risk_scoring_config(rules_dir()))

    assert len(findings) == 1
    assert findings[0].category == "yara"
    assert findings[0].severity == "low"
    assert findings[0].extra_data["total_match_count"] == 30
    assert summaries == []


def test_yara_memory_and_network_correlation_can_be_critical() -> None:
    artifacts = {
        MEMORY_REGION_TABLE: [memory_region()],
        NETWORK_TABLE: [{"id": uuid4(), "pid": 2924, "remote_address": "8.8.8.8", "remote_port": 443}],
        YARA_TABLE: [
            {
                "id": uuid4(),
                "source_plugin": "windows.vadyarascan",
                "rule_name": "RAMSight_Demo_Injection_API_Cluster",
                "target_type": "process_memory",
                "target_identifier": "2924",
                "offset": 0x500000,
            }
        ],
    }
    rules = [
        rule_by_id("MEMORY_PROCESS_INJECTION_CANDIDATE"),
        rule_by_id("MEMORY_REGION_WITH_NETWORK_ACTIVITY"),
        rule_by_id("YARA_MATCH_IN_PROCESS_MEMORY"),
    ]

    findings = evaluate_rules(rules, artifacts, context())
    summaries = build_process_risk_summaries(findings, load_risk_scoring_config(rules_dir()))

    assert len(summaries) == 1
    assert summaries[0].severity == "critical"
    assert summaries[0].extra_data["memory_region_count"] == 1
    assert summaries[0].extra_data["network_endpoint_count"] == 1
    assert summaries[0].extra_data["yara_rule_count"] == 1
    assert summaries[0].extra_data["yara_raw_match_count"] == 1


def test_high_confidence_yara_and_memory_can_be_critical() -> None:
    artifacts = {
        MEMORY_REGION_TABLE: [memory_region()],
        YARA_TABLE: [
            {
                "id": uuid4(),
                "source_plugin": "windows.vadyarascan",
                "rule_name": "Analyst_High_Confidence_Memory_Rule",
                "target_type": "process_memory",
                "target_identifier": "2924",
                "offset": 0x500000,
                "extra_data": {
                    "severity": "high",
                    "confidence": "high",
                    "noisy": False,
                    "requires_correlation": False,
                },
            }
        ],
    }
    rules = [rule_by_id("MEMORY_PROCESS_INJECTION_CANDIDATE"), rule_by_id("YARA_MATCH_IN_PROCESS_MEMORY")]

    findings = evaluate_rules(rules, artifacts, context())
    summaries = build_process_risk_summaries(findings, load_risk_scoring_config(rules_dir()))

    assert len(summaries) == 1
    assert summaries[0].severity == "critical"
    assert summaries[0].extra_data["memory_region_count"] == 1
    assert summaries[0].extra_data["yara_rule_count"] == 1
    assert summaries[0].extra_data["yara_raw_match_count"] == 1


def test_critical_process_summary_requires_independent_evidence_categories() -> None:
    region_one = memory_region()
    region_two = {**memory_region(), "id": uuid4(), "start_address": "0x600000", "end_address": "0x601000"}
    artifacts = {MEMORY_REGION_TABLE: [region_one, region_two]}

    findings = evaluate_rules([rule_by_id("MEMORY_PROCESS_INJECTION_CANDIDATE")], artifacts, context())
    summaries = build_process_risk_summaries(findings, load_risk_scoring_config(rules_dir()))

    assert len(summaries) == 1
    assert summaries[0].severity == "high"
    assert summaries[0].extra_data["total_score"] == 8
    assert summaries[0].extra_data["unique_component_count"] == 2
