# Detection engine tests.

from pathlib import Path
from uuid import uuid4

from app.detection.engine import (
    COMMAND_TABLE,
    MEMORY_REGION_TABLE,
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
                "extra_data": {"severity": "critical"},
            }
        ]
    }

    findings = evaluate_rules([rule_by_id("YARA_MATCH")], artifacts, context())

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].score == 13


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
