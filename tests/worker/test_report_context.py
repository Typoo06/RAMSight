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
        {"id": job_id, "case_id": case_id, "evidence_id": evidence_id, "status": "completed", "os_family": "windows", "plugin_profile": "windows"},
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
