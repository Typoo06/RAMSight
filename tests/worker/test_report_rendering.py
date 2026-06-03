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
