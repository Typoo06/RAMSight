# Database integration for detection findings.

from dataclasses import asdict
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import insert, select
from sqlalchemy.engine import Connection

from app.db.tables import (
    command_artifacts,
    memory_region_artifacts,
    module_artifacts,
    network_artifacts,
    process_artifacts,
    risk_findings,
    yara_matches,
)
from app.detection.engine import evaluate_rules
from app.detection.loader import RulesLoadError, load_detection_rules, load_risk_scoring_config
from app.detection.rules import FindingDraft
from app.detection.scoring import build_process_risk_summaries

ARTIFACT_TABLES = {
    "process_artifacts": process_artifacts,
    "network_artifacts": network_artifacts,
    "module_artifacts": module_artifacts,
    "memory_region_artifacts": memory_region_artifacts,
    "command_artifacts": command_artifacts,
    "yara_matches": yara_matches,
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def load_job_artifacts(conn: Connection, analysis_job_id: UUID) -> dict[str, list[dict]]:
    artifacts = {}
    for table_name, table in ARTIFACT_TABLES.items():
        rows = conn.execute(select(table).where(table.c.analysis_job_id == analysis_job_id)).mappings().all()
        artifacts[table_name] = [dict(row) for row in rows]
    return artifacts


def finding_to_row(finding: FindingDraft, now: datetime) -> dict:
    payload = asdict(finding)
    payload["created_at"] = now
    payload["updated_at"] = now
    return payload


def insert_findings(conn: Connection, findings: list[FindingDraft], now: datetime | None = None) -> int:
    if not findings:
        return 0
    timestamp = now or utc_now()
    conn.execute(insert(risk_findings), [finding_to_row(finding, timestamp) for finding in findings])
    return len(findings)


def run_detection_for_job(conn: Connection, context: dict, rules_dir: str) -> int:
    rules = load_detection_rules(rules_dir)
    scoring_config = load_risk_scoring_config(rules_dir)
    artifacts = load_job_artifacts(conn, context["analysis_job_id"])
    findings = evaluate_rules(rules, artifacts, context)
    findings.extend(build_process_risk_summaries(findings, scoring_config))
    return insert_findings(conn, findings)


def insert_detection_stage_error(conn: Connection, context: dict, error_message: str) -> UUID:
    finding = FindingDraft(
        analysis_job_id=context["analysis_job_id"],
        evidence_id=context["evidence_id"],
        plugin_result_id=None,
        os_family=(context.get("os_family") or "unknown").lower(),
        os_scope="all",
        source_plugin=None,
        rule_id="DETECTION_STAGE_ERROR",
        rule_name="Detection stage error",
        category="detection_error",
        severity="low",
        score=0,
        title="Detection stage error",
        description="Detection did not complete for this job. Artifacts and raw outputs were preserved.",
        artifact_type=None,
        artifact_id=None,
        recommendation="Review worker logs and rule configuration, then rerun detection when available.",
        extra_data={"error_message": error_message[:500]},
    )
    insert_findings(conn, [finding])
    return finding.id


__all__ = [
    "RulesLoadError",
    "insert_detection_stage_error",
    "insert_findings",
    "load_job_artifacts",
    "run_detection_for_job",
]
