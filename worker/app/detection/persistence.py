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
    plugin_results,
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


def load_job_plugin_results(conn: Connection, analysis_job_id: UUID) -> list[dict]:
    rows = conn.execute(select(plugin_results).where(plugin_results.c.analysis_job_id == analysis_job_id)).mappings().all()
    return [dict(row) for row in rows]


PLUGIN_CONTEXT_RULES = {
    "Memory/VAD": ("VOL_PLUGIN_MEMORY_VAD_CONTEXT", "VAD/memory layout context", "medium"),
    "Injection/Hollowing": ("VOL_PLUGIN_INJECTION_CONTEXT", "Injection/hollowing plugin context", "medium"),
    "Thread analysis": ("VOL_PLUGIN_THREAD_CONTEXT", "Thread analysis context", "medium"),
    "Module/DLL": ("VOL_PLUGIN_MODULE_CONTEXT", "Module/DLL inconsistency context", "medium"),
    "Evasion/Hooking": ("VOL_PLUGIN_EVASION_CONTEXT", "Syscall/hooking evasion context", "medium"),
    "Kernel/Rootkit": ("VOL_PLUGIN_KERNEL_CONTEXT", "Kernel/rootkit context", "medium"),
    "Persistence/Context": ("VOL_PLUGIN_PERSISTENCE_CONTEXT", "Persistence/investigation context", "low"),
}


def plugin_context_findings(context: dict, plugin_rows: list[dict]) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for row in plugin_rows:
        if str(row.get("status") or "").lower() != "completed":
            continue
        parsed_count = row.get("parsed_record_count") or 0
        if parsed_count <= 0:
            continue
        extra = row.get("extra_data") if isinstance(row.get("extra_data"), dict) else {}
        category = str(extra.get("plugin_category") or "")
        if category not in PLUGIN_CONTEXT_RULES:
            continue
        rule_id, rule_name, severity = PLUGIN_CONTEXT_RULES[category]
        plugin_name = str(row.get("plugin_name") or row.get("source_plugin") or "Volatility plugin")
        findings.append(
            FindingDraft(
                analysis_job_id=context["analysis_job_id"],
                evidence_id=context["evidence_id"],
                plugin_result_id=row.get("id"),
                os_family=(context.get("os_family") or "unknown").lower(),
                os_scope="windows",
                source_plugin=plugin_name,
                rule_id=rule_id,
                rule_name=rule_name,
                category="plugin_context",
                severity=severity,
                score=5 if severity == "medium" else 2,
                title=f"{rule_name}: {plugin_name}",
                description=(
                    f"{plugin_name} produced {parsed_count} records in the {category} category. "
                    "Treat this as investigation context and correlate it with process, malfind, YARA, network, command-line, and module evidence."
                ),
                artifact_type="plugin_results",
                artifact_id=str(row.get("id")),
                recommendation=(
                    "Review this plugin output as supporting context. Do not treat it as confirmed malware without stronger correlated evidence."
                ),
                extra_data={
                    "finding_intent": "investigation_artifact",
                    "detection_confidence": "context_only",
                    "plugin_category": category,
                    "plugin_name": plugin_name,
                    "cli_plugin_name": extra.get("cli_plugin_name"),
                    "parser_strategy": extra.get("parser_strategy"),
                    "product_purpose": extra.get("product_purpose"),
                    "parsed_record_count": parsed_count,
                },
            )
        )
    return findings


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
    findings.extend(plugin_context_findings(context, load_job_plugin_results(conn, context["analysis_job_id"])))
    findings.extend(build_process_risk_summaries(findings, scoring_config, artifacts))
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
