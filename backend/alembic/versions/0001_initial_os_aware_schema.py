"""Initial OS-aware schema."""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial_os_aware_schema"
down_revision = None
branch_labels = None
depends_on = None


def _timestamps(updated: bool = False) -> list[sa.Column]:
    columns = [sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)]
    if updated:
        columns.append(sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    return columns


def _artifact_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_job_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("plugin_result_id", sa.Uuid(), nullable=True),
        sa.Column("os_family", sa.String(length=20), nullable=False),
        sa.Column("source_plugin", sa.String(length=255), nullable=True),
        sa.Column("raw_record", sa.JSON(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_jobs.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidences.id"]),
        sa.ForeignKeyConstraint(["plugin_result_id"], ["plugin_results.id"]),
        sa.PrimaryKeyConstraint("id"),
    ]


def _artifact_indexes(table_name: str) -> None:
    op.create_index(op.f(f"ix_{table_name}_analysis_job_id"), table_name, ["analysis_job_id"])
    op.create_index(op.f(f"ix_{table_name}_evidence_id"), table_name, ["evidence_id"])
    op.create_index(op.f(f"ix_{table_name}_os_family"), table_name, ["os_family"])
    op.create_index(op.f(f"ix_{table_name}_plugin_result_id"), table_name, ["plugin_result_id"])
    op.create_index(op.f(f"ix_{table_name}_source_plugin"), table_name, ["source_plugin"])


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        *_timestamps(updated=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)

    op.create_table(
        "cases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_code", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        *_timestamps(updated=True),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_cases_case_code"), "cases", ["case_code"], unique=True)
    op.create_index(op.f("ix_cases_created_by_id"), "cases", ["created_by_id"])
    op.create_index(op.f("ix_cases_status"), "cases", ["status"])

    op.create_table(
        "evidences",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("uploaded_by_id", sa.Uuid(), nullable=True),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("md5", sa.String(length=32), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("storage_bucket", sa.String(length=255), nullable=True),
        sa.Column("storage_key", sa.String(length=1024), nullable=True),
        sa.Column("local_path", sa.String(length=1024), nullable=True),
        sa.Column("os_family", sa.String(length=20), nullable=False),
        sa.Column("os_version", sa.String(length=255), nullable=True),
        sa.Column("architecture", sa.String(length=100), nullable=True),
        sa.Column("kernel_version", sa.String(length=255), nullable=True),
        sa.Column("symbol_table", sa.String(length=255), nullable=True),
        sa.Column("acquisition_tool", sa.String(length=255), nullable=True),
        sa.Column("acquisition_time", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(updated=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["uploaded_by_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_evidences_case_id"), "evidences", ["case_id"])
    op.create_index(op.f("ix_evidences_md5"), "evidences", ["md5"])
    op.create_index(op.f("ix_evidences_os_family"), "evidences", ["os_family"])
    op.create_index(op.f("ix_evidences_sha256"), "evidences", ["sha256"])
    op.create_index(op.f("ix_evidences_uploaded_by_id"), "evidences", ["uploaded_by_id"])

    op.create_table(
        "analysis_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("os_family", sa.String(length=20), nullable=False),
        sa.Column("os_version", sa.String(length=255), nullable=True),
        sa.Column("architecture", sa.String(length=100), nullable=True),
        sa.Column("kernel_version", sa.String(length=255), nullable=True),
        sa.Column("symbol_table", sa.String(length=255), nullable=True),
        sa.Column("plugin_profile", sa.String(length=100), nullable=True),
        sa.Column("requested_plugins", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(updated=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidences.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_analysis_jobs_case_id"), "analysis_jobs", ["case_id"])
    op.create_index(op.f("ix_analysis_jobs_created_by_id"), "analysis_jobs", ["created_by_id"])
    op.create_index(op.f("ix_analysis_jobs_evidence_id"), "analysis_jobs", ["evidence_id"])
    op.create_index(op.f("ix_analysis_jobs_os_family"), "analysis_jobs", ["os_family"])
    op.create_index(op.f("ix_analysis_jobs_plugin_profile"), "analysis_jobs", ["plugin_profile"])
    op.create_index(op.f("ix_analysis_jobs_status"), "analysis_jobs", ["status"])

    op.create_table(
        "plugin_results",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_job_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("os_family", sa.String(length=20), nullable=False),
        sa.Column("plugin_profile", sa.String(length=100), nullable=True),
        sa.Column("plugin_name", sa.String(length=255), nullable=False),
        sa.Column("source_plugin", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("raw_output_bucket", sa.String(length=255), nullable=True),
        sa.Column("raw_output_key", sa.String(length=1024), nullable=True),
        sa.Column("parsed_output_bucket", sa.String(length=255), nullable=True),
        sa.Column("parsed_output_key", sa.String(length=1024), nullable=True),
        sa.Column("parsed_record_count", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("extra_data", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(updated=True),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_jobs.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidences.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_plugin_results_analysis_job_id"), "plugin_results", ["analysis_job_id"])
    op.create_index(op.f("ix_plugin_results_evidence_id"), "plugin_results", ["evidence_id"])
    op.create_index(op.f("ix_plugin_results_os_family"), "plugin_results", ["os_family"])
    op.create_index(op.f("ix_plugin_results_plugin_name"), "plugin_results", ["plugin_name"])
    op.create_index(op.f("ix_plugin_results_plugin_profile"), "plugin_results", ["plugin_profile"])
    op.create_index(op.f("ix_plugin_results_source_plugin"), "plugin_results", ["source_plugin"])
    op.create_index(op.f("ix_plugin_results_status"), "plugin_results", ["status"])

    op.create_table(
        "process_artifacts",
        *_artifact_columns(),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("ppid", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("image_path", sa.String(length=1024), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("user_name", sa.String(length=255), nullable=True),
        sa.Column("session_id", sa.Integer(), nullable=True),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exited_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_hidden_candidate", sa.Boolean(), nullable=False),
    )
    _artifact_indexes("process_artifacts")
    op.create_index(op.f("ix_process_artifacts_name"), "process_artifacts", ["name"])
    op.create_index(op.f("ix_process_artifacts_pid"), "process_artifacts", ["pid"])
    op.create_index(op.f("ix_process_artifacts_ppid"), "process_artifacts", ["ppid"])

    op.create_table(
        "network_artifacts",
        *_artifact_columns(),
        sa.Column("protocol", sa.String(length=50), nullable=True),
        sa.Column("local_address", sa.String(length=255), nullable=True),
        sa.Column("local_port", sa.Integer(), nullable=True),
        sa.Column("remote_address", sa.String(length=255), nullable=True),
        sa.Column("remote_port", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(length=100), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=True),
    )
    _artifact_indexes("network_artifacts")
    op.create_index(op.f("ix_network_artifacts_local_address"), "network_artifacts", ["local_address"])
    op.create_index(op.f("ix_network_artifacts_pid"), "network_artifacts", ["pid"])
    op.create_index(op.f("ix_network_artifacts_protocol"), "network_artifacts", ["protocol"])
    op.create_index(op.f("ix_network_artifacts_remote_address"), "network_artifacts", ["remote_address"])
    op.create_index(op.f("ix_network_artifacts_state"), "network_artifacts", ["state"])

    op.create_table(
        "module_artifacts",
        *_artifact_columns(),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("module_name", sa.String(length=255), nullable=True),
        sa.Column("module_path", sa.String(length=1024), nullable=True),
        sa.Column("base_address", sa.String(length=100), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("load_time", sa.DateTime(timezone=True), nullable=True),
    )
    _artifact_indexes("module_artifacts")
    op.create_index(op.f("ix_module_artifacts_module_name"), "module_artifacts", ["module_name"])
    op.create_index(op.f("ix_module_artifacts_pid"), "module_artifacts", ["pid"])

    op.create_table(
        "memory_region_artifacts",
        *_artifact_columns(),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("start_address", sa.String(length=100), nullable=True),
        sa.Column("end_address", sa.String(length=100), nullable=True),
        sa.Column("protection", sa.String(length=100), nullable=True),
        sa.Column("is_executable", sa.Boolean(), nullable=False),
        sa.Column("is_private", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("hexdump_excerpt", sa.Text(), nullable=True),
        sa.Column("disassembly_excerpt", sa.Text(), nullable=True),
    )
    _artifact_indexes("memory_region_artifacts")
    op.create_index(op.f("ix_memory_region_artifacts_pid"), "memory_region_artifacts", ["pid"])
    op.create_index(op.f("ix_memory_region_artifacts_protection"), "memory_region_artifacts", ["protection"])
    op.create_index(op.f("ix_memory_region_artifacts_start_address"), "memory_region_artifacts", ["start_address"])

    op.create_table(
        "command_artifacts",
        *_artifact_columns(),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("shell_type", sa.String(length=100), nullable=True),
        sa.Column("user_name", sa.String(length=255), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
    )
    _artifact_indexes("command_artifacts")
    op.create_index(op.f("ix_command_artifacts_pid"), "command_artifacts", ["pid"])
    op.create_index(op.f("ix_command_artifacts_shell_type"), "command_artifacts", ["shell_type"])

    op.create_table(
        "yara_matches",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_job_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("plugin_result_id", sa.Uuid(), nullable=True),
        sa.Column("os_family", sa.String(length=20), nullable=False),
        sa.Column("source_plugin", sa.String(length=255), nullable=True),
        sa.Column("rule_name", sa.String(length=255), nullable=False),
        sa.Column("namespace", sa.String(length=255), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("target_type", sa.String(length=100), nullable=True),
        sa.Column("target_identifier", sa.String(length=255), nullable=True),
        sa.Column("offset", sa.Integer(), nullable=True),
        sa.Column("matched_text_excerpt", sa.Text(), nullable=True),
        sa.Column("extra_data", sa.JSON(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_jobs.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidences.id"]),
        sa.ForeignKeyConstraint(["plugin_result_id"], ["plugin_results.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_yara_matches_analysis_job_id"), "yara_matches", ["analysis_job_id"])
    op.create_index(op.f("ix_yara_matches_evidence_id"), "yara_matches", ["evidence_id"])
    op.create_index(op.f("ix_yara_matches_os_family"), "yara_matches", ["os_family"])
    op.create_index(op.f("ix_yara_matches_plugin_result_id"), "yara_matches", ["plugin_result_id"])
    op.create_index(op.f("ix_yara_matches_rule_name"), "yara_matches", ["rule_name"])
    op.create_index(op.f("ix_yara_matches_source_plugin"), "yara_matches", ["source_plugin"])
    op.create_index(op.f("ix_yara_matches_target_identifier"), "yara_matches", ["target_identifier"])
    op.create_index(op.f("ix_yara_matches_target_type"), "yara_matches", ["target_type"])

    op.create_table(
        "risk_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_job_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("plugin_result_id", sa.Uuid(), nullable=True),
        sa.Column("os_family", sa.String(length=20), nullable=False),
        sa.Column("os_scope", sa.String(length=20), nullable=False),
        sa.Column("source_plugin", sa.String(length=255), nullable=True),
        sa.Column("rule_id", sa.String(length=255), nullable=True),
        sa.Column("rule_name", sa.String(length=255), nullable=True),
        sa.Column("category", sa.String(length=100), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("artifact_type", sa.String(length=100), nullable=True),
        sa.Column("artifact_id", sa.String(length=100), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("extra_data", sa.JSON(), nullable=True),
        *_timestamps(updated=True),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_jobs.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidences.id"]),
        sa.ForeignKeyConstraint(["plugin_result_id"], ["plugin_results.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_risk_findings_analysis_job_id"), "risk_findings", ["analysis_job_id"])
    op.create_index(op.f("ix_risk_findings_artifact_id"), "risk_findings", ["artifact_id"])
    op.create_index(op.f("ix_risk_findings_artifact_type"), "risk_findings", ["artifact_type"])
    op.create_index(op.f("ix_risk_findings_category"), "risk_findings", ["category"])
    op.create_index(op.f("ix_risk_findings_evidence_id"), "risk_findings", ["evidence_id"])
    op.create_index(op.f("ix_risk_findings_os_family"), "risk_findings", ["os_family"])
    op.create_index(op.f("ix_risk_findings_os_scope"), "risk_findings", ["os_scope"])
    op.create_index(op.f("ix_risk_findings_plugin_result_id"), "risk_findings", ["plugin_result_id"])
    op.create_index(op.f("ix_risk_findings_rule_id"), "risk_findings", ["rule_id"])
    op.create_index(op.f("ix_risk_findings_rule_name"), "risk_findings", ["rule_name"])
    op.create_index(op.f("ix_risk_findings_score"), "risk_findings", ["score"])
    op.create_index(op.f("ix_risk_findings_severity"), "risk_findings", ["severity"])
    op.create_index(op.f("ix_risk_findings_source_plugin"), "risk_findings", ["source_plugin"])

    op.create_table(
        "iocs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_job_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("risk_finding_id", sa.Uuid(), nullable=True),
        sa.Column("os_family", sa.String(length=20), nullable=False),
        sa.Column("source_plugin", sa.String(length=255), nullable=True),
        sa.Column("ioc_type", sa.String(length=100), nullable=False),
        sa.Column("value", sa.String(length=1024), nullable=False),
        sa.Column("normalized_value", sa.String(length=1024), nullable=True),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("extra_data", sa.JSON(), nullable=True),
        *_timestamps(updated=True),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_jobs.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidences.id"]),
        sa.ForeignKeyConstraint(["risk_finding_id"], ["risk_findings.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_iocs_analysis_job_id"), "iocs", ["analysis_job_id"])
    op.create_index(op.f("ix_iocs_evidence_id"), "iocs", ["evidence_id"])
    op.create_index(op.f("ix_iocs_ioc_type"), "iocs", ["ioc_type"])
    op.create_index(op.f("ix_iocs_normalized_value"), "iocs", ["normalized_value"])
    op.create_index(op.f("ix_iocs_os_family"), "iocs", ["os_family"])
    op.create_index(op.f("ix_iocs_risk_finding_id"), "iocs", ["risk_finding_id"])
    op.create_index(op.f("ix_iocs_source_plugin"), "iocs", ["source_plugin"])
    op.create_index(op.f("ix_iocs_value"), "iocs", ["value"])

    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_job_id", sa.Uuid(), nullable=False),
        sa.Column("os_family", sa.String(length=20), nullable=False),
        sa.Column("report_type", sa.String(length=50), nullable=False),
        sa.Column("format", sa.String(length=20), nullable=False),
        sa.Column("storage_bucket", sa.String(length=255), nullable=True),
        sa.Column("storage_key", sa.String(length=1024), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(updated=True),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_jobs.id"]),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidences.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_reports_analysis_job_id"), "reports", ["analysis_job_id"])
    op.create_index(op.f("ix_reports_case_id"), "reports", ["case_id"])
    op.create_index(op.f("ix_reports_evidence_id"), "reports", ["evidence_id"])
    op.create_index(op.f("ix_reports_format"), "reports", ["format"])
    op.create_index(op.f("ix_reports_os_family"), "reports", ["os_family"])
    op.create_index(op.f("ix_reports_report_type"), "reports", ["report_type"])

    op.create_table(
        "analyst_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=True),
        sa.Column("analysis_job_id", sa.Uuid(), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        *_timestamps(updated=True),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_jobs.id"]),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidences.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_analyst_notes_analysis_job_id"), "analyst_notes", ["analysis_job_id"])
    op.create_index(op.f("ix_analyst_notes_case_id"), "analyst_notes", ["case_id"])
    op.create_index(op.f("ix_analyst_notes_created_by_id"), "analyst_notes", ["created_by_id"])
    op.create_index(op.f("ix_analyst_notes_evidence_id"), "analyst_notes", ["evidence_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=100), nullable=True),
        sa.Column("entity_id", sa.String(length=100), nullable=True),
        sa.Column("extra_data", sa.JSON(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"])
    op.create_index(op.f("ix_audit_logs_entity_id"), "audit_logs", ["entity_id"])
    op.create_index(op.f("ix_audit_logs_entity_type"), "audit_logs", ["entity_type"])
    op.create_index(op.f("ix_audit_logs_user_id"), "audit_logs", ["user_id"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("analyst_notes")
    op.drop_table("reports")
    op.drop_table("iocs")
    op.drop_table("risk_findings")
    op.drop_table("yara_matches")
    op.drop_table("command_artifacts")
    op.drop_table("memory_region_artifacts")
    op.drop_table("module_artifacts")
    op.drop_table("network_artifacts")
    op.drop_table("process_artifacts")
    op.drop_table("plugin_results")
    op.drop_table("analysis_jobs")
    op.drop_table("evidences")
    op.drop_table("cases")
    op.drop_table("users")
