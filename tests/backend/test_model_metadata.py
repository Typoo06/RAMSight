# Model metadata registration tests.

from sqlalchemy import Uuid

from app.models import Base


EXPECTED_TABLES = {
    "users",
    "cases",
    "evidences",
    "analysis_jobs",
    "plugin_results",
    "process_artifacts",
    "network_artifacts",
    "module_artifacts",
    "memory_region_artifacts",
    "command_artifacts",
    "yara_matches",
    "iocs",
    "risk_findings",
    "reports",
    "analyst_notes",
    "audit_logs",
}


def test_expected_tables_are_registered() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_all_tables_use_uuid_primary_keys() -> None:
    for table in Base.metadata.tables.values():
        primary_key_columns = list(table.primary_key.columns)
        assert len(primary_key_columns) == 1
        assert primary_key_columns[0].name == "id"
        assert isinstance(primary_key_columns[0].type, Uuid)


def test_no_model_uses_reserved_metadata_column_name() -> None:
    for table in Base.metadata.tables.values():
        assert "metadata" not in table.columns


def test_os_aware_tables_have_expected_fields() -> None:
    for table_name in ["evidences", "analysis_jobs"]:
        table = Base.metadata.tables[table_name]
        assert "os_family" in table.columns
        assert "os_version" in table.columns
        assert "architecture" in table.columns
        assert "kernel_version" in table.columns
        assert "symbol_table" in table.columns

    for table_name in [
        "plugin_results",
        "process_artifacts",
        "network_artifacts",
        "module_artifacts",
        "memory_region_artifacts",
        "command_artifacts",
        "yara_matches",
        "iocs",
        "risk_findings",
    ]:
        table = Base.metadata.tables[table_name]
        assert "os_family" in table.columns
        assert "source_plugin" in table.columns


def test_mutable_status_tables_have_updated_at() -> None:
    for table_name in ["analysis_jobs", "plugin_results", "reports", "risk_findings", "iocs"]:
        assert "updated_at" in Base.metadata.tables[table_name].columns
