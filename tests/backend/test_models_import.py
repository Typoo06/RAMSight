# Import tests for SQLAlchemy models.

from app.models import (
    AnalysisJob,
    AnalystNote,
    AuditLog,
    Case,
    CommandArtifact,
    Evidence,
    IOC,
    MemoryRegionArtifact,
    ModuleArtifact,
    NetworkArtifact,
    PluginResult,
    ProcessArtifact,
    Report,
    RiskFinding,
    User,
    YaraMatch,
)


def test_models_import() -> None:
    assert User.__tablename__ == "users"
    assert Case.__tablename__ == "cases"
    assert Evidence.__tablename__ == "evidences"
    assert AnalysisJob.__tablename__ == "analysis_jobs"
    assert PluginResult.__tablename__ == "plugin_results"
    assert ProcessArtifact.__tablename__ == "process_artifacts"
    assert NetworkArtifact.__tablename__ == "network_artifacts"
    assert ModuleArtifact.__tablename__ == "module_artifacts"
    assert MemoryRegionArtifact.__tablename__ == "memory_region_artifacts"
    assert CommandArtifact.__tablename__ == "command_artifacts"
    assert YaraMatch.__tablename__ == "yara_matches"
    assert IOC.__tablename__ == "iocs"
    assert RiskFinding.__tablename__ == "risk_findings"
    assert Report.__tablename__ == "reports"
    assert AnalystNote.__tablename__ == "analyst_notes"
    assert AuditLog.__tablename__ == "audit_logs"
