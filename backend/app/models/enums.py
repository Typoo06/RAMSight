"""String values used by OS-aware database models."""

from enum import StrEnum


class OSFamily(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


class EvidenceSourceType(StrEnum):
    UPLOAD = "upload"
    MINIO_OBJECT = "minio_object"
    LOCAL_PATH = "local_path"


class AnalysisJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PluginResultStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OSScope(StrEnum):
    ALL = "all"
    WINDOWS = "windows"
    LINUX = "linux"


class ReportFormat(StrEnum):
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"


class ReportType(StrEnum):
    TECHNICAL = "technical"
    EXECUTIVE_SUMMARY = "executive_summary"
    IOC_EXPORT = "ioc_export"
