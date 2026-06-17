# Safe download specifications for generated RAMSight files.

from dataclasses import dataclass

from app.core.config import Settings
from app.models import AnalysisJob, PluginResult, Report
from app.storage.keys import ioc_export_key, report_object_key
from app.storage.validation import normalize_safe_filename
from app.services.errors import NotFoundError, ValidationError


@dataclass(frozen=True)
class DownloadSpec:

    bucket: str
    key: str
    filename: str
    media_type: str
    missing_message: str


def report_download_filename(report: Report) -> str:
    report_format = (report.format or "html").lower()
    report_type = (report.report_type or "technical").lower()
    if report_type == "technical" and report_format == "html":
        return "technical_report.html"
    return normalize_safe_filename(f"{report_type}_report.{report_format}")


def report_media_type(report: Report) -> str:
    if (report.format or "").lower() == "html":
        return "text/html; charset=utf-8"
    return "application/octet-stream"


def report_download_spec(report: Report, settings: Settings) -> DownloadSpec:
    if (report.format or "").lower() != "html":
        raise ValidationError("only HTML report downloads are supported")
    if not report.storage_bucket or not report.storage_key:
        raise NotFoundError("report file is not available")
    if report.storage_bucket != settings.minio_bucket_reports:
        raise ValidationError("report file metadata is invalid")

    filename = report_download_filename(report)
    expected_key = report_object_key(report.case_id, report.analysis_job_id, filename)
    if report.storage_key != expected_key:
        raise ValidationError("report file metadata is invalid")

    return DownloadSpec(
        bucket=report.storage_bucket,
        key=report.storage_key,
        filename=filename,
        media_type=report_media_type(report),
        missing_message="Report file is not available yet.",
    )


def ioc_export_download_spec(job: AnalysisJob, export_format: str, settings: Settings) -> DownloadSpec:
    normalized_format = export_format.lower()
    if normalized_format == "json":
        filename = "ioc_export.json"
        media_type = "application/json"
    elif normalized_format == "csv":
        filename = "ioc_export.csv"
        media_type = "text/csv; charset=utf-8"
    else:
        raise ValidationError("unsupported IOC export format")

    return DownloadSpec(
        bucket=settings.minio_bucket_raw_outputs,
        key=ioc_export_key(job.case_id, job.id, filename),
        filename=filename,
        media_type=media_type,
        missing_message="IOC export is not available for this analysis job.",
    )


def plugin_raw_output_download_spec(plugin_result: PluginResult, settings: Settings) -> DownloadSpec:
    if not plugin_result.raw_output_bucket or not plugin_result.raw_output_key:
        raise NotFoundError("raw plugin output is not available")
    if plugin_result.raw_output_bucket != settings.minio_bucket_raw_outputs:
        raise ValidationError("raw plugin output metadata is invalid")

    safe_plugin_name = normalize_safe_filename(plugin_result.plugin_name.replace(".", "_"))
    return DownloadSpec(
        bucket=plugin_result.raw_output_bucket,
        key=plugin_result.raw_output_key,
        filename=f"{safe_plugin_name}_raw_output.json",
        media_type="application/json",
        missing_message="Raw plugin output is not available for this plugin result.",
    )
