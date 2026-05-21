"""Object key builders for MinIO/S3 storage."""

from pathlib import PurePath
import re
import unicodedata

SAFE_KEY_PART_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def normalize_object_name_part(value: object) -> str:
    """Normalize a user/plugin/id value into a safe object-key component."""
    text = PurePath(str(value)).name.strip()
    normalized = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    safe_value = SAFE_KEY_PART_PATTERN.sub("_", normalized).strip("._-")
    if not safe_value:
        raise ValueError("object key component must contain safe characters")
    return safe_value


def evidence_object_key(case_id: object, evidence_id: object, filename: str) -> str:
    """Build an object key for an uploaded memory dump."""
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"evidence-{normalize_object_name_part(evidence_id)}/"
        f"{normalize_object_name_part(filename)}"
    )


def raw_plugin_output_key(case_id: object, job_id: object, plugin_name: str) -> str:
    """Build an object key for raw plugin JSON output."""
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"job-{normalize_object_name_part(job_id)}/raw/"
        f"{normalize_object_name_part(plugin_name)}.json"
    )


def parsed_plugin_output_key(case_id: object, job_id: object, plugin_name: str) -> str:
    """Build an object key for parsed plugin JSON output."""
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"job-{normalize_object_name_part(job_id)}/parsed/"
        f"{normalize_object_name_part(plugin_name)}.json"
    )


def report_object_key(case_id: object, job_id: object, report_filename: str) -> str:
    """Build an object key for generated reports or report-like exports."""
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"job-{normalize_object_name_part(job_id)}/reports/"
        f"{normalize_object_name_part(report_filename)}"
    )
