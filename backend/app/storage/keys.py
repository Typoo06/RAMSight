# OS-neutral object key helpers for MinIO/S3 paths.

from pathlib import PurePath
import re
import unicodedata

SAFE_KEY_PART_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def normalize_object_name_part(value: object) -> str:
    text = PurePath(str(value)).name.strip()
    normalized = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    safe_value = SAFE_KEY_PART_PATTERN.sub("_", normalized).strip("._-")
    if not safe_value:
        raise ValueError("object key component must contain safe characters")
    return safe_value


def normalize_plugin_name_part(plugin_name: str) -> str:
    return normalize_object_name_part(plugin_name.replace(".", "_"))


def evidence_object_key(case_id: object, evidence_id: object, safe_filename: str) -> str:
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"evidence-{normalize_object_name_part(evidence_id)}/"
        f"{normalize_object_name_part(safe_filename)}"
    )


def raw_plugin_output_key(case_id: object, job_id: object, plugin_name: str) -> str:
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"job-{normalize_object_name_part(job_id)}/raw/"
        f"{normalize_plugin_name_part(plugin_name)}.json"
    )


def parsed_plugin_output_key(case_id: object, job_id: object, plugin_name: str) -> str:
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"job-{normalize_object_name_part(job_id)}/parsed/"
        f"{normalize_plugin_name_part(plugin_name)}.json"
    )


def ioc_export_key(case_id: object, job_id: object, filename: str) -> str:
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"job-{normalize_object_name_part(job_id)}/iocs/"
        f"{normalize_object_name_part(filename)}"
    )


def report_object_key(case_id: object, job_id: object, report_filename: str) -> str:
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"job-{normalize_object_name_part(job_id)}/reports/"
        f"{normalize_object_name_part(report_filename)}"
    )

