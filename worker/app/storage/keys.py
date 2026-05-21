# Object key helpers used by worker output uploads.

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


def raw_plugin_output_key(case_id: object, job_id: object, plugin_name: str) -> str:
    return (
        f"case-{normalize_object_name_part(case_id)}/"
        f"job-{normalize_object_name_part(job_id)}/raw/"
        f"{normalize_object_name_part(plugin_name)}.json"
    )

