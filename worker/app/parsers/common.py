# Shared helpers for Volatility output parsers.

from dataclasses import dataclass
from datetime import datetime
import json
import re
from typing import Any

PLACEHOLDER_STRINGS = {
    "",
    "-",
    "disabled",
    "n/a",
    "na",
    "none",
    "not recorded",
    "null",
    "unknown",
}
WINDOWS_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
WINDOWS_ROOT_PATH_RE = re.compile(r"^[\\/][^\\/]+[\\/]")


@dataclass(frozen=True)
class ParsedArtifactBatch:
    table_name: str
    records: list[dict]


class ParserError(ValueError):
    pass


def load_json_file(path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ParserError("Volatility output is not valid JSON") from exc


def load_raw_wrapper(path) -> dict:
    data = load_json_file(path)
    if not isinstance(data, dict):
        raise ParserError("raw wrapper is not a JSON object")
    return data


def parse_stdout_json(wrapper: dict) -> Any:
    stdout = wrapper.get("stdout") or ""
    if not stdout.strip():
        return []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ParserError("Volatility stdout is not valid JSON") from exc


def normalize_key(value: str) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value))
    text = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")
    return text.lower()


def normalize_record(record: dict) -> dict:
    return {normalize_key(key): value for key, value in record.items()}


def extract_rows(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [normalize_record(row) for row in data if isinstance(row, dict)]
    if not isinstance(data, dict):
        return []

    if isinstance(data.get("rows"), list):
        rows = data["rows"]
        columns = data.get("columns")
        if columns and rows and all(not isinstance(row, dict) for row in rows):
            names = [column.get("name") if isinstance(column, dict) else str(column) for column in columns]
            return [normalize_record(dict(zip(names, row))) for row in rows if isinstance(row, list)]
        return [normalize_record(row) for row in rows if isinstance(row, dict)]

    if isinstance(data.get("tree"), list):
        return [normalize_record(row) for row in data["tree"] if isinstance(row, dict)]
    return []


def first_value(row: dict, aliases: list[str]) -> Any:
    for alias in aliases:
        key = normalize_key(alias)
        if key in row and not is_placeholder_value(row[key]):
            return row[key]
    return None


def is_placeholder_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in PLACEHOLDER_STRINGS
    return False


def to_int(value: Any) -> int | None:
    if is_placeholder_value(value):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def to_str(value: Any) -> str | None:
    if is_placeholder_value(value):
        return None
    return str(value).strip()


def to_bool(value: Any) -> bool:
    if is_placeholder_value(value):
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    text = str(value).strip().lower()
    if text in {"true", "yes", "y", "1", "private"}:
        return True
    if text in {"false", "no", "n", "0", "shared"}:
        return False
    return False


def os_family_from_source_plugin(source_plugin: str | None) -> str:
    if source_plugin and source_plugin.startswith("windows."):
        return "windows"
    if source_plugin and source_plugin.startswith("linux."):
        return "linux"
    return "unknown"


def is_path_like(value: Any, os_family: str | None = None) -> bool:
    text = to_str(value)
    if text is None:
        return False
    normalized_family = (os_family or "unknown").lower()
    if normalized_family == "windows":
        return bool(
            WINDOWS_DRIVE_PATH_RE.match(text)
            or text.startswith("\\\\")
            or text.startswith("//")
            or WINDOWS_ROOT_PATH_RE.match(text)
        )
    if normalized_family == "linux":
        return text.startswith("/") or text.startswith("./") or text.startswith("../")
    return (
        bool(WINDOWS_DRIVE_PATH_RE.match(text))
        or text.startswith("\\\\")
        or text.startswith("//")
        or text.startswith("/")
        or text.startswith("./")
        or text.startswith("../")
    )


def to_path(value: Any, os_family: str | None = None) -> str | None:
    text = to_str(value)
    if text is None or not is_path_like(text, os_family):
        return None
    return text


def to_datetime(value: Any) -> datetime | None:
    text = to_str(value)
    if text is None:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def endpoint_parts(value: Any) -> tuple[str | None, int | None]:
    text = to_str(value)
    if text is None:
        return None, None
    if ":" not in text:
        return text, None
    address, port = text.rsplit(":", 1)
    return address.strip("[]"), to_int(port)


def truncate_text(value: Any, limit: int = 4000) -> str | None:
    text = to_str(value)
    if text is None:
        return None
    return text[:limit]
