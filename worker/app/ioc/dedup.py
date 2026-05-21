# Deterministic IOC normalization and deduplication.

import ipaddress
import re
from dataclasses import replace

from app.ioc.types import (
    IOC_COMMAND_LINE,
    IOC_FILE_PATH,
    IOC_IP_ADDRESS,
    IOC_MEMORY_REGION,
    IOC_MODULE_PATH,
    IOC_NETWORK_ENDPOINT,
    IOC_PID,
    IOC_PLUGIN_REFERENCE,
    IOC_PROCESS_NAME,
    IOC_YARA_RULE,
    IOCRecordDraft,
)

WHITESPACE_RE = re.compile(r"\s+")


def normalize_ip_address(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def normalize_path(value: str, os_family: str | None = None) -> str:
    normalized = value.strip().replace("\\", "/")
    if (os_family or "unknown").lower() == "windows":
        normalized = normalized.lower()
    return normalized


def normalize_endpoint(value: str) -> str:
    address, separator, port = value.strip().strip("[]").rpartition(":")
    normalized_address = normalize_ip_address(address) if separator else None
    if normalized_address and port:
        return f"{normalized_address}:{port}"
    return value.strip().lower()


def normalize_ioc_value(ioc_type: str, value: str, os_family: str | None = None) -> str:
    if ioc_type == IOC_IP_ADDRESS:
        return normalize_ip_address(value) or value.strip().lower()
    if ioc_type == IOC_NETWORK_ENDPOINT:
        return normalize_endpoint(value)
    if ioc_type in {IOC_FILE_PATH, IOC_MODULE_PATH}:
        return normalize_path(value, os_family)
    if ioc_type == IOC_COMMAND_LINE:
        return WHITESPACE_RE.sub(" ", value.strip())
    if ioc_type in {IOC_PROCESS_NAME, IOC_YARA_RULE, IOC_PLUGIN_REFERENCE}:
        return value.strip().lower()
    if ioc_type in {IOC_PID, IOC_MEMORY_REGION}:
        return value.strip().lower()
    return value.strip()


def deduplicate_iocs(iocs: list[IOCRecordDraft]) -> list[IOCRecordDraft]:
    best: dict[tuple, IOCRecordDraft] = {}
    for ioc in iocs:
        normalized_value = ioc.normalized_value or normalize_ioc_value(ioc.ioc_type, ioc.value, ioc.os_family)
        normalized = replace(ioc, normalized_value=normalized_value)
        key = (normalized.analysis_job_id, normalized.ioc_type, normalized.normalized_value, normalized.source_plugin or "")
        existing = best.get(key)
        if existing is None or (normalized.confidence or 0) > (existing.confidence or 0):
            best[key] = normalized
    return [best[key] for key in sorted(best, key=lambda item: (str(item[0]), item[1], item[2], item[3]))]
