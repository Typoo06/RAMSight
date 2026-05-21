# IOC value objects and type names.

from dataclasses import dataclass, field
from uuid import UUID, uuid4

IOC_PROCESS_NAME = "process_name"
IOC_PID = "pid"
IOC_COMMAND_LINE = "command_line"
IOC_IP_ADDRESS = "ip_address"
IOC_NETWORK_ENDPOINT = "network_endpoint"
IOC_FILE_PATH = "file_path"
IOC_MODULE_PATH = "module_path"
IOC_YARA_RULE = "yara_rule"
IOC_MEMORY_REGION = "memory_region"
IOC_PLUGIN_REFERENCE = "plugin_reference"


@dataclass(frozen=True)
class IOCRecordDraft:
    analysis_job_id: UUID
    evidence_id: UUID
    risk_finding_id: UUID | None
    os_family: str
    source_plugin: str | None
    ioc_type: str
    value: str
    normalized_value: str
    context: str | None
    confidence: int | None
    extra_data: dict | None = None
    id: UUID = field(default_factory=uuid4)
