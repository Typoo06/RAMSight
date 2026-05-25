# IOC extraction tests.

from uuid import uuid4

from app.ioc.extractor import (
    COMMAND_TABLE,
    MEMORY_REGION_TABLE,
    MODULE_TABLE,
    NETWORK_TABLE,
    YARA_TABLE,
    extract_iocs,
    is_public_ip,
)
from app.ioc.types import (
    IOC_COMMAND_LINE,
    IOC_FILE_PATH,
    IOC_IP_ADDRESS,
    IOC_MEMORY_REGION,
    IOC_MODULE_PATH,
    IOC_NETWORK_ENDPOINT,
    IOC_PID,
    IOC_YARA_RULE,
)


def context() -> dict:
    return {"analysis_job_id": uuid4(), "evidence_id": uuid4(), "os_family": "windows"}


def iocs_by_type(iocs, ioc_type: str):
    return [ioc for ioc in iocs if ioc.ioc_type == ioc_type]


def risk_finding(artifact_type: str, artifact_id, severity: str = "high") -> dict:
    return {
        "id": uuid4(),
        "artifact_type": artifact_type,
        "artifact_id": str(artifact_id),
        "severity": severity,
        "category": "network",
        "source_plugin": "windows.netscan",
        "rule_id": "TEST_RULE",
        "rule_name": "Test rule",
    }


def test_public_ip_and_network_endpoint_extraction() -> None:
    artifact_id = uuid4()
    artifacts = {
        NETWORK_TABLE: [
            {
                "id": artifact_id,
                "remote_address": "8.8.8.8",
                "remote_port": 443,
                "local_address": "10.0.0.2",
                "local_port": 50000,
                "protocol": "TCP",
                "pid": 42,
                "process_name": "browser.exe",
                "source_plugin": "windows.netscan",
            }
        ]
    }

    iocs = extract_iocs(artifacts, [], context())

    assert iocs_by_type(iocs, IOC_IP_ADDRESS)[0].normalized_value == "8.8.8.8"
    assert iocs_by_type(iocs, IOC_NETWORK_ENDPOINT)[0].normalized_value == "8.8.8.8:443"
    assert iocs_by_type(iocs, IOC_IP_ADDRESS)[0].extra_data["protocol"] == "TCP"


def test_non_public_ip_handling() -> None:
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("169.254.1.1") is False
    assert is_public_ip("224.0.0.1") is False
    assert is_public_ip("0.0.0.0") is False

    artifact_id = uuid4()
    artifacts = {NETWORK_TABLE: [{"id": artifact_id, "remote_address": "192.168.1.2", "remote_port": 445}]}

    assert extract_iocs(artifacts, [], context()) == []

    linked = extract_iocs(artifacts, [risk_finding(NETWORK_TABLE, artifact_id, severity="low")], context())
    network_iocs = [ioc for ioc in linked if ioc.ioc_type in {IOC_IP_ADDRESS, IOC_NETWORK_ENDPOINT}]

    assert len(network_iocs) == 2
    assert all((ioc.confidence or 0) <= 40 for ioc in network_iocs)
    assert network_iocs[0].risk_finding_id is not None


def test_suspicious_command_line_extracted_and_harmless_ignored() -> None:
    artifacts = {
        COMMAND_TABLE: [
            {"id": uuid4(), "command": "powershell.exe -enc " + "SQBFAFgA" * 8, "pid": 10, "process_name": "powershell.exe"},
            {"id": uuid4(), "command": "cmd.exe /c dir", "pid": 11, "process_name": "cmd.exe"},
        ]
    }

    iocs = extract_iocs(artifacts, [], context())

    assert len(iocs_by_type(iocs, IOC_COMMAND_LINE)) == 1
    assert "encoded PowerShell" in iocs_by_type(iocs, IOC_COMMAND_LINE)[0].context


def test_suspicious_module_path_extracted_and_normal_system_module_ignored() -> None:
    artifacts = {
        MODULE_TABLE: [
            {
                "id": uuid4(),
                "module_name": "evil.dll",
                "module_path": "C:\\Users\\Public\\evil.dll",
                "pid": 22,
                "process_name": "sample.exe",
                "source_plugin": "windows.dlllist",
            },
            {
                "id": uuid4(),
                "module_name": "kernel32.dll",
                "module_path": "C:\\Windows\\System32\\kernel32.dll",
                "pid": 22,
                "process_name": "sample.exe",
                "source_plugin": "windows.dlllist",
            },
        ]
    }

    iocs = extract_iocs(artifacts, [], context())

    assert len(iocs_by_type(iocs, IOC_MODULE_PATH)) == 1
    assert iocs_by_type(iocs, IOC_MODULE_PATH)[0].normalized_value == "c:/users/public/evil.dll"


def test_placeholder_path_values_are_not_extracted_as_iocs() -> None:
    module_id = uuid4()
    process_id = uuid4()
    artifacts = {
        MODULE_TABLE: [
            {"id": module_id, "module_name": "missing.dll", "module_path": "Disabled", "source_plugin": "windows.dlllist"}
        ],
        "process_artifacts": [
            {"id": process_id, "pid": 500, "name": "lsass.exe", "image_path": "Not recorded", "source_plugin": "windows.pslist"}
        ],
    }
    findings = [risk_finding(MODULE_TABLE, module_id), risk_finding("process_artifacts", process_id)]

    iocs = extract_iocs(artifacts, findings, context())

    assert iocs_by_type(iocs, IOC_MODULE_PATH) == []
    assert iocs_by_type(iocs, IOC_FILE_PATH) == []


def test_yara_rule_ioc_extraction() -> None:
    artifacts = {
        YARA_TABLE: [
            {
                "id": uuid4(),
                "rule_name": "SuspiciousRule",
                "namespace": "default",
                "tags": ["malware"],
                "target_identifier": "1234",
                "offset": 4096,
                "matched_text_excerpt": "MZ",
                "source_plugin": "yarascan",
                "extra_data": {"severity": "critical"},
            }
        ]
    }

    iocs = extract_iocs(artifacts, [], context())

    assert len(iocs_by_type(iocs, IOC_YARA_RULE)) == 1
    assert iocs_by_type(iocs, IOC_YARA_RULE)[0].extra_data["severity"] == "critical"


def test_memory_region_ioc_extraction() -> None:
    artifacts = {
        MEMORY_REGION_TABLE: [
            {
                "id": uuid4(),
                "pid": 333,
                "process_name": "sample.exe",
                "start_address": "0x1000",
                "end_address": "0x2000",
                "protection": "PAGE_EXECUTE_READWRITE",
                "is_executable": True,
                "is_private": True,
                "source_plugin": "windows.malfind",
            }
        ]
    }

    iocs = extract_iocs(artifacts, [], context())

    assert len(iocs_by_type(iocs, IOC_MEMORY_REGION)) == 1
    assert iocs_by_type(iocs, IOC_MEMORY_REGION)[0].value == "333:0x1000-0x2000"
    assert iocs_by_type(iocs, IOC_MEMORY_REGION)[0].extra_data["is_executable"] is True


def test_memory_region_ioc_uses_clear_fallback_without_unknown_unknown() -> None:
    artifacts = {
        MEMORY_REGION_TABLE: [
            {
                "id": uuid4(),
                "pid": 1128,
                "process_name": "NOTEPAD.exe",
                "start_address": None,
                "end_address": None,
                "protection": "PAGE_EXECUTE_READWRITE",
                "is_executable": True,
                "is_private": True,
                "source_plugin": "windows.malfind",
            }
        ]
    }

    iocs = extract_iocs(artifacts, [], context())

    memory_ioc = iocs_by_type(iocs, IOC_MEMORY_REGION)[0]
    assert memory_ioc.value == "pid:1128:malfind-region:1"
    assert "unknown-unknown" not in memory_ioc.value
    assert memory_ioc.extra_data["region_index"] == 1


def test_risk_finding_id_linkage_and_pid_context() -> None:
    artifact_id = uuid4()
    finding = risk_finding("process_artifacts", artifact_id, severity="high")
    artifacts = {
        "process_artifacts": [
            {
                "id": artifact_id,
                "pid": 777,
                "ppid": 4,
                "name": "odd.exe",
                "image_path": "C:\\Temp\\odd.exe",
                "source_plugin": "windows.pslist",
            }
        ]
    }

    iocs = extract_iocs(artifacts, [finding], context())


    assert any(ioc.risk_finding_id == finding["id"] for ioc in iocs)
    assert any(ioc.ioc_type == "pid" and ioc.value == "777" for ioc in iocs)


def test_deduplication_by_type_value_and_source_plugin() -> None:
    artifact_one = uuid4()
    artifact_two = uuid4()
    artifacts = {
        NETWORK_TABLE: [
            {"id": artifact_one, "remote_address": "8.8.8.8", "remote_port": 443, "source_plugin": "windows.netscan"},
            {"id": artifact_two, "remote_address": "8.8.8.8", "remote_port": 443, "source_plugin": "windows.netscan"},
        ]
    }

    iocs = extract_iocs(artifacts, [], context())

    assert len(iocs_by_type(iocs, IOC_IP_ADDRESS)) == 1
    assert len(iocs_by_type(iocs, IOC_NETWORK_ENDPOINT)) == 1


def test_pid_iocs_deduplicate_across_pslist_and_psscan_sources() -> None:
    pslist_id = uuid4()
    psscan_id = uuid4()
    artifacts = {
        "process_artifacts": [
            {"id": pslist_id, "pid": 777, "name": "odd.exe", "source_plugin": "windows.pslist"},
            {"id": psscan_id, "pid": 777, "name": "odd.exe", "source_plugin": "windows.psscan"},
        ]
    }
    findings = [risk_finding("process_artifacts", pslist_id), risk_finding("process_artifacts", psscan_id)]

    iocs = extract_iocs(artifacts, findings, context())

    assert len(iocs_by_type(iocs, IOC_PID)) == 1
