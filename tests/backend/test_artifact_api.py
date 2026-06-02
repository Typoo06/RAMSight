# Artifact drill-down API tests.

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.main import app
from app.models import (
    AnalysisJob,
    Base,
    Case,
    CommandArtifact,
    Evidence,
    MemoryRegionArtifact,
    ModuleArtifact,
    NetworkArtifact,
    ProcessArtifact,
    YaraMatch,
)


@pytest.fixture()
def client_context():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


def seed_job(db, case_code: str):
    case = Case(case_code=case_code, name=case_code)
    db.add(case)
    db.flush()
    evidence = Evidence(case_id=case.id, original_filename="memory.raw", os_family="windows")
    db.add(evidence)
    db.flush()
    job = AnalysisJob(case_id=case.id, evidence_id=evidence.id, status="completed", os_family="windows")
    db.add(job)
    db.flush()
    return evidence, job


def test_process_artifacts_filter_by_job_pid_source_and_paginate(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        evidence_one, job_one = seed_job(db, "CASE-ARTIFACT-1")
        evidence_two, job_two = seed_job(db, "CASE-ARTIFACT-2")
        db.add_all(
            [
                ProcessArtifact(
                    analysis_job_id=job_one.id,
                    evidence_id=evidence_one.id,
                    os_family="windows",
                    source_plugin="windows.pslist",
                    pid=340,
                    ppid=4,
                    name="svchost.exe",
                    image_path="C:\\Windows\\System32\\svchost.exe",
                    is_hidden_candidate=False,
                    raw_record={"large": "omitted from API"},
                ),
                ProcessArtifact(
                    analysis_job_id=job_one.id,
                    evidence_id=evidence_one.id,
                    os_family="windows",
                    source_plugin="windows.psscan",
                    pid=780,
                    name="notepad.exe",
                    is_hidden_candidate=True,
                ),
                ProcessArtifact(
                    analysis_job_id=job_two.id,
                    evidence_id=evidence_two.id,
                    os_family="windows",
                    source_plugin="windows.pslist",
                    pid=340,
                    name="other.exe",
                    is_hidden_candidate=False,
                ),
            ]
        )
        db.commit()
        job_one_id = str(job_one.id)
    finally:
        db.close()

    response = client.get(
        f"/api/v1/analysis-jobs/{job_one_id}/artifacts/processes",
        params={"pid": 340, "source_plugin": "windows.pslist"},
    )
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["name"] == "svchost.exe"
    assert "raw_record" not in items[0]

    paged = client.get(f"/api/v1/analysis-jobs/{job_one_id}/artifacts/processes", params={"limit": 1, "offset": 1})
    assert paged.status_code == 200
    assert len(paged.json()["items"]) == 1


def test_artifact_endpoints_validate_job_exists(client_context) -> None:
    client, _ = client_context

    response = client.get("/api/v1/analysis-jobs/00000000-0000-0000-0000-000000000000/artifacts/memory-regions")

    assert response.status_code == 404


def test_memory_network_command_and_module_artifact_filters(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        evidence, job = seed_job(db, "CASE-ARTIFACT-FILTERS")
        db.add_all(
            [
                CommandArtifact(
                    analysis_job_id=job.id,
                    evidence_id=evidence.id,
                    os_family="windows",
                    source_plugin="windows.cmdline",
                    pid=340,
                    process_name="svchost.exe",
                    command="svchost.exe -k netsvcs",
                ),
                NetworkArtifact(
                    analysis_job_id=job.id,
                    evidence_id=evidence.id,
                    os_family="windows",
                    source_plugin="windows.netscan",
                    pid=340,
                    process_name="svchost.exe",
                    protocol="TCP",
                    remote_address="8.8.8.8",
                    remote_port=443,
                ),
                ModuleArtifact(
                    analysis_job_id=job.id,
                    evidence_id=evidence.id,
                    os_family="windows",
                    source_plugin="windows.dlllist",
                    pid=340,
                    process_name="svchost.exe",
                    module_name="odd.dll",
                    module_path="C:\\Users\\Public\\odd.dll",
                ),
                MemoryRegionArtifact(
                    analysis_job_id=job.id,
                    evidence_id=evidence.id,
                    os_family="windows",
                    source_plugin="windows.malfind",
                    pid=340,
                    process_name="svchost.exe",
                    start_address="0xcb0000",
                    end_address="0xcbffff",
                    protection="PAGE_EXECUTE_READWRITE",
                    is_executable=True,
                    is_private=True,
                    hexdump_excerpt="4d 5a",
                    disassembly_excerpt="mov eax, eax",
                ),
                MemoryRegionArtifact(
                    analysis_job_id=job.id,
                    evidence_id=evidence.id,
                    os_family="windows",
                    source_plugin="windows.malfind",
                    pid=780,
                    process_name="notepad.exe",
                    start_address="0x1000",
                    end_address="0x2000",
                    protection="PAGE_READWRITE",
                    is_executable=False,
                    is_private=True,
                ),
            ]
        )
        db.commit()
        job_id = str(job.id)
    finally:
        db.close()

    command_response = client.get(f"/api/v1/analysis-jobs/{job_id}/artifacts/commands", params={"pid": 340})
    network_response = client.get(
        f"/api/v1/analysis-jobs/{job_id}/artifacts/network",
        params={"remote_address": "8.8.8.8", "protocol": "TCP"},
    )
    module_response = client.get(f"/api/v1/analysis-jobs/{job_id}/artifacts/modules", params={"pid": 340})
    memory_response = client.get(
        f"/api/v1/analysis-jobs/{job_id}/artifacts/memory-regions",
        params={"executable_only": True},
    )

    assert command_response.status_code == 200
    assert command_response.json()["items"][0]["command"] == "svchost.exe -k netsvcs"
    assert network_response.status_code == 200
    assert network_response.json()["items"][0]["remote_address"] == "8.8.8.8"
    assert module_response.status_code == 200
    assert module_response.json()["items"][0]["module_name"] == "odd.dll"
    assert memory_response.status_code == 200
    memory_items = memory_response.json()["items"]
    assert len(memory_items) == 1
    assert memory_items[0]["start_address"] == "0xcb0000"
    assert memory_items[0]["hexdump_excerpt"] == "4d 5a"


def test_yara_matches_serialize_big_integer_offsets_and_filter_pid_safely(client_context) -> None:
    client, session_factory = client_context
    db = session_factory()
    try:
        evidence, job = seed_job(db, "CASE-YARA-BIGINT")
        large_offset = 9_223_372_000
        db.add_all(
            [
                YaraMatch(
                    analysis_job_id=job.id,
                    evidence_id=evidence.id,
                    os_family="windows",
                    source_plugin="windows.vadyarascan",
                    rule_name="RAMSight_Demo_Injection_API_Cluster",
                    target_type="process_memory",
                    target_identifier="PID 340",
                    offset=large_offset,
                    extra_data={"pid": 340, "offset_raw": hex(large_offset)},
                ),
                YaraMatch(
                    analysis_job_id=job.id,
                    evidence_id=evidence.id,
                    os_family="windows",
                    source_plugin="windows.vadyarascan",
                    rule_name="RAMSight_Demo_PE_Header_In_Memory_Candidate",
                    target_type="process_memory",
                    target_identifier="PID 34",
                    offset=123,
                    extra_data={"pid": 34},
                ),
            ]
        )
        db.commit()
        job_id = str(job.id)
    finally:
        db.close()

    response = client.get(f"/api/v1/analysis-jobs/{job_id}/artifacts/yara-matches", params={"pid": 340})

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["offset"] == large_offset
    assert items[0]["target_identifier"] == "PID 340"
