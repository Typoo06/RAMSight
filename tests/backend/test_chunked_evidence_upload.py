# Browser chunked evidence upload endpoint tests.

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.core.config import get_settings
from app.main import app
from app.models import Base, Case
from app.storage.client import EvidenceUploadResult, StorageObject, get_storage_client
from app.storage.hashing import calculate_file_hashes
from app.storage.keys import evidence_object_key
from app.storage.validation import normalize_safe_filename


class FakeStorageClient:

    def __init__(self) -> None:
        self.uploads: list[dict] = []

    def ensure_buckets(self) -> None:
        return None

    def upload_evidence(self, case_id, evidence_id, path, original_filename):
        safe_filename = normalize_safe_filename(original_filename)
        hashes = calculate_file_hashes(path, chunk_size=3)
        payload = path.read_bytes()
        self.uploads.append(
            {
                "case_id": str(case_id),
                "evidence_id": str(evidence_id),
                "safe_filename": safe_filename,
                "payload": payload,
            }
        )
        return EvidenceUploadResult(
            safe_filename=safe_filename,
            hashes=hashes,
            storage_object=StorageObject(
                bucket="evidence",
                key=evidence_object_key(case_id, evidence_id, safe_filename),
                size_bytes=hashes.size_bytes,
                etag="fake-etag",
            ),
        )


@pytest.fixture()
def client_context(tmp_path, monkeypatch):
    monkeypatch.setenv("EVIDENCE_UPLOAD_TEMP_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("EVIDENCE_UPLOAD_CHUNK_SIZE_BYTES", "4")
    monkeypatch.setenv("EVIDENCE_UPLOAD_SESSION_TTL_SECONDS", "86400")
    monkeypatch.setenv("EVIDENCE_MAX_UPLOAD_BYTES", "32")
    get_settings.cache_clear()

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    fake_storage = FakeStorageClient()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_storage_client] = lambda: fake_storage
    try:
        yield TestClient(app), TestingSessionLocal, fake_storage, tmp_path / "uploads"
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        get_settings.cache_clear()


def seed_case(session_factory) -> Case:
    db = session_factory()
    try:
        case = Case(case_code=f"CASE-UPLOAD-{uuid4()}", name="Chunked upload")
        db.add(case)
        db.commit()
        db.refresh(case)
        return case
    finally:
        db.close()


def initiate(client: TestClient, case_id, filename: str = "memory.raw", size_bytes: int = 10):
    return client.post(
        "/api/v1/evidences/uploads/initiate",
        json={
            "case_id": str(case_id),
            "original_filename": filename,
            "size_bytes": size_bytes,
            "os_family": "windows",
            "architecture": "x64",
        },
    )


def upload_chunk(client: TestClient, upload_id: str, chunk_index: int, payload: bytes):
    return client.put(
        f"/api/v1/evidences/uploads/{upload_id}/chunks/{chunk_index}",
        content=payload,
        headers={"content-type": "application/octet-stream"},
    )


def test_initiate_upload_session_creates_manifest(client_context) -> None:
    client, session_factory, _, upload_root = client_context
    case = seed_case(session_factory)

    response = initiate(client, case.id)

    assert response.status_code == 201
    payload = response.json()
    assert payload["chunk_size"] == 4
    assert payload["max_size_bytes"] == 32
    assert payload["total_chunks"] == 3
    assert (upload_root / payload["upload_id"] / "manifest.json").is_file()
    assert (upload_root / payload["upload_id"] / "evidence.tmp").is_file()


def test_direct_upload_rejects_oversized_file_before_storage_upload(client_context, monkeypatch) -> None:
    monkeypatch.setenv("EVIDENCE_DIRECT_UPLOAD_MAX_BYTES", "4")
    get_settings.cache_clear()
    client, session_factory, fake_storage, _ = client_context
    case = seed_case(session_factory)

    response = client.post(
        "/api/v1/evidences/upload",
        data={"case_id": str(case.id), "os_family": "windows"},
        files={"file": ("memory.raw", b"abcde", "application/octet-stream")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "direct evidence upload exceeds maximum size; use browser chunked upload for large memory dumps"
    )
    assert fake_storage.uploads == []


def test_register_rejects_local_path_for_demo_workflow(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)

    response = client.post(
        "/api/v1/evidences/register",
        json={
            "case_id": str(case.id),
            "source_type": "local_path",
            "original_filename": "memory.raw",
            "local_path": "/mnt/lab/memory.raw",
            "os_family": "windows",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "local_path evidence registration is disabled for the demo workflow; use upload or minio_object"


def test_initiate_rejects_unsafe_extension(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)

    response = initiate(client, case.id, filename="memory.exe")

    assert response.status_code == 400
    assert "unsupported evidence file extension" in response.json()["detail"]


def test_initiate_rejects_declared_size_over_limit(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)

    response = initiate(client, case.id, size_bytes=33)

    assert response.status_code == 400
    assert response.json()["detail"] == "evidence file exceeds maximum upload size"


def test_chunk_upload_rejects_oversized_chunk(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)
    upload_id = initiate(client, case.id).json()["upload_id"]

    response = upload_chunk(client, upload_id, 0, b"abcde")

    assert response.status_code == 400
    assert response.json()["detail"] == "chunk exceeds expected size"


def test_chunk_upload_allows_same_chunk_retry(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)
    upload_id = initiate(client, case.id).json()["upload_id"]

    first = upload_chunk(client, upload_id, 0, b"abcd")
    retry = upload_chunk(client, upload_id, 0, b"abcd")

    assert first.status_code == 200
    assert retry.status_code == 200
    assert retry.json()["received_chunks"] == 1
    assert retry.json()["uploaded_bytes"] == 4


def test_complete_fails_when_chunks_are_missing(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)
    upload_id = initiate(client, case.id).json()["upload_id"]
    upload_chunk(client, upload_id, 0, b"abcd")

    response = client.post(f"/api/v1/evidences/uploads/{upload_id}/complete")

    assert response.status_code == 400
    assert response.json()["detail"] == "upload is missing chunks"


def test_complete_creates_evidence_metadata_and_cleans_temp_session(client_context) -> None:
    client, session_factory, fake_storage, upload_root = client_context
    case = seed_case(session_factory)
    upload_id = initiate(client, case.id).json()["upload_id"]
    upload_chunk(client, upload_id, 0, b"abcd")
    upload_chunk(client, upload_id, 1, b"efgh")
    upload_chunk(client, upload_id, 2, b"ij")

    response = client.post(f"/api/v1/evidences/uploads/{upload_id}/complete")

    assert response.status_code == 201
    payload = response.json()
    assert payload["original_filename"] == "memory.raw"
    assert payload["size_bytes"] == 10
    assert payload["md5"] == "a925576942e94b2ef57a066101b48876"
    assert payload["sha256"] == "72399361da6a7754fec986dca5b7cbaf1c810a28ded4abaf56b2106d06cb78b0"
    assert payload["storage_bucket"] == "evidence"
    assert fake_storage.uploads[0]["payload"] == b"abcdefghij"
    assert not (upload_root / upload_id).exists()


def test_cancel_removes_temp_session(client_context) -> None:
    client, session_factory, _, upload_root = client_context
    case = seed_case(session_factory)
    upload_id = initiate(client, case.id).json()["upload_id"]

    response = client.delete(f"/api/v1/evidences/uploads/{upload_id}")

    assert response.status_code == 204
    assert not (upload_root / upload_id).exists()
