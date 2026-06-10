# Direct multipart evidence upload endpoint tests.

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
from app.storage.client import StorageObject, get_storage_client


class FakeMultipartStorageClient:

    def __init__(self) -> None:
        self.evidence_bucket = "evidence"
        self.created: list[dict] = []
        self.presigned: list[dict] = []
        self.completed: list[dict] = []
        self.aborted: list[dict] = []
        self.deleted: list[dict] = []
        self.stream_payload = b"abcdefghij"
        self.stream_size: int | None = None

    def create_multipart_upload(self, bucket: str, object_key: str, content_type: str | None = None) -> str:
        upload_id = f"fake-upload-{len(self.created) + 1}"
        self.created.append({"bucket": bucket, "key": object_key, "content_type": content_type, "upload_id": upload_id})
        return upload_id

    def presign_upload_part(self, bucket: str, object_key: str, upload_id: str, part_number: int, expires_seconds: int) -> str:
        self.presigned.append({"bucket": bucket, "key": object_key, "upload_id": upload_id, "part_number": part_number})
        return f"http://localhost:9000/{bucket}/{object_key}?partNumber={part_number}"

    def complete_multipart_upload(self, bucket: str, object_key: str, upload_id: str, parts: list[dict[str, object]]) -> StorageObject:
        self.completed.append({"bucket": bucket, "key": object_key, "upload_id": upload_id, "parts": parts})
        size = self.stream_size if self.stream_size is not None else len(self.stream_payload)
        return StorageObject(bucket=bucket, key=object_key, size_bytes=size, etag="complete-etag")

    def abort_multipart_upload(self, bucket: str, object_key: str, upload_id: str) -> None:
        self.aborted.append({"bucket": bucket, "key": object_key, "upload_id": upload_id})

    def delete_object(self, bucket: str, object_key: str) -> None:
        self.deleted.append({"bucket": bucket, "key": object_key})

    def iter_object_chunks(self, bucket: str, object_key: str, chunk_size: int = 1024 * 1024):
        if self.stream_size is None:
            for index in range(0, len(self.stream_payload), chunk_size):
                yield self.stream_payload[index:index + chunk_size]
            return

        remaining = self.stream_size
        while remaining > 0:
            next_size = min(chunk_size, remaining)
            yield b"a" * next_size
            remaining -= next_size


@pytest.fixture()
def client_context(tmp_path, monkeypatch):
    monkeypatch.setenv("EVIDENCE_UPLOAD_TEMP_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("EVIDENCE_MULTIPART_PART_SIZE_BYTES", str(5 * 1024 * 1024))
    monkeypatch.setenv("EVIDENCE_UPLOAD_SESSION_TTL_SECONDS", "86400")
    monkeypatch.setenv("EVIDENCE_MAX_UPLOAD_BYTES", str(12 * 1024 * 1024))
    get_settings.cache_clear()

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    fake_storage = FakeMultipartStorageClient()

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
        case = Case(case_code=f"CASE-MULTIPART-{uuid4()}", name="Multipart upload")
        db.add(case)
        db.commit()
        db.refresh(case)
        return case
    finally:
        db.close()


def initiate(client: TestClient, case_id, filename: str = "memory.raw", size_bytes: int = 10):
    return client.post(
        "/api/v1/evidences/multipart/initiate",
        json={
            "case_id": str(case_id),
            "filename": filename,
            "size_bytes": size_bytes,
            "content_type": "application/octet-stream",
            "os_family": "windows",
            "architecture": "x64",
        },
    )


def record_part(client: TestClient, session_id: str, part_number: int, etag: str = '"etag"', size_bytes: int = 10):
    return client.post(
        f"/api/v1/evidences/multipart/{session_id}/parts",
        json={"part_number": part_number, "etag": etag, "size_bytes": size_bytes},
    )


def test_initiate_multipart_upload_creates_manifest_without_temp_evidence_file(client_context) -> None:
    client, session_factory, fake_storage, upload_root = client_context
    case = seed_case(session_factory)

    response = initiate(client, case.id)

    assert response.status_code == 201
    payload = response.json()
    assert payload["recommended_part_size_bytes"] == 5 * 1024 * 1024
    assert payload["expected_part_count"] == 1
    assert payload["object_key"].startswith(f"case-{case.id}/evidence-")
    session_dir = upload_root / payload["upload_session_id"]
    assert (session_dir / "manifest.json").is_file()
    assert not (session_dir / "evidence.tmp").exists()
    assert fake_storage.created[0]["bucket"] == "evidence"


def test_initiate_multipart_rejects_invalid_extension(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)

    response = initiate(client, case.id, filename="memory.exe")

    assert response.status_code == 400
    assert "unsupported evidence file extension" in response.json()["detail"]


def test_presign_part_rejects_out_of_range_part_number(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)
    session_id = initiate(client, case.id).json()["upload_session_id"]

    response = client.post(f"/api/v1/evidences/multipart/{session_id}/presign-part", json={"part_number": 2})

    assert response.status_code == 400
    assert response.json()["detail"] == "part number is outside the upload range"


def test_record_part_rejects_invalid_etag(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)
    session_id = initiate(client, case.id).json()["upload_session_id"]

    response = record_part(client, session_id, 1, etag="bad\netag")

    assert response.status_code == 400
    assert response.json()["detail"] == "part ETag is invalid"


def test_complete_multipart_requires_all_parts(client_context) -> None:
    client, session_factory, _, _ = client_context
    case = seed_case(session_factory)
    session_id = initiate(client, case.id).json()["upload_session_id"]

    response = client.post(f"/api/v1/evidences/multipart/{session_id}/complete")

    assert response.status_code == 400
    assert response.json()["detail"] == "multipart upload is missing parts"


def test_complete_multipart_sorts_parts_and_creates_evidence_metadata(client_context) -> None:
    client, session_factory, fake_storage, upload_root = client_context
    case = seed_case(session_factory)
    size_bytes = (5 * 1024 * 1024) + 1
    fake_storage.stream_payload = b""
    fake_storage.stream_size = size_bytes
    session_id = initiate(client, case.id, size_bytes=size_bytes).json()["upload_session_id"]
    record_part(client, session_id, 2, etag='"etag-2"', size_bytes=1)
    record_part(client, session_id, 1, etag='"etag-1"', size_bytes=5 * 1024 * 1024)

    response = client.post(f"/api/v1/evidences/multipart/{session_id}/complete")

    assert response.status_code == 201
    payload = response.json()
    assert payload["original_filename"] == "memory.raw"
    assert payload["size_bytes"] == size_bytes
    assert payload["storage_bucket"] == "evidence"
    assert fake_storage.completed[0]["parts"] == [
        {"part_number": 1, "etag": '"etag-1"'},
        {"part_number": 2, "etag": '"etag-2"'},
    ]
    assert not (upload_root / session_id).exists()


def test_complete_multipart_hashes_streamed_object(client_context) -> None:
    client, session_factory, fake_storage, _ = client_context
    case = seed_case(session_factory)
    session_id = initiate(client, case.id).json()["upload_session_id"]
    record_part(client, session_id, 1, etag='"etag-1"', size_bytes=10)

    response = client.post(f"/api/v1/evidences/multipart/{session_id}/complete")

    assert response.status_code == 201
    payload = response.json()
    assert payload["md5"] == "a925576942e94b2ef57a066101b48876"
    assert payload["sha256"] == "72399361da6a7754fec986dca5b7cbaf1c810a28ded4abaf56b2106d06cb78b0"
    assert fake_storage.completed


def test_cancel_multipart_aborts_storage_upload_and_removes_session(client_context) -> None:
    client, session_factory, fake_storage, upload_root = client_context
    case = seed_case(session_factory)
    session_id = initiate(client, case.id).json()["upload_session_id"]

    response = client.delete(f"/api/v1/evidences/multipart/{session_id}")

    assert response.status_code == 204
    assert fake_storage.aborted
    assert not (upload_root / session_id).exists()
