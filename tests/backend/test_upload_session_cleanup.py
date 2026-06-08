# Stale browser upload session cleanup tests.

from datetime import datetime, timedelta, timezone
import json
import os
from uuid import uuid4

from app.core.config import Settings
from app.services.evidence_upload_session_service import cleanup_expired_upload_sessions


def make_settings(upload_root, ttl_seconds: int = 60) -> Settings:
    return Settings(
        EVIDENCE_UPLOAD_TEMP_DIR=upload_root,
        EVIDENCE_UPLOAD_SESSION_TTL_SECONDS=ttl_seconds,
    )


def write_manifest(session_dir, expires_at: datetime | None) -> None:
    session_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "upload_id": session_dir.name,
        "case_id": str(uuid4()),
        "original_filename": "memory.raw",
        "size_bytes": 4,
        "chunk_size": 4,
        "total_chunks": 1,
        "received_chunks": {},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
    (session_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (session_dir / "evidence.tmp").write_bytes(b"")


def test_cleanup_removes_expired_sessions_and_preserves_active(tmp_path) -> None:
    now = datetime(2026, 6, 8, 12, 0, tzinfo=timezone.utc)
    upload_root = tmp_path / "uploads"
    expired = upload_root / str(uuid4())
    active = upload_root / str(uuid4())
    write_manifest(expired, now - timedelta(seconds=1))
    write_manifest(active, now + timedelta(seconds=60))

    counts = cleanup_expired_upload_sessions(make_settings(upload_root), now=now)

    assert counts["scanned"] == 2
    assert counts["removed"] == 1
    assert counts["expired"] == 1
    assert counts["active"] == 1
    assert not expired.exists()
    assert active.exists()


def test_cleanup_ignores_unrelated_files_and_directories(tmp_path) -> None:
    now = datetime(2026, 6, 8, 12, 0, tzinfo=timezone.utc)
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    unrelated_file = upload_root / "notes.txt"
    unrelated_dir = upload_root / "not-a-uuid"
    unrelated_file.write_text("keep", encoding="utf-8")
    unrelated_dir.mkdir()
    (unrelated_dir / "manifest.json").write_text("{}", encoding="utf-8")

    counts = cleanup_expired_upload_sessions(make_settings(upload_root), now=now)

    assert counts["scanned"] == 0
    assert counts["removed"] == 0
    assert counts["ignored"] == 2
    assert unrelated_file.exists()
    assert unrelated_dir.exists()


def test_cleanup_removes_corrupt_session_only_when_stale(tmp_path) -> None:
    now = datetime(2026, 6, 8, 12, 0, tzinfo=timezone.utc)
    upload_root = tmp_path / "uploads"
    stale_corrupt = upload_root / str(uuid4())
    recent_corrupt = upload_root / str(uuid4())
    for session_dir in (stale_corrupt, recent_corrupt):
        session_dir.mkdir(parents=True)
        (session_dir / "manifest.json").write_text("not-json", encoding="utf-8")

    stale_timestamp = (now - timedelta(seconds=120)).timestamp()
    recent_timestamp = (now - timedelta(seconds=10)).timestamp()
    os.utime(stale_corrupt, (stale_timestamp, stale_timestamp))
    os.utime(recent_corrupt, (recent_timestamp, recent_timestamp))

    counts = cleanup_expired_upload_sessions(make_settings(upload_root, ttl_seconds=60), now=now)

    assert counts["scanned"] == 2
    assert counts["removed"] == 1
    assert counts["corrupt_stale"] == 1
    assert counts["active"] == 1
    assert not stale_corrupt.exists()
    assert recent_corrupt.exists()


def test_cleanup_removes_missing_manifest_session_only_when_stale(tmp_path) -> None:
    now = datetime(2026, 6, 8, 12, 0, tzinfo=timezone.utc)
    upload_root = tmp_path / "uploads"
    stale_missing = upload_root / str(uuid4())
    active_missing = upload_root / str(uuid4())
    stale_missing.mkdir(parents=True)
    active_missing.mkdir(parents=True)
    stale_timestamp = (now - timedelta(seconds=120)).timestamp()
    active_timestamp = (now - timedelta(seconds=10)).timestamp()
    os.utime(stale_missing, (stale_timestamp, stale_timestamp))
    os.utime(active_missing, (active_timestamp, active_timestamp))

    counts = cleanup_expired_upload_sessions(make_settings(upload_root, ttl_seconds=60), now=now)

    assert counts["scanned"] == 2
    assert counts["removed"] == 1
    assert counts["corrupt_stale"] == 1
    assert counts["active"] == 1
    assert not stale_missing.exists()
    assert active_missing.exists()
