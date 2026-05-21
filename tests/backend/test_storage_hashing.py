"""Tests for streaming hash calculation."""

import hashlib

from app.storage.hashing import calculate_file_hashes


def test_calculate_file_hashes_streams_file_content(tmp_path) -> None:
    content = b"memory-triage-test-content" * 10
    evidence_path = tmp_path / "sample.raw"
    evidence_path.write_bytes(content)

    result = calculate_file_hashes(evidence_path, chunk_size=7)

    assert result.md5 == hashlib.md5(content, usedforsecurity=False).hexdigest()
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.size_bytes == len(content)
