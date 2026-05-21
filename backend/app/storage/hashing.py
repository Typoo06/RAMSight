"""Streaming file hashing helpers."""

from dataclasses import dataclass
import hashlib
from pathlib import Path

from app.storage.constants import DEFAULT_HASH_CHUNK_SIZE


@dataclass(frozen=True)
class FileHashResult:
    """Hashes and byte size for a file."""

    md5: str
    sha256: str
    size_bytes: int


def calculate_file_hashes(path: Path, chunk_size: int = DEFAULT_HASH_CHUNK_SIZE) -> FileHashResult:
    """Calculate MD5, SHA256, and size while streaming file content."""
    md5_hash = hashlib.md5(usedforsecurity=False)
    sha256_hash = hashlib.sha256()
    size_bytes = 0

    with path.open("rb") as file_obj:
        while chunk := file_obj.read(chunk_size):
            size_bytes += len(chunk)
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return FileHashResult(md5=md5_hash.hexdigest(), sha256=sha256_hash.hexdigest(), size_bytes=size_bytes)
