# Streaming file hashing helpers.

from collections.abc import Iterable
from dataclasses import dataclass
import hashlib
from pathlib import Path

from app.storage.constants import DEFAULT_HASH_CHUNK_SIZE


@dataclass(frozen=True)
class FileHashResult:

    md5: str
    sha256: str
    size_bytes: int


def _md5_hash():
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:
        return hashlib.md5()


def calculate_file_hashes(path: Path, chunk_size: int = DEFAULT_HASH_CHUNK_SIZE) -> FileHashResult:
    md5_hash = _md5_hash()
    sha256_hash = hashlib.sha256()
    size_bytes = 0

    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(chunk_size), b""):
            size_bytes += len(chunk)
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return FileHashResult(md5=md5_hash.hexdigest(), sha256=sha256_hash.hexdigest(), size_bytes=size_bytes)



def calculate_stream_hashes(chunks: Iterable[bytes]) -> FileHashResult:
    md5_hash = _md5_hash()
    sha256_hash = hashlib.sha256()
    size_bytes = 0

    for chunk in chunks:
        if not chunk:
            continue
        size_bytes += len(chunk)
        md5_hash.update(chunk)
        sha256_hash.update(chunk)

    return FileHashResult(md5=md5_hash.hexdigest(), sha256=sha256_hash.hexdigest(), size_bytes=size_bytes)
