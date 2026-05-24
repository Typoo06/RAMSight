# Evidence filename and size validation.

from pathlib import Path, PurePath
import re
import unicodedata

from app.storage.constants import ALLOWED_EVIDENCE_EXTENSIONS

SAFE_FILENAME_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


class EvidenceValidationError(ValueError):
    pass


def normalize_safe_filename(filename: str) -> str:
    name = PurePath(filename).name.strip()
    normalized = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    safe_filename = SAFE_FILENAME_PATTERN.sub("_", normalized).strip("._-")
    if not safe_filename:
        raise EvidenceValidationError("filename must contain safe characters")
    return safe_filename


def validate_evidence_extension(filename: str) -> None:
    extension = PurePath(filename).suffix.lower()
    if extension not in ALLOWED_EVIDENCE_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EVIDENCE_EXTENSIONS))
        raise EvidenceValidationError(f"unsupported evidence file extension; allowed extensions: {allowed}")


def validate_evidence_file(path: Path, max_size_bytes: int | None = None) -> None:
    if not path.is_file():
        raise EvidenceValidationError("evidence file does not exist")

    size_bytes = path.stat().st_size
    if size_bytes <= 0:
        raise EvidenceValidationError("evidence file is empty")
    if max_size_bytes is not None and size_bytes > max_size_bytes:
        raise EvidenceValidationError("evidence file exceeds maximum upload size")

