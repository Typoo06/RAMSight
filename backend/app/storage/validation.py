# Evidence filename and file validation helpers.

from pathlib import PurePath, Path
import re
import unicodedata

from app.storage.constants import ALLOWED_EVIDENCE_EXTENSIONS

SAFE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


class EvidenceValidationError(ValueError):
    pass


def normalize_safe_filename(filename: str) -> str:
    basename = PurePath(filename).name.strip()
    normalized = unicodedata.normalize("NFKD", basename).encode("ascii", "ignore").decode("ascii")
    safe_name = SAFE_NAME_PATTERN.sub("_", normalized).strip("._-")
    if not safe_name:
        raise EvidenceValidationError("filename does not contain safe characters")
    return safe_name


def validate_evidence_extension(filename: str) -> None:
    suffix = PurePath(filename).suffix.lower()
    if suffix not in ALLOWED_EVIDENCE_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EVIDENCE_EXTENSIONS))
        raise EvidenceValidationError(f"unsupported evidence extension '{suffix}'. Allowed: {allowed}")


def validate_evidence_file(path: Path, max_size_bytes: int | None = None) -> None:
    if not path.exists() or not path.is_file():
        raise EvidenceValidationError("evidence path must point to an existing file")
    validate_evidence_extension(path.name)

    size_bytes = path.stat().st_size
    if size_bytes <= 0:
        raise EvidenceValidationError("evidence file must not be empty")
    if max_size_bytes is not None and size_bytes > max_size_bytes:
        raise EvidenceValidationError("evidence file exceeds configured maximum size")
