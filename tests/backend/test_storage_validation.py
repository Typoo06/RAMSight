# Tests for safe evidence validation.

import pytest

from app.storage.validation import (
    EvidenceValidationError,
    normalize_safe_filename,
    validate_evidence_extension,
    validate_evidence_file,
)


@pytest.mark.parametrize("filename", ["sample.raw", "sample.MEM", "sample.vmem", "sample.DMP", "sample.lime"])
def test_validate_evidence_extension_allows_supported_extensions_case_insensitive(filename: str) -> None:
    validate_evidence_extension(filename)


def test_validate_evidence_extension_rejects_unsupported_extension() -> None:
    with pytest.raises(EvidenceValidationError):
        validate_evidence_extension("sample.exe")


def test_validate_evidence_file_rejects_empty_file(tmp_path) -> None:
    evidence_path = tmp_path / "empty.raw"
    evidence_path.write_bytes(b"")

    with pytest.raises(EvidenceValidationError):
        validate_evidence_file(evidence_path)


def test_validate_evidence_file_rejects_file_over_max_size(tmp_path) -> None:
    evidence_path = tmp_path / "sample.mem"
    evidence_path.write_bytes(b"12345")

    with pytest.raises(EvidenceValidationError):
        validate_evidence_file(evidence_path, max_size_bytes=4)


def test_validate_evidence_file_accepts_valid_file(tmp_path) -> None:
    evidence_path = tmp_path / "sample.vmem"
    evidence_path.write_bytes(b"1")

    validate_evidence_file(evidence_path, max_size_bytes=10)


def test_normalize_safe_filename_strips_paths_and_unsafe_characters() -> None:
    assert normalize_safe_filename("../Memory Dump (Lab).RAW") == "Memory_Dump_Lab_.RAW"


def test_normalize_safe_filename_rejects_empty_safe_name() -> None:
    with pytest.raises(EvidenceValidationError):
        normalize_safe_filename("////")
