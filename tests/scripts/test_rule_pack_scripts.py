from pathlib import Path
import sys

import pytest

pytest.importorskip("yara")

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_RULES = REPO_ROOT / "scripts" / "rules"
sys.path.insert(0, str(SCRIPTS_RULES))

import build_yara_pack  # noqa: E402
import rule_pack_common  # noqa: E402
import validate_yara_rules  # noqa: E402
from rule_pack_common import SourceDefinition  # noqa: E402


def write_rule(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def source_definition(tmp_path: Path) -> SourceDefinition:
    return SourceDefinition(
        key="test_source",
        source_repository="example/test-source",
        source_url="https://example.invalid/test-source",
        default_ref="main",
        license_name="Example License",
        rule_paths=("yara",),
        import_root=tmp_path / "rules" / "yara" / "third_party" / "test_source",
        manifest_root=tmp_path / "rules" / "yara" / "manifests",
        rule_extensions={".yar", ".yara"},
        runtime_pack="test_yara",
    )


def test_sigma_source_is_reference_only_not_yara_runtime() -> None:
    assert rule_pack_common.SOURCES["sigmahq"].runtime_pack is None
    assert all("sigmahq" not in sources for sources in rule_pack_common.PACK_SOURCES.values())


def test_validate_source_quarantines_invalid_yara(monkeypatch, tmp_path) -> None:
    source = source_definition(tmp_path)
    write_rule(source.import_root / "valid.yar", "rule ValidRule { condition: false }\n")
    write_rule(source.import_root / "invalid.yar", "rule InvalidRule { condition: }\n")

    monkeypatch.setattr(rule_pack_common, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(validate_yara_rules, "SOURCES", {"test_source": source})
    monkeypatch.setattr(validate_yara_rules, "YARA_ROOT", tmp_path / "rules" / "yara")

    manifest = validate_yara_rules.validate_source("test_source")

    assert manifest["enabled_file_count"] == 1
    assert manifest["disabled_file_count"] == 1
    assert (tmp_path / "rules" / "yara" / "disabled" / "test_source" / "invalid.yar").is_file()


def test_build_pack_uses_validated_yara_manifest_and_skips_duplicates(monkeypatch, tmp_path) -> None:
    yara_root = tmp_path / "rules" / "yara"
    write_rule(yara_root / "third_party" / "elastic" / "first.yar", "rule DuplicateRule { condition: false }\n")
    write_rule(yara_root / "third_party" / "elastic" / "second.yar", "rule DuplicateRule { condition: false }\n")
    manifest_path = yara_root / "manifests" / "elastic_yara.validation.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        """
        {
          "enabled_files": [
            "rules/yara/third_party/elastic/first.yar",
            "rules/yara/third_party/elastic/second.yar"
          ]
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setattr(rule_pack_common, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_yara_pack, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_yara_pack, "YARA_ROOT", yara_root)
    monkeypatch.setattr(build_yara_pack, "PACK_SOURCES", {"elastic_yara": ("elastic",)})

    manifest = build_yara_pack.build_pack("elastic_yara")

    assert (yara_root / "compiled" / "elastic_yara.yar").is_file()
    assert manifest["source_file_count"] == 1
    assert manifest["skipped_file_count"] == 1
