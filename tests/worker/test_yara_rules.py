# YARA rule discovery and profile-pack tests.

from pathlib import Path
import json

from app.yara.rules import (
    list_yara_rule_files,
    load_yara_pack_rule_metadata,
    profile_is_heavy_yara,
    resolve_yara_rules_path,
    yara_pack_for_profile,
)


class DummySettings:
    volatility_yara_rules_path = None

    def __init__(self, rules_dir: Path):
        self.rules_dir = str(rules_dir)


def write_rule(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("rule TestRule { condition: false }\n", encoding="utf-8")


def test_yara_rules_directory_missing_is_safe(tmp_path) -> None:
    assert list_yara_rule_files(tmp_path) == []
    assert resolve_yara_rules_path(DummySettings(tmp_path)) is None


def test_loader_finds_only_compiled_runtime_packs(tmp_path) -> None:
    write_rule(tmp_path / "yara" / "compiled" / "elastic_yara.yar")
    write_rule(tmp_path / "yara" / "disabled" / "archive" / "ramsight_memory_triage_demo.yar")

    rule_files = list_yara_rule_files(tmp_path)

    assert rule_files == [tmp_path / "yara" / "compiled" / "elastic_yara.yar"]
    assert "disabled" not in resolve_yara_rules_path(DummySettings(tmp_path)).parts


def test_profile_pack_mapping_uses_third_party_packs_only(tmp_path) -> None:
    write_rule(tmp_path / "yara" / "compiled" / "elastic_yara.yar")
    write_rule(tmp_path / "yara" / "compiled" / "neo23x0_yara.yar")
    write_rule(tmp_path / "yara" / "compiled" / "third_party_yara_all.yar")
    settings = DummySettings(tmp_path)

    assert yara_pack_for_profile("windows_memory_yara") == "elastic_yara"
    assert resolve_yara_rules_path(settings, plugin_profile="windows_memory_yara") == tmp_path / "yara" / "compiled" / "elastic_yara.yar"
    assert resolve_yara_rules_path(settings, plugin_profile="windows_memory_yara_elastic") == tmp_path / "yara" / "compiled" / "elastic_yara.yar"
    assert resolve_yara_rules_path(settings, plugin_profile="windows_memory_yara_neo23x0") == tmp_path / "yara" / "compiled" / "neo23x0_yara.yar"
    assert resolve_yara_rules_path(settings, plugin_profile="windows_memory_yara_third_party_all") == tmp_path / "yara" / "compiled" / "third_party_yara_all.yar"
    assert resolve_yara_rules_path(settings, plugin_profile="windows_memory_deep_yara_elastic") == tmp_path / "yara" / "compiled" / "elastic_yara.yar"
    assert resolve_yara_rules_path(settings, plugin_profile="windows_memory_deep_yara_neo23x0") == tmp_path / "yara" / "compiled" / "neo23x0_yara.yar"
    assert resolve_yara_rules_path(settings, plugin_profile="windows_memory_deep_yara_third_party_all") == tmp_path / "yara" / "compiled" / "third_party_yara_all.yar"
    assert profile_is_heavy_yara("windows_memory_yara_third_party_all") is True
    assert profile_is_heavy_yara("windows_memory_deep_yara_third_party_all") is True


def test_disabled_or_archived_configured_yara_path_is_rejected(tmp_path) -> None:
    archived_rule = tmp_path / "rules" / "yara" / "disabled" / "archive" / "ramsight_memory_triage_demo.yar"
    write_rule(archived_rule)

    class ArchivedSettings(DummySettings):
        volatility_yara_rules_path = str(archived_rule)

    assert resolve_yara_rules_path(ArchivedSettings(tmp_path / "rules")) is None


def test_load_yara_pack_rule_metadata(tmp_path) -> None:
    manifest = tmp_path / "yara" / "compiled" / "elastic_yara.manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "rules": {
                    "ElasticRule": {
                        "source_pack": "elastic_yara",
                        "source_repository": "https://github.com/elastic/protections-artifacts",
                        "rule_category": "malware",
                        "malware_family": "example",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    metadata = load_yara_pack_rule_metadata(DummySettings(tmp_path), "elastic_yara")

    assert metadata["elasticrule"]["source_pack"] == "elastic_yara"
    assert metadata["elasticrule"]["rule_category"] == "malware"
