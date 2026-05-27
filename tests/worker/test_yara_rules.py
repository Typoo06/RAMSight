# YARA rule discovery tests.

from pathlib import Path

from app.yara.rules import list_yara_rule_files, resolve_yara_rules_path


class DummySettings:
    volatility_yara_rules_path = None

    def __init__(self, rules_dir: Path):
        self.rules_dir = str(rules_dir)


def test_yara_rules_directory_missing_is_safe(tmp_path) -> None:
    assert list_yara_rule_files(tmp_path) == []
    assert resolve_yara_rules_path(DummySettings(tmp_path)) is None


def test_yara_rule_loader_finds_safe_demo_rules(tmp_path) -> None:
    yara_dir = tmp_path / "yara"
    yara_dir.mkdir()
    demo_rule = yara_dir / "ramsight_demo.yar"
    demo_rule.write_text("rule RAMSight_Demo_Test { condition: false }", encoding="utf-8")

    assert list_yara_rule_files(tmp_path) == [demo_rule]
    assert resolve_yara_rules_path(DummySettings(tmp_path)) == demo_rule


def test_configured_yara_rules_directory_is_supported(tmp_path) -> None:
    configured_dir = tmp_path / "configured"
    configured_dir.mkdir()
    demo_rule = configured_dir / "memory.yara"
    demo_rule.write_text("rule RAMSight_Configured_Test { condition: false }", encoding="utf-8")

    class ConfiguredDirectorySettings(DummySettings):
        volatility_yara_rules_path = str(configured_dir)

    assert resolve_yara_rules_path(ConfiguredDirectorySettings(tmp_path)) == demo_rule
