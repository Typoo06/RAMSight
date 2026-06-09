# YARA rule discovery tests.

from pathlib import Path
import re

import yara
from app.yara.rules import list_yara_rule_files, resolve_yara_rules_path

REPO_ROOT = Path(__file__).resolve().parents[2]
YARA_RULES_DIR = REPO_ROOT / "rules" / "yara"
REQUIRED_META_KEYS = {
    "description",
    "author",
    "category",
    "severity",
    "scope",
    "thesis_topic",
    "false_positive_note",
}
RULE_RE = re.compile(r"(?ms)^\s*rule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{(?P<body>.*?)^\}", re.MULTILINE)
META_RE = re.compile(r"(?ms)\bmeta\s*:\s*(?P<meta>.*?)(?:\n\s*strings\s*:|\n\s*condition\s*:)")
META_KEY_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", re.MULTILINE)
CONDITION_RE = re.compile(r"(?ms)\bcondition\s*:\s*(?P<condition>.*)")


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


def test_configured_repo_relative_yara_rules_path_is_supported(tmp_path) -> None:
    rules_dir = tmp_path / "rules"
    yara_dir = rules_dir / "yara"
    yara_dir.mkdir(parents=True)
    demo_rule = yara_dir / "memory.yar"
    demo_rule.write_text("rule RAMSight_Relative_Path_Test { condition: false }", encoding="utf-8")

    class RepoRelativeSettings(DummySettings):
        volatility_yara_rules_path = "rules/yara/memory.yar"

    assert resolve_yara_rules_path(RepoRelativeSettings(rules_dir)) == demo_rule


def test_configured_rules_dir_relative_yara_rules_path_is_supported(tmp_path) -> None:
    rules_dir = tmp_path / "rules"
    yara_dir = rules_dir / "yara"
    yara_dir.mkdir(parents=True)
    demo_rule = yara_dir / "memory.yar"
    demo_rule.write_text("rule RAMSight_Rules_Dir_Relative_Test { condition: false }", encoding="utf-8")

    class RulesDirRelativeSettings(DummySettings):
        volatility_yara_rules_path = "yara/memory.yar"

    assert resolve_yara_rules_path(RulesDirRelativeSettings(rules_dir)) == demo_rule


def project_yara_files() -> list[Path]:
    return sorted(path for path in YARA_RULES_DIR.iterdir() if path.suffix.lower() in {".yar", ".yara"})


def project_yara_rules() -> list[tuple[Path, str, str]]:
    rules = []
    for path in project_yara_files():
        text = path.read_text(encoding="utf-8")
        for match in RULE_RE.finditer(text):
            rules.append((path, match.group("name"), match.group("body")))
    return rules


def test_project_yara_rules_compile() -> None:
    for path in project_yara_files():
        yara.compile(filepath=str(path))


def test_project_yara_rule_names_are_unique() -> None:
    names = [name for _, name, _ in project_yara_rules()]
    assert names
    assert len(names) == len(set(names))


def test_project_yara_rules_have_required_metadata() -> None:
    for path, rule_name, body in project_yara_rules():
        meta_match = META_RE.search(body)
        assert meta_match is not None, f"{path.name}:{rule_name} missing meta block"
        keys = set(META_KEY_RE.findall(meta_match.group("meta")))
        missing = REQUIRED_META_KEYS - keys
        assert not missing, f"{path.name}:{rule_name} missing metadata keys: {sorted(missing)}"


def test_project_yara_rules_avoid_broad_conditions() -> None:
    broad_patterns = ["any of them", "1 of them"]
    for path, rule_name, body in project_yara_rules():
        condition_match = CONDITION_RE.search(body)
        assert condition_match is not None, f"{path.name}:{rule_name} missing condition"
        condition = condition_match.group("condition").lower()
        for pattern in broad_patterns:
            assert pattern not in condition, f"{path.name}:{rule_name} uses broad condition: {pattern}"


def test_project_yara_rules_do_not_match_benign_demo_text() -> None:
    benign_text = (
        b"RAMSight benign validation text. "
        b"This may mention powershell, rundll32.exe, and http://example.invalid separately, "
        b"but it should not contain enough combined context for a triage hit."
    )
    for path in project_yara_files():
        compiled = yara.compile(filepath=str(path))
        assert compiled.match(data=benign_text) == []


def test_project_yara_rules_match_safe_synthetic_context() -> None:
    compiled = yara.compile(filepath=str(YARA_RULES_DIR / "ramsight_memory_triage_demo.yar"))
    synthetic_context = (
        b"VirtualAllocEx WriteProcessMemory CreateRemoteThread PAGE_EXECUTE_READWRITE "
        b"powershell -EncodedCommand FromBase64String Invoke-Expression"
    )
    matches = {match.rule for match in compiled.match(data=synthetic_context)}
    assert "RAMSight_Memory_ProcessInjection_API_Cluster" in matches
    assert "RAMSight_Memory_PowerShell_EncodedCommand_Context" in matches
